"""GitHubAdapter — реализация VCSAdapter поверх GitHub REST API.

T-008: реализован метод `fetch_pr_diff(repo, pr_number) -> PRDiff` через
GitHub Files API (`/pulls/{n}/files`) — он возвращает структурированный
patch на файл, ровно то, что нам нужно для `PRDiff` (system_design §4.2).
Дополнительный вызов `/pulls/{n}` нужен для `head.sha` / `base.sha`,
т.к. Files API их не возвращает.

Ключевые свойства:
- async через `httpx.AsyncClient` (общий с остальным кодом).
- Pagination Files API через `?per_page=100&page=N`, остановка на пустой
  странице или при отсутствии `Link: rel="next"`.
- Soft-limit `vcs_files_soft_limit` (default 300): если PR содержит больше
  файлов, логируем warning и обрезаем (по NFR — не падаем; T-009 урежет ещё).
- Retry-backoff на 5xx: 3 ретрая, exponential 0.5s / 1.0s / 2.0s + jitter.
- 429 / `X-RateLimit-Remaining: 0` → ожидание `X-RateLimit-Reset` или
  `Retry-After` (cap `vcs_rate_limit_wait_cap_seconds`, default 60s).
- 401/403 (без rate-limit headers) → `AuthError` без ретраев.
- 404 → `NotFoundError` без ретраев.
- Токен подключается через `Authorization: Bearer <token>`; в логах
  присутствуют только safe-поля (`repo`, `pr_number`, `status_code`,
  `duration_ms`, `files_count`, `attempt`).
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import random
import time
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from sunsec.contracts import (
    DiffFile,
    InlineComment,
    PostedComment,
    PostedReview,
    PRDiff,
)
from sunsec.vcs.base import (
    AuthError,
    NotFoundError,
    RateLimitError,
    VCSAdapter,
    VCSAdapterError,
)
from sunsec.vcs.patch_parser import parse_patch

log = logging.getLogger(__name__)

# Backoff defaults (exponential, начиная с 0.5s).
_BACKOFF_BASE_SECONDS = 0.5
_BACKOFF_JITTER_SECONDS = 0.25


class GitHubAdapter(VCSAdapter):
    """GitHub реализация VCSAdapter. См. system_design §3.2, ADR-1."""

    def __init__(
        self,
        token: str,
        api_base: str = "https://api.github.com",
        *,
        http_timeout_seconds: float = 30.0,
        max_retries: int = 3,
        files_page_size: int = 100,
        files_soft_limit: int = 300,
        rate_limit_wait_cap_seconds: float = 60.0,
        client: Optional[httpx.AsyncClient] = None,
        sleeper: Any = None,
    ) -> None:
        # ВАЖНО: токен НЕ логируется и НЕ кладётся в __repr__.
        self._token = token
        self._api_base = api_base.rstrip("/")
        self._timeout = http_timeout_seconds
        self._max_retries = max_retries
        self._files_page_size = max(1, min(100, files_page_size))
        self._files_soft_limit = max(1, files_soft_limit)
        self._rate_limit_wait_cap = max(0.0, rate_limit_wait_cap_seconds)
        # `client` можно подменить в тестах: например,
        # `httpx.AsyncClient(transport=httpx.MockTransport(handler))`.
        self._external_client = client
        # `sleeper` — асинхронная функция `async def(sec) -> None`. По умолчанию
        # `asyncio.sleep`; в тестах удобно подменить на стаб (мгновенный или
        # счётчик).
        self._sleep = sleeper if sleeper is not None else asyncio.sleep

    def __repr__(self) -> str:  # безопасный repr — без токена
        return f"GitHubAdapter(api_base={self._api_base!r})"

    # --- Sync ---

    def verify_signature(self, raw_body: bytes, signature_header: str, secret: str) -> bool:
        """HMAC-SHA256 от raw_body, сравнение с `X-Hub-Signature-256`.

        Формат заголовка GitHub: ``sha256=<hex>``. Сравнение через
        `hmac.compare_digest`, без раннего выхода (timing-safe).
        """
        if not signature_header or not secret:
            return False
        if not signature_header.startswith("sha256="):
            return False
        expected = signature_header.split("=", 1)[1].strip()
        mac = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, mac)

    # --- Async: fetch_pr_diff (T-008) ---

    async def fetch_pr_diff(self, repo: str, pr_number: int) -> PRDiff:
        """Выкачивает structured diff PR через Files API.

        Алгоритм:
          1. `GET /repos/{repo}/pulls/{n}` → берём `head.sha` / `base.sha`.
          2. `GET /repos/{repo}/pulls/{n}/files?per_page=100&page=N` —
             пагинация до пустой страницы / отсутствия `Link: rel="next"`.
          3. Для каждого файла парсим `patch` через `parse_patch` → `DiffHunk[]`.
          4. Собираем `PRDiff` (Pydantic — extra=forbid, валидирует структуру).

        Бросает:
          - `NotFoundError` — 404.
          - `AuthError` — 401/403 (без rate-limit-headers).
          - `RateLimitError` — все ретраи на 429/rate-limit исчерпаны.
          - `VCSAdapterError` — 5xx после ретраев или сетевая ошибка.
        """
        start = time.monotonic()
        external = self._external_client is not None
        client = self._external_client or httpx.AsyncClient(
            timeout=self._timeout, base_url=self._api_base
        )
        # Для внешнего клиента не должны менять base_url. Если внешний клиент
        # без base_url — используем абсолютные URL ниже (build_url).
        try:
            pr_json = await self._get_json(client, f"/repos/{repo}/pulls/{pr_number}")
            head_sha = (pr_json.get("head") or {}).get("sha") or ""
            base_sha = (pr_json.get("base") or {}).get("sha") or ""

            files_raw = await self._fetch_all_files(client, repo, pr_number)
        finally:
            if not external:
                await client.aclose()

        diff_files: list[DiffFile] = []
        for raw in files_raw:
            try:
                diff_files.append(_normalize_file(raw))
            except Exception as exc:  # noqa: BLE001
                # Не падаем на одном битом файле — логируем и идём дальше.
                log.warning(
                    "vcs_file_normalize_failed",
                    extra={
                        "repo": repo,
                        "pr_number": pr_number,
                        "filename": (raw or {}).get("filename"),
                        "error_type": type(exc).__name__,
                    },
                )

        duration_ms = int((time.monotonic() - start) * 1000)
        log.info(
            "vcs_fetch_pr_diff_completed",
            extra={
                "repo": repo,
                "pr_number": pr_number,
                "head_sha": head_sha,
                "base_sha": base_sha,
                "files_count": len(diff_files),
                "duration_ms": duration_ms,
            },
        )

        return PRDiff(
            repo=repo,
            pr_number=pr_number,
            head_sha=head_sha,
            base_sha=base_sha,
            files=diff_files,
        )

    async def _fetch_all_files(
        self, client: httpx.AsyncClient, repo: str, pr_number: int
    ) -> list[dict[str, Any]]:
        """Pagination ?per_page=100&page=N. Стоп — пустая страница или нет `next`."""
        collected: list[dict[str, Any]] = []
        page = 1
        soft_limit_hit = False
        while True:
            path = (
                f"/repos/{repo}/pulls/{pr_number}/files"
                f"?per_page={self._files_page_size}&page={page}"
            )
            resp = await self._request_with_retry(client, "GET", path)
            try:
                page_json = resp.json()
            except ValueError as exc:
                raise VCSAdapterError(
                    f"GitHub /pulls/{pr_number}/files returned non-JSON"
                ) from exc

            if not isinstance(page_json, list):
                raise VCSAdapterError(
                    f"GitHub /pulls/{pr_number}/files returned non-array body"
                )
            if not page_json:
                break

            collected.extend(page_json)

            if len(collected) >= self._files_soft_limit:
                soft_limit_hit = True
                # Обрезаем до soft-limit — лишние страницы можем не запрашивать
                collected = collected[: self._files_soft_limit]
                break

            # Если получили меньше чем page_size, дальше точно пусто.
            if len(page_json) < self._files_page_size:
                break

            # Дополнительный сигнал — `Link: rel="next"`. Если нет — больше нечего.
            link = resp.headers.get("Link") or resp.headers.get("link")
            if link and 'rel="next"' not in link:
                break

            page += 1

        if soft_limit_hit:
            log.warning(
                "vcs_files_soft_limit_hit",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "files_soft_limit": self._files_soft_limit,
                    "files_returned": len(collected),
                },
            )

        return collected

    async def _get_json(self, client: httpx.AsyncClient, path: str) -> dict[str, Any]:
        resp = await self._request_with_retry(client, "GET", path)
        try:
            data = resp.json()
        except ValueError as exc:
            raise VCSAdapterError(f"GitHub {path} returned non-JSON body") from exc
        if not isinstance(data, dict):
            raise VCSAdapterError(f"GitHub {path} returned non-object body")
        return data

    async def _request_with_retry(
        self,
        client: httpx.AsyncClient,
        method: str,
        path: str,
        *,
        body: Optional[dict[str, Any]] = None,
    ) -> httpx.Response:
        """Один запрос с retry-backoff. Возвращает 2xx-ответ или бросает.

        Стратегия:
          - 2xx → return.
          - 401/403 без rate-limit-маркеров → `AuthError`, без ретраев.
          - 404 → `NotFoundError`, без ретраев.
          - 429 / 403 c `X-RateLimit-Remaining: 0` → ожидание + повтор
            (учитываем `_max_retries`).
          - 5xx → exponential backoff (0.5/1.0/2.0 с + jitter) до `_max_retries`.
          - 4xx (прочие) → `VCSAdapterError`.
          - Network error (`httpx.RequestError`) → 5xx-стратегия.
        """
        url = path if path.startswith("http") else f"{self._api_base}{path}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "sunsec-bot/0.1",
        }
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        body_bytes: Optional[bytes] = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            try:
                body_bytes = json.dumps(body).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise VCSAdapterError(
                    f"GitHub {method} {_safe_path(path)}: body is not JSON-serializable"
                ) from exc

        last_exc: Exception | None = None
        # `_max_retries` — количество ретраев, всего попыток = +1.
        for attempt in range(0, self._max_retries + 1):
            try:
                resp = await client.request(
                    method, url, headers=headers, content=body_bytes
                )
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt >= self._max_retries:
                    log.warning(
                        "vcs_request_network_error_giveup",
                        extra={
                            "path": _safe_path(path),
                            "attempt": attempt,
                            "error_type": type(exc).__name__,
                        },
                    )
                    raise VCSAdapterError(
                        f"GitHub request failed: {type(exc).__name__}"
                    ) from exc
                await self._backoff(attempt)
                continue

            status = resp.status_code
            if 200 <= status < 300:
                return resp

            # 404 → нет PR / нет доступа.
            if status == 404:
                log.warning(
                    "vcs_request_not_found",
                    extra={"path": _safe_path(path), "status_code": status},
                )
                raise NotFoundError(f"GitHub 404: {_safe_path(path)}")

            # rate-limit обработка (429 и 403 с X-RateLimit-Remaining=0).
            if _is_rate_limited(resp):
                wait_s = _compute_rate_limit_wait(resp, self._rate_limit_wait_cap)
                log.warning(
                    "vcs_rate_limited",
                    extra={
                        "path": _safe_path(path),
                        "status_code": status,
                        "wait_seconds": wait_s,
                        "attempt": attempt,
                        "rate_limit_remaining": resp.headers.get("X-RateLimit-Remaining"),
                        "rate_limit_reset": resp.headers.get("X-RateLimit-Reset"),
                        "retry_after": resp.headers.get("Retry-After"),
                    },
                )
                if attempt >= self._max_retries:
                    raise RateLimitError(
                        f"GitHub rate-limit exhausted after {attempt + 1} attempt(s)"
                    )
                await self._sleep(wait_s)
                continue

            # 401/403 — точно auth, не rate-limit (т.к. _is_rate_limited вернул False).
            if status in (401, 403):
                log.error(
                    "vcs_request_auth_error",
                    extra={"path": _safe_path(path), "status_code": status},
                )
                raise AuthError(f"GitHub {status}: invalid or insufficient token")

            # 5xx → backoff.
            if status >= 500:
                log.warning(
                    "vcs_request_server_error",
                    extra={
                        "path": _safe_path(path),
                        "status_code": status,
                        "attempt": attempt,
                    },
                )
                if attempt >= self._max_retries:
                    raise VCSAdapterError(
                        f"GitHub server error {status} after {attempt + 1} attempt(s)"
                    )
                await self._backoff(attempt)
                continue

            # Прочие 4xx (422, 409, ...) — не ретраим.
            log.error(
                "vcs_request_client_error",
                extra={"path": _safe_path(path), "status_code": status},
            )
            raise VCSAdapterError(f"GitHub {status} on {_safe_path(path)}")

        # Защита от логической ошибки — на сюда мы не должны попасть.
        if last_exc is not None:  # pragma: no cover
            raise VCSAdapterError("GitHub request failed (unreachable)") from last_exc
        raise VCSAdapterError("GitHub request failed (unreachable)")  # pragma: no cover

    async def _backoff(self, attempt: int) -> None:
        # 0.5s → 1.0s → 2.0s → 4.0s ... + случайный jitter до 0.25s.
        delay = _BACKOFF_BASE_SECONDS * (2 ** attempt)
        delay += random.uniform(0.0, _BACKOFF_JITTER_SECONDS)
        await self._sleep(delay)

    # --- Async (T-016): публикация комментариев ---------------------------

    async def post_inline_comment(
        self,
        repo: str,
        pr_number: int,
        comment: InlineComment,
    ) -> PostedComment:
        """POST /repos/{repo}/pulls/{n}/comments — единичный review-comment.

        В MVP `CommentPublisher` пользуется `post_review` (один HTTP-вызов
        на всё). Метод оставлен ради соответствия Protocol'у и используется
        в edge-case сценариях (например, dialog-mode T-019).

        Для inline-комментариев GitHub требует `commit_id`. Если поле не
        задано — оставляем None в payload'е, GitHub ответит 422.
        """
        body = {
            "body": comment.body,
            "path": comment.path,
            "line": comment.line,
            "side": comment.side,
        }
        path = f"/repos/{repo}/pulls/{pr_number}/comments"
        data = await self._post_json(path, body)
        return _to_posted_comment(data)

    async def post_summary_comment(
        self,
        repo: str,
        pr_number: int,
        body: str,
        marker: str,
    ) -> PostedComment:
        """POST /repos/{repo}/issues/{n}/comments — обычный PR-комментарий.

        `marker` — HTML-комментарий идемпотентности; если в `body` его нет,
        добавляем в конец. Это страховка: вызывающий код мог забыть.
        """
        return await self.post_issue_comment(repo, pr_number, _ensure_marker(body, marker))

    async def post_issue_comment(
        self,
        repo: str,
        pr_number: int,
        body: str,
    ) -> PostedComment:
        """POST /repos/{repo}/issues/{n}/comments — обычный PR-комментарий.

        В отличие от `post_summary_comment` не делает manipulation над body —
        вызывающий уже сформировал markdown + маркер.
        """
        path = f"/repos/{repo}/issues/{pr_number}/comments"
        data = await self._post_json(path, {"body": body})
        return _to_posted_comment(data)

    async def post_review(
        self,
        repo: str,
        pr_number: int,
        comments: list[InlineComment],
        summary: str,
        marker: str,
        commit_id: Optional[str] = None,
    ) -> PostedReview:
        """POST /repos/{repo}/pulls/{n}/reviews — review с inline-комментариями.

        Полезная нагрузка:
          - `commit_id` (опц.) — sha PR HEAD; GitHub использует его для
            привязки строк к diff. Если не задан, GitHub берёт текущий HEAD.
          - `body` — summary (с HTML-маркером).
          - `event` — `COMMENT` (бот не аппрувит и не реджектит).
          - `comments[]` — массив `{path, line, side, body}`.

        Возвращает `PostedReview` с `review_id` и счётчиками. Поле
        `summary_posted` — True, если в payload'е был непустой `body`.
        """
        api_comments = [
            {
                "path": c.path,
                "line": c.line,
                "side": c.side,
                "body": c.body,
            }
            for c in comments
        ]
        body_with_marker = _ensure_marker(summary, marker) if summary else ""
        payload: dict[str, Any] = {
            "event": "COMMENT",
            "body": body_with_marker,
            "comments": api_comments,
        }
        if commit_id:
            payload["commit_id"] = commit_id

        path = f"/repos/{repo}/pulls/{pr_number}/reviews"
        data = await self._post_json(path, payload)
        review_id_raw = data.get("id") if isinstance(data, dict) else None
        review_id = int(review_id_raw) if isinstance(review_id_raw, int) else 0
        return PostedReview(
            review_id=review_id,
            comments_posted=len(api_comments),
            summary_posted=bool(body_with_marker),
            deduped=0,
            fallback_to_summary=0,
            skipped=False,
        )

    async def update_issue_comment(
        self,
        repo: str,
        comment_id: int,
        body: str,
    ) -> PostedComment:
        """PATCH /repos/{repo}/issues/comments/{id} — обновление текста."""
        path = f"/repos/{repo}/issues/comments/{comment_id}"
        data = await self._patch_json(path, {"body": body})
        return _to_posted_comment(data)

    async def list_review_comments(
        self, repo: str, pr_number: int
    ) -> list[PostedComment]:
        """GET /repos/{repo}/pulls/{n}/comments (paginated)."""
        path = f"/repos/{repo}/pulls/{pr_number}/comments"
        items = await self._get_paginated(path)
        return [_to_posted_comment(item) for item in items if isinstance(item, dict)]

    async def list_issue_comments(
        self, repo: str, pr_number: int
    ) -> list[PostedComment]:
        """GET /repos/{repo}/issues/{n}/comments (paginated)."""
        path = f"/repos/{repo}/issues/{pr_number}/comments"
        items = await self._get_paginated(path)
        return [_to_posted_comment(item) for item in items if isinstance(item, dict)]

    async def set_status_check(
        self,
        repo: str,
        commit_sha: str,
        state: str,
        description: str,
        context: str,
    ) -> None:
        raise NotImplementedError("Реализация в T-018 (post-MVP)")

    # --- Reply mode (T-019) -----------------------------------------------

    async def reply_to_review_comment(
        self,
        repo: str,
        pr_number: int,
        in_reply_to_id: int,
        body: str,
    ) -> PostedComment:
        """POST /repos/{repo}/pulls/{pr}/comments/{id}/replies — ответ в той
        же ветке inline-обсуждения. GitHub сам ставит `in_reply_to_id` и
        привязку к review."""
        path = f"/repos/{repo}/pulls/{pr_number}/comments/{int(in_reply_to_id)}/replies"
        data = await self._post_json(path, {"body": body})
        return _to_posted_comment(data)

    async def get_review_comment(
        self,
        repo: str,
        comment_id: int,
    ) -> PostedComment:
        """GET /repos/{repo}/pulls/comments/{id} — один inline-комментарий."""
        path = f"/repos/{repo}/pulls/comments/{int(comment_id)}"
        external = self._external_client is not None
        client = self._external_client or httpx.AsyncClient(
            timeout=self._timeout, base_url=self._api_base
        )
        try:
            data = await self._get_json(client, path)
        finally:
            if not external:
                await client.aclose()
        return _to_posted_comment(data)

    # --- Webhook management (Console UI auto-install) ---------------------

    async def create_webhook(
        self,
        repo: str,
        webhook_url: str,
        secret: str,
        *,
        events: tuple[str, ...] = (
            "pull_request",
            "issue_comment",
            "pull_request_review_comment",
        ),
    ) -> dict[str, Any]:
        """POST /repos/{owner}/{repo}/hooks — создаёт webhook на репо.

        Возвращает декодированное тело ответа GitHub (содержит `id`, `url`,
        `config`, `events`, ...). Для нас критичен `id` — сохраняем в БД,
        чтобы потом уметь удалить тот же hook.

        Требует у токена scope `admin:repo_hook` (или `repo` для приватных).
        При недостатке прав — `AuthError`. На 422 (duplicate webhook URL) —
        `VCSAdapterError`.
        """
        path = f"/repos/{repo}/hooks"
        body: dict[str, Any] = {
            "name": "web",
            "active": True,
            "events": list(events),
            "config": {
                "url": webhook_url,
                "content_type": "json",
                "secret": secret,
                "insecure_ssl": "0",
            },
        }
        return await self._post_json(path, body)

    async def delete_webhook(self, repo: str, hook_id: int) -> bool:
        """DELETE /repos/{owner}/{repo}/hooks/{hook_id}.

        Возвращает `True`, если webhook удалён или уже отсутствовал (404).
        Прочие ошибки (auth/server) пробрасываем.
        """
        path = f"/repos/{repo}/hooks/{int(hook_id)}"
        external = self._external_client is not None
        client = self._external_client or httpx.AsyncClient(
            timeout=self._timeout, base_url=self._api_base
        )
        try:
            try:
                await self._request_with_retry(client, "DELETE", path)
            except NotFoundError:
                # Хук уже удалён на стороне GitHub — для нас это «успех».
                return True
        finally:
            if not external:
                await client.aclose()
        return True

    # --- Внутренние helper'ы для POST / PATCH / paginated GET --------------

    async def _post_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return await self._send_json("POST", path, body)

    async def _patch_json(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        return await self._send_json("PATCH", path, body)

    async def _send_json(
        self, method: str, path: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        external = self._external_client is not None
        client = self._external_client or httpx.AsyncClient(
            timeout=self._timeout, base_url=self._api_base
        )
        try:
            resp = await self._request_with_retry(client, method, path, body=body)
        finally:
            if not external:
                await client.aclose()
        try:
            data = resp.json()
        except ValueError as exc:
            raise VCSAdapterError(
                f"GitHub {method} {_safe_path(path)} returned non-JSON body"
            ) from exc
        if not isinstance(data, dict):
            raise VCSAdapterError(
                f"GitHub {method} {_safe_path(path)} returned non-object body"
            )
        return data

    async def _get_paginated(self, path: str) -> list[dict[str, Any]]:
        """GET с автоматической pagination через `?per_page=100&page=N`.

        Останавливаемся на пустой странице или при `len(page) < per_page`.
        Soft-cap — `_files_soft_limit` (используем тот же лимит — для
        review/issue-comments это с большим запасом, в MVP единицы-десятки).
        """
        external = self._external_client is not None
        client = self._external_client or httpx.AsyncClient(
            timeout=self._timeout, base_url=self._api_base
        )
        collected: list[dict[str, Any]] = []
        try:
            page = 1
            while True:
                sep = "&" if "?" in path else "?"
                page_path = f"{path}{sep}per_page={self._files_page_size}&page={page}"
                resp = await self._request_with_retry(client, "GET", page_path)
                try:
                    page_json = resp.json()
                except ValueError as exc:
                    raise VCSAdapterError(
                        f"GitHub {_safe_path(path)} returned non-JSON"
                    ) from exc
                if not isinstance(page_json, list):
                    raise VCSAdapterError(
                        f"GitHub {_safe_path(path)} returned non-array body"
                    )
                if not page_json:
                    break
                collected.extend(page_json)
                if len(collected) >= self._files_soft_limit:
                    collected = collected[: self._files_soft_limit]
                    log.warning(
                        "vcs_paginate_soft_limit_hit",
                        extra={
                            "path": _safe_path(path),
                            "items_returned": len(collected),
                        },
                    )
                    break
                if len(page_json) < self._files_page_size:
                    break
                page += 1
        finally:
            if not external:
                await client.aclose()
        return collected


# --- helpers --------------------------------------------------------------


_GITHUB_STATUS_TO_PRDIFF: dict[str, str] = {
    "added": "added",
    "modified": "modified",
    "removed": "removed",
    "renamed": "renamed",
    # GitHub также может вернуть "changed" / "copied" — нормализуем.
    "changed": "modified",
    "copied": "added",
    "unchanged": "modified",
}


def _normalize_file(raw: dict[str, Any]) -> DiffFile:
    """GitHub Files API item → `DiffFile`. Бросает на отсутствии обязательных полей."""
    path = raw.get("filename")
    if not isinstance(path, str) or not path:
        raise ValueError("filename missing")

    raw_status = raw.get("status") or "modified"
    status = _GITHUB_STATUS_TO_PRDIFF.get(str(raw_status), "modified")

    old_path = raw.get("previous_filename") if status == "renamed" else None

    patch = raw.get("patch")
    # `patch` отсутствует для бинарей и слишком больших файлов (GitHub-side
    # отсечка ~1Mб). Тогда — пустые hunks + is_binary эвристика.
    is_binary = patch is None or (
        isinstance(patch, str)
        and patch.startswith("Binary files ")
    )
    if is_binary:
        hunks = []
    else:
        hunks = parse_patch(patch if isinstance(patch, str) else None)

    return DiffFile(
        path=path,
        status=status,  # type: ignore[arg-type]
        old_path=old_path,
        is_binary=is_binary,
        hunks=hunks,
    )


def _is_rate_limited(resp: httpx.Response) -> bool:
    """GitHub индикаторы rate-limit:
    - 429 (вторичный лимит / abuse detection)
    - 403 c `X-RateLimit-Remaining: 0` (основной лимит)
    """
    if resp.status_code == 429:
        return True
    if resp.status_code == 403:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining is not None:
            try:
                return int(remaining) == 0
            except ValueError:
                return False
    return False


def _compute_rate_limit_wait(resp: httpx.Response, cap_seconds: float) -> float:
    """Вычисляет, сколько ждать перед повтором.

    Приоритет:
      1. `Retry-After` (секунды или HTTP-дата — мы поддерживаем только секунды).
      2. `X-RateLimit-Reset` (unix epoch) − текущее время.
      3. fallback — 1.0с.
    Cap'ится `cap_seconds`.
    """
    retry_after = resp.headers.get("Retry-After")
    if retry_after:
        try:
            return min(max(0.0, float(retry_after)), cap_seconds)
        except ValueError:
            pass

    reset = resp.headers.get("X-RateLimit-Reset")
    if reset:
        try:
            reset_ts = int(reset)
            delta = reset_ts - int(time.time())
            return min(max(0.0, float(delta)), cap_seconds)
        except ValueError:
            pass

    return min(1.0, cap_seconds)


def _safe_path(path: str) -> str:
    """Чистка path от query-параметров для логов (без секретов всё равно, но
    короче и стабильнее по cardinality)."""
    return path.split("?", 1)[0]


def _to_posted_comment(raw: dict[str, Any]) -> PostedComment:
    """GitHub-comment dict → доменный `PostedComment`.

    Терпимо относится к отсутствию полей (минимально нужны `id`, `html_url`).
    `created_at` парсим из ISO; если нет — `now(UTC)` (это не ломает
    дедупликацию по маркеру).
    """
    raw_id = raw.get("id", 0)
    try:
        id_int = int(raw_id) if not isinstance(raw_id, bool) else 0
    except (TypeError, ValueError):
        id_int = 0
    url = raw.get("html_url") or raw.get("url") or ""
    if not isinstance(url, str):
        url = ""
    posted_at = _parse_iso_datetime(raw.get("created_at") or raw.get("updated_at"))
    body = raw.get("body")
    body_str = body if isinstance(body, str) else None
    return PostedComment(
        id=id_int,
        url=url,
        posted_at=posted_at,
        body=body_str,
    )


def _parse_iso_datetime(value: Any) -> datetime:
    """ISO-8601 (Z-suffix или offset) → datetime; иначе now(UTC)."""
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    return datetime.now(tz=timezone.utc)


def _ensure_marker(body: str, marker: str) -> str:
    """Добавляет `marker` в конец `body`, если его там ещё нет.

    Используется для подстраховки: вызывающие методы (CommentPublisher.publish_*)
    уже формируют body с маркером, но если кто-то вызовет `post_summary_comment`
    или `post_review` без маркера — мы добавим его, чтобы идемпотентность не
    ломалась на стороне GitHub.
    """
    if not marker or marker in body:
        return body
    sep = "" if body.endswith("\n") else "\n"
    return f"{body}{sep}\n{marker}"


__all__ = ["GitHubAdapter", "VCSAdapterError", "AuthError", "NotFoundError", "RateLimitError"]
