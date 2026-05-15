"""Integration-тесты pipeline M-2 (webhook → diff → filter).

Контекст T-010 (QA M-2):
  - стык трёх компонентов (`WebhookReceiver` → `GitHubAdapter.fetch_pr_diff` →
    `DiffFilter.apply`) собирается ровно так, как в `app.create_app(...)`,
    но `GitHubAdapter` ходит в API через `httpx.MockTransport` —
    никаких реальных сетевых вызовов.
  - HMAC-подпись webhook'а считается «настоящим» алгоритмом (`hmac.new(...)`),
    чтобы покрыть путь подписи целиком.
  - `BackgroundTasks` FastAPI выполняет `PipelineOrchestrator.process_pr`
    синхронно после ответа — `TestClient.__exit__` дожидается выполнения.

Сценарии (минимум 5 из DoD T-010):
  1. Валидный PR с одним Python-файлом + README + lock-файлом → 1 файл
     прошёл, 2 отфильтрованы; pipeline помечает done.
  2. PR с одними бинарями/локами → 0 прошло, summary-empty.
  3. Force-push (повторный synchronize с новым head_sha) → второй pipeline
     запускается, оба завершаются успехом.
  4. Draft PR (action=opened, draft=true, skip_drafts=true) и `closed`-action →
     200 ignored, pipeline НЕ запускается.
  5. Empty diff (PR без файлов) → 0 файлов, не падает, mark_pr_done.

Запуск:
  PYTHONPATH=src pytest tests/integration/test_pipeline_m2.py -v

Зависимости теста (`fastapi`, `httpx`, `pydantic`) подключаются через
`importorskip` — в окружении без них модуль пропускается целиком (политика
проекта «не ставить пакеты», прогон возложен на CI).
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import pytest

# --- Skip-on-missing-deps ---------------------------------------------------
fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
pytest.importorskip("pydantic")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sunsec.config.settings import Settings  # noqa: E402
from sunsec.filter import build_filter_from_settings  # noqa: E402
from sunsec.pipeline.orchestrator import (  # noqa: E402
    PipelineOrchestrator,
    idempotency_key,
)
from sunsec.state.memory import InMemoryStateStore  # noqa: E402
from sunsec.vcs.github import GitHubAdapter  # noqa: E402
from sunsec.webhook.router import build_router  # noqa: E402
from sunsec.webhook.service import WebhookService  # noqa: E402

SECRET = "integration-secret-please-rotate"


# --- Helpers ----------------------------------------------------------------


def _sign(secret: str, body: bytes) -> str:
    """Считает X-Hub-Signature-256 как реальный GitHub."""
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _payload(
    *,
    action: str = "opened",
    repo_full_name: str = "alice/proj",
    pr_number: int = 42,
    head_sha: str = "head" + "0" * 36,
    base_sha: str = "base" + "0" * 36,
    draft: bool = False,
) -> dict[str, Any]:
    """Минимально-валидный GitHub PR webhook payload (соответствует
    `GitHubPullRequestEvent` Pydantic-схеме)."""
    user = {"login": "alice", "id": 1}
    repo = {"full_name": repo_full_name, "owner": user}
    return {
        "action": action,
        "number": pr_number,
        "pull_request": {
            "id": 100,
            "number": pr_number,
            "state": "open",
            "title": "integration test PR",
            "head": {"sha": head_sha, "ref": "feature", "repo": repo},
            "base": {"sha": base_sha, "ref": "main", "repo": repo},
            "draft": draft,
            "user": user,
        },
        "repository": repo,
        "sender": user,
    }


def _file_item(
    filename: str,
    *,
    status: str = "modified",
    patch: str | None = "@@ -1,1 +1,2 @@\n x\n+y\n",
    previous_filename: str | None = None,
) -> dict[str, Any]:
    """Описание одного файла в GitHub /pulls/{n}/files API."""
    item: dict[str, Any] = {"filename": filename, "status": status}
    if patch is not None:
        item["patch"] = patch
    if previous_filename is not None:
        item["previous_filename"] = previous_filename
    return item


def _json_response(
    status: int, body: Any, headers: dict[str, str] | None = None
) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
    )


def _build_handler(
    *,
    repo: str = "alice/proj",
    pr_number: int = 42,
    head_sha: str = "head" + "0" * 36,
    base_sha: str = "base" + "0" * 36,
    files_per_call: dict[str, list[dict[str, Any]]] | None = None,
    files_default: list[dict[str, Any]] | None = None,
):
    """Возвращает MockTransport-handler, который:
      - На `GET /repos/{repo}/pulls/{n}` отдаёт {head.sha, base.sha} из
        `head_sha`/`base_sha`. Если `files_per_call` передан, head_sha
        переключается по очередному обращению (force-push симуляция).
      - На `GET /repos/{repo}/pulls/{n}/files` отдаёт либо записи из
        `files_per_call[current_head_sha]`, либо `files_default`.
    """
    pr_path = f"/repos/{repo}/pulls/{pr_number}"
    files_path = f"/repos/{repo}/pulls/{pr_number}/files"

    state = {"pr_calls": 0}
    head_shas = (
        list(files_per_call.keys()) if files_per_call else [head_sha]
    )

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == pr_path:
            idx = min(state["pr_calls"], len(head_shas) - 1)
            cur = head_shas[idx]
            state["pr_calls"] += 1
            return _json_response(
                200,
                {
                    "number": pr_number,
                    "head": {"sha": cur},
                    "base": {"sha": base_sha},
                },
            )
        if req.url.path == files_path:
            # Берём файлы текущей итерации (последний выбранный head_sha).
            idx = min(state["pr_calls"] - 1, len(head_shas) - 1)
            if idx < 0:
                idx = 0
            cur = head_shas[idx]
            files = (
                files_per_call[cur] if files_per_call else (files_default or [])
            )
            return _json_response(200, files)
        # «Не должно быть других вызовов» — явный 500, чтобы тест упал заметно.
        return _json_response(500, {"error": f"unexpected path {req.url.path}"})

    return handler


def _build_app_with_handler(
    handler,
    *,
    skip_drafts: bool = True,
) -> tuple[FastAPI, InMemoryStateStore, PipelineOrchestrator]:
    """Собирает FastAPI-app с реальным WebhookService + PipelineOrchestrator,
    но GitHubAdapter ходит через MockTransport (handler)."""
    settings = Settings(
        webhook_secret=SECRET,
        vcs_token="ghp_test_token",
        polza_api_key="dummy",
        log_format="json",
        skip_drafts=skip_drafts,
    )
    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport, base_url=settings.github_api_base)

    # Sleeper «no-op» — чтобы тесты не ждали реально (на случай rate-limit-кейсов
    # внутри handler'а; здесь мы 429 не имитируем, но safe-default).
    async def _no_sleep(_sec: float) -> None:  # pragma: no cover (не вызывается)
        return None

    vcs = GitHubAdapter(
        token=settings.vcs_token,
        api_base=settings.github_api_base,
        client=client,
        sleeper=_no_sleep,
        max_retries=settings.vcs_max_retries,
        files_page_size=settings.vcs_files_page_size,
        files_soft_limit=settings.vcs_files_soft_limit,
        rate_limit_wait_cap_seconds=settings.vcs_rate_limit_wait_cap_seconds,
    )
    state = InMemoryStateStore()
    diff_filter = build_filter_from_settings(settings)
    pipeline = PipelineOrchestrator(vcs=vcs, diff_filter=diff_filter, state=state)
    webhook_service = WebhookService(
        vcs=vcs,
        state=state,
        webhook_secret=settings.webhook_secret,
        skip_drafts=settings.skip_drafts,
    )

    app = FastAPI()
    app.include_router(build_router(service=webhook_service, pipeline=pipeline))
    app.state.state_store = state
    app.state.pipeline = pipeline
    app.state.vcs = vcs
    app.state.diff_filter = diff_filter
    return app, state, pipeline


# --- Сценарий 1: mixed PR (py + README + lock) -----------------------------


def test_mixed_pr_keeps_only_source_filters_readme_and_lock() -> None:
    """1 Python-файл проходит, README + lock-файл фильтруются.

    Доказывает связку webhook → diff → filter: PR-payload валидируется,
    подпись HMAC проходит, GitHubAdapter (через MockTransport) отдаёт
    три файла (один полезный, два мусорных), DiffFilter оставляет один.
    """
    head_sha = "h1" + "a" * 38
    handler = _build_handler(
        head_sha=head_sha,
        files_default=[
            _file_item(
                "src/app.py",
                patch="@@ -1,2 +1,3 @@\n a\n-b\n+B\n+SECRET=\"abc\"\n",
            ),
            _file_item("README.md", patch="@@ -1 +1 @@\n-old\n+new docs\n"),
            _file_item("poetry.lock", patch=None),
        ],
    )
    app, state, _pipeline = _build_app_with_handler(handler)

    body = json.dumps(
        _payload(action="opened", head_sha=head_sha)
    ).encode("utf-8")
    sig = _sign(SECRET, body)

    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "int-mixed-1",
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 202, resp.text
    body_json = resp.json()
    assert body_json["status"] == "accepted"
    assert body_json["head_sha"] == head_sha

    # Pipeline должен пометить ключ как done.
    key = idempotency_key_from_response(body_json)
    assert key in state._done, f"expected {key} in _done, got {state._done}"
    assert key not in state._inprogress


# --- Сценарий 2: только бинари/локи → 0 kept --------------------------------


def test_all_excluded_files_pipeline_completes_with_zero_kept() -> None:
    """PR со всеми «мусорными» файлами → 0 kept, pipeline не падает, done."""
    head_sha = "h2" + "b" * 38
    handler = _build_handler(
        head_sha=head_sha,
        files_default=[
            _file_item("README.md", patch="@@ -1 +1 @@\n-x\n+y\n"),
            _file_item("yarn.lock", patch=None),
            _file_item("image.png", patch=None),  # GitHub Binary
            _file_item("docs/notes.txt", patch="@@ -1 +1 @@\n-a\n+b\n"),
        ],
    )
    app, state, _pipeline = _build_app_with_handler(handler)

    body = json.dumps(
        _payload(action="opened", head_sha=head_sha)
    ).encode("utf-8")
    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(SECRET, body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "int-allexcl-1",
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 202

    # Pipeline дошёл до конца (даже если 0 файлов прошли) → done.
    key = idempotency_key_from_response(resp.json())
    assert key in state._done
    assert key not in state._inprogress


# --- Сценарий 3: force-push (synchronize с новым head_sha) ------------------


def test_force_push_synchronize_runs_pipeline_twice() -> None:
    """Два webhook'а с разными head_sha → две полные итерации pipeline.

    Доказывает что idempotency-ключ зависит от head_sha (см. ADR-5 +
    `idempotency_key`), и force-push (новый head_sha) НЕ блокируется
    предыдущей резервацией.
    """
    head_old = "h3" + "c" * 38
    head_new = "h3" + "d" * 38

    handler = _build_handler(
        files_per_call={
            head_old: [_file_item("src/x.py")],
            head_new: [
                _file_item(
                    "src/x.py",
                    patch="@@ -1 +1,2 @@\n a\n+import os\n",
                )
            ],
        },
    )
    app, state, _pipeline = _build_app_with_handler(handler)

    with TestClient(app) as client:
        # 1) Первый synchronize (старый head_sha)
        body1 = json.dumps(
            _payload(action="synchronize", head_sha=head_old)
        ).encode("utf-8")
        r1 = client.post(
            "/webhook/github",
            content=body1,
            headers={
                "X-Hub-Signature-256": _sign(SECRET, body1),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "int-force-old",
                "Content-Type": "application/json",
            },
        )

        # 2) Второй synchronize (force-push → новый head_sha)
        body2 = json.dumps(
            _payload(action="synchronize", head_sha=head_new)
        ).encode("utf-8")
        r2 = client.post(
            "/webhook/github",
            content=body2,
            headers={
                "X-Hub-Signature-256": _sign(SECRET, body2),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "int-force-new",
                "Content-Type": "application/json",
            },
        )

    assert r1.status_code == 202
    assert r2.status_code == 202
    # Оба ключа должны быть в done — два независимых прогона.
    key_old = idempotency_key_from_response(r1.json())
    key_new = idempotency_key_from_response(r2.json())
    assert key_old != key_new
    assert key_old in state._done
    assert key_new in state._done


# --- Сценарий 4: draft PR / non-whitelist action → ignored ------------------


def test_draft_pr_is_ignored_pipeline_not_invoked() -> None:
    """Draft PR (skip_drafts=True) → 200 ignored, pipeline не запускается.

    Проверка контракта system_design §3.1 «skip drafts» + ADR-5.
    """
    head_sha = "h4" + "e" * 38
    handler = _build_handler(
        head_sha=head_sha, files_default=[_file_item("src/a.py")]
    )
    app, state, _pipeline = _build_app_with_handler(handler, skip_drafts=True)

    body = json.dumps(
        _payload(action="opened", head_sha=head_sha, draft=True)
    ).encode("utf-8")

    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(SECRET, body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "int-draft-1",
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    assert "draft" in resp.json()["reason"].lower()
    # Pipeline не запускался → ключ нигде не зафиксирован.
    assert len(state._done) == 0
    assert len(state._inprogress) == 0


def test_non_whitelist_action_is_ignored_pipeline_not_invoked() -> None:
    """action=closed → 200 ignored. Pipeline НЕ запускается.

    Проверка whitelist `opened/synchronize/reopened/ready_for_review`.
    """
    head_sha = "h4b" + "f" * 37
    handler = _build_handler(
        head_sha=head_sha, files_default=[_file_item("src/a.py")]
    )
    app, state, _pipeline = _build_app_with_handler(handler)

    body = json.dumps(_payload(action="closed", head_sha=head_sha)).encode(
        "utf-8"
    )

    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(SECRET, body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "int-closed-1",
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    assert resp.json()["detail"] == "closed"
    assert len(state._done) == 0
    assert len(state._inprogress) == 0


# --- Сценарий 5: empty diff (no files) --------------------------------------


def test_empty_diff_pipeline_completes_without_failure() -> None:
    """PR без файлов → pipeline не падает, mark_pr_done вызван.

    Edge-case: VCS вернул пустой массив `files`. DiffFilter должен сделать
    пустой FilteredDiff (0 kept, 0 excluded), pipeline → done.
    """
    head_sha = "h5" + "a" * 38
    handler = _build_handler(head_sha=head_sha, files_default=[])
    app, state, _pipeline = _build_app_with_handler(handler)

    body = json.dumps(
        _payload(action="opened", head_sha=head_sha)
    ).encode("utf-8")

    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(SECRET, body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "int-empty-1",
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 202
    key = idempotency_key_from_response(resp.json())
    # Pipeline корректно завершён, даже на пустом diff'е.
    assert key in state._done


# --- Сценарий 6 (bonus): edited (non-whitelist) → ignored -------------------


def test_edited_action_ignored_and_does_not_trigger_pipeline() -> None:
    """action=edited (PR title/body changed) → 200 ignored, без анализа."""
    head_sha = "h6" + "a" * 38
    handler = _build_handler(
        head_sha=head_sha, files_default=[_file_item("src/a.py")]
    )
    app, state, _pipeline = _build_app_with_handler(handler)

    body = json.dumps(_payload(action="edited", head_sha=head_sha)).encode(
        "utf-8"
    )
    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": _sign(SECRET, body),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "int-edited-1",
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    assert len(state._done) == 0


# --- Helpers (post-response) ------------------------------------------------


def idempotency_key_from_response(body_json: dict[str, Any]) -> str:
    """Собрать idempotency-ключ из webhook-ответа (repo + pr_number + head_sha)."""
    return f"{body_json['repo']}#{body_json['pr_number']}@{body_json['head_sha']}"
