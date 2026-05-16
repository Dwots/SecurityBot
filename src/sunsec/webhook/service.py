"""WebhookService — бизнес-логика WebhookReceiver (system_design §3.1).

Выделена из FastAPI-роутера, чтобы:
1. Тесты могли вызывать её без TestClient (быстрее, нагляднее).
2. В будущем (GitLab/Bitbucket) подменять адаптер, не дублируя HTTP-слой.

Алгоритм (см. system_design §3.1):
  1. Прочитать raw body и заголовки.
  2. Проверить HMAC через `verify_signature` (constant-time).
  3. Отфильтровать event type / action / draft.
  4. Распарсить Pydantic-моделью `GitHubPullRequestEvent`.
  5. Проверить idempotency (`X-GitHub-Delivery` + head_sha).
  6. Зарегистрировать PR в state и вернуть `EnqueueAnalysis` —
     роутер запустит `pipeline.process_pr(event)` как background task.

Возврат — типизированный `WebhookOutcome` (sealed-like enum-pattern). Это
держит «решение что отвечать» на стороне сервиса, а роутер просто маппит
исход в HTTP-статус (см. system_design §4.1 «Ошибки WebhookReceiver»).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping, Optional, Union

from pydantic import ValidationError

from sunsec.contracts import (
    GitHubIssueCommentEvent,
    GitHubPullRequestEvent,
    GitHubPullRequestReviewCommentEvent,
)
from sunsec.pipeline.orchestrator import idempotency_key
from sunsec.state.base import StateStore
from sunsec.vcs.base import VCSAdapter
from sunsec.webhook.repo_resolver import (
    ResolvedCredentials,
    resolve_webhook_credentials,
)

# Маркер, по которому распознаём наши собственные комментарии в parent-thread'е
# (как inline, так и issue). Любой комментарий бота содержит подстроку
# `<!-- sunsec:bot:v1:...` — поиск по ней даёт self-detect без отдельного
# хранилища истории. См. comments/publisher.py.
_BOT_COMMENT_MARKER_PREFIX = "sunsec:bot:v1:"

log = logging.getLogger(__name__)

# Whitelist actions, на которые мы реально запускаем анализ.
# `ready_for_review` (черновик → готов) тоже триггерит, как и в system_design §3.1.
ACTION_WHITELIST: frozenset[str] = frozenset({"opened", "synchronize", "reopened", "ready_for_review"})

# Reply-mode (T-019): какие comment-actions триггерят анализ. Только новые
# комментарии — `edited`/`deleted` пропускаем, чтобы избежать петель.
REPLY_ACTION_WHITELIST: frozenset[str] = frozenset({"created"})

# Reply-mode: какие event_type'ы webhook-а считаем reply-кандидатами.
REPLY_EVENT_TYPES: frozenset[str] = frozenset({"issue_comment", "pull_request_review_comment"})

# Заголовки GitHub Webhook (стандарт, см. docs.github.com/webhooks).
HEADER_EVENT = "x-github-event"
HEADER_SIGNATURE = "x-hub-signature-256"
HEADER_DELIVERY = "x-github-delivery"


# --- Исходы (sealed union) -------------------------------------------------


@dataclass(frozen=True)
class InvalidSignature:
    """HMAC не сошёлся. 401."""

    reason: str = "invalid signature"


@dataclass(frozen=True)
class BadRequest:
    """Payload не парсится / отсутствует заголовок. 400."""

    reason: str


@dataclass(frozen=True)
class Ignored:
    """Событие пропущено осознанно (action не в whitelist / draft / wrong event). 200."""

    reason: str
    detail: Optional[str] = None


@dataclass(frozen=True)
class AlreadyProcessed:
    """Повторная доставка / дубль по head_sha. 200, без анализа."""

    reason: str
    idempotency_key: Optional[str] = None


@dataclass(frozen=True)
class EnqueueAnalysis:
    """Готово к запуску в background. 202."""

    event: GitHubPullRequestEvent
    idempotency_key: str
    delivery_id: Optional[str]


@dataclass(frozen=True)
class EnqueueReply:
    """Reply-режим (T-019): пользователь ответил на комментарий бота.

    `kind`:
      - `"inline"` — событие `pull_request_review_comment` (ответ на review-comment).
      - `"issue"`  — событие `issue_comment` (комментарий в PR conversation с @mention).
    """

    payload: Union[GitHubIssueCommentEvent, GitHubPullRequestReviewCommentEvent]
    kind: str  # "inline" | "issue"
    idempotency_key: str
    delivery_id: Optional[str]


WebhookOutcome = Union[
    InvalidSignature,
    BadRequest,
    Ignored,
    AlreadyProcessed,
    EnqueueAnalysis,
    EnqueueReply,
]


# --- Сервис ----------------------------------------------------------------


class WebhookService:
    """Чистая бизнес-логика webhook-приёмки (без FastAPI)."""

    def __init__(
        self,
        *,
        vcs: VCSAdapter,
        state: StateStore,
        webhook_secret: str,
        skip_drafts: bool = True,
        settings: Optional[object] = None,
        bot_username: str = "sunsec-bot",
        enable_reply_mode: bool = True,
    ) -> None:
        self._vcs = vcs
        self._state = state
        self._secret = webhook_secret
        self._skip_drafts = skip_drafts
        # M-9: optional `Settings` (для resolve_webhook_credentials —
        # см. system_design v1.2.1 §12.3). Если None — backward-compat,
        # используем self._secret из конструктора как раньше.
        self._settings = settings
        # Reply-mode (T-019). `bot_username` нормализуем в lower-case для
        # case-insensitive сравнения по GitHub login.
        self._bot_username = (bot_username or "").strip().lower()
        self._enable_reply_mode = bool(enable_reply_mode)

    async def _resolve_secret(self, raw_body: bytes) -> ResolvedCredentials:
        """Peek в JSON, найти `repository.full_name`, резолвнуть credentials.

        Безопасно: до HMAC-проверки мы НЕ обрабатываем payload, только
        читаем имя репо для поиска секрета. Если БД пуста / settings нет —
        возвращаем legacy `self._secret`.
        """
        if self._settings is None:
            # Legacy ветка (M-2/M-7): без settings — secret из __init__.
            return ResolvedCredentials(
                vcs_token="",
                webhook_secret=self._secret,
                source="env",
                repo_full_name=None,
            )
        full_name: Optional[str] = None
        try:
            import json

            payload = json.loads(raw_body.decode("utf-8"))
            if isinstance(payload, dict):
                repo = payload.get("repository")
                if isinstance(repo, dict):
                    fn = repo.get("full_name")
                    if isinstance(fn, str) and fn:
                        full_name = fn
        except Exception:  # noqa: BLE001 — peek best-effort
            full_name = None
        return await resolve_webhook_credentials(
            state=self._state,
            settings=self._settings,
            full_name=full_name,
        )

    async def handle(
        self,
        raw_body: bytes,
        headers: Mapping[str, str],
    ) -> WebhookOutcome:
        """Обработка webhook'а от начала до решения «что отдать клиенту».

        Этот метод НЕ запускает pipeline. Он возвращает `EnqueueAnalysis`,
        и роутер сам пускает `pipeline.process_pr(event)` через `BackgroundTasks`.
        Так контракт «быстро ответить ≤200 мс» (NFR §6) держится явным образом.
        """
        # Заголовки в FastAPI приходят case-insensitively, но Mapping[str,str]
        # в общем случае нет. Нормализуем к lower-case.
        norm = {k.lower(): v for k, v in headers.items()}
        signature = norm.get(HEADER_SIGNATURE, "")
        event_type = norm.get(HEADER_EVENT, "")
        delivery_id = norm.get(HEADER_DELIVERY, "") or None

        # --- 0. Repo resolver (M-9, §12.3): подбираем webhook_secret до HMAC ---
        creds = await self._resolve_secret(raw_body)
        effective_secret = creds.webhook_secret or self._secret

        # --- 1. HMAC ---
        if not self._vcs.verify_signature(raw_body, signature, effective_secret):
            # ВАЖНО: в логи попадает delivery_id (не секрет) и event_type.
            # Сам raw_body / подпись НЕ логируются — это «материал» для возможной
            # атаки и не нужен оператору.
            log.warning(
                "webhook_invalid_signature",
                extra={
                    "delivery_id": delivery_id,
                    "event_type": event_type,
                    "body_size": len(raw_body),
                },
            )
            return InvalidSignature()

        # --- 2. Фильтр по типу события ---
        if event_type == "ping":
            # GitHub шлёт ping при добавлении webhook'а — отвечаем 200 «ignored»,
            # этого достаточно, чтобы UI показал «зелёный».
            log.info("webhook_ping", extra={"delivery_id": delivery_id})
            return Ignored(reason="ping", detail="GitHub setup ping")

        # --- 2a. Reply mode (T-019): comment-events. ---
        if event_type in REPLY_EVENT_TYPES:
            return await self._handle_reply_event(
                event_type=event_type,
                raw_body=raw_body,
                delivery_id=delivery_id,
            )

        if event_type != "pull_request":
            log.info(
                "webhook_ignored_event_type",
                extra={"delivery_id": delivery_id, "event_type": event_type},
            )
            return Ignored(reason="unsupported event type", detail=event_type)

        # --- 3. delivery-id idempotency (до парсинга — самая дешёвая проверка) ---
        if delivery_id and await self._state.seen_delivery(delivery_id):
            log.info(
                "webhook_duplicate_delivery",
                extra={"delivery_id": delivery_id, "event_type": event_type},
            )
            return AlreadyProcessed(reason="duplicate delivery_id")

        # --- 4. Парсинг payload ---
        # Импорт json внутри — нам важна узкая зона отказа.
        import json
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning(
                "webhook_payload_decode_failed",
                extra={"delivery_id": delivery_id, "error_type": type(exc).__name__},
            )
            return BadRequest(reason="payload is not valid JSON")

        # --- 4a. Pre-check action ДО Pydantic-валидации ---
        # GitHub шлёт все pull_request actions на один и тот же endpoint
        # (closed, edited, assigned, labeled, ...). Pydantic `Literal` в
        # GitHubPullRequestEvent.action принимает только whitelist; если
        # сразу гнать в model_validate, мы вернём 400 на легитимный «closed»
        # — это шумит у клиента. Поэтому peek'аем `action` в raw dict и
        # короткозамыкаем «ignored» с 200, как требует DoD T-007.
        if isinstance(payload, dict):
            raw_action = payload.get("action")
            if isinstance(raw_action, str) and raw_action not in ACTION_WHITELIST:
                log.info(
                    "webhook_ignored_action",
                    extra={
                        "delivery_id": delivery_id,
                        "action": raw_action,
                    },
                )
                return Ignored(reason="action not in whitelist", detail=raw_action)

        try:
            event = GitHubPullRequestEvent.model_validate(payload)
        except ValidationError as exc:
            # Пишем только error_count, не дампим payload (там бывают емейлы коммитеров).
            log.warning(
                "webhook_payload_validation_failed",
                extra={
                    "delivery_id": delivery_id,
                    "error_count": len(exc.errors()),
                },
            )
            return BadRequest(reason="payload schema mismatch")

        # --- 6. Опциональный skip draft (system_design §3.1, env SKIP_DRAFTS) ---
        if self._skip_drafts and event.pull_request.draft and event.action != "ready_for_review":
            # `ready_for_review` означает «из черновика → готов» — мы хотим обработать.
            log.info(
                "webhook_ignored_draft",
                extra={
                    "delivery_id": delivery_id,
                    "repo": event.repo,
                    "pr_number": event.pr_number,
                    "action": event.action,
                },
            )
            return Ignored(reason="draft PR (SKIP_DRAFTS=true)")

        # --- 7. head_sha idempotency ---
        key = idempotency_key(event)
        reserved = await self._state.mark_pr_in_progress(key)
        if not reserved:
            log.info(
                "webhook_duplicate_head_sha",
                extra={
                    "delivery_id": delivery_id,
                    "repo": event.repo,
                    "pr_number": event.pr_number,
                    "idempotency_key": key,
                },
            )
            return AlreadyProcessed(reason="head_sha already processed", idempotency_key=key)

        # --- 8. Готово к обработке ---
        log.info(
            "webhook_accepted",
            extra={
                "delivery_id": delivery_id,
                "repo": event.repo,
                "pr_number": event.pr_number,
                "head_sha": event.head_sha,
                "action": event.action,
                "idempotency_key": key,
            },
        )
        return EnqueueAnalysis(event=event, idempotency_key=key, delivery_id=delivery_id)


    # ----------------------------------------------------------------------
    # Reply-mode helpers (T-019)
    # ----------------------------------------------------------------------

    async def _handle_reply_event(
        self,
        *,
        event_type: str,
        raw_body: bytes,
        delivery_id: Optional[str],
    ) -> WebhookOutcome:
        """Ветка обработки `issue_comment` / `pull_request_review_comment`.

        После HMAC + ping короткозамыкания, до перехода к `pull_request`.
        Возвращает `Ignored` для всего, что не «адресовано боту», иначе —
        `EnqueueReply` с `kind` в зависимости от типа события. Self-filter
        (anti-loop) приоритетный.
        """
        if not self._enable_reply_mode:
            log.info(
                "webhook_reply_disabled",
                extra={"delivery_id": delivery_id, "event_type": event_type},
            )
            return Ignored(reason="reply mode disabled", detail=event_type)

        # delivery_id dedup общий с pull_request веткой.
        if delivery_id and await self._state.seen_delivery(delivery_id):
            log.info(
                "webhook_duplicate_delivery",
                extra={"delivery_id": delivery_id, "event_type": event_type},
            )
            return AlreadyProcessed(reason="duplicate delivery_id")

        import json

        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.warning(
                "webhook_payload_decode_failed",
                extra={
                    "delivery_id": delivery_id,
                    "event_type": event_type,
                    "error_type": type(exc).__name__,
                },
            )
            return BadRequest(reason="payload is not valid JSON")

        if not isinstance(payload, dict):
            return BadRequest(reason="payload must be a JSON object")

        raw_action = payload.get("action")
        if not isinstance(raw_action, str) or raw_action not in REPLY_ACTION_WHITELIST:
            log.info(
                "webhook_reply_ignored_action",
                extra={
                    "delivery_id": delivery_id,
                    "event_type": event_type,
                    "action": raw_action,
                },
            )
            return Ignored(
                reason="reply action not in whitelist",
                detail=str(raw_action),
            )

        sender_payload = payload.get("sender") or {}
        sender_login = ""
        if isinstance(sender_payload, dict):
            login = sender_payload.get("login")
            if isinstance(login, str):
                sender_login = login.strip().lower()

        # Self-filter: бот никогда не отвечает на свои же комментарии.
        if self._bot_username and sender_login == self._bot_username:
            log.info(
                "webhook_reply_self_filtered",
                extra={
                    "delivery_id": delivery_id,
                    "event_type": event_type,
                    "sender": sender_login,
                },
            )
            return Ignored(reason="self-reply", detail=sender_login)

        # Парсинг по типу события.
        try:
            if event_type == "issue_comment":
                event_obj: Union[
                    GitHubIssueCommentEvent, GitHubPullRequestReviewCommentEvent
                ] = GitHubIssueCommentEvent.model_validate(payload)
                kind = "issue"
            else:
                event_obj = GitHubPullRequestReviewCommentEvent.model_validate(payload)
                kind = "inline"
        except ValidationError as exc:
            log.warning(
                "webhook_reply_validation_failed",
                extra={
                    "delivery_id": delivery_id,
                    "event_type": event_type,
                    "error_count": len(exc.errors()),
                },
            )
            return BadRequest(reason="reply payload schema mismatch")

        # Триггер бота: для issue_comment — @mention; для inline — reply
        # на наш комментарий (parent body содержит `sunsec:bot:v1:`).
        triggered = await self._reply_event_is_addressed_to_bot(
            event_type=event_type, event_obj=event_obj
        )
        if not triggered:
            log.info(
                "webhook_reply_not_addressed",
                extra={
                    "delivery_id": delivery_id,
                    "event_type": event_type,
                    "repo": event_obj.repo,
                    "pr_number": event_obj.pr_number,
                },
            )
            return Ignored(reason="not addressed to bot", detail=event_type)

        # Idempotency: один ответ на каждый comment_id.
        comment_id = int(event_obj.comment.id)
        key = f"reply:{event_obj.repo}#{event_obj.pr_number}@{comment_id}"
        reserved = await self._state.mark_pr_in_progress(key)
        if not reserved:
            log.info(
                "webhook_reply_duplicate",
                extra={
                    "delivery_id": delivery_id,
                    "event_type": event_type,
                    "repo": event_obj.repo,
                    "pr_number": event_obj.pr_number,
                    "comment_id": comment_id,
                },
            )
            return AlreadyProcessed(
                reason="reply already in progress",
                idempotency_key=key,
            )

        log.info(
            "webhook_reply_accepted",
            extra={
                "delivery_id": delivery_id,
                "event_type": event_type,
                "repo": event_obj.repo,
                "pr_number": event_obj.pr_number,
                "comment_id": comment_id,
                "sender": sender_login,
                "kind": kind,
                "idempotency_key": key,
            },
        )
        return EnqueueReply(
            payload=event_obj,
            kind=kind,
            idempotency_key=key,
            delivery_id=delivery_id,
        )

    async def _reply_event_is_addressed_to_bot(
        self,
        *,
        event_type: str,
        event_obj: Union[
            GitHubIssueCommentEvent, GitHubPullRequestReviewCommentEvent
        ],
    ) -> bool:
        """Проверка, что пользователь действительно адресует бота.

        - `issue_comment`: триггер только если в теле есть `@<bot_username>`
          (case-insensitive) И issue является PR (не обычным issue).
        - `pull_request_review_comment`: триггер если `in_reply_to_id`
          существует и parent-комментарий содержит маркер `sunsec:bot:v1:`
          в body. fetch parent через `vcs.get_review_comment`.
        """
        if event_type == "issue_comment":
            assert isinstance(event_obj, GitHubIssueCommentEvent)
            if not event_obj.is_pull_request:
                return False
            if not self._bot_username:
                return False
            mention = f"@{self._bot_username}"
            body = (event_obj.comment.body or "").lower()
            return mention in body

        assert isinstance(event_obj, GitHubPullRequestReviewCommentEvent)
        in_reply_to = event_obj.comment.in_reply_to_id
        if not in_reply_to:
            return False
        # Пытаемся fetched parent — если падает, возвращаем False (мы НЕ
        # хотим спамить ответами по предположению).
        try:
            parent = await self._vcs.get_review_comment(
                event_obj.repo, int(in_reply_to)
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "webhook_reply_parent_fetch_failed",
                extra={
                    "repo": event_obj.repo,
                    "in_reply_to_id": int(in_reply_to),
                    "error_type": type(exc).__name__,
                },
            )
            return False
        parent_body = (getattr(parent, "body", None) or "")
        return _BOT_COMMENT_MARKER_PREFIX in parent_body


__all__ = [
    "WebhookService",
    "WebhookOutcome",
    "InvalidSignature",
    "BadRequest",
    "Ignored",
    "AlreadyProcessed",
    "EnqueueAnalysis",
    "EnqueueReply",
    "ACTION_WHITELIST",
    "REPLY_ACTION_WHITELIST",
    "REPLY_EVENT_TYPES",
    "HEADER_EVENT",
    "HEADER_SIGNATURE",
    "HEADER_DELIVERY",
]
