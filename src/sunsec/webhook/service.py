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

from sunsec.contracts import GitHubPullRequestEvent
from sunsec.pipeline.orchestrator import idempotency_key
from sunsec.state.base import StateStore
from sunsec.vcs.base import VCSAdapter

log = logging.getLogger(__name__)

# Whitelist actions, на которые мы реально запускаем анализ.
# `ready_for_review` (черновик → готов) тоже триггерит, как и в system_design §3.1.
ACTION_WHITELIST: frozenset[str] = frozenset({"opened", "synchronize", "reopened", "ready_for_review"})

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


WebhookOutcome = Union[InvalidSignature, BadRequest, Ignored, AlreadyProcessed, EnqueueAnalysis]


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
    ) -> None:
        self._vcs = vcs
        self._state = state
        self._secret = webhook_secret
        self._skip_drafts = skip_drafts

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

        # --- 1. HMAC ---
        if not self._vcs.verify_signature(raw_body, signature, self._secret):
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


__all__ = [
    "WebhookService",
    "WebhookOutcome",
    "InvalidSignature",
    "BadRequest",
    "Ignored",
    "AlreadyProcessed",
    "EnqueueAnalysis",
    "ACTION_WHITELIST",
    "HEADER_EVENT",
    "HEADER_SIGNATURE",
    "HEADER_DELIVERY",
]
