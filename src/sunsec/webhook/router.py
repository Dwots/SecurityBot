"""HTTP роутеры: `/health` + `POST /webhook/github`.

T-007: реализован production-ready endpoint:
- HMAC-проверка через `GitHubAdapter.verify_signature`.
- Парсинг `GitHubPullRequestEvent`.
- Идемпотентность по `X-GitHub-Delivery` и `head_sha` (см. system_design §3.1).
- Whitelist action: opened / synchronize / reopened / ready_for_review.
- 401 без диагностики на невалидную подпись.
- Реальная обработка — background-task (`BackgroundTasks`), webhook отвечает быстро.

DI происходит в `app.py` (T-006 application factory). Здесь — только маршруты
и тонкий маппинг исхода `WebhookService.handle` → HTTP-ответ.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

try:
    from fastapi import APIRouter, BackgroundTasks, Request, Response, status  # type: ignore
    from fastapi.responses import JSONResponse  # type: ignore
except ImportError:  # pragma: no cover — для среды без fastapi
    APIRouter = None  # type: ignore[assignment]
    BackgroundTasks = Request = Response = status = JSONResponse = None  # type: ignore[assignment]

from sunsec.webhook.service import (
    AlreadyProcessed,
    BadRequest,
    EnqueueAnalysis,
    Ignored,
    InvalidSignature,
    WebhookService,
)

if TYPE_CHECKING:
    from sunsec.pipeline.orchestrator import PipelineOrchestrator

log = logging.getLogger(__name__)


def build_router(
    *,
    service: WebhookService,
    pipeline: "PipelineOrchestrator",
):
    """Фабрика роутера. DI: сервис + pipeline собираются в app.py.

    Returns:
        FastAPI `APIRouter` с двумя путями: `/health` и `/webhook/github`.
    """
    if APIRouter is None:  # pragma: no cover
        raise RuntimeError("FastAPI не установлен — невозможно построить router.")

    router = APIRouter()

    @router.get("/health")
    async def health() -> dict:
        """Healthcheck для DevOps (T-020). 200 + `{status: ok}`."""
        return {"status": "ok", "service": "sunsec"}

    @router.post("/webhook/github")
    async def github_webhook(request: Request, background_tasks: BackgroundTasks):
        """Приёмник GitHub webhook'ов (PR events).

        Контракт (см. system_design §3.1 / §4.1 «Ошибки WebhookReceiver»):
            - 202 Accepted: подпись валидна, action whitelisted, не дубль → запущен анализ.
            - 200 OK: ignored (action / draft / event_type) или already processed.
            - 400 Bad Request: payload не парсится / не валидна Pydantic-схема.
            - 401 Unauthorized: HMAC не сошёлся (тело ответа без диагностики).
        """
        raw_body = await request.body()
        outcome = await service.handle(raw_body=raw_body, headers=dict(request.headers))

        if isinstance(outcome, InvalidSignature):
            # 401 без подробностей — не подсказываем атакующему, какой ключ ожидаем.
            return JSONResponse(status_code=401, content={"detail": "invalid signature"})

        if isinstance(outcome, BadRequest):
            return JSONResponse(status_code=400, content={"detail": "bad request", "reason": outcome.reason})

        if isinstance(outcome, Ignored):
            return JSONResponse(
                status_code=200,
                content={"status": "ignored", "reason": outcome.reason, "detail": outcome.detail},
            )

        if isinstance(outcome, AlreadyProcessed):
            return JSONResponse(
                status_code=200,
                content={"status": "already_processed", "reason": outcome.reason},
            )

        if isinstance(outcome, EnqueueAnalysis):
            # Реальная тяжёлая работа — в background-task. Webhook отвечает 202
            # в ≤ 200 мс (NFR §6), GitHub не считает доставку failed.
            background_tasks.add_task(pipeline.process_pr, outcome.event)
            return JSONResponse(
                status_code=202,
                content={
                    "status": "accepted",
                    "repo": outcome.event.repo,
                    "pr_number": outcome.event.pr_number,
                    "head_sha": outcome.event.head_sha,
                },
            )

        # Не должно произойти: WebhookOutcome — sealed-like union.
        log.error("webhook_unknown_outcome", extra={"outcome_type": type(outcome).__name__})  # pragma: no cover
        return JSONResponse(status_code=500, content={"detail": "internal error"})

    return router


# --- Backwards-compat (для T-006 app.py, у которого ссылки на router/healthcheck_router) ---
# Реальные роутеры строятся в `build_router(...)`. Если кто-то импортирует
# модуль без DI — оставляем None, чтобы `if router is not None: include` не падал.
if APIRouter is not None:
    healthcheck_router = APIRouter()

    @healthcheck_router.get("/health")
    async def _health_compat() -> dict:
        """Бэкап-маршрут /health на случай, если build_router(...) не позвали.

        В app.py мы предпочитаем build_router (там и /health и /webhook сразу).
        Эта реализация — на случай раннего старта или unit-тестов app без DI.
        """
        return {"status": "ok", "service": "sunsec"}

    router = None  # реальный router строится через build_router(service, pipeline)
else:  # pragma: no cover
    router = None  # type: ignore[assignment]
    healthcheck_router = None  # type: ignore[assignment]


__all__ = ["build_router", "router", "healthcheck_router"]
