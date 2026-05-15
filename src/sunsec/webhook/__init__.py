"""WebhookReceiver — FastAPI router + бизнес-сервис.

T-007: `build_router(service, pipeline)` — основная фабрика. Импортируется в
`sunsec.app.create_app()`.

`router` / `healthcheck_router` — backwards-compat для скелета T-006
(сейчас `router=None`; реальные пути строятся через `build_router`).
"""
from sunsec.webhook.router import build_router, healthcheck_router, router
from sunsec.webhook.service import (
    ACTION_WHITELIST,
    AlreadyProcessed,
    BadRequest,
    EnqueueAnalysis,
    Ignored,
    InvalidSignature,
    WebhookOutcome,
    WebhookService,
)

__all__ = [
    "build_router",
    "router",
    "healthcheck_router",
    "WebhookService",
    "WebhookOutcome",
    "InvalidSignature",
    "BadRequest",
    "Ignored",
    "AlreadyProcessed",
    "EnqueueAnalysis",
    "ACTION_WHITELIST",
]
