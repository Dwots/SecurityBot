"""FastAPI-приложение SunSecurityBot.

Точка сборки: конфиг → логгер → DI (vcs, state, pipeline, webhook-service) → роутер.

T-007: подключён реальный webhook-роутер (`build_router`) с
`GitHubAdapter` / `InMemoryStateStore` / `PipelineOrchestrator` через DI.
"""
from __future__ import annotations

import logging

from sunsec.comments.publisher import CommentPublisher
from sunsec.config import Settings, get_settings
from sunsec.filter import build_filter_from_settings
from sunsec.llm import build_llm_client_from_settings
from sunsec.logging_ext import configure_logging, get_logger
from sunsec.ml import build_fp_filter_from_settings
from sunsec.pipeline.orchestrator import PipelineOrchestrator
from sunsec.state.memory import InMemoryStateStore
from sunsec.vcs.github import GitHubAdapter
from sunsec.webhook.service import WebhookService

log = logging.getLogger(__name__)


def create_app(settings: Settings | None = None):
    """Application factory (FastAPI).

    Можно передать `settings` явно (тесты используют это, чтобы не зависеть
    от `os.environ` через `get_settings`).
    """
    try:
        from fastapi import FastAPI  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "FastAPI не установлен. Запустите `pip install -r requirements.txt`."
        ) from exc

    if settings is None:
        settings = get_settings()

    configure_logging(level=settings.log_level, fmt=settings.log_format)
    logger = get_logger("sunsec.app")
    logger.info(
        "service_starting",
        extra={
            "app_env": settings.app_env,
            "log_level": settings.log_level,
            "vcs_provider": settings.vcs_provider,
            "llm_provider": settings.llm_provider,
            "polza_model_id": settings.polza_model_id,
            "polza_budget_limit_rub": settings.polza_budget_limit_rub,
            "skip_drafts": settings.skip_drafts,
            # ВАЖНО: api_key и vcs_token в extra НЕ кладём.
        },
    )

    # --- DI: vcs / state / pipeline / webhook-service ---
    vcs = GitHubAdapter(
        token=settings.vcs_token,
        api_base=settings.github_api_base,
        http_timeout_seconds=settings.vcs_http_timeout_seconds,
        max_retries=settings.vcs_max_retries,
        files_page_size=settings.vcs_files_page_size,
        files_soft_limit=settings.vcs_files_soft_limit,
        rate_limit_wait_cap_seconds=settings.vcs_rate_limit_wait_cap_seconds,
    )
    state = InMemoryStateStore()
    diff_filter = build_filter_from_settings(settings)
    # LLMClient (T-012). Если ключ polza.ai не задан — не падаем: фабрика
    # создаст провайдера (с warning), а реальный вызов упадёт при первом
    # обращении. Это удобно для запуска webhook без LLM (smoke / dry-run).
    try:
        llm_client = build_llm_client_from_settings(settings)
    except Exception as exc:  # noqa: BLE001 — LLM ошибка не должна валить webhook
        logger.warning(
            "llm_client_init_failed",
            extra={
                "error_type": type(exc).__name__,
                "polza_model_id": settings.polza_model_id,
            },
        )
        llm_client = None
    fp_filter = build_fp_filter_from_settings(settings)
    # T-016: CommentPublisher (publish / publish_empty / publish_budget_exhausted).
    publisher = CommentPublisher(
        vcs=vcs,
        state=state,
        enabled=settings.publish_comments_enabled,
    )
    pipeline = PipelineOrchestrator(
        vcs=vcs,
        diff_filter=diff_filter,
        llm=llm_client,
        state=state,
        fp_filter=fp_filter,
        publisher=publisher,
    )
    webhook_service = WebhookService(
        vcs=vcs,
        state=state,
        webhook_secret=settings.webhook_secret,
        skip_drafts=settings.skip_drafts,
    )

    # --- FastAPI app + роутер ---
    app = FastAPI(title="SunSecurityBot", version="0.1.0")

    from sunsec.webhook.router import build_router

    router = build_router(service=webhook_service, pipeline=pipeline)
    app.include_router(router)

    # Хранилища доступны через `app.state` — пригодится тестам и shutdown-хукам.
    app.state.settings = settings
    app.state.vcs = vcs
    app.state.state_store = state
    app.state.pipeline = pipeline
    app.state.webhook_service = webhook_service
    app.state.diff_filter = diff_filter
    app.state.llm_client = llm_client
    app.state.fp_filter = fp_filter
    app.state.publisher = publisher

    # T-023: опциональный test-UI за флагом ENABLE_TEST_UI (`tmp/gui_plan.md §6`).
    # В prod НЕ включать — даёт прямой доступ к polza.ai без HMAC. Defense-in-depth:
    # бэкэнд защищён флагом + bind на 127.0.0.1 в dev-окружении (см. README).
    if settings.enable_test_ui:
        from sunsec.ui.router import build_ui_router

        ui_router = build_ui_router(
            llm_client=llm_client,
            fp_filter=fp_filter,
            diff_filter=diff_filter,
            budget=llm_client.budget if llm_client is not None else None,
        )
        app.include_router(ui_router)
        logger.info("ui_router_enabled", extra={"path": "/ui"})

    return app
