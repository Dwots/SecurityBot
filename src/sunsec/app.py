"""FastAPI-приложение SunSecurityBot.

Точка сборки: конфиг → логгер → DI (vcs, state, pipeline, webhook-service) → роутер.

T-007: подключён реальный webhook-роутер (`build_router`) с
`GitHubAdapter` / `InMemoryStateStore` / `PipelineOrchestrator` через DI.

T-039 (M-9): на startup до инициализации `Settings()` подгружается
gitignored `data/repos_secrets.env` через `dotenv.load_dotenv(...,
override=False)` — durability фикс RT-012 (см. system_design v1.2.1
§11.7 R-18). Console router `/api/console/*` монтируется при
`ENABLE_CONSOLE_UI=true` (ADR-7).
"""
from __future__ import annotations

import logging
from pathlib import Path

from sunsec.comments.publisher import CommentPublisher
from sunsec.config import Settings, get_settings
from sunsec.filter import build_filter_from_settings
from sunsec.llm import (
    build_llm_client_from_settings,
    build_reply_client_from_settings,
)
from sunsec.logging_ext import configure_logging, get_logger
from sunsec.ml import build_fp_filter_from_settings
from sunsec.pipeline.orchestrator import PipelineOrchestrator
from sunsec.storage import build_storage_from_settings
from sunsec.storage.sqlite_store import SQLiteStateStore
from sunsec.vcs.github import GitHubAdapter
from sunsec.webhook.service import WebhookService

log = logging.getLogger(__name__)


_REPOS_SECRETS_PATH = Path("data") / "repos_secrets.env"


def _load_repos_secrets_if_present(path: Path = _REPOS_SECRETS_PATH) -> bool:
    """Durability fix RT-012: подгрузка gitignored secrets-файла на startup.

    Вызывается **до** `Settings.from_env()` инициализации, чтобы
    `os.environ[REPO_<X>_VCS_TOKEN]` был доступен резолверу webhook'а
    (`webhook_secret_ref` / `vcs_token_ref`).

    `override=False` — реальные env / `.env` имеют приоритет; secrets-файл
    добавляет только те ключи, которых ещё нет.

    Returns:
        True — файл существовал и был подгружен;
        False — файла нет / IOError (логируется warning без plaintext).
    """
    if not path.exists():
        return False
    try:
        from dotenv import load_dotenv  # type: ignore[import-not-found]

        load_dotenv(str(path), override=False)
        log.info(
            "repos_secrets_loaded",
            extra={"file_exists": True},
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "repos_secrets_load_failed",
            extra={"error_type": type(exc).__name__},
        )
        return False


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
        # RT-012: подгрузка `data/repos_secrets.env` ДО `Settings()` —
        # `Settings.from_env()` читает уже обогащённый `os.environ`.
        _load_repos_secrets_if_present()
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
    # M-9: фабрика state-store по `SUNSEC_DB_PATH`.
    # Пусто/`:memory:` → InMemoryStateStore (legacy ADR-3); иначе — SQLiteStateStore.
    state = build_storage_from_settings(settings)
    if isinstance(state, SQLiteStateStore):
        # Применяем DDL / PRAGMA на startup. Идемпотентно (IF NOT EXISTS).
        import asyncio

        from sunsec.storage import run_migrations

        try:
            asyncio.run(run_migrations(state.db_path))
        except RuntimeError:
            # Если уже внутри event-loop (например, тест запустил FastAPI app
            # из async-кода) — schedule в текущий loop без блокировки.
            loop = asyncio.get_event_loop()
            loop.create_task(run_migrations(state.db_path))
        logger.info(
            "storage_initialized",
            extra={"backend": "sqlite", "db_path_set": True},
        )
    else:
        logger.info("storage_initialized", extra={"backend": "memory"})
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
    # T-019: reply-режим. Делим budget с основным `llm_client` — единая
    # корзина рублей (один kill-switch для analyze и reply).
    shared_budget = getattr(llm_client, "budget", None) if llm_client else None
    try:
        reply_client = build_reply_client_from_settings(settings, budget=shared_budget)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "reply_client_init_failed",
            extra={"error_type": type(exc).__name__},
        )
        reply_client = None
    pipeline = PipelineOrchestrator(
        vcs=vcs,
        diff_filter=diff_filter,
        llm=llm_client,
        state=state,
        fp_filter=fp_filter,
        publisher=publisher,
        reply_client=reply_client,
        reply_history_limit=settings.reply_history_limit,
        bot_username=settings.bot_username,
    )
    webhook_service = WebhookService(
        vcs=vcs,
        state=state,
        webhook_secret=settings.webhook_secret,
        skip_drafts=settings.skip_drafts,
        settings=settings,
        bot_username=settings.bot_username,
        enable_reply_mode=settings.enable_reply_mode,
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
    app.state.reply_client = reply_client

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

    # T-039 (M-9): опциональный console UI control plane за флагом
    # ENABLE_CONSOLE_UI. См. system_design v1.2.1 §13 + ADR-7. Pre-condition
    # R-13 HIGH: UI не выставляется в публичную сеть без auth.
    if settings.enable_console_ui:
        from sunsec.ui.console_router import build_console_router
        from sunsec.ui.router import build_ui_router

        # Manual analyze proxy: вызываем `/api/ui/analyze` handler внутренне.
        # Для proxy формируем отдельный UI-router (тот же, что dev UI),
        # достаём handler и используем его в console_router.
        ui_router_for_proxy = build_ui_router(
            llm_client=llm_client,
            fp_filter=fp_filter,
            diff_filter=diff_filter,
            budget=llm_client.budget if llm_client is not None else None,
        )
        analyze_handler = None
        for route in ui_router_for_proxy.routes:
            if getattr(route, "path", "") == "/api/ui/analyze":
                analyze_handler = route.endpoint
                break

        console_router = build_console_router(
            state=state,
            settings=settings,
            llm_client=llm_client,
            manual_analyze_handler=analyze_handler,
        )
        app.include_router(console_router)
        logger.info(
            "console_router_enabled",
            extra={
                "prefix": "/api/console",
                "auth_disabled_warning": True,
                "advice": "NOT for public network without authn (R-13)",
            },
        )

    return app
