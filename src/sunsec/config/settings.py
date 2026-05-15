"""Settings — конфиг приложения, читается из env (и опционально из `.env`).

Источники истины:
- system_design §3.4 / §3.6 / §6 / ADR-2 — env-vars, бюджет, kill-switch.
- agents/artifacts/planner/ml_instructions_polza.md §2/§4/§5 — безопасность ключа.

ВАЖНО: реальные значения секретов берутся ТОЛЬКО из env. Repr Settings маскирует
любые поля с подстроками token/secret/api_key/authorization/password.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from sunsec.logging_ext.redaction import SENSITIVE_KEY_PATTERN

_SECRET_PLACEHOLDER = "***REDACTED***"


def _load_dotenv_if_present(dotenv_path: Optional[Path] = None) -> None:
    """Минимальная подгрузка .env без зависимости от `python-dotenv`.

    Реальный загрузчик подключим в T-012 (uses python-dotenv для совместимости
    с ml_instructions_polza.md §2). Сейчас простая реализация, чтобы тесты и
    `make run` работали без внешних зависимостей.
    """
    if dotenv_path is None:
        # Поиск .env в корне проекта (5 уровней вверх от этого файла).
        here = Path(__file__).resolve()
        for parent in [here.parent, *here.parents]:
            candidate = parent / ".env"
            if candidate.is_file():
                dotenv_path = candidate
                break
    if dotenv_path is None or not dotenv_path.is_file():
        return
    try:
        for raw in dotenv_path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # НЕ перезаписываем уже установленные env-переменные — приоритет окружения.
            if key and key not in os.environ:
                os.environ[key] = value
    except OSError:
        # Любая ошибка чтения .env — не фатально, продолжаем с env как есть.
        return


class Settings(BaseModel):
    """Конфиг приложения. Поля с секретами помечены `is_secret=True` через имя."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    # --- Общие ---
    app_name: str = "sunsec"
    app_env: str = Field(default="dev", description="dev | staging | prod")
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json", description="json | text")
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)

    # --- VCS (GitHub primary, ADR-1) ---
    vcs_provider: str = Field(default="github")
    vcs_token: str = Field(default="", description="GitHub PAT / App token")
    webhook_secret: str = Field(default="", description="HMAC ключ для X-Hub-Signature-256")
    github_api_base: str = Field(default="https://api.github.com")
    vcs_http_timeout_seconds: float = Field(
        default=30.0, ge=1.0, description="httpx-таймаут на один GitHub API запрос"
    )
    vcs_max_retries: int = Field(
        default=3, ge=0, description="Количество ретраев на 5xx (без 429 — у того отдельный путь)"
    )
    vcs_files_page_size: int = Field(
        default=100, ge=1, le=100, description="?per_page для /pulls/{n}/files"
    )
    vcs_files_soft_limit: int = Field(
        default=300,
        ge=1,
        description="При превышении логируем warning и обрезаем выборку (PR > 300 файлов крайне редок)",
    )
    vcs_rate_limit_wait_cap_seconds: float = Field(
        default=60.0, ge=0.0, description="Максимальное ожидание X-RateLimit-Reset / Retry-After (в секундах)"
    )

    # --- LLM polza.ai (ADR-2) ---
    llm_provider: str = Field(default="polza")
    polza_api_key: str = Field(default="", description="Бэрер polza.ai")
    polza_base_url: str = Field(default="https://polza.ai/api/v1")
    polza_model_id: str = Field(default="gpt-4o-mini")
    polza_budget_limit_rub: float = Field(default=80.0, ge=0.0)
    polza_timeout_seconds: float = Field(default=60.0, ge=1.0)
    polza_max_retries: int = Field(default=2, ge=0)
    # Тарифы в рублях за 1K токенов. Дефолты — research §16 (gpt-4o-mini
    # через polza.ai, [ASSUMPTION]: ≈ 15 ₽/1M input, ≈ 60 ₽/1M output).
    # 1K = 1/1000-ая от 1M → 0.015 ₽/1K input, 0.06 ₽/1K output.
    polza_input_rub_per_1k: float = Field(default=0.015, ge=0.0)
    polza_output_rub_per_1k: float = Field(default=0.060, ge=0.0)
    # Стартовый response_format — `json_object` (см. ml_instructions_polza §6).
    # Когда поддержка `json_schema` подтверждена в админке polza.ai — флаг → true.
    polza_use_json_schema: bool = Field(default=False)
    # Параметры LLM-запроса (T-002 / ml_instructions_polza §3).
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    llm_max_tokens: int = Field(default=2048, ge=1)
    allow_direct_fallback: bool = Field(default=False)

    # --- Test UI (dev only, T-023) ---
    # Включает изолированный модуль `src/sunsec/ui/` — `GET /ui` страница
    # тестирования и `/api/ui/*` endpoints (analyze / budget / examples).
    # В prod НЕ включать: даёт прямой доступ к polza.ai без HMAC-проверки
    # GitHub webhook. См. `tmp/gui_plan.md §6` и README раздел «Test UI».
    # Env-loader: `ENABLE_TEST_UI` (см. `Settings.from_env`).
    enable_test_ui: bool = Field(
        default=False,
        description="Включить /ui и /api/ui/* (dev only). Env: ENABLE_TEST_UI.",
    )

    # --- Pipeline behavior ---
    publish_empty_pr_comment: bool = Field(default=False)
    # T-016: master-switch для CommentPublisher. В test/dev — выключаем, чтобы
    # юнит-тесты не ходили в GitHub. В prod — включён по умолчанию.
    publish_comments_enabled: bool = Field(default=True)
    skip_drafts: bool = Field(default=True)
    state_store_backend: str = Field(default="memory")

    # --- FalsePositiveFilter (T-013) ---
    fp_min_confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Порог confidence для пост-фильтра LLM-находок (T-013)",
    )
    fp_skip_llm_if_prescan_found: bool = Field(
        default=False,
        description="Если pre-scan нашёл известный секрет — пропускать LLM-вызов целиком (экономия)",
    )

    # --- DiffFilter (T-009) ---
    # Списки переопределяются env как CSV: `FILTER_EXCLUDE_EXTENSIONS=.md,.png`,
    # `FILTER_EXCLUDE_NAMES=.gitignore,LICENSE`, `FILTER_EXCLUDE_GLOBS=vendor/**,*.min.*`.
    # Если env не задан — берутся defaults (см. `sunsec.filter.config.DEFAULT_*`).
    # Хранение как tuple → frozen-friendly, сериализуется как list при необходимости.
    filter_exclude_extensions: Optional[tuple[str, ...]] = None
    filter_exclude_names: Optional[tuple[str, ...]] = None
    filter_exclude_globs: Optional[tuple[str, ...]] = None
    # Старое имя (для совместимости с T-006 — НЕ удаляем сразу).
    filter_blacklist_extensions: tuple[str, ...] = (
        ".md", ".txt", ".rst",
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
        ".pdf", ".zip", ".tar", ".gz",
        ".lock", ".sum",
        ".ico", ".woff", ".woff2", ".ttf", ".eot",
    )

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        v_norm = v.upper()
        if v_norm not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError(f"log_level must be one of DEBUG/INFO/WARNING/ERROR/CRITICAL, got {v!r}")
        return v_norm

    @field_validator("log_format")
    @classmethod
    def _validate_log_format(cls, v: str) -> str:
        v_norm = v.lower()
        if v_norm not in {"json", "text"}:
            raise ValueError("log_format must be 'json' or 'text'")
        return v_norm

    # --- Безопасный repr (никаких секретов в логах/трейсбеках) ---

    def __repr__(self) -> str:
        return self._safe_repr()

    def __str__(self) -> str:
        return self._safe_repr()

    def _safe_repr(self) -> str:
        parts: list[str] = []
        for name, value in self.model_dump().items():
            if SENSITIVE_KEY_PATTERN.search(name) and value:
                parts.append(f"{name}={_SECRET_PLACEHOLDER}")
            else:
                parts.append(f"{name}={value!r}")
        return f"Settings({', '.join(parts)})"

    @classmethod
    def from_env(cls, env: Optional[dict[str, str]] = None) -> "Settings":
        """Собирает Settings из переменных окружения (или подменённого dict)."""
        if env is None:
            _load_dotenv_if_present()
            env = dict(os.environ)

        def get(name: str, default: object = None) -> object:
            v = env.get(name)
            if v is None or v == "":
                return default
            return v

        # bool / int / float parsing
        def as_bool(v: object, default: bool) -> bool:
            if v is None:
                return default
            if isinstance(v, bool):
                return v
            return str(v).strip().lower() in {"1", "true", "yes", "on"}

        def as_csv_tuple(v: object) -> Optional[tuple[str, ...]]:
            """CSV → tuple строк (с trim/skip-empty). None → не задано, дефолт в коде."""
            if v is None or v == "":
                return None
            if isinstance(v, (list, tuple)):
                return tuple(str(x).strip() for x in v if str(x).strip())
            return tuple(item.strip() for item in str(v).split(",") if item.strip())

        raw: dict[str, object] = {
            "app_name": get("APP_NAME", "sunsec"),
            "app_env": get("APP_ENV", "dev"),
            "log_level": get("LOG_LEVEL", "INFO"),
            "log_format": get("LOG_FORMAT", "json"),
            "host": get("HOST", "0.0.0.0"),
            "port": int(get("PORT", 8000)),  # type: ignore[arg-type]
            "vcs_provider": get("VCS_PROVIDER", "github"),
            "vcs_token": get("VCS_TOKEN", "") or get("GITHUB_TOKEN", ""),
            "webhook_secret": get("WEBHOOK_SECRET", ""),
            "github_api_base": get("GITHUB_API_BASE", "https://api.github.com"),
            "vcs_http_timeout_seconds": float(get("VCS_HTTP_TIMEOUT_SECONDS", 30.0)),  # type: ignore[arg-type]
            "vcs_max_retries": int(get("VCS_MAX_RETRIES", 3)),  # type: ignore[arg-type]
            "vcs_files_page_size": int(get("VCS_FILES_PAGE_SIZE", 100)),  # type: ignore[arg-type]
            "vcs_files_soft_limit": int(get("VCS_FILES_SOFT_LIMIT", 300)),  # type: ignore[arg-type]
            "vcs_rate_limit_wait_cap_seconds": float(get("VCS_RATE_LIMIT_WAIT_CAP_SECONDS", 60.0)),  # type: ignore[arg-type]
            "llm_provider": get("LLM_PROVIDER", "polza"),
            "polza_api_key": get("POLZA_API_KEY", "") or get("LLM_API_KEY", ""),
            "polza_base_url": get("POLZA_BASE_URL", "https://polza.ai/api/v1"),
            "polza_model_id": get("POLZA_MODEL_ID", "gpt-4o-mini"),
            "polza_budget_limit_rub": float(get("POLZA_BUDGET_LIMIT_RUB", 80.0)),  # type: ignore[arg-type]
            "polza_timeout_seconds": float(get("POLZA_TIMEOUT_SECONDS", get("LLM_TIMEOUT_SECONDS", 60.0))),  # type: ignore[arg-type]
            "polza_max_retries": int(get("POLZA_MAX_RETRIES", get("LLM_MAX_RETRIES", 2))),  # type: ignore[arg-type]
            "polza_input_rub_per_1k": float(get("POLZA_INPUT_RUB_PER_1K", 0.015)),  # type: ignore[arg-type]
            "polza_output_rub_per_1k": float(get("POLZA_OUTPUT_RUB_PER_1K", 0.060)),  # type: ignore[arg-type]
            "polza_use_json_schema": as_bool(get("POLZA_USE_JSON_SCHEMA"), False),
            "llm_temperature": float(get("LLM_TEMPERATURE", 0.0)),  # type: ignore[arg-type]
            "llm_max_tokens": int(get("LLM_MAX_TOKENS", 2048)),  # type: ignore[arg-type]
            "allow_direct_fallback": as_bool(get("ALLOW_DIRECT_FALLBACK"), False),
            "enable_test_ui": as_bool(get("ENABLE_TEST_UI"), False),
            "publish_empty_pr_comment": as_bool(get("PUBLISH_EMPTY_PR_COMMENT"), False),
            "publish_comments_enabled": as_bool(
                get("PUBLISH_COMMENTS_ENABLED"), True
            ),
            "skip_drafts": as_bool(get("SKIP_DRAFTS"), True),
            "state_store_backend": get("STATE_STORE_BACKEND", "memory"),
            "filter_exclude_extensions": as_csv_tuple(get("FILTER_EXCLUDE_EXTENSIONS")),
            "filter_exclude_names": as_csv_tuple(get("FILTER_EXCLUDE_NAMES")),
            "filter_exclude_globs": as_csv_tuple(get("FILTER_EXCLUDE_GLOBS")),
            "fp_min_confidence": float(get("FP_MIN_CONFIDENCE", 0.5)),  # type: ignore[arg-type]
            "fp_skip_llm_if_prescan_found": as_bool(
                get("FP_SKIP_LLM_IF_PRESCAN_FOUND"), False
            ),
        }
        return cls(**raw)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Кэшированный singleton конфига приложения."""
    return Settings.from_env()
