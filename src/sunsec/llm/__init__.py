"""LLM-слой SunSecurityBot.

Двухуровневая модель (system_design §3.4):
- `LLMClient` — доменный фасад (`FilteredDiff → LLMResponseSchema`).
- `LLMProvider` — транспортный Protocol; реализации для polza.ai —
  `PolzaProvider`, для OpenRouter — `OpenRouterProvider` (T-031).

Вспомогательные:
- `PromptBuilder` (system_design §3.4) — компонует messages с системным
  промптом v1.0.0 (`prompts.SYSTEM_PROMPT_V1`).
- `BudgetCounter` (ADR-2) — kill-switch на бюджете LLM-провайдера. С M-8
  Replan #4 — две **независимые корзины** (polza + openrouter); фабрика
  выбирает счётчик по `LLM_PROVIDER` env.
"""
import logging

from sunsec.llm.base import (
    BudgetExceeded,
    LLMParseError,
    LLMProvider,
    LLMProviderUnavailable,
    LLMRawResponse,
    LLMTimeout,
    PromptPayload,
    TokenUsage,
)
from sunsec.llm.budget import BudgetCounter
from sunsec.llm.client import LLMClient
from sunsec.llm.openrouter_provider import OpenRouterProvider
from sunsec.llm.polza_provider import PolzaProvider
from sunsec.llm.prompt_builder import PromptBuilder
from sunsec.llm.prompts import (
    EMPTY_SUMMARY,
    PROMPT_VERSION,
    REPLY_PROMPT_VERSION,
    REPLY_SYSTEM_PROMPT_V1,
    SYSTEM_PROMPT_V1,
)
from sunsec.llm.reply_client import ChatTurn, ReplyClient

log = logging.getLogger(__name__)

__all__ = [
    # transport
    "BudgetExceeded",
    "LLMParseError",
    "LLMProvider",
    "LLMProviderUnavailable",
    "LLMRawResponse",
    "LLMTimeout",
    "PromptPayload",
    "TokenUsage",
    # domain
    "BudgetCounter",
    "LLMClient",
    "OpenRouterProvider",
    "PolzaProvider",
    "PromptBuilder",
    "ReplyClient",
    "ChatTurn",
    "PROMPT_VERSION",
    "SYSTEM_PROMPT_V1",
    "REPLY_PROMPT_VERSION",
    "REPLY_SYSTEM_PROMPT_V1",
    "EMPTY_SUMMARY",
    # factory
    "build_llm_client_from_settings",
    "build_reply_client_from_settings",
]


def build_llm_client_from_settings(settings) -> LLMClient:
    """Удобная DI-фабрика (используется `app.py`).

    Принимает уже собранный `Settings` (см. `sunsec.config`). Никаких
    `os.environ` тут — `Settings` сам подгружает `.env` и валидирует.

    Выбор провайдера — по `settings.llm_provider` (`polza` | `openrouter`).
    Default `polza` (backwards compat). Бюджет — отдельный `BudgetCounter`
    на каждый провайдер (две независимые корзины: `POLZA_BUDGET_LIMIT_RUB`
    и `OPENROUTER_BUDGET_LIMIT_RUB`).
    """
    provider_kind = str(getattr(settings, "llm_provider", "polza") or "polza").strip().lower()

    if provider_kind == "openrouter":
        api_key = str(getattr(settings, "openrouter_api_key", "") or "")
        if not api_key:
            # Понятная ошибка на старте приложения вместо падения на первом analyze.
            raise ValueError(
                "LLM_PROVIDER=openrouter requires non-empty OPENROUTER_API_KEY in env / .env"
            )
        provider = OpenRouterProvider(
            api_key=api_key,
            base_url=settings.openrouter_base_url,
            model_id=settings.openrouter_model_id,
            timeout_seconds=settings.openrouter_timeout_seconds,
            max_retries=settings.openrouter_max_retries,
            temperature=settings.llm_temperature,
            max_tokens=settings.llm_max_tokens,
            input_rub_per_1k=settings.openrouter_input_rub_per_1k,
            output_rub_per_1k=settings.openrouter_output_rub_per_1k,
            usd_rub_rate=settings.openrouter_usd_rub_rate,
            use_usage_cost=settings.openrouter_use_usage_cost,
            use_models_rotation=settings.openrouter_use_models_rotation,
            fallback_model_ids=tuple(settings.openrouter_fallback_model_ids or ()),
            use_json_schema=settings.openrouter_use_json_schema,
        )
        builder = PromptBuilder(use_json_schema=settings.openrouter_use_json_schema)
        budget = BudgetCounter(limit_rub=settings.openrouter_budget_limit_rub)
        log.info(
            "llm_client_built",
            extra={
                "provider": "openrouter",
                "model": settings.openrouter_model_id,
                "budget_limit_rub": settings.openrouter_budget_limit_rub,
                "use_models_rotation": settings.openrouter_use_models_rotation,
                "fallback_count": len(settings.openrouter_fallback_model_ids or ()),
                "use_usage_cost": settings.openrouter_use_usage_cost,
            },
        )
        return LLMClient(provider=provider, builder=builder, budget=budget)

    # Default / explicit "polza" — backwards compat.
    provider = PolzaProvider(
        api_key=settings.polza_api_key,
        base_url=settings.polza_base_url,
        model_id=settings.polza_model_id,
        timeout_seconds=settings.polza_timeout_seconds,
        max_retries=settings.polza_max_retries,
        temperature=settings.llm_temperature,
        max_tokens=settings.llm_max_tokens,
        input_rub_per_1k=settings.polza_input_rub_per_1k,
        output_rub_per_1k=settings.polza_output_rub_per_1k,
    )
    builder = PromptBuilder(use_json_schema=settings.polza_use_json_schema)
    budget = BudgetCounter(limit_rub=settings.polza_budget_limit_rub)
    log.info(
        "llm_client_built",
        extra={
            "provider": "polza",
            "model": settings.polza_model_id,
            "budget_limit_rub": settings.polza_budget_limit_rub,
        },
    )
    return LLMClient(provider=provider, builder=builder, budget=budget)


def build_reply_client_from_settings(
    settings,
    *,
    budget: BudgetCounter | None = None,
) -> ReplyClient | None:
    """DI-фабрика для `ReplyClient` (T-019).

    Если reply-режим выключен (`enable_reply_mode=false`) — возвращает `None`,
    pipeline пропустит публикацию и не будет требовать клиент в DI.

    Параметры (api_key/base_url/model_id) берутся у того же провайдера, что
    активен для основного анализа (см. `build_llm_client_from_settings`).
    `budget` опционален: если передан — используется тот же kill-switch,
    что и у `LLMClient` (одна корзина рублей). Если None — клиент работает
    без бюджета (НЕ рекомендуется для prod).
    """
    if not getattr(settings, "enable_reply_mode", True):
        log.info("reply_client_disabled", extra={"reason": "enable_reply_mode=false"})
        return None

    provider_kind = str(
        getattr(settings, "llm_provider", "polza") or "polza"
    ).strip().lower()

    if provider_kind == "openrouter":
        api_key = str(getattr(settings, "openrouter_api_key", "") or "")
        if not api_key:
            log.warning(
                "reply_client_skipped_no_key",
                extra={"provider": "openrouter"},
            )
            return None
        rc = ReplyClient(
            api_key=api_key,
            base_url=settings.openrouter_base_url,
            model_id=settings.openrouter_model_id,
            budget=budget,
            timeout_seconds=settings.openrouter_timeout_seconds,
            max_retries=settings.openrouter_max_retries,
            temperature=0.3,
            max_tokens=settings.reply_max_tokens,
            input_rub_per_1k=settings.openrouter_input_rub_per_1k,
            output_rub_per_1k=settings.openrouter_output_rub_per_1k,
        )
        log.info(
            "reply_client_built",
            extra={
                "provider": "openrouter",
                "model": settings.openrouter_model_id,
                "max_tokens": settings.reply_max_tokens,
                "budget_shared": budget is not None,
            },
        )
        return rc

    # polza (default)
    api_key = str(getattr(settings, "polza_api_key", "") or "")
    if not api_key:
        log.warning("reply_client_skipped_no_key", extra={"provider": "polza"})
        return None
    rc = ReplyClient(
        api_key=api_key,
        base_url=settings.polza_base_url,
        model_id=settings.polza_model_id,
        budget=budget,
        timeout_seconds=settings.polza_timeout_seconds,
        max_retries=settings.polza_max_retries,
        temperature=0.3,
        max_tokens=settings.reply_max_tokens,
        input_rub_per_1k=settings.polza_input_rub_per_1k,
        output_rub_per_1k=settings.polza_output_rub_per_1k,
    )
    log.info(
        "reply_client_built",
        extra={
            "provider": "polza",
            "model": settings.polza_model_id,
            "max_tokens": settings.reply_max_tokens,
            "budget_shared": budget is not None,
        },
    )
    return rc
