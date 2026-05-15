"""LLM-слой SunSecurityBot.

Двухуровневая модель (system_design §3.4):
- `LLMClient` — доменный фасад (`FilteredDiff → LLMResponseSchema`).
- `LLMProvider` — транспортный Protocol; реализация для polza.ai —
  `PolzaProvider`.

Вспомогательные:
- `PromptBuilder` (system_design §3.4) — компонует messages с системным
  промптом v1.0.0 (`prompts.SYSTEM_PROMPT_V1`).
- `BudgetCounter` (ADR-2) — kill-switch на бюджете polza.ai.
"""
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
from sunsec.llm.polza_provider import PolzaProvider
from sunsec.llm.prompt_builder import PromptBuilder
from sunsec.llm.prompts import PROMPT_VERSION, SYSTEM_PROMPT_V1

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
    "PolzaProvider",
    "PromptBuilder",
    "PROMPT_VERSION",
    "SYSTEM_PROMPT_V1",
    # factory
    "build_llm_client_from_settings",
]


def build_llm_client_from_settings(settings) -> LLMClient:
    """Удобная DI-фабрика (используется `app.py`).

    Принимает уже собранный `Settings` (см. `sunsec.config`). Никаких
    `os.environ` тут — `Settings` сам подгружает `.env` и валидирует.
    """
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
    return LLMClient(provider=provider, builder=builder, budget=budget)
