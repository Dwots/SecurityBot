"""LLMProvider Protocol + транспортные типы.

См. system_design §3.4 (двухуровневая модель после RT-003):
- `LLMClient` — доменный фасад (FilteredDiff → LLMResponseSchema).
- `LLMProvider` — транспорт (PromptPayload → LLMRawResponse).
"""
from __future__ import annotations

from typing import Any, Optional, Protocol

from pydantic import BaseModel, ConfigDict


# --- Ошибки LLM-слоя ---

class LLMError(Exception):
    """Базовый класс LLM-ошибок."""


class BudgetExceeded(LLMError):
    """ADR-2 kill-switch: бюджет polza.ai исчерпан."""


class LLMTimeout(LLMError):
    """Таймаут после исчерпания retries."""


class LLMParseError(LLMError):
    """Невалидный JSON / схема после ретрая."""


class LLMProviderUnavailable(LLMError):
    """Primary провайдер недоступен и fallback не разрешён / тоже упал."""


# --- Транспортные типы ---

class TokenUsage(BaseModel):
    model_config = ConfigDict(extra="ignore")
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class PromptPayload(BaseModel):
    """Что PromptBuilder отдаёт провайдеру."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)
    system: str
    user: str
    response_schema: Optional[dict[str, Any]] = None
    response_format: str = "json_object"  # "json_object" | "json_schema"


class LLMRawResponse(BaseModel):
    """Что провайдер возвращает в `LLMClient`. Не покидает границ LLMClient."""

    model_config = ConfigDict(extra="ignore", arbitrary_types_allowed=True)
    model: str
    content: str
    usage: TokenUsage
    latency_ms: float = 0.0


class LLMProvider(Protocol):
    """Транспортный Protocol (см. system_design §3.4)."""

    name: str  # "polza" | "openai_direct" | "anthropic_direct" | ...

    async def analyze(self, prompt: PromptPayload) -> LLMRawResponse:
        ...

    def estimate_cost_rub(self, usage: TokenUsage) -> float:
        ...
