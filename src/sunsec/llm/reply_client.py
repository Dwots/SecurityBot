"""ReplyClient — диалоговый LLM-клиент (T-019).

Отличается от `LLMClient` (T-012):
- Не использует JSON-схему — провайдер возвращает обычный markdown-текст.
- Принимает `list[ChatTurn]` (thread) вместо `FilteredDiff`.
- Использует отдельный системный промпт (`REPLY_SYSTEM_PROMPT_V1`).
- Делит общий `BudgetCounter` с основным анализом — kill-switch единый,
  одна корзина.

Конструктор сам создаёт `openai.AsyncOpenAI` поверх параметров, чтобы НЕ
вмешиваться в `PolzaProvider`/`OpenRouterProvider` (они жёстко требуют
`response_format=json_object`). Параметры (api_key/base_url/model_id) —
ровно те же, что у активного `LLMProvider` (см. фабрику).

Безопасность (как в polza_provider.py):
- Ключ хранится в RAM, никогда не логируется.
- Из SDK-исключений извлекаются только safe-поля.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict

from sunsec.llm.base import (
    BudgetExceeded,
    LLMParseError,
    LLMProviderUnavailable,
    LLMTimeout,
    TokenUsage,
)
from sunsec.llm.budget import BudgetCounter
from sunsec.llm.prompts import REPLY_PROMPT_VERSION, REPLY_SYSTEM_PROMPT_V1

log = logging.getLogger(__name__)


_SAFE_OPENAI_ERROR_FIELDS = ("status_code", "code", "message", "param", "type")
_RESERVED_LOGRECORD_FIELDS = {"message", "asctime", "msg", "args", "name", "levelname"}


def _safe_error_dict(exc: BaseException) -> dict[str, Any]:
    out: dict[str, Any] = {"error_class": type(exc).__name__}
    for field in _SAFE_OPENAI_ERROR_FIELDS:
        val = getattr(exc, field, None)
        if val is None:
            continue
        key = f"error_{field}" if field in _RESERVED_LOGRECORD_FIELDS else field
        out[key] = val
    return out


class ChatTurn(BaseModel):
    """Одно сообщение в треде диалога."""

    model_config = ConfigDict(extra="forbid")
    role: str  # "user" | "assistant" — system добавляет ReplyClient сам
    content: str


class ReplyClient:
    """Доменный LLM-клиент для диалога в reply-режиме."""

    name: str = "reply"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model_id: str,
        budget: Optional[BudgetCounter] = None,
        timeout_seconds: float = 60.0,
        max_retries: int = 2,
        temperature: float = 0.3,
        max_tokens: int = 600,
        input_rub_per_1k: float = 0.015,
        output_rub_per_1k: float = 0.060,
        system_prompt: str = REPLY_SYSTEM_PROMPT_V1,
        prompt_version: str = REPLY_PROMPT_VERSION,
        client: Any | None = None,
    ) -> None:
        if not api_key:
            log.warning(
                "reply_client_initialized_without_api_key",
                extra={"base_url": base_url, "model_id": model_id},
            )
        self._api_key = api_key
        self._base_url = base_url
        self._model_id = model_id
        self._timeout = float(timeout_seconds)
        self._max_retries = int(max_retries)
        self._temperature = float(temperature)
        self._max_tokens = int(max_tokens)
        self._input_rub_per_1k = float(input_rub_per_1k)
        self._output_rub_per_1k = float(output_rub_per_1k)
        self._system = system_prompt
        self._prompt_version = prompt_version
        self._budget = budget
        self._client = client or self._build_default_client()

    @property
    def prompt_version(self) -> str:
        return self._prompt_version

    @property
    def budget(self) -> Optional[BudgetCounter]:
        return self._budget

    def estimate_cost_rub(self, usage: TokenUsage) -> float:
        prompt = max(0, int(usage.prompt_tokens))
        completion = max(0, int(usage.completion_tokens))
        return (
            prompt / 1000.0 * self._input_rub_per_1k
            + completion / 1000.0 * self._output_rub_per_1k
        )

    async def reply(
        self,
        thread: list[ChatTurn],
        *,
        repo: str,
        pr_number: int,
        comment_id: int,
    ) -> str:
        """Сгенерировать ответ на reply. Возвращает уже готовый markdown-текст.

        Контракт ошибок:
        - `BudgetExceeded` → raise; pipeline ловит и публикует короткое
          уведомление о выработке бюджета вместо ответа.
        - `LLMTimeout`/`LLMProviderUnavailable` → raise; pipeline пропускает
          публикацию.
        - Любой другой fault — raise, pipeline логирует и не отвечает.
        """
        if not thread:
            raise ValueError("ReplyClient.reply requires non-empty thread")

        # Резервируем worst-case: prompt_tokens ≈ sum(len)/3 + system_size/3.
        # Очень грубо — но это лишь резерв, реальная стоимость списывается
        # после ответа.
        approx_prompt_tokens = (
            sum(len(t.content) for t in thread) // 3
            + len(self._system) // 3
            + 32
        )
        approx_completion_tokens = self._max_tokens
        worst_case_usage = TokenUsage(
            prompt_tokens=approx_prompt_tokens,
            completion_tokens=approx_completion_tokens,
            total_tokens=approx_prompt_tokens + approx_completion_tokens,
        )
        estimated_cost = self.estimate_cost_rub(worst_case_usage)

        reservation_id: int | None = None
        if self._budget is not None:
            reservation_id = self._budget.check_and_reserve(estimated_cost)

        messages: list[dict[str, str]] = [{"role": "system", "content": self._system}]
        for turn in thread:
            role = turn.role if turn.role in {"user", "assistant"} else "user"
            messages.append({"role": role, "content": turn.content})

        t0 = time.monotonic()
        actual_cost = 0.0
        usage = TokenUsage()
        model_used = self._model_id
        try:
            try:
                resp = await self._client.chat.completions.create(
                    model=self._model_id,
                    messages=messages,
                    temperature=self._temperature,
                    max_tokens=self._max_tokens,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "llm_reply_call_failed",
                    extra={
                        "provider": self.name,
                        "model": self._model_id,
                        "repo": repo,
                        "pr_number": pr_number,
                        "comment_id": comment_id,
                        "duration_ms": int((time.monotonic() - t0) * 1000),
                        **_safe_error_dict(exc),
                    },
                )
                raise self._map_sdk_exception(exc) from None

            usage = self._extract_usage(resp)
            actual_cost = self.estimate_cost_rub(usage)
            model_used = getattr(resp, "model", self._model_id) or self._model_id
            try:
                content = resp.choices[0].message.content or ""
            except (AttributeError, IndexError, TypeError) as exc:
                raise LLMParseError(
                    "LLM reply response missing choices[0].message.content"
                ) from exc

            latency_ms = (time.monotonic() - t0) * 1000.0
            log.info(
                "llm_reply_completed",
                extra={
                    "provider": self.name,
                    "model": str(model_used),
                    "repo": repo,
                    "pr_number": pr_number,
                    "comment_id": comment_id,
                    "prompt_version": self._prompt_version,
                    "prompt_tokens": int(usage.prompt_tokens),
                    "completion_tokens": int(usage.completion_tokens),
                    "cost_rub": round(actual_cost, 6),
                    "latency_ms": int(latency_ms),
                    "budget_spent_rub": (
                        round(self._budget.spent_rub, 6) if self._budget else None
                    ),
                    "budget_remaining_rub": (
                        round(
                            max(0.0, self._budget.limit_rub - self._budget.spent_rub),
                            6,
                        )
                        if self._budget is not None
                        else None
                    ),
                },
            )
            return str(content).strip()
        finally:
            if self._budget is not None and reservation_id is not None:
                try:
                    self._budget.commit(actual_cost, reservation_id)
                except Exception:  # noqa: BLE001
                    try:
                        self._budget.release(reservation_id)
                    except Exception:  # noqa: BLE001
                        pass

    # --- internals ---

    def _build_default_client(self) -> Any:
        try:
            from openai import AsyncOpenAI  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise LLMProviderUnavailable(
                "openai SDK не установлен. `pip install openai>=1.30`."
            ) from exc
        return AsyncOpenAI(
            base_url=self._base_url,
            api_key=self._api_key,
            timeout=self._timeout,
            max_retries=self._max_retries,
        )

    @staticmethod
    def _extract_usage(resp: Any) -> TokenUsage:
        u = getattr(resp, "usage", None)
        if u is None:
            return TokenUsage()
        if isinstance(u, dict):
            data = u
        else:
            try:
                data = u.model_dump()
            except AttributeError:
                try:
                    data = u.dict()
                except AttributeError:
                    data = {
                        "prompt_tokens": getattr(u, "prompt_tokens", 0),
                        "completion_tokens": getattr(u, "completion_tokens", 0),
                        "total_tokens": getattr(u, "total_tokens", 0),
                    }
        try:
            return TokenUsage.model_validate(data)
        except Exception:  # noqa: BLE001
            return TokenUsage()

    def _map_sdk_exception(self, exc: BaseException) -> Exception:
        try:
            import openai  # type: ignore
        except ImportError:  # pragma: no cover
            return LLMProviderUnavailable(f"unknown LLM error: {type(exc).__name__}")
        if isinstance(exc, getattr(openai, "APITimeoutError", tuple())):
            return LLMTimeout("LLM reply timeout after retries")
        if isinstance(exc, getattr(openai, "APIConnectionError", tuple())):
            return LLMProviderUnavailable("LLM reply connection error")
        if isinstance(exc, getattr(openai, "RateLimitError", tuple())):
            return LLMProviderUnavailable("LLM reply rate limit (retries exhausted)")
        if isinstance(exc, getattr(openai, "APIStatusError", tuple())):
            return LLMProviderUnavailable(
                f"LLM reply status error: {getattr(exc, 'status_code', '?')}"
            )
        if isinstance(exc, getattr(openai, "APIError", tuple())):
            return LLMProviderUnavailable("LLM reply api error")
        return LLMProviderUnavailable(
            f"unknown LLM reply error: {type(exc).__name__}"
        )

    def __repr__(self) -> str:
        return (
            f"ReplyClient(model={self._model_id!r}, base_url={self._base_url!r}, "
            f"timeout={self._timeout}s)"
        )


__all__ = ["ReplyClient", "ChatTurn"]
