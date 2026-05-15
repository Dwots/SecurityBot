"""PolzaProvider — транспортный слой над polza.ai (OpenAI-compatible).

См. system_design §3.4 (двухуровневая модель) и ml_instructions_polza §3.

Конструкция:
- Внутри `openai.AsyncOpenAI(base_url=POLZA_BASE_URL, api_key=POLZA_API_KEY)`.
- `analyze(prompt)` → один `chat.completions.create` с `temperature=0.0`,
  `response_format={"type":"json_object"}` или `json_schema` (флаг).
- `max_retries` и `timeout` отдаём в SDK — он сам делает экспоненциальный
  backoff на 429/5xx (см. llm_provider_choice §15.3, §17.1).
- Стоимость считаем тут же из `resp.usage.prompt_tokens` / `completion_tokens`
  по тарифам Settings (research §16, дефолты — gpt-4o-mini через polza).
- Любые exception из SDK логируем БЕЗ `request`/`response` объектов (там
  могут быть `Authorization` заголовки) — только `status_code` / `code`
  / `message` / `param` (ml_instructions_polza §4).

Импорт `openai` — отложенный (в `__init__`), потому что:
1. Оркестратор может не иметь SDK установленным (тесты идут без него).
2. Пакет `sunsec.llm` импортируется из других модулей (контракты) — не
   хотим тянуть тяжёлую зависимость на старте.

Тесты `tests/unit/test_llm_*` мокают этот класс целиком через `unittest.mock`
и НЕ инстанцируют реальный `openai.AsyncOpenAI` — реальный smoke-call
оставлен на T-014/T-015 (по решению QA, чтобы не жечь 90 ₽ бюджета).
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

from pydantic import ValidationError

from sunsec.llm.base import (
    LLMParseError,
    LLMProviderUnavailable,
    LLMRawResponse,
    LLMTimeout,
    PromptPayload,
    TokenUsage,
)

log = logging.getLogger(__name__)


# Безопасный набор полей при логировании ошибок SDK. См. §4 ml_instructions_polza.
# Ключи — РОВНО названия атрибутов openai.* exception'ов; при логировании
# через `extra=...` поле `message` переименовывается в `error_message`, потому
# что `LogRecord.message` зарезервирован stdlib-логгером.
_SAFE_OPENAI_ERROR_FIELDS = ("status_code", "code", "message", "param", "type")
_RESERVED_LOGRECORD_FIELDS = {"message", "asctime", "msg", "args", "name", "levelname"}


def _safe_error_dict(exc: BaseException) -> dict[str, Any]:
    """Извлекает только безопасные поля из openai.APIError / APIStatusError.

    НЕ трогаем `exc.request` / `exc.response` — там Authorization header.
    Поля, имена которых конфликтуют с `LogRecord` (например, `message`),
    переименовываются с префиксом `error_`.
    """
    out: dict[str, Any] = {"error_class": type(exc).__name__}
    for field in _SAFE_OPENAI_ERROR_FIELDS:
        val = getattr(exc, field, None)
        if val is None:
            continue
        key = f"error_{field}" if field in _RESERVED_LOGRECORD_FIELDS else field
        out[key] = val
    return out


class PolzaProvider:
    """Транспортный `LLMProvider` для polza.ai.

    Соответствует `LLMProvider` Protocol из `sunsec.llm.base`.
    """

    name: str = "polza"

    def __init__(
        self,
        *,
        api_key: str,
        base_url: str,
        model_id: str,
        timeout_seconds: float = 60.0,
        max_retries: int = 2,
        temperature: float = 0.0,
        max_tokens: int = 2048,
        input_rub_per_1k: float = 0.015,
        output_rub_per_1k: float = 0.060,
        client: Any | None = None,
    ) -> None:
        if not api_key:
            # Не падаем — позволяем создавать провайдера в тестовом режиме
            # с моком client. Реальный вызов без ключа упадёт на стороне SDK.
            log.warning(
                "polza_provider_initialized_without_api_key",
                extra={"base_url": base_url, "model_id": model_id},
            )
        self._api_key = api_key  # хранится в RAM, никогда не логируется
        self._base_url = base_url
        self._model_id = model_id
        self._timeout = float(timeout_seconds)
        self._max_retries = int(max_retries)
        self._temperature = float(temperature)
        self._max_tokens = int(max_tokens)
        self._input_rub_per_1k = float(input_rub_per_1k)
        self._output_rub_per_1k = float(output_rub_per_1k)

        if client is None:
            client = self._build_default_client()
        self._client = client

    # --- public API ---

    @property
    def model_id(self) -> str:
        return self._model_id

    def estimate_cost_rub(self, usage: TokenUsage) -> float:
        """Стоимость в рублях по тарифу модели (research §16)."""
        prompt = max(0, int(usage.prompt_tokens))
        completion = max(0, int(usage.completion_tokens))
        return (
            prompt / 1000.0 * self._input_rub_per_1k
            + completion / 1000.0 * self._output_rub_per_1k
        )

    async def analyze(self, prompt: PromptPayload) -> LLMRawResponse:
        """Один вызов `chat.completions.create` к polza.ai.

        Преобразует SDK-ошибки в LLM-доменные исключения. Не логирует ключи.
        """
        messages = [
            {"role": "system", "content": prompt.system},
            {"role": "user", "content": prompt.user},
        ]
        kwargs: dict[str, Any] = {
            "model": self._model_id,
            "messages": messages,
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }
        kwargs["response_format"] = self._build_response_format(prompt)

        t0 = time.monotonic()
        try:
            resp = await self._client.chat.completions.create(**kwargs)
        except Exception as exc:  # noqa: BLE001 — нормализуем SDK-ошибки
            domain_exc = self._map_sdk_exception(exc)
            log.warning(
                "llm_call_failed",
                extra={
                    "provider": self.name,
                    "model": self._model_id,
                    "duration_ms": int((time.monotonic() - t0) * 1000),
                    **_safe_error_dict(exc),
                },
            )
            raise domain_exc from None  # `from None`: НЕ цепляем traceback с request

        latency_ms = (time.monotonic() - t0) * 1000.0
        return self._build_raw_response(resp, latency_ms)

    # --- internals ---

    def _build_default_client(self) -> Any:
        """Лениво импортируем `openai.AsyncOpenAI`.

        Если SDK не установлен — поднимем понятную ошибку при первой
        попытке вызова (а не на импорте модуля).
        """
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

    def _build_response_format(self, prompt: PromptPayload) -> dict[str, Any]:
        if prompt.response_format == "json_schema" and prompt.response_schema:
            return {
                "type": "json_schema",
                "json_schema": {
                    "name": "sunsec_llm_response",
                    "schema": prompt.response_schema,
                    "strict": True,
                },
            }
        return {"type": "json_object"}

    def _build_raw_response(self, resp: Any, latency_ms: float) -> LLMRawResponse:
        """SDK-объект → `LLMRawResponse`. Защищён от отсутствия полей."""
        # `resp.choices[0].message.content` — стандарт OpenAI.
        try:
            content = resp.choices[0].message.content or ""
        except (AttributeError, IndexError, TypeError) as exc:
            raise LLMParseError("LLM response missing choices[0].message.content") from exc

        usage = self._extract_usage(resp)
        model = getattr(resp, "model", self._model_id) or self._model_id
        return LLMRawResponse(
            model=str(model),
            content=str(content),
            usage=usage,
            latency_ms=float(latency_ms),
        )

    @staticmethod
    def _extract_usage(resp: Any) -> TokenUsage:
        u = getattr(resp, "usage", None)
        if u is None:
            return TokenUsage()
        # SDK возвращает pydantic-like объекты OR dict.
        if isinstance(u, dict):
            data = u
        else:
            try:
                data = u.model_dump()  # pydantic v2
            except AttributeError:
                try:
                    data = u.dict()  # pydantic v1
                except AttributeError:
                    data = {
                        "prompt_tokens": getattr(u, "prompt_tokens", 0),
                        "completion_tokens": getattr(u, "completion_tokens", 0),
                        "total_tokens": getattr(u, "total_tokens", 0),
                    }
        try:
            return TokenUsage.model_validate(data)
        except ValidationError:
            return TokenUsage()

    def _map_sdk_exception(self, exc: BaseException) -> Exception:
        """openai.* → доменные LLM-ошибки.

        Импорт `openai.*` отложенный — если SDK не установлен и сюда попало
        не-openai-исключение, возвращаем `LLMProviderUnavailable`.
        """
        try:
            import openai  # type: ignore
        except ImportError:  # pragma: no cover
            return LLMProviderUnavailable(f"unknown LLM error: {type(exc).__name__}")

        # Таймаут.
        if isinstance(exc, getattr(openai, "APITimeoutError", tuple())):
            return LLMTimeout("polza.ai timeout after retries")
        # 5xx / прочее API.
        if isinstance(exc, getattr(openai, "APIConnectionError", tuple())):
            return LLMProviderUnavailable("polza.ai connection error")
        if isinstance(exc, getattr(openai, "RateLimitError", tuple())):
            # SDK уже исчерпал retries → пробрасываем как Unavailable.
            return LLMProviderUnavailable("polza.ai rate limit (retries exhausted)")
        if isinstance(exc, getattr(openai, "APIStatusError", tuple())):
            return LLMProviderUnavailable(
                f"polza.ai status error: {getattr(exc, 'status_code', '?')}"
            )
        if isinstance(exc, getattr(openai, "APIError", tuple())):
            return LLMProviderUnavailable("polza.ai api error")
        return LLMProviderUnavailable(f"unknown LLM error: {type(exc).__name__}")

    def __repr__(self) -> str:  # без ключа
        return (
            f"PolzaProvider(model={self._model_id!r}, base_url={self._base_url!r}, "
            f"timeout={self._timeout}s, max_retries={self._max_retries})"
        )


__all__ = ["PolzaProvider"]
