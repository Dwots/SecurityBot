"""OpenRouterProvider — транспортный слой над OpenRouter (OpenAI-compatible).

См. `agents/artifacts/researcher/llm_provider_choice.md` §21–32 (Пересмотр
2026-05-16: DeepSeek V4 Flash / Qwen3 Coder (free) / MiMo V2 Pro) и
`agents/artifacts/backend/openrouter_provider.md`.

Аддитивный наследник модели `PolzaProvider` (на ~80% структурно идентичен).
Отличия:

1. **`_compute_cost_rub` устойчив к rate=0** (Qwen3 Coder free): никаких
   DBZ, никаких отрицательных значений; при нулевых тарифах возвращает 0.0.

2. **Опционально использует `usage.cost`** от OpenRouter (USD-стоимость
   в каждом ответе). При `use_usage_cost=True` приоритет над расчётом
   по `_per_1K` ставкам: `cost_rub = usage.cost * usd_rub_rate`.
   Default false — tariff-режим (предсказуемее).

3. **`models[]` rotation** (T-030 §24.4) — при `use_models_rotation=True`
   в request body передаётся массив `models=[primary, *fallback_model_ids]`
   через `extra_body`. OpenRouter сам fallback'ит при ошибке/rate-limit.

4. **Отдельный kill-switch** `OPENROUTER_BUDGET_LIMIT_RUB` — оркеструется
   фабрикой `build_llm_client_from_settings` (отдельный `BudgetCounter`,
   не пересекается с `POLZA_BUDGET_LIMIT_RUB`).

5. **`model_used`** — реально-исполненная модель из `resp.model` (при
   `models[]` rotation OpenRouter возвращает echoed модель, иногда с
   суффиксом-датой вроде `deepseek/deepseek-v4-flash-20260423`).
   Прокидывается через стандартное `LLMRawResponse.model`.

Безопасность:
- Ключ `OPENROUTER_API_KEY` — только в RAM, никогда не логируется и не
  попадает в `repr()`.
- `_safe_error_dict` извлекает только безопасные поля openai-ошибок
  (без `request`/`response`/`headers` с Authorization).

Контракт `LLMProvider` Protocol (system_design §3.4) НЕ меняется —
класс полностью совместим с `LLMClient` и через DI взаимозаменяем с
`PolzaProvider`.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional, Sequence

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


# Безопасный набор полей при логировании ошибок SDK (см. polza_provider §_safe_error_dict).
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


class OpenRouterProvider:
    """Транспортный `LLMProvider` для OpenRouter.

    Соответствует `LLMProvider` Protocol из `sunsec.llm.base`.
    """

    name: str = "openrouter"

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
        input_rub_per_1k: float = 0.01064,
        output_rub_per_1k: float = 0.02128,
        usd_rub_rate: float = 95.0,
        use_usage_cost: bool = False,
        use_models_rotation: bool = False,
        fallback_model_ids: Optional[Sequence[str]] = None,
        use_json_schema: bool = False,
        client: Any | None = None,
    ) -> None:
        if not api_key:
            # Аналогично PolzaProvider — позволяем создавать в тестовом режиме
            # с моком client. Реальный вызов без ключа упадёт на стороне SDK.
            log.warning(
                "openrouter_provider_initialized_without_api_key",
                extra={"base_url": base_url, "model_id": model_id},
            )
        self._api_key = api_key  # хранится в RAM, никогда не логируется
        self._base_url = base_url
        self._model_id = model_id
        self._timeout = float(timeout_seconds)
        self._max_retries = int(max_retries)
        self._temperature = float(temperature)
        self._max_tokens = int(max_tokens)
        self._input_rub_per_1k = max(0.0, float(input_rub_per_1k))
        self._output_rub_per_1k = max(0.0, float(output_rub_per_1k))
        self._usd_rub_rate = float(usd_rub_rate)
        self._use_usage_cost = bool(use_usage_cost)
        self._use_models_rotation = bool(use_models_rotation)
        # Нормализуем fallback-список: trim, skip-empty, unique-preserve-order.
        seen: set[str] = set()
        normalized: list[str] = []
        for mid in fallback_model_ids or ():
            mid_s = str(mid).strip()
            if not mid_s or mid_s in seen:
                continue
            seen.add(mid_s)
            normalized.append(mid_s)
        self._fallback_model_ids: tuple[str, ...] = tuple(normalized)
        self._use_json_schema = bool(use_json_schema)

        # Warning при конфликтной конфигурации (DoD T-031).
        if self._fallback_model_ids and not self._use_models_rotation:
            log.warning(
                "openrouter_fallback_models_provided_but_rotation_disabled",
                extra={
                    "fallback_count": len(self._fallback_model_ids),
                    "model_id": self._model_id,
                },
            )

        if client is None:
            client = self._build_default_client()
        self._client = client

        # `_last_usage_cost_usd` — диагностическое поле; обновляется в analyze
        # из `usage.cost` (если OpenRouter его прислал). Используется в логах,
        # не в публичном API.
        self._last_usage_cost_usd: Optional[float] = None

    # --- public API ---

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def fallback_model_ids(self) -> tuple[str, ...]:
        return self._fallback_model_ids

    @property
    def use_models_rotation(self) -> bool:
        return self._use_models_rotation

    def estimate_cost_rub(self, usage: TokenUsage) -> float:
        """Стоимость в рублях для текущего usage.

        Вызывается `LLMClient` дважды:
        1. ДО analyze (через `_estimate_cost`) — для kill-switch резервации.
           На этой стадии `_last_usage_cost_usd is None`, считаем по tariff-table.
        2. ПОСЛЕ analyze — `actual_cost = provider.estimate_cost_rub(raw.usage)`.
           На этой стадии `_last_usage_cost_usd` уже выставлен в `analyze`.
           При `use_usage_cost=True` приоритет — конверсия `usage.cost * usd_rub_rate`.

        Устойчив к нулевым тарифам (Qwen3 Coder free) — никаких DBZ.
        """
        prompt = max(0, int(getattr(usage, "prompt_tokens", 0) or 0))
        completion = max(0, int(getattr(usage, "completion_tokens", 0) or 0))
        usage_cost_usd = self._last_usage_cost_usd if self._use_usage_cost else None
        return self._compute_cost_rub(
            prompt_tokens=prompt,
            completion_tokens=completion,
            usage_cost_usd=usage_cost_usd,
        )

    async def analyze(self, prompt: PromptPayload) -> LLMRawResponse:
        """Один вызов `chat.completions.create` к OpenRouter.

        Преобразует SDK-ошибки в LLM-доменные исключения. Не логирует ключи.
        При `use_models_rotation=True` — передаёт `extra_body={"models": [...]}`.
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

        extra_body = self._build_extra_body()
        if extra_body:
            kwargs["extra_body"] = extra_body

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
            raise domain_exc from None

        latency_ms = (time.monotonic() - t0) * 1000.0
        return self._build_raw_response(resp, latency_ms)

    # --- internals ---

    def _build_default_client(self) -> Any:
        """Лениво импортируем `openai.AsyncOpenAI` для OpenRouter base_url."""
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
        # Для OpenRouter с mixed-rotation (Qwen3 Coder free не поддерживает
        # response_format) глобальный флаг `use_json_schema` контролирует поведение.
        if (
            self._use_json_schema
            and prompt.response_format == "json_schema"
            and prompt.response_schema
        ):
            return {
                "type": "json_schema",
                "json_schema": {
                    "name": "sunsec_llm_response",
                    "schema": prompt.response_schema,
                    "strict": True,
                },
            }
        return {"type": "json_object"}

    def _build_extra_body(self) -> dict[str, Any]:
        """Собирает OpenRouter-специфичные поля для request body."""
        extra: dict[str, Any] = {}
        if self._use_models_rotation:
            # OpenRouter принимает `models: [primary, *fallbacks]` в body.
            # Primary должен быть в списке — кладём первым.
            models_list = [self._model_id, *self._fallback_model_ids]
            # Уникализируем с сохранением порядка (на случай если primary
            # случайно встретился в fallback CSV).
            seen: set[str] = set()
            unique_models: list[str] = []
            for m in models_list:
                if m not in seen:
                    seen.add(m)
                    unique_models.append(m)
            extra["models"] = unique_models
        return extra

    def _build_raw_response(self, resp: Any, latency_ms: float) -> LLMRawResponse:
        """SDK-объект → `LLMRawResponse`. Защищён от отсутствия полей."""
        try:
            content = resp.choices[0].message.content or ""
        except (AttributeError, IndexError, TypeError) as exc:
            raise LLMParseError("LLM response missing choices[0].message.content") from exc

        usage = self._extract_usage(resp)
        # `model_used` — реальная модель, которой OpenRouter ответил
        # (важно при `models[]` rotation). Прокидываем через стандартное
        # поле `LLMRawResponse.model` — оно уже есть в контракте.
        model_used = getattr(resp, "model", self._model_id) or self._model_id

        # Опционально захватываем `usage.cost` (USD), если OpenRouter прислал.
        usage_cost_usd = self._extract_usage_cost_usd(resp)
        self._last_usage_cost_usd = usage_cost_usd

        # Логируем при rotation, какая модель реально ответила (для T-033/T-034).
        if self._use_models_rotation and model_used and model_used != self._model_id:
            log.info(
                "openrouter_rotation_fallback_used",
                extra={
                    "provider": self.name,
                    "primary_model": self._model_id,
                    "model_used": model_used,
                    "fallback_count": len(self._fallback_model_ids),
                },
            )

        # Cost-расчёт идёт по приоритету: usage.cost (если включено) → tariff-table.
        cost_rub = self._compute_cost_rub(
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            usage_cost_usd=usage_cost_usd if self._use_usage_cost else None,
        )

        # Прикрепляем cost к usage через mutable side-channel? Нет — контракт
        # `LLMRawResponse` это не предусматривает; `LLMClient` сам считает
        # `cost_rub = provider.estimate_cost_rub(raw.usage)`. Чтобы `usage.cost`
        # учитывался, мы переопределяем поведение через `estimate_cost_rub`
        # ниже (он смотрит на `_last_usage_cost_usd` при `use_usage_cost=True`).
        log.debug(
            "openrouter_call_built_response",
            extra={
                "provider": self.name,
                "model_used": model_used,
                "primary_model": self._model_id,
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "usage_cost_usd": usage_cost_usd,
                "cost_rub_provider": cost_rub,
                "use_usage_cost": self._use_usage_cost,
            },
        )

        return LLMRawResponse(
            model=str(model_used),
            content=str(content),
            usage=usage,
            latency_ms=float(latency_ms),
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
        except ValidationError:
            return TokenUsage()

    @staticmethod
    def _extract_usage_cost_usd(resp: Any) -> Optional[float]:
        """OpenRouter-специфичное поле `usage.cost` (USD, float).

        Может отсутствовать (например, при ошибке SDK или для некоторых моделей).
        Возвращает None если не нашли — это сигнал перейти на tariff-fallback.
        """
        u = getattr(resp, "usage", None)
        if u is None:
            return None
        # dict-форма
        if isinstance(u, dict):
            cost = u.get("cost")
        else:
            cost = getattr(u, "cost", None)
            if cost is None:
                # Иногда SDK даёт pydantic-объект, у которого custom-поля
                # видны только через model_dump() с extra=allow.
                try:
                    dump = u.model_dump()
                    cost = dump.get("cost")
                except (AttributeError, TypeError):
                    cost = None
        if cost is None:
            return None
        try:
            return float(cost)
        except (TypeError, ValueError):
            return None

    def _compute_cost_rub(
        self,
        *,
        prompt_tokens: int,
        completion_tokens: int,
        usage_cost_usd: Optional[float] = None,
    ) -> float:
        """Стоимость в рублях.

        Приоритет:
        1. Если `usage_cost_usd` передан (use_usage_cost=True ИЛИ из analyze)
           → `cost_rub = usage_cost_usd * usd_rub_rate`. Это точное значение,
           которое OpenRouter списал с баланса.
        2. Иначе — tariff-table: `prompt * input/1000 + completion * output/1000`.

        Устойчив к нулевым тарифам (Qwen3 Coder free) — никаких DBZ, никаких
        отрицательных значений. `max(0, ...)` гарантирует, что отрицательные
        токены (теоретически возможные при битом usage) не дадут отрицательный cost.
        """
        if usage_cost_usd is not None and usage_cost_usd >= 0.0:
            return float(usage_cost_usd) * self._usd_rub_rate

        prompt = max(0, int(prompt_tokens or 0))
        completion = max(0, int(completion_tokens or 0))
        # Никаких делений — только умножение/сложение. rate=0 → 0.0 корректно.
        cost = (
            prompt / 1000.0 * self._input_rub_per_1k
            + completion / 1000.0 * self._output_rub_per_1k
        )
        return max(0.0, cost)

    def _map_sdk_exception(self, exc: BaseException) -> Exception:
        """openai.* → доменные LLM-ошибки (аналогично PolzaProvider)."""
        try:
            import openai  # type: ignore
        except ImportError:  # pragma: no cover
            return LLMProviderUnavailable(f"unknown LLM error: {type(exc).__name__}")

        if isinstance(exc, getattr(openai, "APITimeoutError", tuple())):
            return LLMTimeout("openrouter timeout after retries")
        if isinstance(exc, getattr(openai, "APIConnectionError", tuple())):
            return LLMProviderUnavailable("openrouter connection error")
        if isinstance(exc, getattr(openai, "RateLimitError", tuple())):
            return LLMProviderUnavailable("openrouter rate limit (retries exhausted)")
        if isinstance(exc, getattr(openai, "APIStatusError", tuple())):
            return LLMProviderUnavailable(
                f"openrouter status error: {getattr(exc, 'status_code', '?')}"
            )
        if isinstance(exc, getattr(openai, "APIError", tuple())):
            return LLMProviderUnavailable("openrouter api error")
        return LLMProviderUnavailable(f"unknown LLM error: {type(exc).__name__}")

    def __repr__(self) -> str:  # без ключа
        rotation = "on" if self._use_models_rotation else "off"
        fb_count = len(self._fallback_model_ids)
        return (
            f"OpenRouterProvider(model={self._model_id!r}, base_url={self._base_url!r}, "
            f"timeout={self._timeout}s, max_retries={self._max_retries}, "
            f"rotation={rotation}, fallback_count={fb_count})"
        )


__all__ = ["OpenRouterProvider", "_safe_error_dict"]
