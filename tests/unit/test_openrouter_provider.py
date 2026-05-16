"""Unit-тесты OpenRouterProvider (T-031).

Покрытие — по DoD T-031:
1. happy-path tariff-режим (один вызов через mock) → корректный `LLMRawResponse`,
   `cost_rub` рассчитан по `input/output_rub_per_1k`.
2. happy-path `usage.cost` режим (флаг `use_usage_cost=True`) → cost_rub из
   `usage.cost * usd_rub_rate` имеет приоритет над tariff-table.
3. `_compute_cost_rub` при rate=0 (Qwen3 Coder free) → возвращает 0.0, не падает.
4. `models[]` rotation: `use_models_rotation=True` → в request body `extra_body`
   содержит `models=[primary, *fallbacks]` (а не одиночный `model=`).
5. fallback без rotation → лог-warning + поведение как одна модель.
6. безопасность: `__repr__` без api_key; `_safe_error_dict` без Authorization
   / request / response.
7. timeout SDK → `LLMTimeout`.
8. 5xx через SDK → `LLMProviderUnavailable`.
9. factory `build_llm_client_from_settings(LLM_PROVIDER=openrouter)` → клиент с
   `OpenRouterProvider` + отдельный `BudgetCounter`.
10. factory backwards compat: `LLM_PROVIDER=polza` (default) → `PolzaProvider`.
11. factory: пустой `OPENROUTER_API_KEY` при `LLM_PROVIDER=openrouter` →
    понятная ошибка на старте.
12. BudgetExceeded для openrouter — отдельная корзина (polza budget не трогается).

Все тесты — mock-only (никаких реальных HTTP).
"""
from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("pydantic")

from sunsec.config.settings import Settings  # noqa: E402
from sunsec.contracts import (  # noqa: E402
    AddedLine,
    FilteredDiff,
    FilteredDiffFile,
)
from sunsec.llm import build_llm_client_from_settings  # noqa: E402
from sunsec.llm.base import (  # noqa: E402
    BudgetExceeded,
    LLMProviderUnavailable,
    LLMTimeout,
    PromptPayload,
    TokenUsage,
)
from sunsec.llm.budget import BudgetCounter  # noqa: E402
from sunsec.llm.client import LLMClient  # noqa: E402
from sunsec.llm.openrouter_provider import OpenRouterProvider, _safe_error_dict  # noqa: E402
from sunsec.llm.polza_provider import PolzaProvider  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_response(
    *,
    content: str = '{"findings": [], "summary": "No security issues detected in diff."}',
    prompt_tokens: int = 3000,
    completion_tokens: int = 200,
    model: str = "deepseek/deepseek-v4-flash",
    usage_cost: float | None = None,
) -> MagicMock:
    """Сборщик mock-объекта в формате openai-SDK ответа."""
    fake_message = MagicMock()
    fake_message.content = content
    fake_choice = MagicMock()
    fake_choice.message = fake_message
    fake_response = MagicMock()
    fake_response.choices = [fake_choice]
    fake_response.model = model
    usage_dict: dict[str, Any] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }
    if usage_cost is not None:
        usage_dict["cost"] = usage_cost
    fake_response.usage = usage_dict
    return fake_response


def _make_filtered_diff() -> FilteredDiff:
    return FilteredDiff(
        repo="acme/example",
        pr_number=42,
        head_sha="deadbeef",
        files=[
            FilteredDiffFile(
                path="users.py",
                language="python",
                added_lines=[AddedLine(new_line_no=12, content="q = f'SELECT ...'")],
            )
        ],
        estimated_input_tokens=128,
        content_hash="abc123",
    )


def _make_payload() -> PromptPayload:
    return PromptPayload(system="sys", user="user diff")


# ---------------------------------------------------------------------------
# 1. Happy-path — tariff-режим
# ---------------------------------------------------------------------------


async def test_openrouter_provider_happy_path_tariff_mode() -> None:
    """tariff-режим: один вызов → корректный raw_response, cost по rate-table."""
    fake_create = AsyncMock(
        return_value=_make_fake_response(
            prompt_tokens=1000,
            completion_tokens=500,
            usage_cost=None,  # tariff-режим — usage.cost не задан/игнорируется
        )
    )
    fake_client = MagicMock()
    fake_client.chat.completions.create = fake_create

    provider = OpenRouterProvider(
        api_key="sk-or-v1-test-1234",
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        input_rub_per_1k=0.01064,
        output_rub_per_1k=0.02128,
        use_usage_cost=False,
        client=fake_client,
    )

    raw = await provider.analyze(_make_payload())

    assert raw.usage.prompt_tokens == 1000
    assert raw.usage.completion_tokens == 500
    assert raw.model == "deepseek/deepseek-v4-flash"

    # Cost: 1000/1000 * 0.01064 + 500/1000 * 0.02128 = 0.01064 + 0.01064 = 0.02128.
    cost = provider.estimate_cost_rub(raw.usage)
    assert cost == pytest.approx(0.02128, rel=1e-6)

    # Параметры запроса — primary model, без models[] rotation.
    fake_create.assert_called_once()
    kwargs = fake_create.call_args.kwargs
    assert kwargs["model"] == "deepseek/deepseek-v4-flash"
    assert kwargs["temperature"] == 0.0
    assert "extra_body" not in kwargs  # rotation off → нет extra_body


# ---------------------------------------------------------------------------
# 2. Happy-path — usage.cost режим
# ---------------------------------------------------------------------------


async def test_openrouter_provider_usage_cost_mode_overrides_tariff() -> None:
    """При `use_usage_cost=True` cost_rub = usage.cost * usd_rub_rate (приоритет)."""
    fake_create = AsyncMock(
        return_value=_make_fake_response(
            prompt_tokens=3000,
            completion_tokens=500,
            usage_cost=0.0005,  # USD, точное значение от OpenRouter
        )
    )
    fake_client = MagicMock()
    fake_client.chat.completions.create = fake_create

    provider = OpenRouterProvider(
        api_key="sk-or-v1-test-5678",
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        input_rub_per_1k=999.0,  # абсурдно большой tariff — должен игнорироваться
        output_rub_per_1k=999.0,
        usd_rub_rate=95.0,
        use_usage_cost=True,
        client=fake_client,
    )

    raw = await provider.analyze(_make_payload())
    cost = provider.estimate_cost_rub(raw.usage)
    # 0.0005 USD × 95.0 = 0.0475 ₽ — приоритет над абсурдным tariff.
    assert cost == pytest.approx(0.0005 * 95.0, rel=1e-6)


# ---------------------------------------------------------------------------
# 3. `_compute_cost_rub` при rate=0 (Qwen3 Coder free)
# ---------------------------------------------------------------------------


def test_compute_cost_rub_zero_rate_no_dbz_no_negative() -> None:
    """rate=0 → cost=0.0, не падает на любом усage."""
    provider = OpenRouterProvider(
        api_key="sk-or-v1-test-free",
        base_url="https://openrouter.ai/api/v1",
        model_id="qwen/qwen3-coder:free",
        input_rub_per_1k=0.0,
        output_rub_per_1k=0.0,
        use_usage_cost=False,
        client=MagicMock(),
    )

    # Большое число токенов — всё равно 0.
    usage = TokenUsage(prompt_tokens=999_999, completion_tokens=999_999, total_tokens=1_999_998)
    cost = provider.estimate_cost_rub(usage)
    assert cost == 0.0

    # Прямой вызов внутренней функции — те же гарантии.
    cost2 = provider._compute_cost_rub(
        prompt_tokens=1_000_000,
        completion_tokens=1_000_000,
        usage_cost_usd=None,
    )
    assert cost2 == 0.0

    # Even с usage_cost_usd=0.0 — корректно 0 (не None, не negative).
    cost3 = provider._compute_cost_rub(
        prompt_tokens=100,
        completion_tokens=50,
        usage_cost_usd=0.0,
    )
    assert cost3 == 0.0


# ---------------------------------------------------------------------------
# 4. `models[]` rotation в request body
# ---------------------------------------------------------------------------


async def test_openrouter_provider_models_rotation_in_request_body() -> None:
    """use_models_rotation=True → kwargs['extra_body']['models'] = [primary, *fb]."""
    fake_create = AsyncMock(return_value=_make_fake_response())
    fake_client = MagicMock()
    fake_client.chat.completions.create = fake_create

    provider = OpenRouterProvider(
        api_key="sk-or-v1-test-rot",
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        use_models_rotation=True,
        fallback_model_ids=("xiaomi/mimo-v2-pro", "qwen/qwen3-coder:free"),
        client=fake_client,
    )

    await provider.analyze(_make_payload())

    kwargs = fake_create.call_args.kwargs
    assert kwargs["model"] == "deepseek/deepseek-v4-flash"
    assert "extra_body" in kwargs
    assert kwargs["extra_body"]["models"] == [
        "deepseek/deepseek-v4-flash",
        "xiaomi/mimo-v2-pro",
        "qwen/qwen3-coder:free",
    ]


async def test_openrouter_provider_rotation_dedup_primary_in_fallbacks() -> None:
    """Если primary случайно встретился в fallback CSV — дублей в models[] нет."""
    fake_create = AsyncMock(return_value=_make_fake_response())
    fake_client = MagicMock()
    fake_client.chat.completions.create = fake_create

    provider = OpenRouterProvider(
        api_key="sk-or-v1-test-dedup",
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        use_models_rotation=True,
        fallback_model_ids=(
            "xiaomi/mimo-v2-pro",
            "deepseek/deepseek-v4-flash",  # дубль primary
            "qwen/qwen3-coder:free",
        ),
        client=fake_client,
    )
    await provider.analyze(_make_payload())
    models_list = fake_create.call_args.kwargs["extra_body"]["models"]
    # Дубль убран.
    assert models_list.count("deepseek/deepseek-v4-flash") == 1
    assert models_list == [
        "deepseek/deepseek-v4-flash",
        "xiaomi/mimo-v2-pro",
        "qwen/qwen3-coder:free",
    ]


# ---------------------------------------------------------------------------
# 5. Fallback без rotation → warning
# ---------------------------------------------------------------------------


def test_openrouter_provider_warns_on_fallbacks_without_rotation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """fallback_model_ids непустой + use_models_rotation=False → warning."""
    caplog.set_level(logging.WARNING, logger="sunsec.llm.openrouter_provider")

    OpenRouterProvider(
        api_key="sk-or-v1-test-warn",
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        use_models_rotation=False,
        fallback_model_ids=("xiaomi/mimo-v2-pro",),
        client=MagicMock(),
    )

    warns = [
        r for r in caplog.records
        if r.message == "openrouter_fallback_models_provided_but_rotation_disabled"
    ]
    assert warns, "expected warning when fallbacks set but rotation off"


# ---------------------------------------------------------------------------
# 6. Безопасность — __repr__ без api_key, _safe_error_dict
# ---------------------------------------------------------------------------


def test_openrouter_provider_repr_does_not_leak_api_key() -> None:
    """repr(OpenRouterProvider) не содержит api_key."""
    secret = "sk-or-v1-LEAKED-1234567890abcdef"
    provider = OpenRouterProvider(
        api_key=secret,
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        client=MagicMock(),
    )
    rep = repr(provider)
    assert secret not in rep
    assert "OpenRouterProvider" in rep
    assert "deepseek/deepseek-v4-flash" in rep
    # `rotation` присутствует — диагностически полезно.
    assert "rotation=" in rep


def test_safe_error_dict_strips_request_response_headers() -> None:
    """_safe_error_dict не пропускает request/response/headers."""
    secret = "sk-or-v1-LEAKED-2345"

    class _FakeAPIError(Exception):
        status_code = 500
        code = "internal_error"
        message = "internal server error"
        param = None
        type = "api_error"
        request = MagicMock()
        response = MagicMock()

    err = _FakeAPIError(f"original repr contains {secret}")
    err.request.headers = {"Authorization": f"Bearer {secret}"}

    safe = _safe_error_dict(err)
    assert "request" not in safe
    assert "response" not in safe
    assert "headers" not in safe
    # Безопасные поля присутствуют.
    assert safe["error_class"] == "_FakeAPIError"
    assert safe["status_code"] == 500
    # secret нигде в dump-е.
    assert secret not in json.dumps(safe, default=str)


async def test_openrouter_provider_does_not_leak_key_in_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """При SDK exception ключ не уходит в лог llm_call_failed."""
    secret = "sk-or-v1-LEAKED-secret-do-not-print"

    class _FakeAPIError(Exception):
        status_code = 503
        code = "service_unavailable"
        message = "upstream error"
        param = None
        type = "api_error"
        request = MagicMock()
        response = MagicMock()

    err = _FakeAPIError(f"orig {secret}")
    err.request.headers = {"Authorization": f"Bearer {secret}"}

    async def _raising_create(**kwargs: Any) -> Any:
        raise err

    fake_client = MagicMock()
    fake_client.chat.completions.create = _raising_create

    provider = OpenRouterProvider(
        api_key=secret,
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        max_retries=0,
        client=fake_client,
    )

    caplog.set_level(logging.WARNING, logger="sunsec.llm.openrouter_provider")
    with pytest.raises(LLMProviderUnavailable):
        await provider.analyze(_make_payload())

    failed = [r for r in caplog.records if r.message == "llm_call_failed"]
    assert failed, "expected llm_call_failed log"
    for rec in failed:
        for value in rec.__dict__.values():
            assert secret not in str(value)


# ---------------------------------------------------------------------------
# 7. Timeout → LLMTimeout
# ---------------------------------------------------------------------------


async def test_openrouter_provider_maps_timeout_to_domain_exception() -> None:
    """SDK APITimeoutError → LLMTimeout."""
    pytest.importorskip("openai")
    import openai

    async def _raising(**kwargs: Any) -> Any:
        raise openai.APITimeoutError(request=MagicMock())

    fake_client = MagicMock()
    fake_client.chat.completions.create = _raising

    provider = OpenRouterProvider(
        api_key="sk-or-v1-test-timeout",
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        max_retries=0,
        client=fake_client,
    )

    with pytest.raises(LLMTimeout):
        await provider.analyze(_make_payload())


# ---------------------------------------------------------------------------
# 8. 5xx → LLMProviderUnavailable
# ---------------------------------------------------------------------------


async def test_openrouter_provider_maps_status_error_to_unavailable() -> None:
    """SDK APIStatusError (5xx) → LLMProviderUnavailable."""
    pytest.importorskip("openai")
    import openai

    fake_resp = MagicMock()
    fake_resp.status_code = 503
    fake_resp.headers = {}

    async def _raising(**kwargs: Any) -> Any:
        raise openai.APIStatusError(
            "Service Unavailable", response=fake_resp, body={"error": "x"}
        )

    fake_client = MagicMock()
    fake_client.chat.completions.create = _raising

    provider = OpenRouterProvider(
        api_key="sk-or-v1-test-503",
        base_url="https://openrouter.ai/api/v1",
        model_id="deepseek/deepseek-v4-flash",
        max_retries=0,
        client=fake_client,
    )

    with pytest.raises(LLMProviderUnavailable):
        await provider.analyze(_make_payload())


# ---------------------------------------------------------------------------
# 9. factory → OpenRouterProvider
# ---------------------------------------------------------------------------


def test_factory_builds_openrouter_client_when_provider_is_openrouter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LLM_PROVIDER=openrouter → клиент с OpenRouterProvider + отдельный budget."""
    settings = Settings.from_env(env={
        "LLM_PROVIDER": "openrouter",
        "OPENROUTER_API_KEY": "sk-or-v1-test-factory",
        "OPENROUTER_MODEL_ID": "deepseek/deepseek-v4-flash",
        "OPENROUTER_BUDGET_LIMIT_RUB": "42.5",
        "OPENROUTER_USE_MODELS_ROTATION": "true",
        "OPENROUTER_FALLBACK_MODEL_IDS": "xiaomi/mimo-v2-pro,qwen/qwen3-coder:free",
        # polza-ветку оставляем дефолтной — её фабрика не должна выбрать.
    })

    # Подменяем построение openai-клиента (чтобы не строить реальный HTTPX).
    monkeypatch.setattr(
        OpenRouterProvider, "_build_default_client", lambda self: MagicMock()
    )

    client = build_llm_client_from_settings(settings)

    assert isinstance(client, LLMClient)
    assert client._provider.name == "openrouter"  # type: ignore[attr-defined]
    assert isinstance(client._provider, OpenRouterProvider)  # type: ignore[attr-defined]
    assert client._provider.model_id == "deepseek/deepseek-v4-flash"  # type: ignore[attr-defined]
    assert client._provider.use_models_rotation is True  # type: ignore[attr-defined]
    assert client._provider.fallback_model_ids == (  # type: ignore[attr-defined]
        "xiaomi/mimo-v2-pro", "qwen/qwen3-coder:free"
    )
    # Бюджет — отдельная корзина, лимит из OPENROUTER_BUDGET_LIMIT_RUB.
    assert isinstance(client.budget, BudgetCounter)
    assert client.budget.limit_rub == pytest.approx(42.5)


# ---------------------------------------------------------------------------
# 10. factory backwards compat (default polza)
# ---------------------------------------------------------------------------


def test_factory_defaults_to_polza_for_backwards_compat(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default LLM_PROVIDER=polza → PolzaProvider (как было до M-8)."""
    settings = Settings.from_env(env={
        # LLM_PROVIDER не задан вовсе → default 'polza'.
        "POLZA_API_KEY": "test-polza-key",
        "POLZA_MODEL_ID": "gpt-4o-mini",
        "POLZA_BUDGET_LIMIT_RUB": "80",
    })

    monkeypatch.setattr(
        PolzaProvider, "_build_default_client", lambda self: MagicMock()
    )

    client = build_llm_client_from_settings(settings)
    assert isinstance(client._provider, PolzaProvider)  # type: ignore[attr-defined]
    assert client._provider.name == "polza"  # type: ignore[attr-defined]
    assert client.budget.limit_rub == pytest.approx(80.0)


# ---------------------------------------------------------------------------
# 11. factory: empty OPENROUTER_API_KEY → ValueError на старте
# ---------------------------------------------------------------------------


def test_factory_raises_on_empty_openrouter_api_key() -> None:
    """LLM_PROVIDER=openrouter без ключа → понятная ошибка вместо silent-failure."""
    settings = Settings.from_env(env={
        "LLM_PROVIDER": "openrouter",
        "OPENROUTER_API_KEY": "",  # пусто
    })

    with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
        build_llm_client_from_settings(settings)


# ---------------------------------------------------------------------------
# 12. BudgetExceeded — отдельная корзина (polza не трогается)
# ---------------------------------------------------------------------------


async def test_openrouter_budget_is_independent_from_polza(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Принудительный лимит 0.0001 ₽ → BudgetExceeded на первом analyze;
    polza-бюджет (отсутствующий в этой ветке) не задействован."""
    settings = Settings.from_env(env={
        "LLM_PROVIDER": "openrouter",
        "OPENROUTER_API_KEY": "sk-or-v1-test-budget",
        "OPENROUTER_BUDGET_LIMIT_RUB": "0.0001",
        "POLZA_BUDGET_LIMIT_RUB": "1000",  # большой polza budget — не должен влиять
    })

    fake_create = AsyncMock(return_value=_make_fake_response())
    fake_client = MagicMock()
    fake_client.chat.completions.create = fake_create

    monkeypatch.setattr(
        OpenRouterProvider, "_build_default_client", lambda self: fake_client
    )

    client = build_llm_client_from_settings(settings)
    assert client.budget.limit_rub == pytest.approx(0.0001)

    with pytest.raises(BudgetExceeded):
        await client.analyze(_make_filtered_diff())

    # Провайдер НЕ был вызван (kill-switch сработал до).
    fake_create.assert_not_called()


# ---------------------------------------------------------------------------
# 13. Settings — новые env-переменные парсятся
# ---------------------------------------------------------------------------


def test_settings_parses_all_new_openrouter_env_vars() -> None:
    """Все новые env-переменные подхватываются Settings.from_env корректно."""
    s = Settings.from_env(env={
        "LLM_PROVIDER": "openrouter",
        "OPENROUTER_API_KEY": "sk-or-v1-test-env",
        "OPENROUTER_BASE_URL": "https://openrouter.ai/api/v1",
        "OPENROUTER_MODEL_ID": "xiaomi/mimo-v2-pro",
        "OPENROUTER_TIMEOUT_SECONDS": "45",
        "OPENROUTER_MAX_RETRIES": "3",
        "OPENROUTER_INPUT_RUB_PER_1K": "0.05",
        "OPENROUTER_OUTPUT_RUB_PER_1K": "0.15",
        "OPENROUTER_USD_RUB_RATE": "100.0",
        "OPENROUTER_USE_USAGE_COST": "true",
        "OPENROUTER_USE_JSON_SCHEMA": "false",
        "OPENROUTER_USE_MODELS_ROTATION": "true",
        "OPENROUTER_FALLBACK_MODEL_IDS": "qwen/qwen3-coder:free,deepseek/deepseek-v4-flash:free",
        "OPENROUTER_BUDGET_LIMIT_RUB": "75",
    })

    assert s.llm_provider == "openrouter"
    assert s.openrouter_api_key == "sk-or-v1-test-env"
    assert s.openrouter_base_url == "https://openrouter.ai/api/v1"
    assert s.openrouter_model_id == "xiaomi/mimo-v2-pro"
    assert s.openrouter_timeout_seconds == pytest.approx(45.0)
    assert s.openrouter_max_retries == 3
    assert s.openrouter_input_rub_per_1k == pytest.approx(0.05)
    assert s.openrouter_output_rub_per_1k == pytest.approx(0.15)
    assert s.openrouter_usd_rub_rate == pytest.approx(100.0)
    assert s.openrouter_use_usage_cost is True
    assert s.openrouter_use_json_schema is False
    assert s.openrouter_use_models_rotation is True
    assert s.openrouter_fallback_model_ids == (
        "qwen/qwen3-coder:free",
        "deepseek/deepseek-v4-flash:free",
    )
    assert s.openrouter_budget_limit_rub == pytest.approx(75.0)
    # POLZA_BUDGET_LIMIT_RUB не тронут — default 80.
    assert s.polza_budget_limit_rub == pytest.approx(80.0)


def test_settings_openrouter_defaults_when_env_empty() -> None:
    """Без env-переменных Settings даёт default-ы из артефакта T-030."""
    s = Settings.from_env(env={})
    assert s.openrouter_api_key == ""
    assert s.openrouter_base_url == "https://openrouter.ai/api/v1"
    assert s.openrouter_model_id == "deepseek/deepseek-v4-flash"
    assert s.openrouter_input_rub_per_1k == pytest.approx(0.01064)
    assert s.openrouter_output_rub_per_1k == pytest.approx(0.02128)
    assert s.openrouter_usd_rub_rate == pytest.approx(95.0)
    assert s.openrouter_use_usage_cost is False
    assert s.openrouter_use_models_rotation is False
    assert s.openrouter_fallback_model_ids == ()
    assert s.openrouter_budget_limit_rub == pytest.approx(50.0)
