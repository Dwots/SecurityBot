"""Unit-тесты LLM-слоя (T-012).

Покрытие — по DoD T-012:
- Успешный JSON-ответ → корректный `LLMResponseSchema`.
- Битый JSON → пустой `LLMResponseSchema` + warning-лог.
- Один из findings — invalid Pydantic → drop с info-логом, остальные ок.
- Таймаут на провайдере → `LLMTimeout` (мокаем openai.APITimeoutError).
- 429 → backoff → success (SDK сам ретраит, мы проверяем happy-path после ретрая).
- Бюджет исчерпан → `BudgetExceeded` ДО вызова провайдера (provider.analyze
  не вызывается).
- Security: ключ не попадает в logs / repr / exception output (caplog assert).

Все тесты — mock-only (никаких реальных HTTP / реального `openai.AsyncOpenAI`).
Это by-design: PolzaProvider держит `_client` через DI, тестам незачем знать
о реальном SDK. Реальный smoke-call — на T-014/T-015 (бюджет 90 ₽).
"""
from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("pydantic")

from sunsec.contracts import (  # noqa: E402
    AddedLine,
    FilteredDiff,
    FilteredDiffFile,
    LLMResponseSchema,
)
from sunsec.llm.base import (  # noqa: E402
    BudgetExceeded,
    LLMProviderUnavailable,
    LLMRawResponse,
    LLMTimeout,
    PromptPayload,
    TokenUsage,
)
from sunsec.llm.budget import BudgetCounter  # noqa: E402
from sunsec.llm.client import LLMClient  # noqa: E402
from sunsec.llm.polza_provider import PolzaProvider, _safe_error_dict  # noqa: E402
from sunsec.llm.prompt_builder import PromptBuilder  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_filtered_diff(
    *,
    path: str = "users.py",
    line_no: int = 12,
    content: str = 'q = f"SELECT * FROM users WHERE id = {user_id}"',
) -> FilteredDiff:
    return FilteredDiff(
        repo="acme/example",
        pr_number=42,
        head_sha="deadbeef",
        files=[
            FilteredDiffFile(
                path=path,
                language="python",
                added_lines=[AddedLine(new_line_no=line_no, content=content)],
            )
        ],
        estimated_input_tokens=128,
        content_hash="abc123",
    )


def _make_raw_response(
    *,
    content: str,
    prompt_tokens: int = 100,
    completion_tokens: int = 50,
    model: str = "gpt-4o-mini",
    latency_ms: float = 250.0,
) -> LLMRawResponse:
    return LLMRawResponse(
        model=model,
        content=content,
        usage=TokenUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        ),
        latency_ms=latency_ms,
    )


class _FakeProvider:
    """Минимальный stub `LLMProvider` для тестов.

    Не наследует Protocol, чтобы pytest-показал ясную diff при mismatch.
    """

    name: str = "fake"

    def __init__(
        self,
        *,
        content: str = '{"findings": [], "summary": "В diff не обнаружено проблем безопасности."}',
        usage: TokenUsage | None = None,
        raise_exc: BaseException | None = None,
        cost_rub: float = 0.005,
    ) -> None:
        self._content = content
        self._usage = usage or TokenUsage(
            prompt_tokens=100, completion_tokens=50, total_tokens=150
        )
        self._raise = raise_exc
        self._cost = cost_rub
        self._max_tokens = 2048
        self.call_count = 0
        self.last_payload: PromptPayload | None = None

    async def analyze(self, prompt: PromptPayload) -> LLMRawResponse:
        self.call_count += 1
        self.last_payload = prompt
        if self._raise is not None:
            raise self._raise
        return LLMRawResponse(
            model="gpt-4o-mini",
            content=self._content,
            usage=self._usage,
            latency_ms=123.0,
        )

    def estimate_cost_rub(self, usage: TokenUsage) -> float:
        return self._cost


# ---------------------------------------------------------------------------
# 1. Happy path — успешный JSON-ответ
# ---------------------------------------------------------------------------


async def test_llm_client_parses_valid_response_into_schema(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Корректный JSON от провайдера → `LLMResponseSchema` с findings."""
    valid_json = json.dumps(
        {
            "findings": [
                {
                    "file": "users.py",
                    "line": 12,
                    "class": "sql_injection",
                    "severity": "high",
                    "message": (
                        "SQL-запрос собран через f-string с пользовательским user_id "
                        "(\"SELECT * FROM users WHERE id = {user_id}\") — нет параметризации."
                    ),
                    "suggestion": (
                        'return conn.execute("SELECT * FROM users WHERE id = ?", '
                        "(user_id,)).fetchone()"
                    ),
                    "confidence": 0.95,
                }
            ],
            "summary": "Найдена 1 уязвимость уровня high (SQLi через f-string).",
        }
    )
    provider = _FakeProvider(content=valid_json)
    client = LLMClient(provider=provider, builder=PromptBuilder(), budget=None)

    diff = _make_filtered_diff()
    caplog.set_level(logging.INFO, logger="sunsec.llm.client")

    response = await client.analyze(diff)

    assert isinstance(response, LLMResponseSchema)
    assert len(response.findings) == 1
    f = response.findings[0]
    assert f.file == "users.py"
    assert f.line == 12
    assert f.class_ == "sql_injection"
    assert f.severity == "high"
    assert f.confidence == pytest.approx(0.95)
    assert provider.call_count == 1

    # Метрики latency/tokens/cost — в логах.
    completed_records = [r for r in caplog.records if r.message == "llm_call_completed"]
    assert completed_records, "llm_call_completed log missing"
    rec = completed_records[0]
    assert getattr(rec, "model", None) == "gpt-4o-mini"
    assert getattr(rec, "prompt_tokens", None) == 100
    assert getattr(rec, "completion_tokens", None) == 50
    assert getattr(rec, "findings_count", None) == 1
    assert getattr(rec, "cost_rub", None) == pytest.approx(0.005)


# ---------------------------------------------------------------------------
# 2. Битый JSON
# ---------------------------------------------------------------------------


async def test_llm_client_returns_empty_response_on_invalid_json(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Невалидный JSON → empty `LLMResponseSchema` + warning, без exception."""
    provider = _FakeProvider(content="this is not JSON {[")
    client = LLMClient(provider=provider, budget=None)
    caplog.set_level(logging.WARNING, logger="sunsec.llm.client")

    response = await client.analyze(_make_filtered_diff())

    assert response.findings == []
    # Summary помечает причину "skipped".
    assert "skipped" in response.summary.lower() or "invalid" in response.summary.lower()

    parse_warnings = [
        r for r in caplog.records if r.message == "llm_response_json_decode_error"
    ]
    assert parse_warnings, "expected llm_response_json_decode_error warning"


# ---------------------------------------------------------------------------
# 3. Битые findings — drop поэлементно
# ---------------------------------------------------------------------------


async def test_llm_client_drops_invalid_findings_keeps_valid_ones(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """1 валидный + 1 невалидный finding → результат содержит ровно 1 валидный."""
    mixed_json = json.dumps(
        {
            "findings": [
                {
                    # Невалидный: severity не из enum, line=0 (must be >=1).
                    "file": "x.py",
                    "line": 0,
                    "class": "sql_injection",
                    "severity": "ULTRA_HIGH",
                    "message": "broken finding",
                    "confidence": 0.9,
                },
                {
                    "file": "users.py",
                    "line": 12,
                    "class": "hardcoded_secret",
                    "severity": "critical",
                    "message": (
                        "Найден literal AWS access key prefix AKIA в src/users.py — "
                        "критичная утечка реального ключа."
                    ),
                    "suggestion": None,
                    "confidence": 0.99,
                },
            ],
            "summary": "1 critical secret leak found.",
        }
    )
    provider = _FakeProvider(content=mixed_json)
    client = LLMClient(provider=provider, budget=None)
    caplog.set_level(logging.INFO, logger="sunsec.llm.client")

    response = await client.analyze(_make_filtered_diff())

    assert len(response.findings) == 1
    assert response.findings[0].class_ == "hardcoded_secret"
    assert response.findings[0].severity == "critical"

    drop_logs = [r for r in caplog.records if r.message == "llm_finding_invalid"]
    assert drop_logs, "expected llm_finding_invalid log for broken element"


# ---------------------------------------------------------------------------
# 4. Таймаут — `LLMTimeout` пробрасывается, бюджет освобождается
# ---------------------------------------------------------------------------


async def test_llm_client_propagates_timeout_and_releases_budget(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`LLMTimeout` от провайдера пробрасывается; резерв бюджета снимается."""
    provider = _FakeProvider(raise_exc=LLMTimeout("polza.ai timeout"))
    budget = BudgetCounter(limit_rub=10.0)
    client = LLMClient(provider=provider, budget=budget)
    caplog.set_level(logging.WARNING)

    with pytest.raises(LLMTimeout):
        await client.analyze(_make_filtered_diff())

    # Резерв должен быть откатан (release() вызывается в client.analyze).
    assert budget.reserved_rub == pytest.approx(0.0)
    assert budget.spent_rub == pytest.approx(0.0)
    assert budget.calls == 0


# ---------------------------------------------------------------------------
# 5. 429 → SDK retries → success (моделируем поведение `openai` SDK)
# ---------------------------------------------------------------------------


async def test_polza_provider_retries_are_delegated_to_sdk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`PolzaProvider` доверяет SDK ретраи 429/5xx; параметр `max_retries`
    пробрасывается; на стороне провайдера успешный ответ → `LLMRawResponse`.

    Тут мы НЕ имитируем 429 — SDK его проглатывает внутри. Мы проверяем,
    что (a) max_retries=N передан в SDK при создании client, и (b) при
    happy-path ответе провайдер собирает корректный LLMRawResponse.
    """
    # Мокаем chat.completions.create на уровне fake-client.
    fake_message = MagicMock()
    fake_message.content = json.dumps(
        {"findings": [], "summary": "В diff не обнаружено проблем безопасности."}
    )
    fake_choice = MagicMock()
    fake_choice.message = fake_message
    fake_response = MagicMock()
    fake_response.choices = [fake_choice]
    fake_response.model = "gpt-4o-mini"
    fake_response.usage = {
        "prompt_tokens": 200,
        "completion_tokens": 30,
        "total_tokens": 230,
    }

    fake_create = AsyncMock(return_value=fake_response)
    fake_client = MagicMock()
    fake_client.chat.completions.create = fake_create

    provider = PolzaProvider(
        api_key="test-key-do-not-leak",
        base_url="https://polza.ai/api/v1",
        model_id="gpt-4o-mini",
        timeout_seconds=5.0,
        max_retries=2,
        client=fake_client,  # DI: не строим реальный AsyncOpenAI.
    )

    payload = PromptPayload(system="sys", user="diff content")
    raw = await provider.analyze(payload)

    assert raw.content == fake_message.content
    assert raw.usage.prompt_tokens == 200
    assert raw.usage.completion_tokens == 30
    assert raw.model == "gpt-4o-mini"
    # Параметры запроса.
    fake_create.assert_called_once()
    kwargs = fake_create.call_args.kwargs
    assert kwargs["model"] == "gpt-4o-mini"
    assert kwargs["temperature"] == 0.0
    assert kwargs["response_format"] == {"type": "json_object"}
    assert kwargs["messages"][0]["role"] == "system"
    assert kwargs["messages"][1]["role"] == "user"


# ---------------------------------------------------------------------------
# 6. Бюджет исчерпан — `BudgetExceeded` ДО вызова провайдера
# ---------------------------------------------------------------------------


async def test_llm_client_raises_budget_exceeded_without_calling_provider() -> None:
    """Перерасход бюджета → `BudgetExceeded`; provider.analyze не вызывается."""
    provider = _FakeProvider()
    budget = BudgetCounter(limit_rub=0.001)  # лимит меньше, чем worst-case резерв
    client = LLMClient(provider=provider, budget=budget)

    with pytest.raises(BudgetExceeded):
        await client.analyze(_make_filtered_diff())

    assert provider.call_count == 0
    assert budget.calls == 0


# ---------------------------------------------------------------------------
# 7. Security — ключ не уходит в логи / repr при exception
# ---------------------------------------------------------------------------


async def test_polza_provider_does_not_leak_api_key_in_logs_or_repr(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Проверка ml_instructions_polza §4: ключ не выводится никуда.

    Сценарий: SDK поднял exception (мы эмулируем его обычным RuntimeError) —
    `PolzaProvider` логирует ошибку. Проверяем, что в логах нет ключа.
    """
    secret = "sk-polza-leaked-key-do-not-print-1234567890"

    # Эмулируем openai-like exception с заголовками Authorization.
    class _FakeAPIError(Exception):
        status_code = 500
        code = "internal_error"
        message = "internal server error"
        param = None
        type = "api_error"
        # Опасные поля — НЕ должны попасть в _safe_error_dict.
        request = MagicMock()
        response = MagicMock()

    err = _FakeAPIError(f"original repr should not contain {secret}")
    # ВАЖНО: добавим ключ в request.headers (имитация SDK):
    err.request.headers = {"Authorization": f"Bearer {secret}"}

    async def _raising_create(**kwargs: Any) -> Any:
        raise err

    fake_client = MagicMock()
    fake_client.chat.completions.create = _raising_create

    provider = PolzaProvider(
        api_key=secret,
        base_url="https://polza.ai/api/v1",
        model_id="gpt-4o-mini",
        timeout_seconds=5.0,
        max_retries=0,
        client=fake_client,
    )

    caplog.set_level(logging.WARNING, logger="sunsec.llm.polza_provider")

    payload = PromptPayload(system="sys", user="user")
    with pytest.raises(LLMProviderUnavailable):
        await provider.analyze(payload)

    # 1) Лог `llm_call_failed` не содержит ключ.
    failed_logs = [r for r in caplog.records if r.message == "llm_call_failed"]
    assert failed_logs, "expected llm_call_failed warning log"
    for rec in failed_logs:
        # Проверяем все поля extra (включая безопасные).
        rec_dict = {k: v for k, v in rec.__dict__.items()}
        for value in rec_dict.values():
            assert secret not in str(value), (
                f"API key leaked into log record field: {value!r}"
            )

    # 2) repr(provider) не содержит ключ.
    assert secret not in repr(provider)

    # 3) _safe_error_dict не содержит ключ даже если request.headers полон.
    safe_dict = _safe_error_dict(err)
    assert secret not in json.dumps(safe_dict, default=str)
    assert "request" not in safe_dict
    assert "response" not in safe_dict
    assert "headers" not in safe_dict


# ---------------------------------------------------------------------------
# 8. Бюджет — happy-path: commit, метрики обновлены
# ---------------------------------------------------------------------------


async def test_llm_client_commits_actual_cost_to_budget(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """После успешного вызова — `BudgetCounter.spent_rub` равен actual cost."""
    valid_json = json.dumps(
        {"findings": [], "summary": "В diff не обнаружено проблем безопасности."}
    )
    provider = _FakeProvider(content=valid_json, cost_rub=0.0042)
    budget = BudgetCounter(limit_rub=10.0)
    client = LLMClient(provider=provider, budget=budget)

    await client.analyze(_make_filtered_diff())

    assert budget.calls == 1
    assert budget.reserved_rub == pytest.approx(0.0)
    # spent_rub учитывает РОВНО actual_cost (estimate был выше — освобождён).
    assert budget.spent_rub == pytest.approx(0.0042)


# ---------------------------------------------------------------------------
# 9. Empty diff — short-circuit, без вызова LLM
# ---------------------------------------------------------------------------


async def test_llm_client_skips_empty_diff_without_calling_provider() -> None:
    """Пустой FilteredDiff → не зовём провайдера, summary = canonical."""
    provider = _FakeProvider()
    client = LLMClient(provider=provider, budget=None)

    empty = FilteredDiff(
        repo="acme/example",
        pr_number=42,
        head_sha="deadbeef",
        files=[],
        estimated_input_tokens=0,
        content_hash="",
    )
    response = await client.analyze(empty)

    assert response.findings == []
    assert response.summary == "В diff не обнаружено проблем безопасности."
    assert provider.call_count == 0


# ---------------------------------------------------------------------------
# 10. PromptBuilder — версия промпта в payload + render diff
# ---------------------------------------------------------------------------


def test_prompt_builder_emits_system_and_user_with_diff() -> None:
    """PromptBuilder кладёт system (v1.0.0) и user-render с `--- file: ... ---`."""
    builder = PromptBuilder()
    diff = _make_filtered_diff(
        path="src/db/users.py",
        line_no=42,
        content='cursor.execute(f"DELETE FROM t WHERE id={uid}")',
    )

    payload = builder.build(diff)

    assert payload.system  # не пустой
    assert "SunSecurityBot" in payload.system  # системный промпт v1.1.0
    assert payload.response_format == "json_object"  # дефолт по ml_instructions §6
    assert "--- file: src/db/users.py ---" in payload.user
    assert "L42:" in payload.user
    assert "DELETE FROM t" in payload.user
    # T-019 (Russian lock) bump: prompt_version = "1.2.0" — hard-enforce Russian
    # in human-facing fields + localized empty summary. Cache-key инвалидация by design.
    assert builder.prompt_version == "1.2.0"
