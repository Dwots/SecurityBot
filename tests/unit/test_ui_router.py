"""Unit-тесты test UI роутера (T-023).

Покрытие — по DoD (3 теста минимум):
1. `GET /api/ui/examples` → 200, 4 примера с непустыми `files`.
2. `POST /api/ui/analyze` с моком `LLMClient.analyze` → 200, `llm.status="ok"`,
   findings присутствуют, budget-объект на месте.
3. `POST /api/ui/analyze` с пустым `code` на всех файлах → 200,
   `llm.status="skipped_empty"`, провайдер НЕ вызывался.

Дополнительно (для регресса по DoD-пункту 10):
4. `GET /api/ui/budget` → 200 и схема `{spent_rub, limit_rub, remaining_rub, limit_percent}`.
5. `POST /api/ui/analyze` >50 KB → 413.
6. `POST /api/ui/analyze` с battle-test `BudgetExceeded` → 200 + `llm.status="budget_exceeded"`.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sunsec.contracts import Finding, LLMResponseSchema  # noqa: E402
from sunsec.llm.base import BudgetExceeded  # noqa: E402
from sunsec.llm.budget import BudgetCounter  # noqa: E402
from sunsec.ml.false_positive_filter import FalsePositiveFilter  # noqa: E402
from sunsec.ui.router import build_ui_router  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_client(*, llm_client=None, budget=None) -> TestClient:
    """Минимальный TestClient с UI-роутером."""
    app = FastAPI()
    fp = FalsePositiveFilter()
    router = build_ui_router(
        llm_client=llm_client,
        fp_filter=fp,
        diff_filter=None,
        budget=budget,
    )
    app.include_router(router)
    return TestClient(app)


def _fake_llm_response(findings: list[dict]) -> LLMResponseSchema:
    return LLMResponseSchema(
        findings=[Finding.model_validate(f) for f in findings],
        summary="Test summary." if findings else "No issues detected.",
    )


# ---------------------------------------------------------------------------
# 1. GET /api/ui/examples
# ---------------------------------------------------------------------------


def test_get_examples_returns_four_examples_with_files():
    client = _make_client(llm_client=None, budget=BudgetCounter(80.0))
    resp = client.get("/api/ui/examples")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 4, f"expected 4 examples, got {len(data)}"
    names = {ex["name"] for ex in data}
    assert names == {
        "sqli_simple.py",
        "secret_aws.py",
        "xss_react.jsx",
        "clean_code.py",
    }
    for ex in data:
        assert "description" in ex and ex["description"]
        assert "files" in ex and isinstance(ex["files"], list)
        assert len(ex["files"]) >= 1
        for f in ex["files"]:
            assert f["path"]
            assert f["code"], f"example {ex['name']!r} has empty code"


# ---------------------------------------------------------------------------
# 2. POST /api/ui/analyze + замоканный LLMClient → llm.status=ok
# ---------------------------------------------------------------------------


def test_analyze_with_mocked_llm_returns_ok_status_and_findings():
    budget = BudgetCounter(80.0)

    # Мокаем LLMClient: только нужный для роутера API (`.analyze`, `.budget`,
    # `._provider.name`, `.prompt_version`). Достаточно MagicMock + AsyncMock.
    llm_findings = [
        {
            "file": "app/views.py",
            "line": 3,
            "class": "sql_injection",
            "severity": "high",
            "message": "f-string SQL без параметризации обнаружено в cursor.execute.",
            "suggestion": "Use cursor.execute('... WHERE id = ?', (uid,)).",
            "confidence": 0.9,
        }
    ]
    fake_resp = _fake_llm_response(llm_findings)

    llm_client = MagicMock()
    llm_client.analyze = AsyncMock(return_value=fake_resp)
    llm_client.prompt_version = "v1"
    llm_client._provider = MagicMock()
    llm_client._provider.name = "polza"
    llm_client.budget = budget

    client = _make_client(llm_client=llm_client, budget=budget)
    payload = {
        "files": [
            {
                "path": "app/views.py",
                "language": "python",
                "code": (
                    "def search(q):\n"
                    "    cursor.execute(f\"SELECT * FROM t WHERE c='{q}'\")\n"
                    "    return cursor.fetchone()\n"
                ),
            }
        ]
    }
    resp = client.post("/api/ui/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # llm.status=ok + findings присутствуют
    assert data["llm"]["status"] == "ok"
    assert data["llm"]["model"] == "polza"
    assert "latency_ms" in data["llm"]
    assert isinstance(data["findings"], list)
    # Хотя бы одна находка от LLM должна пройти FP-фильтр
    assert any(f["class"] == "sql_injection" for f in data["findings"])

    # budget-объект на месте
    assert "budget" in data
    assert {"spent_rub", "limit_rub", "remaining_rub"}.issubset(data["budget"].keys())
    assert data["budget"]["limit_rub"] == 80.0

    # Провайдер вызывался ровно один раз
    llm_client.analyze.assert_awaited_once()


# ---------------------------------------------------------------------------
# 3. POST /api/ui/analyze с пустым code → skipped_empty, провайдер НЕ вызван
# ---------------------------------------------------------------------------


def test_analyze_empty_code_skips_llm_call():
    budget = BudgetCounter(80.0)
    llm_client = MagicMock()
    llm_client.analyze = AsyncMock(return_value=_fake_llm_response([]))
    llm_client.prompt_version = "v1"
    llm_client._provider = MagicMock()
    llm_client._provider.name = "polza"
    llm_client.budget = budget

    client = _make_client(llm_client=llm_client, budget=budget)
    payload = {
        "files": [
            {"path": "a.py", "language": "python", "code": ""},
            {"path": "b.py", "language": "python", "code": ""},
        ]
    }
    resp = client.post("/api/ui/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["llm"]["status"] == "skipped_empty"
    assert data["findings"] == []
    # ВАЖНО: провайдер НЕ вызывался (short-circuit на is_empty()).
    llm_client.analyze.assert_not_awaited()


# ---------------------------------------------------------------------------
# 4. GET /api/ui/budget — схема ответа
# ---------------------------------------------------------------------------


def test_get_budget_returns_full_schema():
    budget = BudgetCounter(50.0)
    client = _make_client(llm_client=None, budget=budget)
    resp = client.get("/api/ui/budget")
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) == {"spent_rub", "limit_rub", "remaining_rub", "limit_percent"}
    assert data["limit_rub"] == 50.0
    assert data["spent_rub"] == 0.0
    assert data["remaining_rub"] == 50.0
    assert data["limit_percent"] == 0.0


# ---------------------------------------------------------------------------
# 5. Soft-limit 50 KB → 413
# ---------------------------------------------------------------------------


def test_analyze_over_50kb_returns_413():
    client = _make_client(llm_client=None, budget=BudgetCounter(80.0))
    huge = "x" * (51 * 1024)  # 51 KB
    payload = {"files": [{"path": "huge.py", "language": "python", "code": huge}]}
    resp = client.post("/api/ui/analyze", json=payload)
    assert resp.status_code == 413


# ---------------------------------------------------------------------------
# 6. BudgetExceeded → 200 OK + llm.status="budget_exceeded"
# ---------------------------------------------------------------------------


def test_analyze_budget_exceeded_returns_200_with_status():
    budget = BudgetCounter(80.0)
    llm_client = MagicMock()
    llm_client.analyze = AsyncMock(side_effect=BudgetExceeded("test budget exhausted"))
    llm_client.prompt_version = "v1"
    llm_client._provider = MagicMock()
    llm_client._provider.name = "polza"
    llm_client.budget = budget

    client = _make_client(llm_client=llm_client, budget=budget)
    payload = {
        "files": [
            {
                "path": "x.py",
                "language": "python",
                "code": "x = 1\ny = 2\n",
            }
        ]
    }
    resp = client.post("/api/ui/analyze", json=payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["llm"]["status"] == "budget_exceeded"


# ---------------------------------------------------------------------------
# 7. ValidationError → 422 (Pydantic)
# ---------------------------------------------------------------------------


def test_analyze_invalid_payload_returns_422():
    client = _make_client(llm_client=None, budget=BudgetCounter(80.0))
    # files: пустой массив → нарушение min_length=1
    resp = client.post("/api/ui/analyze", json={"files": []})
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert isinstance(detail, list)
    assert any("files" in (err.get("loc") or []) for err in detail)
