"""Unit-тесты `BudgetCounter` — kill-switch ADR-2 (T-012).

DoD T-012:
- `POLZA_BUDGET_LIMIT_RUB` (default 80) — берётся из Settings.
- Перед каждым вызовом `total_spend < limit`.
- При превышении — `BudgetExceeded`, без auto-fallback на платный.
- Потокобезопасность (несколько PR параллельно).
"""
from __future__ import annotations

import threading

import pytest

pytest.importorskip("pydantic")

from sunsec.llm.base import BudgetExceeded  # noqa: E402
from sunsec.llm.budget import BudgetCounter  # noqa: E402


def test_budget_check_and_reserve_within_limit_returns_id() -> None:
    b = BudgetCounter(limit_rub=10.0)
    rid = b.check_and_reserve(estimated_cost_rub=1.5)
    assert isinstance(rid, int)
    assert b.reserved_rub == pytest.approx(1.5)
    assert b.spent_rub == pytest.approx(0.0)


def test_budget_check_and_reserve_raises_on_overflow() -> None:
    b = BudgetCounter(limit_rub=1.0)
    with pytest.raises(BudgetExceeded):
        b.check_and_reserve(estimated_cost_rub=1.01)
    # Резерв НЕ должен увеличиться при отказе.
    assert b.reserved_rub == pytest.approx(0.0)


def test_budget_commit_records_actual_cost_and_releases_reservation() -> None:
    b = BudgetCounter(limit_rub=10.0)
    rid = b.check_and_reserve(estimated_cost_rub=2.0)
    # Фактическая стоимость ниже резерва — освобождаем хвост.
    b.commit(actual_cost_rub=0.7, reservation_id=rid)

    assert b.reserved_rub == pytest.approx(0.0)
    assert b.spent_rub == pytest.approx(0.7)
    assert b.calls == 1


def test_budget_release_rolls_back_reservation_without_spending() -> None:
    b = BudgetCounter(limit_rub=10.0)
    rid = b.check_and_reserve(estimated_cost_rub=3.0)
    b.release(rid)
    assert b.reserved_rub == pytest.approx(0.0)
    assert b.spent_rub == pytest.approx(0.0)
    assert b.calls == 0


def test_budget_parallel_reservations_are_serialized() -> None:
    """Резервируем из 8 потоков ровно лимит — все должны успеть, без обмана."""
    limit = 8.0
    per_call = 1.0
    b = BudgetCounter(limit_rub=limit)
    successes: list[int] = []
    failures: list[BaseException] = []

    def _worker() -> None:
        try:
            rid = b.check_and_reserve(estimated_cost_rub=per_call)
            b.commit(actual_cost_rub=per_call, reservation_id=rid)
            successes.append(rid)
        except BudgetExceeded as exc:
            failures.append(exc)

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(successes) == 8
    assert not failures
    assert b.spent_rub == pytest.approx(limit)
    assert b.reserved_rub == pytest.approx(0.0)


def test_budget_repr_does_not_contain_secret_like_data() -> None:
    """`repr(BudgetCounter)` — только цифры/состояние, никаких ключей."""
    b = BudgetCounter(limit_rub=80.0)
    b.check_and_reserve(estimated_cost_rub=0.01)
    s = repr(b)
    assert "BudgetCounter" in s
    assert "limit=80.00" in s
    # На всякий случай: репр не содержит подозрительных префиксов.
    assert "sk-" not in s
    assert "Bearer" not in s
