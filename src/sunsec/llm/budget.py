"""BudgetCounter — process-local kill-switch для polza.ai (ADR-2).

Семантика (см. `ml_instructions_polza.md §5`, `tracking_table.md T-012`):

1. `check_and_reserve(estimated_cost_rub)` — перед каждым LLM-вызовом.
   Если `total_spend + estimated > limit` → `BudgetExceeded` (вызов
   провайдера НЕ происходит, fallback на платный direct тоже НЕ
   срабатывает — это by design, см. DoD T-012).
   При успехе резерв учитывается, чтобы параллельные PR в одном процессе
   не пробили лимит вместе.

2. `commit(actual_cost_rub, reservation_id)` — после реального ответа
   провайдера. Корректирует фактический spend (actual может быть выше
   или ниже estimated). Если вызова не было / был перехвачен — вызывается
   `release(reservation_id)` для отката резервации.

3. `release(reservation_id)` — откат, например при таймауте до получения
   usage. Без release зарезервированный estimated «висит» до перезапуска.

Хранилище: in-memory, со ВСЕМИ операциями под `threading.Lock` (поскольку
несколько PR могут обрабатываться параллельно: FastAPI BackgroundTasks +
ThreadPoolExecutor для синхронной обвязки). Lock — process-local; в
много-процессной деплое (gunicorn workers > 1) каждый воркер ведёт
свой счётчик — для MVP приемлемо (см. tech debt в `llm_client.md`).

**MVP**: память, при рестарте процесса сбрасывается. Persistent backend
(Redis/sqlite) — backlog (см. tech debt notes в `llm_client.md`).
"""
from __future__ import annotations

import itertools
import threading

from sunsec.llm.base import BudgetExceeded, TokenUsage


class BudgetCounter:
    """Thread-safe счётчик расходов LLM с резервациями."""

    def __init__(self, limit_rub: float) -> None:
        self._limit_rub = float(limit_rub)
        self._spent_rub = 0.0
        self._reserved_rub = 0.0
        self._calls = 0
        self._lock = threading.Lock()
        self._reservations: dict[int, float] = {}
        self._res_counter = itertools.count(1)

    # --- read-only views ---

    @property
    def limit_rub(self) -> float:
        return self._limit_rub

    @property
    def spent_rub(self) -> float:
        with self._lock:
            return self._spent_rub

    @property
    def reserved_rub(self) -> float:
        with self._lock:
            return self._reserved_rub

    @property
    def calls(self) -> int:
        with self._lock:
            return self._calls

    def exceeded(self) -> bool:
        with self._lock:
            return (self._spent_rub + self._reserved_rub) >= self._limit_rub

    # --- core operations ---

    def check(self) -> None:
        """Лёгкая проверка без резервации (для предварительного skip)."""
        with self._lock:
            if (self._spent_rub + self._reserved_rub) >= self._limit_rub:
                raise BudgetExceeded(
                    f"LLM budget exhausted: "
                    f"spent={self._spent_rub:.4f} ₽, reserved={self._reserved_rub:.4f} ₽, "
                    f"limit={self._limit_rub:.2f} ₽"
                )

    def check_and_reserve(self, estimated_cost_rub: float) -> int:
        """Резервирует `estimated_cost_rub` или бросает `BudgetExceeded`.

        Возвращает `reservation_id` для последующего `commit` / `release`.
        """
        estimated = max(0.0, float(estimated_cost_rub))
        with self._lock:
            projected = self._spent_rub + self._reserved_rub + estimated
            if projected > self._limit_rub:
                raise BudgetExceeded(
                    f"LLM budget would be exceeded: "
                    f"projected={projected:.4f} ₽ > limit={self._limit_rub:.2f} ₽ "
                    f"(spent={self._spent_rub:.4f}, reserved={self._reserved_rub:.4f}, "
                    f"estimated={estimated:.4f})"
                )
            self._reserved_rub += estimated
            res_id = next(self._res_counter)
            self._reservations[res_id] = estimated
            return res_id

    def commit(self, actual_cost_rub: float, reservation_id: int) -> None:
        """Фиксирует фактический spend и снимает резерв."""
        actual = max(0.0, float(actual_cost_rub))
        with self._lock:
            reserved = self._reservations.pop(reservation_id, 0.0)
            self._reserved_rub = max(0.0, self._reserved_rub - reserved)
            self._spent_rub += actual
            self._calls += 1

    def release(self, reservation_id: int) -> None:
        """Откатывает резервацию без фиксации spend (например, при таймауте)."""
        with self._lock:
            reserved = self._reservations.pop(reservation_id, 0.0)
            self._reserved_rub = max(0.0, self._reserved_rub - reserved)

    # Совместимость с T-006: старый сигнатурный метод `record(cost, usage?)`.
    def record(self, cost_rub: float, usage: TokenUsage | None = None) -> None:
        with self._lock:
            self._spent_rub += float(cost_rub)
            self._calls += 1

    def __repr__(self) -> str:  # без секретов
        return (
            f"BudgetCounter(limit={self._limit_rub:.2f} ₽, "
            f"spent={self.spent_rub:.4f} ₽, reserved={self.reserved_rub:.4f} ₽, "
            f"calls={self.calls})"
        )
