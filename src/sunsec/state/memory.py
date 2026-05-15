"""InMemoryStateStore — RAM-реализация StateStore для MVP (ADR-3).

В T-007 расширена двумя возможностями для webhook-receiver:

- `seen_delivery(delivery_id)` — отметка о ранее обработанной доставке GitHub
  (`X-GitHub-Delivery`), чтобы повторная попытка GitHub'а не запускала анализ
  второй раз. См. system_design §3.1 (idempotency), §3.6 (StateStore).
- `mark_pr_in_progress` уже был; теперь возвращает False как для уже
  in-progress, так и для уже done PR (см. ниже).

TTL-обёртка в MVP не реализована (см. ADR-3 — рестарт = сброс). Эпизодически
старые записи можно очистить вручную через `reset()` (тесты).
"""
from __future__ import annotations

import asyncio
from typing import Optional

from sunsec.contracts import LLMResponseSchema


class InMemoryStateStore:
    """Минимальная in-memory реализация StateStore.

    Все мутации защищены asyncio.Lock'ом — webhook-handler async, разные PR
    могут приходить параллельно. Lock дешёвый, гарантирует, что
    `mark_pr_in_progress` атомарен (check-and-set).
    """

    def __init__(self) -> None:
        self._inprogress: set[str] = set()
        self._done: set[str] = set()
        self._llm_cache: dict[str, LLMResponseSchema] = {}
        self._posted: set[tuple[str, int, str]] = set()
        # T-007: delivery-id дедупликация (GitHub `X-GitHub-Delivery` UUID).
        self._seen_deliveries: set[str] = set()
        self._lock = asyncio.Lock()

    # --- PR idempotency (по head_sha-ключу) -------------------------------

    async def mark_pr_in_progress(self, key: str, ttl: int = 86400) -> bool:
        """Атомарный check-and-set: True если зарезервировали, False если уже занят.

        Args:
            key: `idempotency_key(event)` — `f"{repo}#{pr}@{head_sha}"`.
            ttl: TTL в секундах (в MVP игнорируется, см. ADR-3).
        Returns:
            True — ключ был свободен, текущий вызов «взял» его.
            False — ключ уже in-progress либо done; повторный анализ не нужен.
        """
        async with self._lock:
            if key in self._inprogress or key in self._done:
                return False
            self._inprogress.add(key)
            return True

    async def mark_pr_done(self, key: str) -> None:
        async with self._lock:
            self._inprogress.discard(key)
            self._done.add(key)

    async def mark_pr_failed(self, key: str) -> None:
        """Снимает резервацию, но НЕ помечает done — повторная доставка попробует снова."""
        async with self._lock:
            self._inprogress.discard(key)

    # --- Delivery-id idempotency (T-007) ---------------------------------

    async def seen_delivery(self, delivery_id: str) -> bool:
        """Атомарный check-and-set по `X-GitHub-Delivery` UUID.

        Returns:
            True — этот delivery_id уже видели (повторная доставка).
            False — первая встреча, регистрируем.
        """
        if not delivery_id:
            # Если GitHub не прислал заголовок — fall through на head_sha-ключ.
            return False
        async with self._lock:
            if delivery_id in self._seen_deliveries:
                return True
            self._seen_deliveries.add(delivery_id)
            return False

    # --- LLM кэш (для T-012) ---------------------------------------------

    async def get_cached_llm_response(self, cache_key: str) -> Optional[LLMResponseSchema]:
        async with self._lock:
            return self._llm_cache.get(cache_key)

    async def set_cached_llm_response(self, cache_key: str, response: LLMResponseSchema) -> None:
        async with self._lock:
            self._llm_cache[cache_key] = response

    # --- Дедупликация публикаций (для T-016) -----------------------------

    async def has_posted_finding(self, repo: str, pr_number: int, finding_hash: str) -> bool:
        async with self._lock:
            return (repo, pr_number, finding_hash) in self._posted

    async def register_posted_finding(self, repo: str, pr_number: int, finding_hash: str) -> None:
        async with self._lock:
            self._posted.add((repo, pr_number, finding_hash))

    # --- Тестовая утилита ------------------------------------------------

    def reset(self) -> None:
        """Сброс всего состояния (для unit-тестов)."""
        self._inprogress.clear()
        self._done.clear()
        self._llm_cache.clear()
        self._posted.clear()
        self._seen_deliveries.clear()
