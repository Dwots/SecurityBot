"""Persistence-слой SunSecurityBot (M-9, system_design v1.2.1 §11).

Точка входа: `build_storage_from_settings(settings)` — фабрика,
возвращающая `StateStore`-совместимую реализацию:

- если `settings.sunsec_db_path` пуст или равен `:memory:` —
  `InMemoryStateStore` (legacy ADR-3 поведение для M-0..M-8 тестов /
  smoke без durable layer);
- иначе — `SQLiteStateStore(db_path)` (durable, M-9).
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from sunsec.state.memory import InMemoryStateStore
from sunsec.storage.errors import (
    StorageConflictError,
    StorageError,
    StorageNotFoundError,
)
from sunsec.storage.migrations import run_migrations
from sunsec.storage.schema import (
    ALL_DDL_STATEMENTS,
    PRAGMA_STATEMENTS,
    SCHEMA_VERSION,
)
from sunsec.storage.sqlite_store import SQLiteStateStore

if TYPE_CHECKING:
    from sunsec.config import Settings
    from sunsec.state.base import StateStore

log = logging.getLogger(__name__)


def build_storage_from_settings(settings: "Settings") -> "StateStore":
    """Фабрика state-store по конфигу (system_design §11.6).

    - `SUNSEC_DB_PATH` пуст / отсутствует / `:memory:` → `InMemoryStateStore`.
    - Любое другое значение → `SQLiteStateStore(path)`.

    Schema-инициализация для durable варианта делается **снаружи** этой
    фабрики, через `await run_migrations(path)` на startup в `app.py`.
    Так фабрика остаётся синхронной и не блокирует event-loop в DI.
    """
    db_path = getattr(settings, "sunsec_db_path", "") or ""
    if not db_path or db_path == ":memory:":
        log.info("storage_backend_selected", extra={"backend": "memory"})
        return InMemoryStateStore()
    log.info(
        "storage_backend_selected",
        extra={"backend": "sqlite", "db_path_set": True},
    )
    return SQLiteStateStore(db_path)


__all__ = [
    "build_storage_from_settings",
    "run_migrations",
    "SQLiteStateStore",
    "InMemoryStateStore",
    "StorageError",
    "StorageConflictError",
    "StorageNotFoundError",
    "SCHEMA_VERSION",
    "ALL_DDL_STATEMENTS",
    "PRAGMA_STATEMENTS",
]
