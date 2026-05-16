"""Schema-initialization для SQLite persistence (system_design v1.2.1 §11.2).

В MVP нет Alembic — `run_migrations` идемпотентно прогоняет
`ALL_DDL_STATEMENTS` (все `IF NOT EXISTS`) и применяет PRAGMA-настройки
(`journal_mode=WAL`, `foreign_keys=ON`, `synchronous=NORMAL`).

Вызывается из `sunsec.app.create_app` на startup сервиса. Безопасно
вызывать многократно — двойной вызов на одной БД не падает.
"""
from __future__ import annotations

import logging
from pathlib import Path

import aiosqlite

from sunsec.storage.schema import (
    ADDITIVE_MIGRATIONS,
    ALL_DDL_STATEMENTS,
    PRAGMA_STATEMENTS,
)

log = logging.getLogger(__name__)


def _is_in_memory(db_path: str) -> bool:
    return db_path == ":memory:" or db_path.startswith("file::memory:")


def _ensure_parent_dir(db_path: str) -> None:
    """Если родительская директория `./data/sunsec.db` не существует — создаём."""
    if _is_in_memory(db_path):
        return
    parent = Path(db_path).resolve().parent
    parent.mkdir(parents=True, exist_ok=True)


async def run_migrations(db_path: str) -> None:
    """Применяет DDL + PRAGMA на указанной БД.

    Args:
        db_path: путь к SQLite-файлу или `:memory:`.

    Безопасно при повторном вызове. Структурно логирует начало/конец
    (без potentially-sensitive path-значений в production-логах — путь
    в `extra={"db_path_set": True}`, а не сам путь).
    """
    _ensure_parent_dir(db_path)
    log.info(
        "storage_migrations_start",
        extra={"db_path_set": bool(db_path), "ddl_count": len(ALL_DDL_STATEMENTS)},
    )
    async with aiosqlite.connect(db_path) as db:
        for pragma in PRAGMA_STATEMENTS:
            try:
                await db.execute(pragma)
            except aiosqlite.Error:
                # WAL/synchronous могут быть not-supported на in-memory —
                # это не критично, продолжаем DDL-применение.
                log.debug("storage_pragma_failed", extra={"pragma": pragma})
        for stmt in ALL_DDL_STATEMENTS:
            await db.execute(stmt)
        # ALTER TABLE ADD COLUMN не имеет IF NOT EXISTS в SQLite — повторный
        # запуск на уже-мигрированной БД падает с "duplicate column name".
        # Трактуем эту ошибку как no-op (миграция уже применена).
        for stmt in ADDITIVE_MIGRATIONS:
            try:
                await db.execute(stmt)
            except aiosqlite.OperationalError as exc:
                msg = str(exc).lower()
                if "duplicate column" in msg:
                    log.debug(
                        "storage_additive_migration_skipped",
                        extra={"reason": "column_exists"},
                    )
                    continue
                raise
        await db.commit()
    log.info(
        "storage_migrations_done",
        extra={
            "ddl_count": len(ALL_DDL_STATEMENTS),
            "additive_count": len(ADDITIVE_MIGRATIONS),
        },
    )


__all__ = ["run_migrations"]
