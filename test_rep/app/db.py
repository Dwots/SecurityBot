"""Database layer — clean baseline.

ВАЖНО: этот файл намеренно НЕ содержит уязвимостей. Все SQL-запросы
параметризованы через `?`-плейсхолдеры sqlite3 / DB-API 2.0. Файл
используется как контроль качества FP-фильтра SunSecurityBot:
бот НЕ должен оставлять inline-комментарии в этом файле.
"""
from __future__ import annotations

import logging
import sqlite3
from typing import Any, Optional

from config.settings import get_settings

log = logging.getLogger(__name__)


def get_connection() -> sqlite3.Connection:
    """Открыть соединение к локальной sqlite-базе.

    Settings — env-driven, секретов в коде нет.
    """
    settings = get_settings()
    conn = sqlite3.connect(settings.db_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_user_by_id_safe(user_id: int) -> Optional[dict[str, Any]]:
    """Параметризованный SELECT по id.

    Использует `?`-плейсхолдер, user_id передаётся вторым аргументом
    как tuple. Структура запроса не меняется от значения user_id.
    """
    conn = get_connection()
    try:
        # clean: параметризованный запрос
        row = conn.execute(
            "SELECT id, name, email, bio FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if row is None:
            return None
        return {"id": row[0], "name": row[1], "email": row[2], "bio": row[3]}
    finally:
        conn.close()


def list_users_by_role_safe(role: str, limit: int = 50) -> list[dict[str, Any]]:
    """Параметризованный SELECT с несколькими параметрами."""
    conn = get_connection()
    try:
        # clean: параметризация через `?, ?`
        cursor = conn.execute(
            "SELECT id, name, email FROM users WHERE role = ? LIMIT ?",
            (role, limit),
        )
        return [
            {"id": r[0], "name": r[1], "email": r[2]} for r in cursor.fetchall()
        ]
    finally:
        conn.close()


def create_user_safe(name: str, email: str, role: str) -> int:
    """Параметризованный INSERT.

    Возвращает rowid вставленной записи.
    """
    conn = get_connection()
    try:
        # clean: параметризованный INSERT
        cursor = conn.execute(
            "INSERT INTO users (name, email, role) VALUES (?, ?, ?)",
            (name, email, role),
        )
        conn.commit()
        return int(cursor.lastrowid or 0)
    finally:
        conn.close()
