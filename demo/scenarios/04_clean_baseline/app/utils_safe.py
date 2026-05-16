"""Демо-модуль БЕЗ уязвимостей — для показа «чистого» PR.

Ожидаемый результат от SunSecurityBot: 0 findings, summary —
«В diff не обнаружено проблем безопасности.»
"""
from __future__ import annotations

import html
import os
import sqlite3
from typing import Iterable


def get_db_url() -> str:
    """Безопасный геттер: секрет — в env, в коде только имя переменной."""
    return os.environ.get("DATABASE_URL", "sqlite:///app.db")


def get_stripe_key() -> str | None:
    """Безопасно: ключ читается из env, дефолт — None (а не литерал)."""
    return os.getenv("STRIPE_SECRET_KEY")


def find_active_users(
    conn: sqlite3.Connection,
    role: str,
    limit: int = 100,
) -> list[tuple]:
    """Параметризованный SQL — нет SQL-инъекции."""
    return conn.execute(
        "SELECT id, email FROM users WHERE role = ? AND active = 1 LIMIT ?",
        (role, int(limit)),
    ).fetchall()


def sanitize_for_html(s: str) -> str:
    """Эскейпинг через stdlib — XSS невозможен."""
    return html.escape(s, quote=True)


def bulk_insert_events(
    conn: sqlite3.Connection,
    events: Iterable[tuple[str, str, float]],
) -> int:
    """executemany с placeholder'ами — каждая запись параметризована."""
    cur = conn.executemany(
        "INSERT INTO events (kind, payload, ts) VALUES (?, ?, ?)",
        list(events),
    )
    conn.commit()
    return cur.rowcount or 0
