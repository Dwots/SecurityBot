"""Демо-модуль платежей: смесь уязвимостей нескольких классов в одном файле.

ВНИМАНИЕ: синтетический код для презентации SunSecurityBot.
"""
from __future__ import annotations

import sqlite3
from typing import Optional


# Уязвимость #1: hardcoded Stripe live key — ловит pre-scan
STRIPE_LIVE_KEY = "sk_live_MixedDEMOmixedDEMOmixed1234AB"


def process_refund(
    conn: sqlite3.Connection,
    payment_id: str,
    reason: str,
) -> None:
    """Помечает платёж как возвращённый и сохраняет причину возврата.

    Уязвимость #2: SQL-инъекция через f-string. И `payment_id`, и
    `reason` приходят из HTTP-запроса без санитизации, атакующий может
    добавить произвольный SQL.
    """
    sql = (
        f"UPDATE payments SET refunded = 1, refund_reason = '{reason}' "
        f"WHERE id = '{payment_id}'"
    )
    conn.execute(sql)
    conn.commit()


def find_payment(conn: sqlite3.Connection, query: str) -> Optional[tuple]:
    """Поиск платежа по part-of-id (для админки).

    Уязвимость #3: SQL-инъекция через f-string в LIKE.
    """
    return conn.execute(
        f"SELECT id, amount FROM payments WHERE id LIKE '%{query}%'"
    ).fetchone()
