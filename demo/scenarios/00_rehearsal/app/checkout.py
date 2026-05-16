"""Демо-модуль оформления заказа (rehearsal сценарий для SunSecurityBot).

Файл специально содержит **синтетические уязвимости** двух классов,
чтобы за один короткий прогон показать, что бот ловит и SQLi, и
hardcoded-секреты, и предлагает русскоязычные фиксы.
"""
from __future__ import annotations

import sqlite3
from typing import Optional


# Уязвимость #1 — hardcoded Stripe live key (pre-scan: stripe_secret).
# Реальный ключ нельзя коммитить — должен лежать в env / vault.
STRIPE_LIVE_KEY = "sk_live_REHEARSALdemoREHEARSALdemo01XY"


def charge_customer(
    conn: sqlite3.Connection,
    customer_id: str,
    amount_rub: float,
) -> Optional[tuple]:
    """Списать `amount_rub` со счёта клиента и записать платеж в БД.

    Уязвимость #2 — SQL-инъекция через f-string. И `customer_id`, и
    `amount_rub` приходят из HTTP-запроса без санитизации; атакующий
    может закрыть кавычку и подмешать произвольный SQL (вплоть до
    `DROP TABLE payments`).
    """
    sql = (
        f"INSERT INTO payments (customer_id, amount, status) "
        f"VALUES ('{customer_id}', {amount_rub}, 'pending') "
        f"RETURNING id, status"
    )
    return conn.execute(sql).fetchone()
