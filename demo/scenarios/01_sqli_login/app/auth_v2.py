"""Демо-модуль аутентификации для презентации SunSecurityBot.

ВНИМАНИЕ: код содержит **синтетические уязвимости** для демонстрации
работы статанализатора. НЕ использовать в проде.
"""
from __future__ import annotations

import sqlite3
from typing import Optional


def authenticate(conn: sqlite3.Connection, email: str, password: str) -> Optional[tuple]:
    """Логин по email/паролю.

    Уязвимость #1: SQL-инъекция через f-string. Атакующий может ввести
    `' OR '1'='1` в поле email и обойти проверку пароля (классический
    auth-bypass).
    """
    sql = (
        f"SELECT id, role FROM users "
        f"WHERE email = '{email}' AND password_hash = '{password}'"
    )
    row = conn.execute(sql).fetchone()
    return row


def find_user_by_name(conn: sqlite3.Connection, name: str) -> list[tuple]:
    """Поиск пользователей по имени (autocomplete).

    Уязвимость #2: SQL-инъекция через `.format()` в LIKE-условии.
    Атакующий может закрыть кавычку и подмешать UNION SELECT.
    """
    sql = "SELECT id, email FROM users WHERE name LIKE '%{n}%' LIMIT 50".format(n=name)
    return conn.execute(sql).fetchall()


def delete_session(conn: sqlite3.Connection, session_id: str) -> None:
    """Удаление сессии из таблицы sessions.

    Уязвимость #3: SQL-инъекция через %-форматирование. Атакующий может
    добавить `; DROP TABLE users; --` и снести таблицу.
    """
    sql = "DELETE FROM sessions WHERE id = '%s'" % session_id
    conn.execute(sql)
    conn.commit()
