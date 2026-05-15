"""HTTP handlers.

ВНИМАНИЕ: этот модуль СОДЕРЖИТ намеренные уязвимости для тестирования
SunSecurityBot (см. test_rep/README.md). Не использовать в production.
"""
from __future__ import annotations

import logging
import sqlite3
from typing import Any

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.db import get_connection, get_user_by_id_safe

log = logging.getLogger(__name__)

router = APIRouter()


@router.get("/search")
def search(q: str = Query(default="", min_length=0, max_length=200)) -> JSONResponse:
    """Поиск пользователей по части имени.

    VULN: SQL-инъекция через f-string. Параметр `q` уходит в SQL-запрос
    без параметризации — классический CWE-89 (vuln_taxonomy §3.4 SQLi-1).
    """
    log.info("search_requested", extra={"q_length": len(q)})
    conn = get_connection()
    try:
        # vuln: f-string SQL без параметризации
        sql = f"SELECT id, name, email FROM users WHERE name LIKE '%{q}%'"
        rows = conn.execute(sql).fetchall()
        result = [{"id": r[0], "name": r[1], "email": r[2]} for r in rows]
        return JSONResponse({"query": q, "results": result, "count": len(result)})
    finally:
        conn.close()


@router.post("/login")
def login(email: str = Form(...), password: str = Form(...)) -> JSONResponse:
    """Логин по email + password.

    VULN: SQL-инъекция через .format() в auth-роуте — потенциальный
    auth bypass классическим `' OR '1'='1` (vuln_taxonomy §3.4 SQLi-2,
    severity=critical).
    """
    log.info("login_attempt", extra={"email_domain": email.split("@")[-1] if "@" in email else "?"})
    conn = get_connection()
    try:
        # vuln: .format() SQL без параметризации на auth-endpoint
        sql_template = "SELECT id, role FROM users WHERE email = '{e}' AND pw_hash = '{p}'"
        sql = sql_template.format(e=email, p=password)
        row = conn.execute(sql).fetchone()
        if row is None:
            return JSONResponse({"ok": False, "error": "invalid_credentials"}, status_code=401)
        return JSONResponse({"ok": True, "user_id": row[0], "role": row[1]})
    finally:
        conn.close()


@router.get("/profile/{user_id}", response_class=HTMLResponse)
def profile(request: Request, user_id: int) -> HTMLResponse:
    """Профиль пользователя — рендер Jinja2-шаблона `profile.html`.

    Сам handler читает данные через clean DB-слой (см. `app/db.py`),
    но шаблон `templates/profile.html` отключает auto-escape через
    `| safe` на user.bio — это XSS (см. README §2).
    """
    user = get_user_by_id_safe(user_id)
    if user is None:
        return HTMLResponse("<h1>User not found</h1>", status_code=404)
    templates = request.app.state.templates
    return templates.TemplateResponse(
        "profile.html",
        {"request": request, "user": user},
    )


@router.get("/users/{user_id}")
def get_user(user_id: int) -> JSONResponse:
    """CLEAN: вернуть пользователя через параметризованный SQL.

    Этот handler — baseline без уязвимостей. Используется как
    «контроль FP-фильтра»: bot НЕ должен сюда писать комментарии.
    """
    user = get_user_by_id_safe(user_id)
    if user is None:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse({"user": user})
