"""Test UI router (T-023, `tmp/gui_plan.md §3`).

4 endpoint'а под флагом `ENABLE_TEST_UI=true`:

- `GET /ui` — отдача `static/index.html` (фронт T-024). Если файл ещё
  не залит — отдаём placeholder, чтобы endpoint не падал.
- `POST /api/ui/analyze` — главный: сырой код → synthetic FilteredDiff →
  pre-LLM scan → LLM (polza.ai) → postprocess → JSON.
- `GET /api/ui/budget` — текущий бюджет polza.ai (через `LLMClient.budget`).
- `GET /api/ui/examples` — 4 встроенных примера (sqli / secret / xss / clean).

Контракты НЕ меняются: на вход/выход — стандартные модели `sunsec.contracts`.
DI: фабрика принимает `llm_client`, `fp_filter`, `diff_filter`, `budget`.
`diff_filter` передаётся ради future-proof (см. план §9) — текущие endpoint'ы
не вызывают его напрямую, т.к. построение FilteredDiff идёт через
`synthetic_filtered_diff` (намеренный bypass DiffFilter для UI).

Ошибки `BudgetExceeded` / `LLMTimeout` / `LLMProviderUnavailable` → 200 OK
с соответствующим `llm.status` (НЕ 5xx — пользователь должен это увидеть
в UI). Pydantic ValidationError → 422. >50 KB → 413. Любое другое → 500
с `error_type`, БЕЗ traceback в ответе.
"""
from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Optional

try:
    from fastapi import APIRouter, HTTPException, status  # type: ignore
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse  # type: ignore
except ImportError:  # pragma: no cover — для среды без fastapi
    APIRouter = None  # type: ignore[assignment]
    HTTPException = status = FileResponse = HTMLResponse = JSONResponse = None  # type: ignore[assignment]

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from sunsec.contracts import Finding
from sunsec.llm.base import BudgetExceeded, LLMProviderUnavailable, LLMTimeout
from sunsec.llm.budget import BudgetCounter
from sunsec.ui.synthetic import FileIn, synthetic_filtered_diff

log = logging.getLogger(__name__)


# Soft-limit на размер запроса (см. `tmp/gui_plan.md §9 риск 3`).
_MAX_TOTAL_BYTES = 50 * 1024  # 50 KB суммарно по полю `code`.

# Папка со static-файлами (фронт T-024).
_STATIC_DIR = Path(__file__).resolve().parent / "static"
_INDEX_HTML = _STATIC_DIR / "index.html"


# ---------------------------------------------------------------------------
# Pydantic-модели запроса/ответа
# ---------------------------------------------------------------------------


class AnalyzeFile(BaseModel):
    """Один файл в запросе на анализ."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., min_length=1, max_length=512)
    language: Optional[str] = Field(default=None, max_length=64)
    # `code` без `max_length` — soft-limit считается в handler'е (см. ниже)
    # и возвращает 413, а не 422, как требует план (`tmp/gui_plan.md §3 ошибки`).
    # Жёсткий hard-cap — на уровне total суммы по всем файлам в запросе.
    code: str = Field(default="")


class AnalyzeRequest(BaseModel):
    """Запрос на анализ — массив файлов (1..50)."""

    model_config = ConfigDict(extra="forbid")

    files: list[AnalyzeFile] = Field(..., min_length=1, max_length=50)


# ---------------------------------------------------------------------------
# 4 встроенных примера (`/api/ui/examples`, `tmp/gui_plan.md §3 таблица`)
# ---------------------------------------------------------------------------
#
# Каждый пример привязан к классу из `agents/artifacts/researcher/vuln_taxonomy.md`:
#  - sqli_simple.py    → §3 sql_injection / high (CWE-89 SQLi-1: Python f-string)
#  - secret_aws.py     → §4 hardcoded_secret / critical (HC-3 AKIA-ключ)
#  - xss_react.jsx     → §5 xss / medium-high (dangerouslySetInnerHTML)
#  - clean_code.py     → clean baseline (параметризация + env-секрет)
#
# КЛЮЧИ — фейковые, для FP-detector демо:
#  - AKIAIOSFODNN7EXAMPLE — официальный AWS example-key (документация AWS).
#  - sk_live_FAKE... — обозначен `# fake — for FP-detector demo`.
# Никаких реальных секретов в коде/тестах/артефактах.

_EXAMPLES: list[dict[str, Any]] = [
    {
        "name": "sqli_simple.py",
        "description": (
            "F-string SQL внутри cursor.execute. "
            "Класс vuln_taxonomy §3 (sql_injection / high)."
        ),
        "files": [
            {
                "path": "app/views.py",
                "language": "python",
                "code": (
                    "import sqlite3\n"
                    "\n"
                    "def find_user(conn: sqlite3.Connection, user_id: str):\n"
                    "    cursor = conn.cursor()\n"
                    "    # SQLi (vuln_taxonomy §3): user_id попадает в SQL без параметризации.\n"
                    "    query = f\"SELECT id, email FROM users WHERE id = {user_id}\"\n"
                    "    cursor.execute(query)\n"
                    "    return cursor.fetchone()\n"
                ),
            }
        ],
    },
    {
        "name": "secret_aws.py",
        "description": (
            "Hardcoded AWS access key (AKIA-pattern) + fake Stripe secret. "
            "Класс vuln_taxonomy §4 (hardcoded_secret / critical, pre-scan)."
        ),
        "files": [
            {
                "path": "config/secrets.py",
                "language": "python",
                "code": (
                    "# WARNING: захардкоженные ключи — vuln_taxonomy §4 HC-3.\n"
                    "# AWS example-key (официальный dummy AKIAIOSFODNN7EXAMPLE,\n"
                    "# безопасен в публичных источниках). pre-scan ловит как critical.\n"
                    "AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\"\n"
                    "AWS_SECRET_ACCESS_KEY = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"
                    "\n"
                    "# fake — for FP-detector demo (sk_live_ префикс ловится regex'ом).\n"
                    "STRIPE_SECRET = \"sk_live_FAKE0000aaaaBBBBccccDDDDeeee\"\n"
                ),
            }
        ],
    },
    {
        "name": "xss_react.jsx",
        "description": (
            "dangerouslySetInnerHTML от пользовательского ввода. "
            "Класс vuln_taxonomy §5 (xss / medium-high)."
        ),
        "files": [
            {
                "path": "frontend/Profile.jsx",
                "language": "javascript",
                "code": (
                    "import React from 'react';\n"
                    "\n"
                    "export function Profile({ user }) {\n"
                    "  // XSS (vuln_taxonomy §5): user.bio попадает в DOM без санитизации.\n"
                    "  return (\n"
                    "    <div className=\"bio\"\n"
                    "         dangerouslySetInnerHTML={{ __html: user.bio }} />\n"
                    "  );\n"
                    "}\n"
                ),
            }
        ],
    },
    {
        "name": "clean_code.py",
        "description": (
            "Параметризованный SQL + env-секрет — baseline для FP-free поведения. "
            "Ожидание: 0 findings."
        ),
        "files": [
            {
                "path": "app/db_clean.py",
                "language": "python",
                "code": (
                    "import os\n"
                    "import sqlite3\n"
                    "\n"
                    "# env-getter — НЕ секрет (vuln_taxonomy §4.3 anti-signals).\n"
                    "DB_PASSWORD = os.environ.get(\"DB_PASSWORD\", \"\")\n"
                    "\n"
                    "def find_user(conn: sqlite3.Connection, user_id: int):\n"
                    "    # Параметризация — vuln_taxonomy §3.3 anti-signals SQLi.\n"
                    "    cursor = conn.cursor()\n"
                    "    cursor.execute(\n"
                    "        \"SELECT id, email FROM users WHERE id = ?\",\n"
                    "        (user_id,),\n"
                    "    )\n"
                    "    return cursor.fetchone()\n"
                ),
            }
        ],
    },
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    """Сериализуем Finding с alias `class_` → `class` (для фронта)."""
    return {
        "file": f.file,
        "line": f.line,
        "class": f.class_,
        "severity": f.severity,
        "message": f.message,
        "suggestion": f.suggestion,
        "confidence": f.confidence,
    }


def _budget_snapshot(budget: Optional[BudgetCounter]) -> dict[str, Any]:
    """Снимок текущего бюджета. None → нули (LLM disabled)."""
    if budget is None:
        return {"spent_rub": 0.0, "limit_rub": 0.0, "remaining_rub": 0.0}
    spent = round(budget.spent_rub, 6)
    limit = round(budget.limit_rub, 6)
    remaining = round(max(0.0, limit - spent), 6)
    return {"spent_rub": spent, "limit_rub": limit, "remaining_rub": remaining}


def _budget_with_percent(budget: Optional[BudgetCounter]) -> dict[str, Any]:
    """Снимок + `limit_percent` (для статус-бара в UI)."""
    snap = _budget_snapshot(budget)
    limit = snap["limit_rub"]
    pct = (snap["spent_rub"] / limit * 100.0) if limit > 0 else 0.0
    snap["limit_percent"] = round(pct, 2)
    return snap


def _empty_llm_stats(model: str, status_str: str, latency_ms: int = 0) -> dict[str, Any]:
    return {
        "status": status_str,
        "model": model,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "cost_rub": 0.0,
        "latency_ms": latency_ms,
    }


# ---------------------------------------------------------------------------
# build_ui_router
# ---------------------------------------------------------------------------


def build_ui_router(
    *,
    llm_client: Any,
    fp_filter: Any,
    diff_filter: Any = None,  # noqa: ARG001 — future-proof, не используется сейчас
    budget: Optional[BudgetCounter] = None,
) -> Any:
    """Фабрика test-UI роутера. См. модуль-docstring.

    Args:
        llm_client: `LLMClient` или None (если polza.ai не сконфигурирован).
        fp_filter: `FalsePositiveFilter`.
        diff_filter: `DiffFilter` — НЕ используется в текущей реализации
            (UI делает `synthetic_filtered_diff` напрямую), но принимается
            ради будущей вкладки «Replay diff» (см. `tmp/gui_plan.md §1.2 NB`).
        budget: `BudgetCounter` (`llm_client.budget`) или None.
    """
    if APIRouter is None:  # pragma: no cover
        raise RuntimeError("FastAPI не установлен — невозможно построить UI router.")

    router = APIRouter()

    @router.get("/ui")
    async def ui_index() -> Any:
        """Отдаёт `static/index.html` (фронт T-024). Placeholder, если файла нет."""
        if _INDEX_HTML.is_file():
            return FileResponse(str(_INDEX_HTML), media_type="text/html")
        # Заглушка под T-024 — endpoint не должен падать, пока фронт не залит.
        placeholder = (
            "<!doctype html>\n"
            "<html><head><meta charset='utf-8'>"
            "<title>SunSecurityBot — Test UI</title></head>"
            "<body style='font-family:sans-serif;max-width:640px;margin:40px auto'>"
            "<h1>SunSecurityBot — Test UI</h1>"
            "<p>UI page (T-024 in progress).</p>"
            "<p>Backend endpoints доступны:</p>"
            "<ul>"
            "<li><code>POST /api/ui/analyze</code></li>"
            "<li><code>GET /api/ui/budget</code></li>"
            "<li><code>GET /api/ui/examples</code></li>"
            "</ul>"
            "<p>См. <code>tmp/gui_plan.md</code>.</p>"
            "</body></html>"
        )
        return HTMLResponse(content=placeholder, status_code=200)

    @router.get("/api/ui/budget")
    async def get_budget() -> dict[str, Any]:
        """Текущий бюджет polza.ai (`tmp/gui_plan.md §3`)."""
        return _budget_with_percent(budget)

    @router.get("/api/ui/examples")
    async def get_examples() -> list[dict[str, Any]]:
        """4 встроенных примера (`tmp/gui_plan.md §3`).

        Single source of truth для кнопок «Examples» во фронте T-024.
        """
        return _EXAMPLES

    @router.post("/api/ui/analyze")
    async def analyze(payload: dict[str, Any]) -> Any:
        """Главный endpoint: код → findings + LLM-stats + budget.

        Контракт ошибок — см. модуль-docstring.
        """
        model_id = getattr(llm_client, "prompt_version", None) or "unknown"
        # `prompt_version` — не модель; реальная модель приходит в `LLMRawResponse.model`.
        # Чтобы фронту было понятнее без вызова LLM — попробуем достать имя через
        # `llm_client._provider.name` если есть.
        provider_name = "unknown"
        if llm_client is not None:
            provider = getattr(llm_client, "_provider", None)
            if provider is not None:
                provider_name = getattr(provider, "name", "unknown")
        del model_id  # помечен использованным выше, реальная модель — в `raw.model`

        # --- 1) Валидация Pydantic. ValidationError → 422 ---
        try:
            request = AnalyzeRequest.model_validate(payload)
        except ValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=[
                    {
                        "loc": list(err.get("loc", ())),
                        "msg": err.get("msg", ""),
                        "type": err.get("type", ""),
                    }
                    for err in exc.errors()
                ],
            ) from None

        # --- 2) Soft-limit 50 KB суммарно (`tmp/gui_plan.md §9 риск 3`) ---
        total_bytes = sum(len(f.code.encode("utf-8")) for f in request.files)
        if total_bytes > _MAX_TOTAL_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=(
                    f"Суммарный размер code превышает soft-limit "
                    f"{_MAX_TOTAL_BYTES} bytes ({total_bytes} bytes получено). "
                    f"Уменьши объём кода в запросе."
                ),
            )

        # --- 3) Synthetic FilteredDiff (без DiffFilter, см. план §4) ---
        files_in = [
            FileIn(path=f.path, code=f.code, language=f.language)
            for f in request.files
        ]
        filtered = synthetic_filtered_diff(files_in)

        # --- 4) Pre-LLM scan (детерминированный secret-detector) ---
        try:
            pre_scan = fp_filter.pre_llm_scan(filtered)
        except Exception as exc:  # noqa: BLE001 — изоляция UI от багов в FP-фильтре
            log.exception("ui_pre_scan_failed")
            return JSONResponse(
                status_code=500,
                content={
                    "error_type": type(exc).__name__,
                    "detail": "pre_llm_scan failed (internal). См. server logs.",
                },
            )

        # --- 5) Особый случай: пустой code на всех файлах → skipped_empty ---
        if filtered.is_empty():
            # LLM НЕ вызывается; postprocess всё равно прогоняем
            # (на pre_scan, хоть его и не будет, т.к. added_lines пуст).
            try:
                final_findings = fp_filter.postprocess(
                    [], filtered, pre_scan_findings=pre_scan
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("ui_postprocess_failed_empty")
                return JSONResponse(
                    status_code=500,
                    content={
                        "error_type": type(exc).__name__,
                        "detail": "postprocess failed (internal). См. server logs.",
                    },
                )
            return _build_response(
                summary="Нет кода для анализа (все файлы пустые).",
                findings=final_findings,
                pre_scan=pre_scan,
                dropped=[],
                excluded=filtered.excluded_files,
                llm_stats=_empty_llm_stats(
                    model=provider_name, status_str="skipped_empty"
                ),
                budget_snap=_budget_snapshot(budget),
            )

        # --- 6) LLM-вызов (с обработкой бюджета / таймаута / unavailable) ---
        if llm_client is None:
            # LLM disabled на старте (например, polza.ai ключ не задан).
            # pre-scan и postprocess всё равно отрабатываем.
            log.info("ui_analyze_llm_disabled", extra={"repo": filtered.repo})
            try:
                final_findings = fp_filter.postprocess(
                    [], filtered, pre_scan_findings=pre_scan
                )
            except Exception as exc:  # noqa: BLE001
                log.exception("ui_postprocess_failed_llm_disabled")
                return JSONResponse(
                    status_code=500,
                    content={
                        "error_type": type(exc).__name__,
                        "detail": "postprocess failed (internal). См. server logs.",
                    },
                )
            return _build_response(
                summary="LLM disabled (POLZA_API_KEY не задан или клиент не инициализирован).",
                findings=final_findings,
                pre_scan=pre_scan,
                dropped=[],
                excluded=filtered.excluded_files,
                llm_stats=_empty_llm_stats(
                    model=provider_name, status_str="provider_unavailable"
                ),
                budget_snap=_budget_snapshot(budget),
            )

        t0 = time.monotonic()
        llm_status = "ok"
        llm_response = None
        llm_summary: Optional[str] = None
        try:
            llm_response = await llm_client.analyze(filtered)
            llm_summary = llm_response.summary
        except BudgetExceeded as exc:
            llm_status = "budget_exceeded"
            llm_summary = f"Бюджет polza.ai исчерпан: {exc}"
            log.info("ui_analyze_budget_exceeded", extra={"repo": filtered.repo})
        except LLMTimeout as exc:
            llm_status = "timeout"
            llm_summary = (
                f"Таймаут polza.ai после retries. "
                f"Проверь сеть/доступность провайдера. ({exc})"
            )
            log.warning("ui_analyze_timeout", extra={"repo": filtered.repo})
        except LLMProviderUnavailable as exc:
            llm_status = "provider_unavailable"
            llm_summary = (
                f"polza.ai недоступен (HTTP 5xx / fallback запрещён). "
                f"Проверь POLZA_API_KEY в .env. ({exc})"
            )
            log.warning(
                "ui_analyze_provider_unavailable", extra={"repo": filtered.repo}
            )
        except Exception as exc:  # noqa: BLE001 — изолируем UI от любых неожиданных
            log.exception("ui_analyze_unexpected_error")
            return JSONResponse(
                status_code=500,
                content={
                    "error_type": type(exc).__name__,
                    "detail": "LLM analyze failed (internal). См. server logs.",
                },
            )

        latency_ms = int((time.monotonic() - t0) * 1000)

        # --- 7) Postprocess (FP-фильтр) ---
        llm_findings = llm_response.findings if llm_response is not None else []
        try:
            final_findings = fp_filter.postprocess(
                llm_findings, filtered, pre_scan_findings=pre_scan
            )
        except Exception as exc:  # noqa: BLE001
            log.exception("ui_postprocess_failed")
            return JSONResponse(
                status_code=500,
                content={
                    "error_type": type(exc).__name__,
                    "detail": "postprocess failed (internal). См. server logs.",
                },
            )

        # dropped_by_fp: то, что было на входе postprocess, но не попало в kept.
        kept_keys = {(f.file, f.line, f.class_) for f in final_findings}
        candidates = list(pre_scan) + list(llm_findings)
        dropped: list[dict[str, Any]] = []
        seen_drop: set[tuple[str, int, str]] = set()
        for f in candidates:
            key = (f.file, f.line, f.class_)
            if key in kept_keys:
                continue
            if key in seen_drop:
                continue
            seen_drop.add(key)
            dropped.append(_finding_to_dict(f))

        # --- 8) LLM stats для фронта ---
        # raw_model / tokens / cost из последнего вызова — у нас в LLMClient нет
        # публичного "last_raw". Парсим из лог-снимка budget (snapshot ДО vs ПОСЛЕ
        # не считаем тут — фронт сам пересчитает через /api/ui/budget). Для cost
        # отдаём дельту spent_before vs spent_after через `budget.spent_rub`.
        # Это упрощение, sufficient для UI: см. план §3 «llm.cost_rub».
        budget_after = _budget_snapshot(budget)
        # prompt_tokens / completion_tokens у нас нет в API LLMClient.analyze
        # (он возвращает только `LLMResponseSchema`); они логируются внутри.
        # Для UI отдаём 0 — фронт-карточка просто не покажет деталь. Это явная
        # упрощённая реализация: реальные tokens пишутся в server logs
        # (`llm_call_completed`), а юзер видит cost через дельту бюджета.
        llm_stats = {
            "status": llm_status,
            "model": provider_name,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "cost_rub": 0.0,  # фронт сам считает по дельте /api/ui/budget
            "latency_ms": latency_ms,
        }

        return _build_response(
            summary=llm_summary or "",
            findings=final_findings,
            pre_scan=pre_scan,
            dropped=[d for d in dropped],
            excluded=filtered.excluded_files,
            llm_stats=llm_stats,
            budget_snap=budget_after,
        )

    return router


def _build_response(
    *,
    summary: str,
    findings: list[Finding],
    pre_scan: list[Finding],
    dropped: list[dict[str, Any]],
    excluded: list[Any],
    llm_stats: dict[str, Any],
    budget_snap: dict[str, Any],
) -> dict[str, Any]:
    """Сборка JSON-ответа `/api/ui/analyze` (см. `tmp/gui_plan.md §3 ответ`)."""
    return {
        "summary": summary,
        "findings": [_finding_to_dict(f) for f in findings],
        "pre_scan_findings": [_finding_to_dict(f) for f in pre_scan],
        "dropped_by_fp": dropped,
        "excluded_files": [
            {
                "path": ex.path,
                "reason": ex.reason,
                "detail": ex.detail,
            }
            for ex in excluded
        ],
        "llm": llm_stats,
        "budget": budget_snap,
    }


__all__ = ["build_ui_router", "AnalyzeFile", "AnalyzeRequest"]
