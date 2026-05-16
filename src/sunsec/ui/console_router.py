"""Console UI HTTP router (M-9, T-039).

Источник истины — `system_design.md v1.2.1 §13` (10 endpoint'ов:
`budget` / `settings` / `checks` / `checks/{id}` / `manual/analyze` /
`repos` × 4 / `dashboard`).

Все Pydantic-контракты — `src/sunsec/contracts/console.py` с
`alias_generator=to_camel` (camelCase наружу).

Безопасность (см. §13.5, R-12, R-13):
- `SettingsOut` — explicit allow-list; `*_API_KEY` / `*_TOKEN` / `*_SECRET`
  никогда не сериализуются.
- `RepoConfigOut` — БЕЗ plaintext `vcs_token` / `webhook_secret`; только
  `*_ref` имена env-переменных + boolean-индикаторы.
- POST/PATCH `/repos`: значения секретов попадают в `os.environ[ref]` +
  gitignored `data/repos_secrets.env` через `python-dotenv.set_key`.
  В лог НЕ пишутся; см. RT-012 backend-fix.

Auth pre-condition (R-13 HIGH): MVP — single-user dev-режим, без authn;
не выставлять `/api/console/*` в публичную сеть.
"""
from __future__ import annotations

import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

try:
    from fastapi import APIRouter, HTTPException, Query, status  # type: ignore
    from fastapi.responses import JSONResponse, Response  # type: ignore
except ImportError:  # pragma: no cover
    APIRouter = None  # type: ignore[assignment]
    HTTPException = Query = status = JSONResponse = Response = None  # type: ignore[assignment]

from pydantic import ValidationError

from sunsec.contracts.console import (
    BudgetOut,
    CheckDetailsOut,
    CheckSummaryOut,
    DashboardOut,
    FindingDetailOut,
    FindingsBySeverityOut,
    ManualAnalyzeIn,
    ManualAnalyzeOut,
    ManualFindingOut,
    ManualLLMMetaOut,
    RepoConfigIn,
    RepoConfigOut,
    RepoConfigPatchIn,
    SettingsOut,
    SeverityCountsOut,
    TimelineEntryOut,
    TunnelOut,
    WebhookInstallIn,
    WebhookInstallOut,
)
from sunsec.contracts.storage import (
    CheckRecord,
    RepoConfigRecord,
)
from sunsec.storage.errors import (
    StorageConflictError,
    StorageError,
    StorageNotFoundError,
)

log = logging.getLogger(__name__)

# Default путь для gitignored secrets-файла (RT-012 backend-fix).
# Может быть переопределён в фабрике (для тестов через tmp_path).
DEFAULT_REPOS_SECRETS_PATH = Path("data") / "repos_secrets.env"

# Названия секретных env-переменных, которые НЕ должны попасть ни в один
# response (`SettingsOut` уже фильтрует на уровне модели; это backup-grep
# для защиты от случайного добавления нового секрета в Settings).
_SECRET_NAME_RE = re.compile(r"(api[_-]?key|token|secret|password)", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def slug_for_repo(full_name: str) -> str:
    """Нормализация `owner/repo` → `OWNER_REPO` (alphanumeric_underscore).

    Spec — `system_design v1.2.1 §13.4` («Слаг функция»):
        slug = re.sub(r'[^A-Za-z0-9]+', '_', full_name).strip('_').upper()
    """
    return re.sub(r"[^A-Za-z0-9]+", "_", full_name).strip("_").upper()


def vcs_token_ref_name(full_name: str) -> str:
    """`REPO_<NORMALIZED>_VCS_TOKEN` — детерминированное имя env-переменной."""
    return f"REPO_{slug_for_repo(full_name)}_VCS_TOKEN"


def webhook_secret_ref_name(full_name: str) -> str:
    """`REPO_<NORMALIZED>_WEBHOOK_SECRET`."""
    return f"REPO_{slug_for_repo(full_name)}_WEBHOOK_SECRET"


def _record_to_repo_out(rec: RepoConfigRecord) -> RepoConfigOut:
    """Конвертация persistence-модели в HTTP-response (без секретов)."""
    return RepoConfigOut(
        id=rec.id,
        full_name=rec.full_name,
        vcs_provider=rec.vcs_provider,
        vcs_token_ref=rec.vcs_token_ref,
        webhook_secret_ref=rec.webhook_secret_ref,
        vcs_token_set=bool(rec.vcs_token_ref and os.environ.get(rec.vcs_token_ref)),
        webhook_secret_set=bool(
            rec.webhook_secret_ref and os.environ.get(rec.webhook_secret_ref)
        ),
        llm_provider_override=rec.llm_provider_override,
        enabled=bool(rec.enabled),
        created_at=rec.created_at,
        updated_at=rec.updated_at,
        last_seen_at=rec.last_seen_at,
        webhook_id=rec.webhook_id,
        webhook_url=rec.webhook_url,
    )


def _record_to_check_summary(rec: CheckRecord) -> CheckSummaryOut:
    severity = SeverityCountsOut(
        critical=int(rec.severity_counts.get("critical", 0) or 0),
        high=int(rec.severity_counts.get("high", 0) or 0),
        medium=int(rec.severity_counts.get("medium", 0) or 0),
        low=int(rec.severity_counts.get("low", 0) or 0),
        info=int(rec.severity_counts.get("info", 0) or 0),
    )
    return CheckSummaryOut(
        id=rec.id,
        repository=rec.repo,
        pr_number=rec.pr_number,
        pr_title=rec.pr_title,
        author=rec.author,
        source_branch=rec.source_branch,
        target_branch=rec.target_branch,
        head_sha=rec.head_sha,
        base_sha=rec.base_sha,
        action=rec.action,
        status=rec.status,
        llm_status=rec.llm_status,
        started_at=rec.started_at,
        duration_ms=rec.duration_ms,
        files_checked=rec.files_checked,
        files_skipped=rec.files_skipped,
        findings_count=rec.findings_count,
        severity_counts=severity,
        pr_url=rec.pr_url,
        cost_rub=rec.cost_rub,
    )


def _budget_snapshot(budget: Optional[Any]) -> BudgetOut:
    """Снимок `BudgetCounter` → `BudgetOut`. None → нули."""
    if budget is None:
        return BudgetOut(
            spent_rub=0.0,
            limit_rub=0.0,
            remaining_rub=0.0,
            limit_percent=0.0,
            calls_count=0,
        )
    spent = float(getattr(budget, "spent_rub", 0.0) or 0.0)
    limit = float(getattr(budget, "limit_rub", 0.0) or 0.0)
    remaining = max(0.0, limit - spent)
    pct = (spent / limit * 100.0) if limit > 0 else 0.0
    calls = int(getattr(budget, "calls", 0) or 0)
    return BudgetOut(
        spent_rub=round(spent, 6),
        limit_rub=round(limit, 6),
        remaining_rub=round(remaining, 6),
        limit_percent=round(pct, 2),
        calls_count=calls,
    )


def _settings_to_out(settings: Any) -> SettingsOut:
    """Explicit allow-list (§13.5). Любое поле не в этом списке — НЕ попадёт в response."""
    excludes = getattr(settings, "filter_exclude_extensions", None) or ()
    names = getattr(settings, "filter_exclude_names", None) or ()
    globs = getattr(settings, "filter_exclude_globs", None) or ()

    # Provider-aware: model / budget / timeout / retries — берём из активного провайдера.
    provider_kind = (
        str(getattr(settings, "llm_provider", "polza") or "polza").strip().lower()
    )
    if provider_kind == "openrouter":
        model = settings.openrouter_model_id
        timeout = int(settings.openrouter_timeout_seconds)
        retries = int(settings.openrouter_max_retries)
        budget_limit = float(settings.openrouter_budget_limit_rub)
    else:
        model = settings.polza_model_id
        timeout = int(settings.polza_timeout_seconds)
        retries = int(settings.polza_max_retries)
        budget_limit = float(settings.polza_budget_limit_rub)

    return SettingsOut(
        app_env=str(settings.app_env),
        vcs_provider=str(settings.vcs_provider),
        github_api_base=str(settings.github_api_base),
        llm_provider=provider_kind,
        model=str(model),
        temperature=float(settings.llm_temperature),
        max_tokens=int(settings.llm_max_tokens),
        timeout_seconds=timeout,
        max_retries=retries,
        budget_limit_rub=budget_limit,
        publish_comments_enabled=bool(settings.publish_comments_enabled),
        skip_drafts=bool(settings.skip_drafts),
        state_store_backend=str(settings.state_store_backend),
        fp_min_confidence=float(settings.fp_min_confidence),
        filter_exclude_extensions=[str(x) for x in excludes],
        filter_exclude_names=[str(x) for x in names],
        filter_exclude_globs=[str(x) for x in globs],
        enable_console_ui=bool(getattr(settings, "enable_console_ui", False)),
    )


def _persist_secret(
    *,
    repos_secrets_path: Path,
    ref: str,
    value: str,
) -> bool:
    """Запись секрета в `os.environ` + gitignored `data/repos_secrets.env`.

    RT-012 backend-fix: durability через `python-dotenv.set_key`. При
    IOError / read-only FS — лог warning (без plaintext!) и fallback на
    in-process env-патч (теряется при рестарте; см. R-18).

    Args:
        repos_secrets_path: путь к gitignored файлу (тесты подменяют
            на `tmp_path`).
        ref: имя env-переменной (например `REPO_FOO_BAR_VCS_TOKEN`).
        value: plaintext-секрет (логи НЕ пишутся).

    Returns:
        True — запись в файл успешна; False — только in-process env.
    """
    if not value:
        return False
    # 1) Всегда — in-process env (минимум для текущего процесса).
    os.environ[ref] = value
    # 2) Durability — через python-dotenv.
    try:
        repos_secrets_path.parent.mkdir(parents=True, exist_ok=True)
        if not repos_secrets_path.exists():
            repos_secrets_path.touch(mode=0o600)
        from dotenv import set_key  # type: ignore[import-not-found]

        set_key(
            str(repos_secrets_path),
            ref,
            value,
            quote_mode="never",
            export=False,
        )
        log.info(
            "console_secret_persisted",
            extra={
                "ref": ref,
                "file_exists": True,
            },
        )
        return True
    except Exception as exc:  # noqa: BLE001 — IOError / OSError / etc.
        # Никогда не логируем value! Только индикатор.
        log.warning(
            "console_secret_persist_failed",
            extra={
                "ref": ref,
                "error_type": type(exc).__name__,
            },
        )
        return False


def _normalize_full_name(full_name: str) -> str:
    """Trim + lower-case basic-validation. Pydantic min_length уже отработал."""
    return (full_name or "").strip()


def _validate_full_name_format(full_name: str) -> None:
    """`owner/repo` — есть ровно один '/', обе части не пусты."""
    if "/" not in full_name:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=[
                {
                    "loc": ["body", "fullName"],
                    "msg": "fullName must be in form owner/repo",
                    "type": "value_error.format",
                }
            ],
        )
    parts = full_name.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=[
                {
                    "loc": ["body", "fullName"],
                    "msg": "fullName must be in form owner/repo",
                    "type": "value_error.format",
                }
            ],
        )


# ---------------------------------------------------------------------------
# build_console_router
# ---------------------------------------------------------------------------


def build_console_router(
    *,
    state: Any,
    settings: Any,
    llm_client: Any = None,
    manual_analyze_handler: Optional[Callable[[dict], Awaitable[Any]]] = None,
    repos_secrets_path: Optional[Path] = None,
    github_adapter_factory: Optional[Callable[[str], Any]] = None,
    tunnel_probe: Optional[Callable[[], Awaitable[Optional[str]]]] = None,
) -> Any:
    """Фабрика console-роутера. DI — все зависимости приходят снаружи.

    Args:
        state: `StateStore` (InMemoryStateStore или SQLiteStateStore — оба
            поддерживают M-9 методы из system_design v1.2.1 §11.5).
        settings: `Settings` — для `SettingsOut` + budget config.
        llm_client: `LLMClient` или None — для `BudgetOut` snapshot.
        manual_analyze_handler: callable `(payload) -> Awaitable[ManualAnalyzeOut|dict]`
            для `POST /api/console/manual/analyze`. Если None — endpoint
            вернёт 503 (proxy не подключен).
        repos_secrets_path: путь к gitignored secrets-файлу (RT-012).
            По умолчанию `data/repos_secrets.env`. Тесты подменяют на
            `tmp_path / "repos_secrets.env"`.
    """
    if APIRouter is None:  # pragma: no cover
        raise RuntimeError("FastAPI не установлен — невозможно построить router.")

    secrets_path = Path(repos_secrets_path) if repos_secrets_path else DEFAULT_REPOS_SECRETS_PATH
    router = APIRouter(prefix="/api/console", tags=["console"])

    budget = getattr(llm_client, "budget", None) if llm_client is not None else None

    # --- Lazy imports / helpers for webhook auto-install --------------------
    # GitHubAdapter — конструируется per-repo через токен из env-ref.
    # Тестам удобно подменить `github_adapter_factory`; по умолчанию используем
    # реальный `GitHubAdapter` с `settings.github_api_base`.
    def _default_github_factory(token: str) -> Any:
        from sunsec.vcs.github import GitHubAdapter

        return GitHubAdapter(
            token=token,
            api_base=str(getattr(settings, "github_api_base", "https://api.github.com")),
        )

    gh_factory = github_adapter_factory or _default_github_factory

    # Tunnel probe — дёргает ngrok admin API. Тесты подменяют на стаб,
    # возвращающий заданный URL или None.
    async def _default_tunnel_probe() -> Optional[str]:
        import httpx  # локальный импорт — httpx уже в зависимостях

        admin_url = str(getattr(settings, "ngrok_admin_url", "http://127.0.0.1:4040")).rstrip("/")
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                resp = await client.get(f"{admin_url}/api/tunnels")
            if resp.status_code != 200:
                return None
            data = resp.json()
        except Exception:  # noqa: BLE001 — ngrok может быть выключен, это норма
            return None
        tunnels = data.get("tunnels") if isinstance(data, dict) else None
        if not isinstance(tunnels, list):
            return None
        # Предпочитаем https-туннель (для GitHub webhook secure).
        https = next(
            (t.get("public_url") for t in tunnels if isinstance(t, dict)
             and isinstance(t.get("public_url"), str)
             and t["public_url"].startswith("https://")),
            None,
        )
        if https:
            return https
        # Fallback: первый туннель с public_url.
        return next(
            (t.get("public_url") for t in tunnels if isinstance(t, dict)
             and isinstance(t.get("public_url"), str)),
            None,
        )

    tunnel_probe_fn = tunnel_probe or _default_tunnel_probe

    async def _resolve_public_url() -> tuple[Optional[str], Optional[str]]:
        """(`public_url`, `source`) — где source ∈ {'config','ngrok',None}."""
        configured = str(getattr(settings, "public_base_url", "") or "").strip()
        if configured:
            return configured.rstrip("/"), "config"
        url = await tunnel_probe_fn()
        if url:
            return url.rstrip("/"), "ngrok"
        return None, None

    # ------------------------------------------------------------------
    # 1. GET /api/console/budget
    # ------------------------------------------------------------------
    @router.get("/budget", response_model=BudgetOut)
    async def get_budget() -> BudgetOut:
        return _budget_snapshot(budget)

    # ------------------------------------------------------------------
    # 2. GET /api/console/settings
    # ------------------------------------------------------------------
    @router.get("/settings", response_model=SettingsOut)
    async def get_settings_view() -> SettingsOut:
        return _settings_to_out(settings)

    # ------------------------------------------------------------------
    # 3. GET /api/console/checks
    # ------------------------------------------------------------------
    @router.get("/checks", response_model=list[CheckSummaryOut])
    async def list_checks(
        status_: Optional[str] = Query(default=None, alias="status"),
        repo: Optional[str] = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ) -> list[CheckSummaryOut]:
        rows = await state.list_checks(
            status=status_, repo=repo, limit=limit, offset=offset
        )
        return [_record_to_check_summary(r) for r in rows]

    # ------------------------------------------------------------------
    # 4. GET /api/console/checks/{id}
    # ------------------------------------------------------------------
    @router.get("/checks/{check_id}", response_model=CheckDetailsOut)
    async def get_check_details(check_id: str) -> CheckDetailsOut:
        check = await state.get_check(check_id)
        if check is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"detail": "check not found", "code": "CHECK_NOT_FOUND"},
            )
        findings = list(await state.list_findings(check_id))
        # Timeline — synthesized из финального состояния check'и (§13.3.4).
        timeline: list[TimelineEntryOut] = []
        if check.started_at and check.finished_at:
            duration_ms = check.duration_ms or 0
            timeline = [
                TimelineEntryOut(
                    stage="Webhook Accepted",
                    status="success",
                    duration_ms=0,
                    message=f"action={check.action or 'unknown'}",
                ),
                TimelineEntryOut(
                    stage="Diff Filtered",
                    status="success",
                    duration_ms=0,
                    message=(
                        f"{check.files_checked} files to scan, "
                        f"{check.files_skipped} skipped"
                    ),
                ),
                TimelineEntryOut(
                    stage="LLM Analyzed",
                    status=(
                        "success" if check.llm_status in (None, "ok") else "failed"
                    ),
                    duration_ms=duration_ms,
                    message=f"findings={check.findings_count}",
                ),
            ]
        finding_details = [
            FindingDetailOut(
                id=f.id,
                file=f.file,
                line=f.line,
                **{"class": f.class_},
                severity=f.severity,
                confidence=f.confidence,
                message=f.message,
                suggestion=f.suggestion,
                status=f.status,
                code_context=f.code_context,
            )
            for f in findings
        ]
        return CheckDetailsOut(
            id=check.id,
            repository=check.repo,
            pr_number=check.pr_number,
            pr_title=check.pr_title,
            status=check.status,
            llm_provider=check.llm_provider,
            llm_model=check.llm_model,
            cost_rub=check.cost_rub,
            started_at=check.started_at,
            duration_ms=check.duration_ms,
            base_sha=check.base_sha,
            head_sha=check.head_sha,
            action=check.action,
            summary=check.summary,
            timeline=timeline,
            findings=finding_details,
            skipped_files=[],  # MVP §13.3.4 — пустой список (нет таблицы детализации)
        )

    # ------------------------------------------------------------------
    # 5. POST /api/console/manual/analyze
    # ------------------------------------------------------------------
    @router.post("/manual/analyze", response_model=ManualAnalyzeOut)
    async def manual_analyze(payload: dict[str, Any]) -> Any:
        # 1) Pydantic-валидация (camelCase / snake_case оба варианта).
        try:
            request = ManualAnalyzeIn.model_validate(payload)
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

        if manual_analyze_handler is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={
                    "detail": "manual analyze handler not configured",
                    "code": "MANUAL_ANALYZE_UNAVAILABLE",
                },
            )

        t0 = time.monotonic()
        # 2) Проксируем в M-6 `/api/ui/analyze` handler. Контракт response
        # содержит {summary, findings, llm, ...}. Пересобираем в ManualAnalyzeOut.
        ui_payload = {
            "files": [
                {"path": f.path, "code": f.code, "language": f.language}
                for f in request.files
            ]
        }
        ui_resp: Any
        try:
            ui_resp = await manual_analyze_handler(ui_payload)
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001 — изоляция console-роутера
            log.exception("console_manual_analyze_failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "detail": "manual analyze failed",
                    "code": "MANUAL_ANALYZE_ERROR",
                    "error_type": type(exc).__name__,
                },
            ) from exc

        # ui_resp может быть JSONResponse или dict.
        ui_data: dict[str, Any]
        if isinstance(ui_resp, dict):
            ui_data = ui_resp
        elif hasattr(ui_resp, "body"):
            # JSONResponse — распарсим body.
            import json

            try:
                ui_data = json.loads(ui_resp.body.decode("utf-8"))
            except Exception:  # noqa: BLE001
                ui_data = {}
        else:
            ui_data = {}

        summary = str(ui_data.get("summary") or "")
        raw_findings = ui_data.get("findings") or []
        manual_findings: list[ManualFindingOut] = []
        for idx, f in enumerate(raw_findings):
            if not isinstance(f, dict):
                continue
            file_path = str(f.get("file") or (request.files[0].path if request.files else ""))
            code_context = f.get("code_context") or f.get("codeContext")
            if code_context is None:
                # Backend-side вырезание ±5 строк из request (§13.3.5 Architect decision).
                code_context = _extract_code_context(
                    files=request.files, file=file_path, line=int(f.get("line") or 1)
                )
            manual_findings.append(
                ManualFindingOut(
                    severity=str(f.get("severity") or "info"),
                    **{"class": str(f.get("class") or "")},
                    file=file_path,
                    line=int(f.get("line") or 1),
                    message=str(f.get("message") or ""),
                    suggestion=f.get("suggestion"),
                    confidence=f.get("confidence"),
                    code_context=code_context,
                )
            )

        llm_raw = ui_data.get("llm") or {}
        latency_ms = int(llm_raw.get("latency_ms") or (time.monotonic() - t0) * 1000)
        meta = ManualLLMMetaOut(
            status=str(llm_raw.get("status") or "ok"),
            model=str(llm_raw.get("model") or ""),
            cost_rub=float(llm_raw.get("cost_rub") or 0.0),
            latency_ms=latency_ms,
        )
        return ManualAnalyzeOut(
            summary=summary,
            findings=manual_findings,
            llm=meta,
        )

    # ------------------------------------------------------------------
    # 6. GET /api/console/repos
    # ------------------------------------------------------------------
    @router.get("/repos", response_model=list[RepoConfigOut])
    async def list_repos() -> list[RepoConfigOut]:
        rows = list(await state.list_repos())
        return [_record_to_repo_out(r) for r in rows]

    # ------------------------------------------------------------------
    # 7. POST /api/console/repos
    # ------------------------------------------------------------------
    @router.post("/repos", response_model=RepoConfigOut, status_code=201)
    async def create_repo(payload: dict[str, Any]) -> RepoConfigOut:
        try:
            data = RepoConfigIn.model_validate(payload)
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

        full_name = _normalize_full_name(data.full_name)
        _validate_full_name_format(full_name)
        if data.vcs_provider != "github":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=[
                    {
                        "loc": ["body", "vcsProvider"],
                        "msg": "only 'github' supported in MVP",
                        "type": "value_error.enum",
                    }
                ],
            )

        # Существование (UNIQUE constraint preview — лучше 409 чем 500).
        existing = await state.get_repo_by_full_name(full_name)
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": f"Repo with full_name={full_name} already registered",
                    "code": "REPO_DUPLICATE",
                },
            )

        token_ref = vcs_token_ref_name(full_name)
        secret_ref = webhook_secret_ref_name(full_name)

        # Persist секреты (RT-012). НИКАКИХ plaintext в логах!
        if data.vcs_token:
            _persist_secret(
                repos_secrets_path=secrets_path,
                ref=token_ref,
                value=data.vcs_token,
            )
        if data.webhook_secret:
            _persist_secret(
                repos_secrets_path=secrets_path,
                ref=secret_ref,
                value=data.webhook_secret,
            )

        now = datetime.now(timezone.utc)
        record = RepoConfigRecord(
            id=str(uuid.uuid4()),
            full_name=full_name,
            vcs_provider=data.vcs_provider,
            vcs_token_ref=token_ref if data.vcs_token else None,
            webhook_secret_ref=secret_ref if data.webhook_secret else None,
            llm_provider_override=data.llm_provider_override,
            enabled=data.enabled,
            created_at=now,
            updated_at=now,
            last_seen_at=None,
        )

        try:
            saved = await state.upsert_repo(record)
        except StorageConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "detail": str(exc),
                    "code": "REPO_DUPLICATE",
                },
            ) from None
        except StorageError as exc:
            log.exception("console_repo_upsert_failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "detail": "storage error",
                    "code": "STORAGE_ERROR",
                    "error_type": type(exc).__name__,
                },
            ) from None

        log.info(
            "console_repo_created",
            extra={
                "repo": full_name,
                "vcs_token_ref": token_ref if data.vcs_token else None,
                "webhook_secret_ref": secret_ref if data.webhook_secret else None,
                "enabled": data.enabled,
            },
        )
        return _record_to_repo_out(saved)

    # ------------------------------------------------------------------
    # 8. PATCH /api/console/repos/{id}
    # ------------------------------------------------------------------
    @router.patch("/repos/{repo_id}", response_model=RepoConfigOut)
    async def patch_repo(repo_id: str, payload: dict[str, Any]) -> RepoConfigOut:
        try:
            data = RepoConfigPatchIn.model_validate(payload)
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

        existing = await state.get_repo(repo_id)
        if existing is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"detail": "Repo not found", "code": "REPO_NOT_FOUND"},
            )

        token_ref = existing.vcs_token_ref or vcs_token_ref_name(existing.full_name)
        secret_ref = (
            existing.webhook_secret_ref
            or webhook_secret_ref_name(existing.full_name)
        )

        if data.vcs_token:
            _persist_secret(
                repos_secrets_path=secrets_path,
                ref=token_ref,
                value=data.vcs_token,
            )
        if data.webhook_secret:
            _persist_secret(
                repos_secrets_path=secrets_path,
                ref=secret_ref,
                value=data.webhook_secret,
            )

        now = datetime.now(timezone.utc)
        updated = existing.model_copy(
            update={
                "vcs_provider": data.vcs_provider or existing.vcs_provider,
                "vcs_token_ref": token_ref
                if (data.vcs_token or existing.vcs_token_ref)
                else None,
                "webhook_secret_ref": secret_ref
                if (data.webhook_secret or existing.webhook_secret_ref)
                else None,
                "llm_provider_override": (
                    data.llm_provider_override
                    if data.llm_provider_override is not None
                    else existing.llm_provider_override
                ),
                "enabled": (
                    data.enabled if data.enabled is not None else existing.enabled
                ),
                "updated_at": now,
            },
            deep=True,
        )

        try:
            saved = await state.upsert_repo(updated)
        except StorageError as exc:
            log.exception("console_repo_patch_failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "detail": "storage error",
                    "code": "STORAGE_ERROR",
                    "error_type": type(exc).__name__,
                },
            ) from None

        log.info(
            "console_repo_patched",
            extra={
                "repo": existing.full_name,
                "enabled": saved.enabled,
            },
        )
        return _record_to_repo_out(saved)

    # ------------------------------------------------------------------
    # 9. DELETE /api/console/repos/{id}
    # ------------------------------------------------------------------
    @router.delete("/repos/{repo_id}", status_code=204)
    async def delete_repo(repo_id: str) -> Response:
        try:
            removed = await state.delete_repo(repo_id)
        except StorageNotFoundError:
            removed = False
        except StorageError as exc:
            log.exception("console_repo_delete_failed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail={
                    "detail": "storage error",
                    "code": "STORAGE_ERROR",
                    "error_type": type(exc).__name__,
                },
            ) from None
        if not removed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"detail": "Repo not found", "code": "REPO_NOT_FOUND"},
            )
        log.info("console_repo_deleted", extra={"repo_id": repo_id})
        return Response(status_code=204)

    # ------------------------------------------------------------------
    # 9b. GET /api/console/tunnel — detect ngrok / configured public URL
    # ------------------------------------------------------------------
    @router.get("/tunnel", response_model=TunnelOut)
    async def get_tunnel() -> TunnelOut:
        url, source = await _resolve_public_url()
        if url:
            return TunnelOut(running=True, public_url=url, source=source)
        return TunnelOut(running=False, source=None)

    # ------------------------------------------------------------------
    # 9c. POST /api/console/repos/{repo_id}/webhook — install GitHub hook
    # ------------------------------------------------------------------
    @router.post(
        "/repos/{repo_id}/webhook",
        response_model=WebhookInstallOut,
        status_code=201,
    )
    async def install_webhook(repo_id: str, payload: dict[str, Any]) -> WebhookInstallOut:
        try:
            data = WebhookInstallIn.model_validate(payload or {})
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

        rec = await state.get_repo(repo_id)
        if rec is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"detail": "Repo not found", "code": "REPO_NOT_FOUND"},
            )

        # Resolve public URL: либо из payload, либо config, либо ngrok.
        public_url: Optional[str] = None
        url_source: Optional[str] = None
        if data.public_url:
            public_url = data.public_url.rstrip("/")
            url_source = "request"
        else:
            public_url, url_source = await _resolve_public_url()
        if not public_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "detail": (
                        "No public URL available. Start ngrok (`ngrok http 8000`), "
                        "set PUBLIC_BASE_URL in .env, or pass publicUrl in the request body."
                    ),
                    "code": "TUNNEL_UNAVAILABLE",
                },
            )

        webhook_target = f"{public_url}/webhook/github"

        # Достаём plaintext-токен и secret из env-ref'ов.
        token = (
            os.environ.get(rec.vcs_token_ref) if rec.vcs_token_ref else None
        )
        secret = (
            os.environ.get(rec.webhook_secret_ref) if rec.webhook_secret_ref else None
        )
        if not token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "detail": "Repo has no VCS token (env-ref missing). Edit repo and set Token first.",
                    "code": "REPO_TOKEN_MISSING",
                },
            )
        if not secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "detail": "Repo has no webhook secret. Edit repo and set Webhook Secret first.",
                    "code": "REPO_WEBHOOK_SECRET_MISSING",
                },
            )

        # Если уже установлен — пытаемся удалить предыдущий, чтобы не плодить
        # дубли на стороне GitHub (старый URL stale при смене ngrok).
        adapter = gh_factory(token)
        if rec.webhook_id:
            try:
                await adapter.delete_webhook(rec.full_name, int(rec.webhook_id))
                log.info(
                    "console_webhook_replaced_old",
                    extra={
                        "repo": rec.full_name,
                        "old_webhook_id": rec.webhook_id,
                    },
                )
            except Exception as exc:  # noqa: BLE001 — best-effort cleanup
                log.warning(
                    "console_webhook_old_delete_failed",
                    extra={
                        "repo": rec.full_name,
                        "old_webhook_id": rec.webhook_id,
                        "error_type": type(exc).__name__,
                    },
                )

        # Создаём новый webhook на GitHub.
        try:
            hook = await adapter.create_webhook(rec.full_name, webhook_target, secret)
        except Exception as exc:  # noqa: BLE001
            # AuthError / VCSAdapterError / NotFoundError — превращаем в 4xx.
            log.warning(
                "console_webhook_install_failed",
                extra={
                    "repo": rec.full_name,
                    "error_type": type(exc).__name__,
                    "url_source": url_source,
                },
            )
            # 404 от GitHub = repo не существует / нет доступа.
            from sunsec.vcs.base import AuthError, NotFoundError

            if isinstance(exc, NotFoundError):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail={
                        "detail": f"GitHub 404 for repo {rec.full_name}: not found or token lacks access",
                        "code": "GITHUB_REPO_NOT_FOUND",
                    },
                ) from None
            if isinstance(exc, AuthError):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "detail": "GitHub rejected the token. Need admin:repo_hook (or repo) scope.",
                        "code": "GITHUB_AUTH_ERROR",
                    },
                ) from None
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "detail": f"GitHub webhook install failed: {type(exc).__name__}",
                    "code": "GITHUB_API_ERROR",
                },
            ) from None

        hook_id = int(hook.get("id") or 0)
        if not hook_id:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "detail": "GitHub response missing hook id",
                    "code": "GITHUB_API_BAD_RESPONSE",
                },
            )

        await state.set_repo_webhook(
            rec.id, webhook_id=hook_id, webhook_url=webhook_target
        )
        log.info(
            "console_webhook_installed",
            extra={
                "repo": rec.full_name,
                "webhook_id": hook_id,
                "url_source": url_source,
            },
        )
        return WebhookInstallOut(webhook_id=hook_id, webhook_url=webhook_target)

    # ------------------------------------------------------------------
    # 9d. DELETE /api/console/repos/{repo_id}/webhook — remove GitHub hook
    # ------------------------------------------------------------------
    @router.delete("/repos/{repo_id}/webhook", status_code=204)
    async def remove_webhook(repo_id: str) -> Response:
        rec = await state.get_repo(repo_id)
        if rec is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"detail": "Repo not found", "code": "REPO_NOT_FOUND"},
            )
        if not rec.webhook_id:
            # Идемпотентность: ничего не установлено — успех.
            await state.clear_repo_webhook(rec.id)
            return Response(status_code=204)

        token = (
            os.environ.get(rec.vcs_token_ref) if rec.vcs_token_ref else None
        )
        if not token:
            # Без токена не можем дёрнуть GitHub. Чистим только локальную запись.
            await state.clear_repo_webhook(rec.id)
            log.warning(
                "console_webhook_local_only_clear",
                extra={
                    "repo": rec.full_name,
                    "reason": "missing_token",
                },
            )
            return Response(status_code=204)

        adapter = gh_factory(token)
        try:
            await adapter.delete_webhook(rec.full_name, int(rec.webhook_id))
        except Exception as exc:  # noqa: BLE001
            from sunsec.vcs.base import AuthError

            if isinstance(exc, AuthError):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "detail": "GitHub rejected the token while deleting webhook.",
                        "code": "GITHUB_AUTH_ERROR",
                    },
                ) from None
            log.warning(
                "console_webhook_delete_failed",
                extra={
                    "repo": rec.full_name,
                    "webhook_id": rec.webhook_id,
                    "error_type": type(exc).__name__,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail={
                    "detail": f"GitHub webhook delete failed: {type(exc).__name__}",
                    "code": "GITHUB_API_ERROR",
                },
            ) from None

        await state.clear_repo_webhook(rec.id)
        log.info(
            "console_webhook_removed",
            extra={"repo": rec.full_name, "webhook_id": rec.webhook_id},
        )
        return Response(status_code=204)

    # ------------------------------------------------------------------
    # 10. GET /api/console/dashboard
    # ------------------------------------------------------------------
    @router.get("/dashboard", response_model=DashboardOut)
    async def get_dashboard() -> DashboardOut:
        # Recent checks (last 5 ORDER BY started_at DESC).
        try:
            recent_rows = list(await state.list_checks(limit=5, offset=0))
        except StorageError:
            recent_rows = []
        recent_summary = [_record_to_check_summary(r) for r in recent_rows]

        sev = FindingsBySeverityOut()
        cost_total = 0.0
        cost_today = 0.0
        completed = 0
        total = 0
        today = datetime.now(timezone.utc).date()
        for r in recent_summary:
            total += 1
            if r.status == "completed":
                completed += 1
            sev.critical += r.severity_counts.critical
            sev.high += r.severity_counts.high
            sev.medium += r.severity_counts.medium
            sev.low += r.severity_counts.low
            sev.info += r.severity_counts.info
            cost_total += float(r.cost_rub or 0.0)
            if r.started_at and r.started_at.date() == today:
                cost_today += float(r.cost_rub or 0.0)
        success_rate = (completed / total) if total > 0 else 0.0

        try:
            repos = list(await state.list_repos())
            repos_count = sum(1 for r in repos if r.enabled)
        except StorageError:
            repos_count = 0

        return DashboardOut(
            recent_checks=recent_summary,
            findings_by_severity=sev,
            llm_cost_today=round(cost_today, 6),
            llm_cost_total=round(cost_total, 6),
            success_rate=round(success_rate, 4),
            repos_count=repos_count,
        )

    return router


def _extract_code_context(
    *, files: list[Any], file: str, line: int, window: int = 5
) -> Optional[str]:
    """Backend-side вырезание ±`window` строк (system_design §13.3.5)."""
    for f in files:
        if f.path == file:
            lines = (f.code or "").splitlines()
            start = max(0, line - 1 - window)
            end = min(len(lines), line + window)
            return "\n".join(lines[start:end])
    if files:
        # Fallback: первый файл (consistent с MOCK_DATA behaviour).
        lines = (files[0].code or "").splitlines()
        start = max(0, line - 1 - window)
        end = min(len(lines), line + window)
        return "\n".join(lines[start:end])
    return None


__all__ = [
    "build_console_router",
    "slug_for_repo",
    "vcs_token_ref_name",
    "webhook_secret_ref_name",
    "DEFAULT_REPOS_SECRETS_PATH",
]
