"""Pydantic-контракты Console UI HTTP API (T-039).

Источник истины — `system_design.md v1.2.1 §13.3 / §13.4`.

Все модели — Pydantic v2 BaseModel с `model_config =
ConfigDict(alias_generator=to_camel, populate_by_name=True)` — на проводе
camelCase (минимизация переделки `tmp/front.html`), внутри Python — snake_case.

Безопасность: ни одна *Out-модель НЕ содержит plaintext-секретов.
`RepoConfigOut` — только `*_ref` имена env-переменных; `SettingsOut` —
explicit allow-list по `system_design §13.5`.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field
from pydantic.alias_generators import to_camel


class _ConsoleBase(BaseModel):
    """Базовый класс для всех console-контрактов.

    `alias_generator=to_camel` + `populate_by_name=True` — модель принимает
    оба варианта (`fullName` / `full_name`) на входе и сериализует камелями
    на выход. `from_attributes=True` — чтобы можно было собирать из ORM/
    dataclass-like объектов (Pydantic v2 равноценно `from_orm`).
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


# ---------------------------------------------------------------------------
# §13.3.1 GET /api/console/budget
# ---------------------------------------------------------------------------


class BudgetOut(_ConsoleBase):
    """Снимок LLM-бюджета (BudgetCounter, ADR-2 / §3.4 / §3.6)."""

    spent_rub: float
    limit_rub: float
    remaining_rub: float
    limit_percent: float
    calls_count: int


# ---------------------------------------------------------------------------
# §13.3.2 GET /api/console/settings
# ---------------------------------------------------------------------------


class SettingsOut(_ConsoleBase):
    """Read-only снимок Settings БЕЗ секретов.

    Explicit allow-list (§13.5): любое поле `Settings`, имя которого
    содержит `_api_key` / `_token` / `_secret` / `_password` — в эту
    модель НЕ попадает (даже если завтра вырастет `Settings`).
    """

    app_env: str
    vcs_provider: str
    github_api_base: str
    llm_provider: str
    model: str
    temperature: float
    max_tokens: int
    timeout_seconds: int
    max_retries: int
    budget_limit_rub: float
    publish_comments_enabled: bool
    skip_drafts: bool
    state_store_backend: str
    fp_min_confidence: float
    filter_exclude_extensions: list[str]
    filter_exclude_names: list[str]
    filter_exclude_globs: list[str]
    enable_console_ui: bool


# ---------------------------------------------------------------------------
# §13.3.3 GET /api/console/checks
# ---------------------------------------------------------------------------


class SeverityCountsOut(_ConsoleBase):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class CheckSummaryOut(_ConsoleBase):
    """Один элемент списка истории проверок (`MOCK_DATA.checks[*]`)."""

    id: str
    repository: str
    pr_number: int
    pr_title: Optional[str] = None
    author: Optional[str] = None
    source_branch: Optional[str] = None
    target_branch: Optional[str] = None
    head_sha: Optional[str] = None
    base_sha: Optional[str] = None
    action: Optional[str] = None
    status: str
    llm_status: Optional[str] = None
    started_at: datetime
    duration_ms: Optional[int] = None
    files_checked: int = 0
    files_skipped: int = 0
    findings_count: int = 0
    severity_counts: SeverityCountsOut = Field(default_factory=SeverityCountsOut)
    pr_url: Optional[str] = None
    cost_rub: float = 0.0


# ---------------------------------------------------------------------------
# §13.3.4 GET /api/console/checks/{id}
# ---------------------------------------------------------------------------


class TimelineEntryOut(_ConsoleBase):
    stage: str
    status: str
    duration_ms: int
    message: Optional[str] = None


class FindingDetailOut(_ConsoleBase):
    """Finding с alias `class_` → `class` (внешний JSON — `class`)."""

    id: str
    file: str
    line: int
    class_: str = Field(alias="class")
    severity: str
    confidence: Optional[float] = None
    message: str
    suggestion: Optional[str] = None
    status: str
    code_context: Optional[str] = None


class SkippedFileOut(_ConsoleBase):
    path: str
    reason: str
    detail: Optional[str] = None


class CheckDetailsOut(_ConsoleBase):
    id: str
    repository: str
    pr_number: int
    pr_title: Optional[str] = None
    status: str
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    cost_rub: float = 0.0
    started_at: datetime
    duration_ms: Optional[int] = None
    base_sha: Optional[str] = None
    head_sha: Optional[str] = None
    action: Optional[str] = None
    summary: Optional[str] = None
    timeline: list[TimelineEntryOut] = Field(default_factory=list)
    findings: list[FindingDetailOut] = Field(default_factory=list)
    skipped_files: list[SkippedFileOut] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# §13.3.5 POST /api/console/manual/analyze
# ---------------------------------------------------------------------------


class ManualFileIn(_ConsoleBase):
    path: str = Field(..., min_length=1, max_length=512)
    code: str = Field(default="")
    language: Optional[str] = Field(default=None, max_length=64)


class ManualAnalyzeIn(_ConsoleBase):
    files: list[ManualFileIn] = Field(..., min_length=1, max_length=50)


class ManualFindingOut(_ConsoleBase):
    severity: str
    class_: str = Field(alias="class")
    file: str
    line: int
    message: str
    suggestion: Optional[str] = None
    confidence: Optional[float] = None
    code_context: Optional[str] = None


class ManualLLMMetaOut(_ConsoleBase):
    status: str
    model: str
    cost_rub: float
    latency_ms: int


class ManualAnalyzeOut(_ConsoleBase):
    summary: str
    findings: list[ManualFindingOut]
    llm: ManualLLMMetaOut


# ---------------------------------------------------------------------------
# §13.3.6 GET /api/console/dashboard (опциональный)
# ---------------------------------------------------------------------------


class FindingsBySeverityOut(_ConsoleBase):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class DashboardOut(_ConsoleBase):
    recent_checks: list[CheckSummaryOut] = Field(default_factory=list)
    findings_by_severity: FindingsBySeverityOut = Field(
        default_factory=FindingsBySeverityOut
    )
    llm_cost_today: float = 0.0
    llm_cost_total: float = 0.0
    success_rate: float = 0.0
    repos_count: int = 0


# ---------------------------------------------------------------------------
# §13.4 CRUD /api/console/repos
# ---------------------------------------------------------------------------


class RepoConfigIn(_ConsoleBase):
    """POST body. `vcs_token` / `webhook_secret` — write-only; в response не возвращаются."""

    full_name: str = Field(..., min_length=3, max_length=200)
    vcs_provider: str = "github"
    vcs_token: Optional[str] = Field(default=None, repr=False)
    webhook_secret: Optional[str] = Field(default=None, repr=False)
    llm_provider_override: Optional[str] = None
    enabled: bool = True


class RepoConfigPatchIn(_ConsoleBase):
    """PATCH body — все поля Optional."""

    vcs_provider: Optional[str] = None
    vcs_token: Optional[str] = Field(default=None, repr=False)
    webhook_secret: Optional[str] = Field(default=None, repr=False)
    llm_provider_override: Optional[str] = None
    enabled: Optional[bool] = None


class RepoConfigOut(_ConsoleBase):
    """GET/POST/PATCH response. БЕЗ plaintext-секретов — только `*_ref`-имена."""

    id: str
    full_name: str
    vcs_provider: str
    vcs_token_ref: Optional[str] = None
    webhook_secret_ref: Optional[str] = None
    vcs_token_set: bool = False
    webhook_secret_set: bool = False
    llm_provider_override: Optional[str] = None
    enabled: bool
    created_at: datetime
    updated_at: datetime
    last_seen_at: Optional[datetime] = None
    # M-9+: GitHub webhook auto-install (Console UI). NULL пока не установлен.
    webhook_id: Optional[int] = None
    webhook_url: Optional[str] = None


class TunnelOut(_ConsoleBase):
    """`GET /api/console/tunnel` — статус публичного туннеля.

    Используется UI для авто-подстановки Payload URL при установке
    webhook. Источник — либо `Settings.public_base_url` (если задан),
    либо ngrok admin API.
    """

    running: bool = False
    public_url: Optional[str] = None
    source: Optional[str] = None  # 'config' | 'ngrok' | None
    error: Optional[str] = None


class WebhookInstallIn(_ConsoleBase):
    """`POST /api/console/repos/{id}/webhook` — body."""

    # Если не передано, сервер возьмёт текущий туннель (config / ngrok).
    public_url: Optional[str] = None


class WebhookInstallOut(_ConsoleBase):
    """`POST /api/console/repos/{id}/webhook` — response."""

    webhook_id: int
    webhook_url: str


__all__ = [
    "BudgetOut",
    "SettingsOut",
    "SeverityCountsOut",
    "CheckSummaryOut",
    "TimelineEntryOut",
    "FindingDetailOut",
    "SkippedFileOut",
    "CheckDetailsOut",
    "ManualFileIn",
    "ManualAnalyzeIn",
    "ManualFindingOut",
    "ManualLLMMetaOut",
    "ManualAnalyzeOut",
    "FindingsBySeverityOut",
    "DashboardOut",
    "TunnelOut",
    "WebhookInstallIn",
    "WebhookInstallOut",
    "RepoConfigIn",
    "RepoConfigPatchIn",
    "RepoConfigOut",
]
