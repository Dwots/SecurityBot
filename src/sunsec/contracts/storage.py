"""Pydantic-модели persistence-слоя (system_design v1.2.1 §11.5).

Контракты `CheckRecord` / `FindingRecord` / `CommentRecord` / `RepoConfigRecord`
— единственный язык, на котором pipeline / HTTP-router общаются со
`StateStore`-методами `save_check` / `save_findings` / `save_comments` /
`upsert_repo`.

DDL для соответствующих SQL-таблиц — `sunsec.storage.schema`.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


_SEVERITY_DEFAULT: dict[str, int] = {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
}


class CheckRecord(BaseModel):
    """Запись `checks` (системный design §11.3.1).

    Поле `severity_counts` — словарь `{critical/high/medium/low/info → int}`,
    в БД хранится в денормализованных колонках `severity_counts_*`.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    repo: str
    pr_number: int
    pr_title: Optional[str] = None
    author: Optional[str] = None
    source_branch: Optional[str] = None
    target_branch: Optional[str] = None
    head_sha: str
    base_sha: Optional[str] = None
    action: Optional[str] = None
    status: str
    llm_status: Optional[str] = None
    llm_provider: Optional[str] = None
    llm_model: Optional[str] = None
    started_at: datetime
    finished_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    files_checked: int = 0
    files_skipped: int = 0
    findings_count: int = 0
    cost_rub: float = 0.0
    pr_url: Optional[str] = None
    summary: Optional[str] = None
    severity_counts: dict[str, int] = Field(
        default_factory=lambda: dict(_SEVERITY_DEFAULT)
    )


class FindingRecord(BaseModel):
    """Запись `findings` (§11.3.2). `class_` — alias на SQL-колонку `class`."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    id: str
    check_id: str
    file: str
    line: int
    class_: str = Field(alias="class")
    severity: str
    confidence: Optional[float] = None
    message: str
    suggestion: Optional[str] = None
    status: str = "pending"
    code_context: Optional[str] = None


class CommentRecord(BaseModel):
    """Запись `comments` (§11.3.3)."""

    model_config = ConfigDict(extra="ignore")

    id: str
    check_id: str
    finding_id: Optional[str] = None
    kind: str
    marker: Optional[str] = None
    posted_at: datetime
    vcs_comment_id: Optional[str] = None
    vcs_url: Optional[str] = None
    body_excerpt: Optional[str] = None


class RepoConfigRecord(BaseModel):
    """Запись `repo_configs` (§11.3.4).

    Внимание: ни `vcs_token`, ни `webhook_secret` в plaintext в эту модель
    не попадают — только `*_ref` имена env-переменных (см. §11.4).
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    full_name: str
    vcs_provider: str = "github"
    vcs_token_ref: Optional[str] = None
    webhook_secret_ref: Optional[str] = None
    llm_provider_override: Optional[str] = None
    enabled: bool = True
    created_at: datetime
    updated_at: datetime
    last_seen_at: Optional[datetime] = None


__all__ = [
    "CheckRecord",
    "FindingRecord",
    "CommentRecord",
    "RepoConfigRecord",
]
