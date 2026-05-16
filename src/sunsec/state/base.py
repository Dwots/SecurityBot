"""StateStore Protocol. См. system_design §3.6 + v1.2.1 §11.5.

M-2/M-7 методы (`mark_pr_*`, `seen_delivery`, `get_cached_llm_response` /
`set_cached_llm_response`, `has_posted_finding` / `register_posted_finding`)
— не меняются, цитируются для полноты.

M-9 методы (`save_check`, `update_check_status`, `get_check`, `list_checks`,
`save_findings`, `list_findings`, `save_comments`, `list_comments`,
`list_repos`, `get_repo`, `get_repo_by_full_name`, `upsert_repo`,
`delete_repo`, `touch_repo_seen`) — durable layer (см. system_design
v1.2.1 §11). `InMemoryStateStore` поднимает их на in-memory dicts для
unit-/integration-тестов; `SQLiteStateStore` — реальная durable
реализация.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional, Protocol, Sequence

from sunsec.contracts import LLMResponseSchema
from sunsec.contracts.storage import (
    CheckRecord,
    CommentRecord,
    FindingRecord,
    RepoConfigRecord,
)


class StateStore(Protocol):
    # --- Existing (M-2/M-7) — НЕ менять ---
    async def mark_pr_in_progress(self, key: str, ttl: int = 86400) -> bool: ...
    async def mark_pr_done(self, key: str) -> None: ...
    async def mark_pr_failed(self, key: str) -> None: ...
    async def seen_delivery(self, delivery_id: str) -> bool: ...
    async def get_cached_llm_response(
        self, cache_key: str
    ) -> Optional[LLMResponseSchema]: ...
    async def set_cached_llm_response(
        self, cache_key: str, response: LLMResponseSchema
    ) -> None: ...
    async def has_posted_finding(
        self, repo: str, pr_number: int, finding_hash: str
    ) -> bool: ...
    async def register_posted_finding(
        self, repo: str, pr_number: int, finding_hash: str
    ) -> None: ...

    # --- New in M-9 (system_design v1.2.1 §11.5) ---

    # checks lifecycle
    async def save_check(self, check: CheckRecord) -> None: ...

    async def update_check_status(
        self,
        check_id: str,
        *,
        status: Optional[str] = None,
        llm_status: Optional[str] = None,
        llm_provider: Optional[str] = None,
        llm_model: Optional[str] = None,
        files_checked: Optional[int] = None,
        files_skipped: Optional[int] = None,
        findings_count: Optional[int] = None,
        cost_rub: Optional[float] = None,
        summary: Optional[str] = None,
        severity_counts: Optional[dict[str, int]] = None,
        finished_at: Optional[datetime] = None,
        duration_ms: Optional[int] = None,
    ) -> None: ...

    async def get_check(self, check_id: str) -> Optional[CheckRecord]: ...

    async def list_checks(
        self,
        *,
        status: Optional[str] = None,
        repo: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Sequence[CheckRecord]: ...

    # findings batch
    async def save_findings(
        self, check_id: str, findings: Sequence[FindingRecord]
    ) -> None: ...

    async def list_findings(self, check_id: str) -> Sequence[FindingRecord]: ...

    # comments audit
    async def save_comments(
        self, check_id: str, comments: Sequence[CommentRecord]
    ) -> None: ...

    async def list_comments(self, check_id: str) -> Sequence[CommentRecord]: ...

    # repo registry
    async def list_repos(self) -> Sequence[RepoConfigRecord]: ...

    async def get_repo(self, repo_id: str) -> Optional[RepoConfigRecord]: ...

    async def get_repo_by_full_name(
        self, full_name: str
    ) -> Optional[RepoConfigRecord]: ...

    async def upsert_repo(self, repo: RepoConfigRecord) -> RepoConfigRecord: ...

    async def delete_repo(self, repo_id: str) -> bool: ...

    async def touch_repo_seen(self, full_name: str) -> None: ...
