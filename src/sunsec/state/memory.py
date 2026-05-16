"""InMemoryStateStore — RAM-реализация StateStore для MVP (ADR-3).

M-2/M-7 поведение (`mark_pr_in_progress` / `mark_pr_done` /
`mark_pr_failed` / `seen_delivery` / `get_cached_llm_response` /
`set_cached_llm_response` / `has_posted_finding` /
`register_posted_finding`) — без изменений.

M-9 расширение (system_design v1.2.1 §11.5): новые методы
(`save_check` / `update_check_status` / `save_findings` /
`save_comments` / `get_check` / `list_*` / `*_repo*`) поднимаются как
in-memory dicts. Логика упрощённая (без CASCADE / транзакций /
UNIQUE-enforcement за пределами `full_name`) — этого достаточно для
unit-тестов / regression-сценариев, где БД явно не нужна. В production
durable-режиме используется `SQLiteStateStore`.
"""
from __future__ import annotations

import asyncio
import copy
from datetime import datetime
from typing import Optional, Sequence

from sunsec.contracts import LLMResponseSchema
from sunsec.contracts.storage import (
    CheckRecord,
    CommentRecord,
    FindingRecord,
    RepoConfigRecord,
)

_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 5)


class InMemoryStateStore:
    """Минимальная in-memory реализация StateStore.

    Все мутации защищены asyncio.Lock'ом — webhook-handler async, разные PR
    могут приходить параллельно. Lock дешёвый, гарантирует, что
    `mark_pr_in_progress` атомарен (check-and-set).
    """

    def __init__(self) -> None:
        self._inprogress: set[str] = set()
        self._done: set[str] = set()
        self._llm_cache: dict[str, LLMResponseSchema] = {}
        self._posted: set[tuple[str, int, str]] = set()
        # T-007: delivery-id дедупликация (GitHub `X-GitHub-Delivery` UUID).
        self._seen_deliveries: set[str] = set()
        # M-9: durable-shape данные (хранятся in-memory).
        self._checks: dict[str, CheckRecord] = {}
        self._findings: dict[str, list[FindingRecord]] = {}
        self._comments: dict[str, list[CommentRecord]] = {}
        self._repos: dict[str, RepoConfigRecord] = {}  # PK → record
        self._repos_by_full_name: dict[str, str] = {}  # full_name → PK
        self._lock = asyncio.Lock()

    # --- PR idempotency (по head_sha-ключу) -------------------------------

    async def mark_pr_in_progress(self, key: str, ttl: int = 86400) -> bool:
        """Атомарный check-and-set: True если зарезервировали, False если уже занят.

        Args:
            key: `idempotency_key(event)` — `f"{repo}#{pr}@{head_sha}"`.
            ttl: TTL в секундах (в MVP игнорируется, см. ADR-3).
        Returns:
            True — ключ был свободен, текущий вызов «взял» его.
            False — ключ уже in-progress либо done; повторный анализ не нужен.
        """
        async with self._lock:
            if key in self._inprogress or key in self._done:
                return False
            self._inprogress.add(key)
            return True

    async def mark_pr_done(self, key: str) -> None:
        async with self._lock:
            self._inprogress.discard(key)
            self._done.add(key)

    async def mark_pr_failed(self, key: str) -> None:
        """Снимает резервацию, но НЕ помечает done — повторная доставка попробует снова."""
        async with self._lock:
            self._inprogress.discard(key)

    # --- Delivery-id idempotency (T-007) ---------------------------------

    async def seen_delivery(self, delivery_id: str) -> bool:
        """Атомарный check-and-set по `X-GitHub-Delivery` UUID.

        Returns:
            True — этот delivery_id уже видели (повторная доставка).
            False — первая встреча, регистрируем.
        """
        if not delivery_id:
            # Если GitHub не прислал заголовок — fall through на head_sha-ключ.
            return False
        async with self._lock:
            if delivery_id in self._seen_deliveries:
                return True
            self._seen_deliveries.add(delivery_id)
            return False

    # --- LLM кэш (для T-012) ---------------------------------------------

    async def get_cached_llm_response(self, cache_key: str) -> Optional[LLMResponseSchema]:
        async with self._lock:
            return self._llm_cache.get(cache_key)

    async def set_cached_llm_response(self, cache_key: str, response: LLMResponseSchema) -> None:
        async with self._lock:
            self._llm_cache[cache_key] = response

    # --- Дедупликация публикаций (для T-016) -----------------------------

    async def has_posted_finding(self, repo: str, pr_number: int, finding_hash: str) -> bool:
        async with self._lock:
            return (repo, pr_number, finding_hash) in self._posted

    async def register_posted_finding(self, repo: str, pr_number: int, finding_hash: str) -> None:
        async with self._lock:
            self._posted.add((repo, pr_number, finding_hash))

    # --- Тестовая утилита ------------------------------------------------

    def reset(self) -> None:
        """Сброс всего состояния (для unit-тестов)."""
        self._inprogress.clear()
        self._done.clear()
        self._llm_cache.clear()
        self._posted.clear()
        self._seen_deliveries.clear()
        self._checks.clear()
        self._findings.clear()
        self._comments.clear()
        self._repos.clear()
        self._repos_by_full_name.clear()

    # =====================================================================
    # M-9: durable-shape методы (in-memory bookkeeping, см. system_design §11.5)
    # =====================================================================

    async def save_check(self, check: CheckRecord) -> None:
        async with self._lock:
            self._checks[check.id] = check.model_copy(deep=True)

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
    ) -> None:
        async with self._lock:
            cur = self._checks.get(check_id)
            if cur is None:
                return  # no-op; SQLite drop-and-ignore поведение
            patch: dict = {}
            if status is not None:
                patch["status"] = status
            if llm_status is not None:
                patch["llm_status"] = llm_status
            if llm_provider is not None:
                patch["llm_provider"] = llm_provider
            if llm_model is not None:
                patch["llm_model"] = llm_model
            if files_checked is not None:
                patch["files_checked"] = int(files_checked)
            if files_skipped is not None:
                patch["files_skipped"] = int(files_skipped)
            if findings_count is not None:
                patch["findings_count"] = int(findings_count)
            if cost_rub is not None:
                patch["cost_rub"] = float(cost_rub)
            if summary is not None:
                patch["summary"] = summary
            if finished_at is not None:
                patch["finished_at"] = finished_at
            if duration_ms is not None:
                patch["duration_ms"] = int(duration_ms)
            if severity_counts is not None:
                merged = dict(cur.severity_counts or {})
                for k in _SEVERITY_KEYS:
                    if k in severity_counts:
                        merged[k] = int(severity_counts[k] or 0)
                patch["severity_counts"] = merged
            self._checks[check_id] = cur.model_copy(update=patch, deep=True)

    async def get_check(self, check_id: str) -> Optional[CheckRecord]:
        async with self._lock:
            rec = self._checks.get(check_id)
            return rec.model_copy(deep=True) if rec is not None else None

    async def list_checks(
        self,
        *,
        status: Optional[str] = None,
        repo: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CheckRecord]:
        async with self._lock:
            items = list(self._checks.values())
        if status is not None:
            items = [c for c in items if c.status == status]
        if repo is not None:
            items = [c for c in items if c.repo == repo]
        items.sort(key=lambda c: c.started_at, reverse=True)
        return [c.model_copy(deep=True) for c in items[offset : offset + limit]]

    async def save_findings(
        self, check_id: str, findings: Sequence[FindingRecord]
    ) -> None:
        if not findings:
            return
        async with self._lock:
            bucket = self._findings.setdefault(check_id, [])
            for f in findings:
                bucket.append(f.model_copy(deep=True))

    async def list_findings(self, check_id: str) -> list[FindingRecord]:
        async with self._lock:
            items = list(self._findings.get(check_id, []))
        items.sort(key=lambda f: (_severity_rank(f.severity), f.file, f.line))
        return [f.model_copy(deep=True) for f in items]

    async def save_comments(
        self, check_id: str, comments: Sequence[CommentRecord]
    ) -> None:
        if not comments:
            return
        async with self._lock:
            bucket = self._comments.setdefault(check_id, [])
            for c in comments:
                bucket.append(c.model_copy(deep=True))

    async def list_comments(self, check_id: str) -> list[CommentRecord]:
        async with self._lock:
            items = list(self._comments.get(check_id, []))
        items.sort(key=lambda c: c.posted_at)
        return [c.model_copy(deep=True) for c in items]

    async def list_repos(self) -> list[RepoConfigRecord]:
        async with self._lock:
            items = list(self._repos.values())
        items.sort(key=lambda r: r.full_name)
        return [r.model_copy(deep=True) for r in items]

    async def get_repo(self, repo_id: str) -> Optional[RepoConfigRecord]:
        async with self._lock:
            rec = self._repos.get(repo_id)
            return rec.model_copy(deep=True) if rec is not None else None

    async def get_repo_by_full_name(
        self, full_name: str
    ) -> Optional[RepoConfigRecord]:
        async with self._lock:
            pk = self._repos_by_full_name.get(full_name)
            if pk is None:
                return None
            rec = self._repos.get(pk)
            return rec.model_copy(deep=True) if rec is not None else None

    async def upsert_repo(self, repo: RepoConfigRecord) -> RepoConfigRecord:
        async with self._lock:
            existing_pk = self._repos_by_full_name.get(repo.full_name)
            if existing_pk is not None and existing_pk != repo.id:
                # Маппим под существующий PK, чтобы full_name остался уникальным.
                stored = repo.model_copy(update={"id": existing_pk}, deep=True)
            else:
                stored = repo.model_copy(deep=True)
            self._repos[stored.id] = stored
            self._repos_by_full_name[stored.full_name] = stored.id
            return stored.model_copy(deep=True)

    async def delete_repo(self, repo_id: str) -> bool:
        async with self._lock:
            rec = self._repos.pop(repo_id, None)
            if rec is None:
                return False
            self._repos_by_full_name.pop(rec.full_name, None)
            return True

    async def touch_repo_seen(self, full_name: str) -> None:
        async with self._lock:
            pk = self._repos_by_full_name.get(full_name)
            if pk is None:
                return
            cur = self._repos.get(pk)
            if cur is None:
                return
            self._repos[pk] = cur.model_copy(
                update={"last_seen_at": datetime.utcnow()}, deep=True
            )
