"""SQLiteStateStore — durable реализация `StateStore` (system_design v1.2.1 §11).

Используется как primary state-store при `SUNSEC_DB_PATH=./data/sunsec.db`
(не `:memory:`). Под капотом — `aiosqlite` с per-request connections
(§11.6). Все мутации — параметризованные запросы, никаких f-string в SQL.

Существующие 8 методов M-2/M-7 (`mark_pr_in_progress`, `mark_pr_done`,
`mark_pr_failed`, `seen_delivery`, `get_cached_llm_response`,
`set_cached_llm_response`, `has_posted_finding`, `register_posted_finding`)
делегируются `InMemoryStateStore`-под-капотом — они не нуждаются в
durability (рестарт = сброс кэшей, ADR-3 остаётся в силе).

Новые 11 методов M-9 — durable INSERT/UPDATE/SELECT в SQLite.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Optional, Sequence

import aiosqlite

from sunsec.contracts import LLMResponseSchema
from sunsec.contracts.storage import (
    CheckRecord,
    CommentRecord,
    FindingRecord,
    RepoConfigRecord,
)
from sunsec.state.memory import InMemoryStateStore
from sunsec.storage.errors import StorageConflictError, StorageError

log = logging.getLogger(__name__)


_SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")


def _row_to_check(row: aiosqlite.Row) -> CheckRecord:
    d = dict(row)
    severity_counts = {
        k: int(d.get(f"severity_counts_{k}") or 0) for k in _SEVERITY_KEYS
    }
    return CheckRecord(
        id=d["id"],
        repo=d["repo"],
        pr_number=int(d["pr_number"]),
        pr_title=d.get("pr_title"),
        author=d.get("author"),
        source_branch=d.get("source_branch"),
        target_branch=d.get("target_branch"),
        head_sha=d["head_sha"],
        base_sha=d.get("base_sha"),
        action=d.get("action"),
        status=d["status"],
        llm_status=d.get("llm_status"),
        llm_provider=d.get("llm_provider"),
        llm_model=d.get("llm_model"),
        started_at=_parse_dt(d["started_at"]),
        finished_at=_parse_dt(d.get("finished_at")),
        duration_ms=(int(d["duration_ms"]) if d.get("duration_ms") is not None else None),
        files_checked=int(d.get("files_checked") or 0),
        files_skipped=int(d.get("files_skipped") or 0),
        findings_count=int(d.get("findings_count") or 0),
        cost_rub=float(d.get("cost_rub") or 0.0),
        pr_url=d.get("pr_url"),
        summary=d.get("summary"),
        severity_counts=severity_counts,
    )


def _row_to_finding(row: aiosqlite.Row) -> FindingRecord:
    d = dict(row)
    return FindingRecord(
        id=d["id"],
        check_id=d["check_id"],
        file=d["file"],
        line=int(d["line"]),
        **{"class": d["class"]},
        severity=d["severity"],
        confidence=(float(d["confidence"]) if d.get("confidence") is not None else None),
        message=d["message"],
        suggestion=d.get("suggestion"),
        status=d.get("status") or "pending",
        code_context=d.get("code_context"),
    )


def _row_to_comment(row: aiosqlite.Row) -> CommentRecord:
    d = dict(row)
    return CommentRecord(
        id=d["id"],
        check_id=d["check_id"],
        finding_id=d.get("finding_id"),
        kind=d["kind"],
        marker=d.get("marker"),
        posted_at=_parse_dt(d["posted_at"]),
        vcs_comment_id=d.get("vcs_comment_id"),
        vcs_url=d.get("vcs_url"),
        body_excerpt=d.get("body_excerpt"),
    )


def _row_to_repo(row: aiosqlite.Row) -> RepoConfigRecord:
    d = dict(row)
    wh_id_raw = d.get("webhook_id")
    return RepoConfigRecord(
        id=d["id"],
        full_name=d["full_name"],
        vcs_provider=d.get("vcs_provider") or "github",
        vcs_token_ref=d.get("vcs_token_ref"),
        webhook_secret_ref=d.get("webhook_secret_ref"),
        llm_provider_override=d.get("llm_provider_override"),
        enabled=bool(d.get("enabled", 1)),
        created_at=_parse_dt(d["created_at"]),
        updated_at=_parse_dt(d["updated_at"]),
        last_seen_at=_parse_dt(d.get("last_seen_at")),
        webhook_id=(int(wh_id_raw) if wh_id_raw is not None else None),
        webhook_url=d.get("webhook_url"),
    )


def _parse_dt(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        # SQLite ISO-формат
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return value
    return value


def _fmt_dt(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.isoformat()


class SQLiteStateStore:
    """Durable `StateStore`.

    Жизненный цикл соединения — per-request (`async with aiosqlite.connect`),
    см. system_design §11.6. Все SQL-запросы параметризованы (`?`).

    Существующие 8 методов M-2/M-7 делегируются `InMemoryStateStore` — они
    не durable (ADR-3 in-memory остаётся в силе для idempotency / LLM-cache /
    posted-finding registry).
    """

    def __init__(self, db_path: str) -> None:
        if not db_path:
            raise ValueError("db_path must be non-empty")
        self._db_path = db_path
        # Существующие методы M-2/M-7 — in-memory, не трогаем БД.
        self._memory = InMemoryStateStore()

    def __repr__(self) -> str:
        # БЕЗ потенциально-чувствительного пути (см. T-038 п.9 безопасность).
        return f"SQLiteStateStore(db_path_set=True)"

    @property
    def db_path(self) -> str:
        return self._db_path

    # ---------------------------------------------------------------------
    # Existing M-2/M-7 methods — делегируются in-memory backend'у
    # ---------------------------------------------------------------------

    async def mark_pr_in_progress(self, key: str, ttl: int = 86400) -> bool:
        return await self._memory.mark_pr_in_progress(key, ttl)

    async def mark_pr_done(self, key: str) -> None:
        await self._memory.mark_pr_done(key)

    async def mark_pr_failed(self, key: str) -> None:
        await self._memory.mark_pr_failed(key)

    async def seen_delivery(self, delivery_id: str) -> bool:
        return await self._memory.seen_delivery(delivery_id)

    async def get_cached_llm_response(self, cache_key: str) -> Optional[LLMResponseSchema]:
        return await self._memory.get_cached_llm_response(cache_key)

    async def set_cached_llm_response(
        self, cache_key: str, response: LLMResponseSchema
    ) -> None:
        await self._memory.set_cached_llm_response(cache_key, response)

    async def has_posted_finding(
        self, repo: str, pr_number: int, finding_hash: str
    ) -> bool:
        return await self._memory.has_posted_finding(repo, pr_number, finding_hash)

    async def register_posted_finding(
        self, repo: str, pr_number: int, finding_hash: str
    ) -> None:
        await self._memory.register_posted_finding(repo, pr_number, finding_hash)

    # ---------------------------------------------------------------------
    # New M-9 methods — durable SQLite
    # ---------------------------------------------------------------------

    async def save_check(self, check: CheckRecord) -> None:
        sc = check.severity_counts or {}
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("PRAGMA foreign_keys=ON")
            await db.execute(
                """
                INSERT OR REPLACE INTO checks (
                    id, repo, pr_number, pr_title, author,
                    source_branch, target_branch, head_sha, base_sha, action,
                    status, llm_status, llm_provider, llm_model,
                    started_at, finished_at, duration_ms,
                    files_checked, files_skipped, findings_count, cost_rub,
                    pr_url, summary,
                    severity_counts_critical, severity_counts_high,
                    severity_counts_medium, severity_counts_low,
                    severity_counts_info
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    check.id,
                    check.repo,
                    check.pr_number,
                    check.pr_title,
                    check.author,
                    check.source_branch,
                    check.target_branch,
                    check.head_sha,
                    check.base_sha,
                    check.action,
                    check.status,
                    check.llm_status,
                    check.llm_provider,
                    check.llm_model,
                    _fmt_dt(check.started_at),
                    _fmt_dt(check.finished_at),
                    check.duration_ms,
                    check.files_checked,
                    check.files_skipped,
                    check.findings_count,
                    check.cost_rub,
                    check.pr_url,
                    check.summary,
                    int(sc.get("critical", 0) or 0),
                    int(sc.get("high", 0) or 0),
                    int(sc.get("medium", 0) or 0),
                    int(sc.get("low", 0) or 0),
                    int(sc.get("info", 0) or 0),
                ),
            )
            await db.commit()

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
        fields: list[str] = []
        values: list[Any] = []

        def add(col: str, val: Any) -> None:
            fields.append(f"{col}=?")
            values.append(val)

        if status is not None:
            add("status", status)
        if llm_status is not None:
            add("llm_status", llm_status)
        if llm_provider is not None:
            add("llm_provider", llm_provider)
        if llm_model is not None:
            add("llm_model", llm_model)
        if files_checked is not None:
            add("files_checked", int(files_checked))
        if files_skipped is not None:
            add("files_skipped", int(files_skipped))
        if findings_count is not None:
            add("findings_count", int(findings_count))
        if cost_rub is not None:
            add("cost_rub", float(cost_rub))
        if summary is not None:
            add("summary", summary)
        if finished_at is not None:
            add("finished_at", _fmt_dt(finished_at))
        if duration_ms is not None:
            add("duration_ms", int(duration_ms))
        if severity_counts is not None:
            for key in _SEVERITY_KEYS:
                if key in severity_counts:
                    add(f"severity_counts_{key}", int(severity_counts[key] or 0))

        if not fields:
            return  # ничего не передали — no-op

        values.append(check_id)
        sql = f"UPDATE checks SET {', '.join(fields)} WHERE id=?"
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(sql, tuple(values))
            await db.commit()

    async def get_check(self, check_id: str) -> Optional[CheckRecord]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM checks WHERE id=?", (check_id,)
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                return None
            return _row_to_check(row)

    async def list_checks(
        self,
        *,
        status: Optional[str] = None,
        repo: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[CheckRecord]:
        clauses: list[str] = []
        values: list[Any] = []
        if status is not None:
            clauses.append("status=?")
            values.append(status)
        if repo is not None:
            clauses.append("repo=?")
            values.append(repo)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"SELECT * FROM checks {where} "
            f"ORDER BY started_at DESC LIMIT ? OFFSET ?"
        )
        values.extend([int(limit), int(offset)])
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, tuple(values))
            rows = await cursor.fetchall()
            await cursor.close()
        return [_row_to_check(r) for r in rows]

    async def save_findings(
        self, check_id: str, findings: Sequence[FindingRecord]
    ) -> None:
        if not findings:
            return
        rows = [
            (
                f.id,
                check_id,
                f.file,
                int(f.line),
                f.class_,
                f.severity,
                (float(f.confidence) if f.confidence is not None else None),
                f.message,
                f.suggestion,
                f.status or "pending",
                f.code_context,
            )
            for f in findings
        ]
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("PRAGMA foreign_keys=ON")
            try:
                await db.executemany(
                    """
                    INSERT INTO findings (
                        id, check_id, file, line, class, severity, confidence,
                        message, suggestion, status, code_context
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                await db.commit()
            except aiosqlite.IntegrityError as exc:
                await db.rollback()
                raise StorageError(f"findings_insert_failed: {exc}") from exc

    async def list_findings(self, check_id: str) -> list[FindingRecord]:
        # ORDER BY severity DESC — критические наверху; SQLite сортирует строки
        # лексикографически. Чтобы критика была сверху — сначала по custom
        # rank, потом по line.
        sql = """
            SELECT * FROM findings WHERE check_id=?
            ORDER BY
              CASE severity
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                WHEN 'medium' THEN 2
                WHEN 'low' THEN 3
                WHEN 'info' THEN 4
                ELSE 5
              END,
              file, line
        """
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(sql, (check_id,))
            rows = await cursor.fetchall()
            await cursor.close()
        return [_row_to_finding(r) for r in rows]

    async def save_comments(
        self, check_id: str, comments: Sequence[CommentRecord]
    ) -> None:
        if not comments:
            return
        rows = [
            (
                c.id,
                check_id,
                c.finding_id,
                c.kind,
                c.marker,
                _fmt_dt(c.posted_at),
                c.vcs_comment_id,
                c.vcs_url,
                c.body_excerpt,
            )
            for c in comments
        ]
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("PRAGMA foreign_keys=ON")
            try:
                await db.executemany(
                    """
                    INSERT INTO comments (
                        id, check_id, finding_id, kind, marker,
                        posted_at, vcs_comment_id, vcs_url, body_excerpt
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                await db.commit()
            except aiosqlite.IntegrityError as exc:
                await db.rollback()
                raise StorageError(f"comments_insert_failed: {exc}") from exc

    async def list_comments(self, check_id: str) -> list[CommentRecord]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM comments WHERE check_id=? ORDER BY posted_at",
                (check_id,),
            )
            rows = await cursor.fetchall()
            await cursor.close()
        return [_row_to_comment(r) for r in rows]

    async def list_repos(self) -> list[RepoConfigRecord]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM repo_configs ORDER BY full_name"
            )
            rows = await cursor.fetchall()
            await cursor.close()
        return [_row_to_repo(r) for r in rows]

    async def get_repo(self, repo_id: str) -> Optional[RepoConfigRecord]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM repo_configs WHERE id=?", (repo_id,)
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                return None
            return _row_to_repo(row)

    async def get_repo_by_full_name(
        self, full_name: str
    ) -> Optional[RepoConfigRecord]:
        async with aiosqlite.connect(self._db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM repo_configs WHERE full_name=?", (full_name,)
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                return None
            return _row_to_repo(row)

    async def upsert_repo(self, repo: RepoConfigRecord) -> RepoConfigRecord:
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute("PRAGMA foreign_keys=ON")
            db.row_factory = aiosqlite.Row
            try:
                await db.execute(
                    """
                    INSERT INTO repo_configs (
                        id, full_name, vcs_provider, vcs_token_ref,
                        webhook_secret_ref, llm_provider_override,
                        enabled, created_at, updated_at, last_seen_at,
                        webhook_id, webhook_url
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(full_name) DO UPDATE SET
                        vcs_provider=excluded.vcs_provider,
                        vcs_token_ref=excluded.vcs_token_ref,
                        webhook_secret_ref=excluded.webhook_secret_ref,
                        llm_provider_override=excluded.llm_provider_override,
                        enabled=excluded.enabled,
                        updated_at=excluded.updated_at,
                        last_seen_at=COALESCE(excluded.last_seen_at, repo_configs.last_seen_at),
                        webhook_id=COALESCE(excluded.webhook_id, repo_configs.webhook_id),
                        webhook_url=COALESCE(excluded.webhook_url, repo_configs.webhook_url)
                    """,
                    (
                        repo.id,
                        repo.full_name,
                        repo.vcs_provider,
                        repo.vcs_token_ref,
                        repo.webhook_secret_ref,
                        repo.llm_provider_override,
                        1 if repo.enabled else 0,
                        _fmt_dt(repo.created_at),
                        _fmt_dt(repo.updated_at),
                        _fmt_dt(repo.last_seen_at),
                        repo.webhook_id,
                        repo.webhook_url,
                    ),
                )
                await db.commit()
            except aiosqlite.IntegrityError as exc:
                await db.rollback()
                raise StorageConflictError(
                    f"repo_configs_conflict: {exc}"
                ) from exc

            cursor = await db.execute(
                "SELECT * FROM repo_configs WHERE full_name=?",
                (repo.full_name,),
            )
            row = await cursor.fetchone()
            await cursor.close()
            if row is None:
                # теоретически невозможно — INSERT/UPDATE только что прошёл
                raise StorageError("upsert_repo_post_read_missing")
            return _row_to_repo(row)

    async def delete_repo(self, repo_id: str) -> bool:
        async with aiosqlite.connect(self._db_path) as db:
            cursor = await db.execute(
                "DELETE FROM repo_configs WHERE id=?", (repo_id,)
            )
            await db.commit()
            deleted = cursor.rowcount or 0
            await cursor.close()
        return deleted > 0

    async def touch_repo_seen(self, full_name: str) -> None:
        now_iso = datetime.utcnow().isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                "UPDATE repo_configs SET last_seen_at=? WHERE full_name=?",
                (now_iso, full_name),
            )
            await db.commit()

    async def set_repo_webhook(
        self, repo_id: str, *, webhook_id: int, webhook_url: str
    ) -> None:
        now_iso = datetime.utcnow().isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                UPDATE repo_configs
                   SET webhook_id=?, webhook_url=?, updated_at=?
                 WHERE id=?
                """,
                (int(webhook_id), webhook_url, now_iso, repo_id),
            )
            await db.commit()

    async def clear_repo_webhook(self, repo_id: str) -> None:
        now_iso = datetime.utcnow().isoformat()
        async with aiosqlite.connect(self._db_path) as db:
            await db.execute(
                """
                UPDATE repo_configs
                   SET webhook_id=NULL, webhook_url=NULL, updated_at=?
                 WHERE id=?
                """,
                (now_iso, repo_id),
            )
            await db.commit()


__all__ = ["SQLiteStateStore"]
