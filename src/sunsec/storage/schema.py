"""SQL DDL для persistence-слоя (system_design v1.2.1 §11.3).

Все блоки — `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`,
идемпотентно применяются на каждый startup через `migrations.run_migrations`.

При schema-эволюции — добавляй новый блок снизу, всегда `IF NOT EXISTS`;
для destructive-изменений (ALTER TABLE / DROP COLUMN) — отдельный
выделенный шаг с PR review (см. §11.2, R-15).
"""
from __future__ import annotations

SCHEMA_VERSION = "1"


CREATE_TABLE_CHECKS = """
CREATE TABLE IF NOT EXISTS checks (
    id                          TEXT PRIMARY KEY,
    repo                        TEXT NOT NULL,
    pr_number                   INTEGER NOT NULL,
    pr_title                    TEXT,
    author                      TEXT,
    source_branch               TEXT,
    target_branch               TEXT,
    head_sha                    TEXT NOT NULL,
    base_sha                    TEXT,
    action                      TEXT,
    status                      TEXT NOT NULL,
    llm_status                  TEXT,
    llm_provider                TEXT,
    llm_model                   TEXT,
    started_at                  TIMESTAMP NOT NULL,
    finished_at                 TIMESTAMP,
    duration_ms                 INTEGER,
    files_checked               INTEGER DEFAULT 0,
    files_skipped               INTEGER DEFAULT 0,
    findings_count              INTEGER DEFAULT 0,
    cost_rub                    REAL DEFAULT 0.0,
    pr_url                      TEXT,
    summary                     TEXT,
    severity_counts_critical    INTEGER DEFAULT 0,
    severity_counts_high        INTEGER DEFAULT 0,
    severity_counts_medium      INTEGER DEFAULT 0,
    severity_counts_low         INTEGER DEFAULT 0,
    severity_counts_info        INTEGER DEFAULT 0
)
"""

CREATE_INDEX_CHECKS_REPO_STARTED = """
CREATE INDEX IF NOT EXISTS idx_checks_repo_started
    ON checks(repo, started_at DESC)
"""


CREATE_TABLE_FINDINGS = """
CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    check_id        TEXT NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    file            TEXT NOT NULL,
    line            INTEGER NOT NULL,
    class           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      REAL,
    message         TEXT NOT NULL,
    suggestion      TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    code_context    TEXT
)
"""

CREATE_INDEX_FINDINGS_CHECK = """
CREATE INDEX IF NOT EXISTS idx_findings_check
    ON findings(check_id)
"""


CREATE_TABLE_COMMENTS = """
CREATE TABLE IF NOT EXISTS comments (
    id              TEXT PRIMARY KEY,
    check_id        TEXT NOT NULL REFERENCES checks(id) ON DELETE CASCADE,
    finding_id      TEXT REFERENCES findings(id) ON DELETE SET NULL,
    kind            TEXT NOT NULL,
    marker          TEXT,
    posted_at       TIMESTAMP NOT NULL,
    vcs_comment_id  TEXT,
    vcs_url         TEXT,
    body_excerpt    TEXT
)
"""

CREATE_INDEX_COMMENTS_CHECK = """
CREATE INDEX IF NOT EXISTS idx_comments_check
    ON comments(check_id)
"""


CREATE_TABLE_REPO_CONFIGS = """
CREATE TABLE IF NOT EXISTS repo_configs (
    id                      TEXT PRIMARY KEY,
    full_name               TEXT NOT NULL UNIQUE,
    vcs_provider            TEXT NOT NULL DEFAULT 'github',
    vcs_token_ref           TEXT,
    webhook_secret_ref      TEXT,
    llm_provider_override   TEXT,
    enabled                 INTEGER NOT NULL DEFAULT 1,
    created_at              TIMESTAMP NOT NULL,
    updated_at              TIMESTAMP NOT NULL,
    last_seen_at            TIMESTAMP,
    webhook_id              INTEGER,
    webhook_url             TEXT
)
"""

CREATE_INDEX_REPO_CONFIGS_FULL_NAME = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_repo_configs_full_name
    ON repo_configs(full_name)
"""


# Применяется последовательно в `migrations.run_migrations`.
# Порядок важен: таблицы — до индексов на них; FK-таблицы — после parent.
ALL_DDL_STATEMENTS: list[str] = [
    CREATE_TABLE_CHECKS,
    CREATE_INDEX_CHECKS_REPO_STARTED,
    CREATE_TABLE_FINDINGS,
    CREATE_INDEX_FINDINGS_CHECK,
    CREATE_TABLE_COMMENTS,
    CREATE_INDEX_COMMENTS_CHECK,
    CREATE_TABLE_REPO_CONFIGS,
    CREATE_INDEX_REPO_CONFIGS_FULL_NAME,
]


# Additive migrations for evolving existing tables.
# SQLite не поддерживает `ALTER TABLE ADD COLUMN IF NOT EXISTS` — поэтому
# каждое выражение выполняется через try/except в `run_migrations`, дубликат
# колонки трактуется как no-op.
ADDITIVE_MIGRATIONS: list[str] = [
    "ALTER TABLE repo_configs ADD COLUMN webhook_id INTEGER",
    "ALTER TABLE repo_configs ADD COLUMN webhook_url TEXT",
]


PRAGMA_STATEMENTS: list[str] = [
    "PRAGMA journal_mode=WAL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA synchronous=NORMAL",
]


__all__ = [
    "SCHEMA_VERSION",
    "ALL_DDL_STATEMENTS",
    "ADDITIVE_MIGRATIONS",
    "PRAGMA_STATEMENTS",
    "CREATE_TABLE_CHECKS",
    "CREATE_TABLE_FINDINGS",
    "CREATE_TABLE_COMMENTS",
    "CREATE_TABLE_REPO_CONFIGS",
    "CREATE_INDEX_CHECKS_REPO_STARTED",
    "CREATE_INDEX_FINDINGS_CHECK",
    "CREATE_INDEX_COMMENTS_CHECK",
    "CREATE_INDEX_REPO_CONFIGS_FULL_NAME",
]
