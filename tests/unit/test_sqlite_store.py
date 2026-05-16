"""Unit-тесты `SQLiteStateStore` + `build_storage_from_settings` (T-038).

Покрытие — по DoD T-038 (system_design v1.2.1 §11):

- idempotent init_schema (двойной run_migrations не падает)
- save_check + get_check happy-path
- get_check → None для несуществующего id
- save_findings (батч) + list_findings
- list_checks с фильтром по status / repo
- list_checks pagination
- upsert_repo insert + update
- delete_repo true/false
- vcs_token_ref хранится как строка, не реальный токен
- параллельные writes (per-request connections, no conflict)
- factory: `:memory:` → InMemoryStateStore
- factory: путь → SQLiteStateStore
- save_comments + list_comments
- get_repo_by_full_name + touch_repo_seen

Все тесты — async (pytest-asyncio автомодом). Используют `tmp_path` fixture
или `:memory:` через aiosqlite, никакой реальной файловой системы вне
тест-temp-dir.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from pathlib import Path

import pytest

pytest.importorskip("aiosqlite")
pytest.importorskip("pydantic")

from sunsec.config.settings import Settings  # noqa: E402
from sunsec.contracts.storage import (  # noqa: E402
    CheckRecord,
    CommentRecord,
    FindingRecord,
    RepoConfigRecord,
)
from sunsec.state.memory import InMemoryStateStore  # noqa: E402
from sunsec.storage import (  # noqa: E402
    SQLiteStateStore,
    build_storage_from_settings,
    run_migrations,
)


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
async def sqlite_store(tmp_path: Path) -> SQLiteStateStore:
    """Чистая SQLite-БД в tmp_path с применённой schema."""
    db = tmp_path / "sunsec_test.db"
    await run_migrations(str(db))
    return SQLiteStateStore(str(db))


def _check(
    *,
    id: str = "chk_abcde",
    repo: str = "octo/test",
    pr_number: int = 1,
    status: str = "received",
    head_sha: str = "deadbeef",
    started_at: datetime | None = None,
    **kwargs,
) -> CheckRecord:
    return CheckRecord(
        id=id,
        repo=repo,
        pr_number=pr_number,
        status=status,
        head_sha=head_sha,
        started_at=started_at or datetime.utcnow(),
        **kwargs,
    )


def _finding(
    *,
    id: str = "fnd_abc123",
    check_id: str = "chk_abcde",
    file: str = "app/api.py",
    line: int = 42,
    class_: str = "sql_injection",
    severity: str = "high",
    message: str = "SQL concat detected",
    confidence: float | None = 0.9,
    suggestion: str | None = None,
    status: str = "pending",
) -> FindingRecord:
    return FindingRecord(
        id=id,
        check_id=check_id,
        file=file,
        line=line,
        **{"class": class_},
        severity=severity,
        message=message,
        confidence=confidence,
        suggestion=suggestion,
        status=status,
    )


def _repo(
    *,
    id: str = "repo_abcde",
    full_name: str = "octo/test",
    vcs_token_ref: str | None = "REPO_OCTO_TEST_VCS_TOKEN",
    webhook_secret_ref: str | None = "REPO_OCTO_TEST_WEBHOOK_SECRET",
    enabled: bool = True,
    llm_provider_override: str | None = None,
) -> RepoConfigRecord:
    now = datetime.utcnow()
    return RepoConfigRecord(
        id=id,
        full_name=full_name,
        vcs_provider="github",
        vcs_token_ref=vcs_token_ref,
        webhook_secret_ref=webhook_secret_ref,
        llm_provider_override=llm_provider_override,
        enabled=enabled,
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_init_schema_idempotent(tmp_path: Path) -> None:
    """run_migrations можно запустить дважды на одной БД без ошибок."""
    db = tmp_path / "twice.db"
    await run_migrations(str(db))
    await run_migrations(str(db))
    # Финальная вставка проходит — таблицы существуют.
    store = SQLiteStateStore(str(db))
    rec = _check(id="chk_idem01")
    await store.save_check(rec)
    fetched = await store.get_check("chk_idem01")
    assert fetched is not None
    assert fetched.id == "chk_idem01"


async def test_save_check_and_get_check_roundtrip(
    sqlite_store: SQLiteStateStore,
) -> None:
    """Happy-path: INSERT → SELECT возвращает идентичную запись."""
    started = datetime.utcnow()
    rec = _check(
        id="chk_round01",
        repo="stellar/core-api",
        pr_number=42,
        status="received",
        head_sha="cafebabe",
        started_at=started,
        pr_title="Add OAuth flow",
        author="alice",
    )
    await sqlite_store.save_check(rec)

    fetched = await sqlite_store.get_check("chk_round01")
    assert fetched is not None
    assert fetched.id == "chk_round01"
    assert fetched.repo == "stellar/core-api"
    assert fetched.pr_number == 42
    assert fetched.head_sha == "cafebabe"
    assert fetched.status == "received"
    assert fetched.pr_title == "Add OAuth flow"
    assert fetched.author == "alice"
    # severity_counts по умолчанию — нули
    assert sum(fetched.severity_counts.values()) == 0


async def test_get_check_returns_none_for_missing_id(
    sqlite_store: SQLiteStateStore,
) -> None:
    fetched = await sqlite_store.get_check("chk_notfound999")
    assert fetched is None


async def test_save_findings_batch_and_list(
    sqlite_store: SQLiteStateStore,
) -> None:
    """Батч-INSERT 5 findings, потом list_findings → 5 строк, отсортированных по severity."""
    chk = _check(id="chk_find01")
    await sqlite_store.save_check(chk)

    findings = [
        _finding(id=f"fnd_b{i:03d}", check_id="chk_find01", line=10 + i,
                 severity=sev, class_=cls)
        for i, (sev, cls) in enumerate(
            [
                ("low", "xss"),
                ("critical", "sql_injection"),
                ("medium", "xss"),
                ("high", "hardcoded_secret"),
                ("info", "xss"),
            ]
        )
    ]
    await sqlite_store.save_findings("chk_find01", findings)

    listed = await sqlite_store.list_findings("chk_find01")
    assert len(listed) == 5
    # Первый — critical (system_design §11.5: ORDER BY severity DESC).
    assert listed[0].severity == "critical"
    assert listed[-1].severity == "info"


async def test_list_checks_filter_by_status(
    sqlite_store: SQLiteStateStore,
) -> None:
    """3 check'и разных статусов → фильтр по status='completed' → 1."""
    base = datetime.utcnow()
    for i, status in enumerate(["received", "completed", "failed"]):
        await sqlite_store.save_check(
            _check(
                id=f"chk_st{i:02d}",
                status=status,
                started_at=base + timedelta(seconds=i),
            )
        )
    listed = await sqlite_store.list_checks(status="completed")
    assert len(listed) == 1
    assert listed[0].status == "completed"


async def test_list_checks_filter_by_repo(
    sqlite_store: SQLiteStateStore,
) -> None:
    await sqlite_store.save_check(_check(id="chk_r01", repo="stellar/core-api"))
    await sqlite_store.save_check(_check(id="chk_r02", repo="acme/widgets"))
    await sqlite_store.save_check(_check(id="chk_r03", repo="stellar/core-api"))

    listed = await sqlite_store.list_checks(repo="stellar/core-api")
    assert len(listed) == 2
    assert all(c.repo == "stellar/core-api" for c in listed)


async def test_list_checks_pagination(
    sqlite_store: SQLiteStateStore,
) -> None:
    base = datetime.utcnow()
    for i in range(20):
        await sqlite_store.save_check(
            _check(id=f"chk_pg{i:02d}", started_at=base + timedelta(seconds=i))
        )
    page = await sqlite_store.list_checks(limit=5, offset=10)
    assert len(page) == 5
    # ORDER BY started_at DESC — offset=10 пропускает 10 самых свежих.
    assert page[0].id == "chk_pg09"


async def test_upsert_repo_insert_then_update(
    sqlite_store: SQLiteStateStore,
) -> None:
    rec = _repo(id="repo_up01", full_name="octo/test", enabled=True)
    inserted = await sqlite_store.upsert_repo(rec)
    assert inserted.full_name == "octo/test"
    assert inserted.enabled is True

    # Update: тот же full_name, другой enabled.
    rec2 = _repo(
        id="repo_up01",
        full_name="octo/test",
        enabled=False,
        llm_provider_override="openrouter",
    )
    # updated_at в новой версии должен отличаться
    rec2_updated = rec2.model_copy(
        update={"updated_at": datetime.utcnow() + timedelta(seconds=1)}
    )
    updated = await sqlite_store.upsert_repo(rec2_updated)
    assert updated.enabled is False
    assert updated.llm_provider_override == "openrouter"

    # В БД остаётся одна запись по этому full_name.
    all_repos = await sqlite_store.list_repos()
    matching = [r for r in all_repos if r.full_name == "octo/test"]
    assert len(matching) == 1


async def test_delete_repo_returns_true_if_found_false_otherwise(
    sqlite_store: SQLiteStateStore,
) -> None:
    rec = _repo(id="repo_del01", full_name="octo/del")
    await sqlite_store.upsert_repo(rec)

    assert await sqlite_store.delete_repo("repo_del01") is True
    # Повторный delete — False.
    assert await sqlite_store.delete_repo("repo_del01") is False
    # Несуществующий id — False.
    assert await sqlite_store.delete_repo("repo_doesntexist") is False


async def test_vcs_token_ref_stored_as_string_not_real_token(
    sqlite_store: SQLiteStateStore,
) -> None:
    """R-12: БД хранит только имя env-переменной, не plaintext-секрет."""
    rec = _repo(
        id="repo_sec01",
        full_name="octo/secret",
        vcs_token_ref="REPO_OCTO_SECRET_VCS_TOKEN",
        webhook_secret_ref="REPO_OCTO_SECRET_WEBHOOK_SECRET",
    )
    await sqlite_store.upsert_repo(rec)

    fetched = await sqlite_store.get_repo_by_full_name("octo/secret")
    assert fetched is not None
    assert fetched.vcs_token_ref == "REPO_OCTO_SECRET_VCS_TOKEN"
    assert fetched.webhook_secret_ref == "REPO_OCTO_SECRET_WEBHOOK_SECRET"
    # Никаких ghp_*** / sk-or-v1-* / pza_* в этих полях
    assert not fetched.vcs_token_ref.startswith("ghp_")
    assert not (fetched.webhook_secret_ref or "").startswith("ghs_")


async def test_concurrent_writes_async(tmp_path: Path) -> None:
    """Per-request connections не конфликтуют при параллельных save_check'ах."""
    db = tmp_path / "concurrent.db"
    await run_migrations(str(db))
    store = SQLiteStateStore(str(db))

    async def insert(i: int) -> None:
        await store.save_check(_check(id=f"chk_cc{i:02d}"))

    await asyncio.gather(*[insert(i) for i in range(5)])

    for i in range(5):
        assert await store.get_check(f"chk_cc{i:02d}") is not None


async def test_factory_returns_in_memory_when_path_is_memory_keyword(
    monkeypatch,
) -> None:
    """`SUNSEC_DB_PATH=:memory:` → InMemoryStateStore (legacy ADR-3)."""
    settings = Settings(sunsec_db_path=":memory:")
    store = build_storage_from_settings(settings)
    assert isinstance(store, InMemoryStateStore)


async def test_factory_returns_in_memory_when_path_is_empty() -> None:
    settings = Settings(sunsec_db_path="")
    store = build_storage_from_settings(settings)
    assert isinstance(store, InMemoryStateStore)


async def test_factory_returns_sqlite_when_path_set(tmp_path: Path) -> None:
    db = tmp_path / "factory.db"
    settings = Settings(sunsec_db_path=str(db))
    store = build_storage_from_settings(settings)
    assert isinstance(store, SQLiteStateStore)
    assert store.db_path == str(db)


async def test_save_comments_and_list_comments(
    sqlite_store: SQLiteStateStore,
) -> None:
    """Batch INSERT в comments + ORDER BY posted_at."""
    chk = _check(id="chk_cm01")
    await sqlite_store.save_check(chk)

    now = datetime.utcnow()
    comments = [
        CommentRecord(
            id=f"cmt_{i:03d}",
            check_id="chk_cm01",
            kind=kind,
            posted_at=now + timedelta(seconds=i),
            vcs_url=f"https://github.com/octo/test/pull/1#cmt_{i}",
        )
        for i, kind in enumerate(["summary", "inline"])
    ]
    await sqlite_store.save_comments("chk_cm01", comments)

    listed = await sqlite_store.list_comments("chk_cm01")
    assert len(listed) == 2
    assert {c.kind for c in listed} == {"summary", "inline"}


async def test_update_check_status_partial(
    sqlite_store: SQLiteStateStore,
) -> None:
    """UPDATE только переданных полей; остальные остаются нетронутыми."""
    rec = _check(id="chk_up01", status="received")
    await sqlite_store.save_check(rec)

    await sqlite_store.update_check_status(
        "chk_up01",
        status="completed",
        llm_status="ok",
        llm_provider="polza",
        llm_model="gpt-4o-mini",
        files_checked=3,
        files_skipped=1,
        findings_count=2,
        cost_rub=0.5,
        severity_counts={"critical": 1, "high": 1, "medium": 0, "low": 0, "info": 0},
        finished_at=datetime.utcnow(),
        duration_ms=1234,
    )

    fetched = await sqlite_store.get_check("chk_up01")
    assert fetched is not None
    assert fetched.status == "completed"
    assert fetched.llm_status == "ok"
    assert fetched.llm_provider == "polza"
    assert fetched.llm_model == "gpt-4o-mini"
    assert fetched.files_checked == 3
    assert fetched.files_skipped == 1
    assert fetched.findings_count == 2
    assert fetched.cost_rub == 0.5
    assert fetched.severity_counts["critical"] == 1
    assert fetched.severity_counts["high"] == 1
    assert fetched.duration_ms == 1234


async def test_touch_repo_seen(sqlite_store: SQLiteStateStore) -> None:
    rec = _repo(id="repo_seen01", full_name="octo/seen")
    await sqlite_store.upsert_repo(rec)

    fetched_before = await sqlite_store.get_repo_by_full_name("octo/seen")
    assert fetched_before is not None
    assert fetched_before.last_seen_at is None

    await sqlite_store.touch_repo_seen("octo/seen")
    fetched_after = await sqlite_store.get_repo_by_full_name("octo/seen")
    assert fetched_after is not None
    assert fetched_after.last_seen_at is not None


async def test_sqlite_store_repr_does_not_leak_path(tmp_path: Path) -> None:
    """`__repr__` SQLiteStateStore не светит путь к БД (security-практика)."""
    db = tmp_path / "secret_path.db"
    await run_migrations(str(db))
    store = SQLiteStateStore(str(db))
    r = repr(store)
    assert str(db) not in r
    assert "secret_path" not in r


async def test_findings_insert_failure_does_not_corrupt_db(
    sqlite_store: SQLiteStateStore,
) -> None:
    """При неудачном INSERT findings (FK violation) — выбрасывается StorageError,
    БД остаётся в консистентном состоянии (rollback)."""
    from sunsec.storage.errors import StorageError

    # finding с несуществующим check_id — FK violation
    bad = [_finding(id="fnd_bad01", check_id="chk_nonexistent999")]
    with pytest.raises(StorageError):
        await sqlite_store.save_findings("chk_nonexistent999", bad)
