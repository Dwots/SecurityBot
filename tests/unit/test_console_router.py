"""Unit-тесты Console UI HTTP router (T-039, M-9).

Покрытие (по DoD T-039 ≥12 тестов; здесь 16+):
1. ENABLE_CONSOLE_UI=false → /api/console/* → 404.
2. GET /api/console/budget — snapshot.
3. GET /api/console/settings — нет секретов в response.
4. GET /api/console/checks — фильтр по status.
5. GET /api/console/checks — pagination.
6. GET /api/console/checks/{id} — 404 vs 200.
7. POST /api/console/repos — happy-path; в response нет plaintext-токена.
8. POST /api/console/repos — пишет в `data/repos_secrets.env` (tmp_path).
9. POST /api/console/repos — camelCase и snake_case оба варианта на входе.
10. PATCH /api/console/repos/{id} — toggle enabled.
11. DELETE /api/console/repos/{id} — 404 vs 204.
12. POST /api/console/manual/analyze — proxy → 200.
13. POST /api/console/manual/analyze — invalid payload → 422.
14. Webhook resolver: репо в БД → token из env-переменной.
15. Webhook resolver: репо НЕ в БД → fallback на Settings.vcs_token.
16. Startup: load_dotenv(data/repos_secrets.env) до Settings() — токен доступен.
17. Slug-функция: edge cases (-, ., многоуровневое).
"""
from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("pydantic")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sunsec.config.settings import Settings  # noqa: E402
from sunsec.contracts.storage import (  # noqa: E402
    CheckRecord,
    FindingRecord,
    RepoConfigRecord,
)
from sunsec.state.memory import InMemoryStateStore  # noqa: E402
from sunsec.ui.console_router import (  # noqa: E402
    build_console_router,
    slug_for_repo,
    vcs_token_ref_name,
    webhook_secret_ref_name,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_settings(**overrides: Any) -> Settings:
    base = dict(
        app_env="test",
        vcs_token="dummy",
        webhook_secret="dummy",
        polza_api_key="dummy",
        openrouter_api_key="dummy",
        enable_console_ui=True,
        log_format="json",
    )
    base.update(overrides)
    return Settings(**base)


def _make_check(
    *,
    id_: str,
    repo: str = "alice/proj",
    pr_number: int = 1,
    status: str = "completed",
    started_at: datetime | None = None,
    severity_counts: dict[str, int] | None = None,
) -> CheckRecord:
    if started_at is None:
        started_at = datetime.now(timezone.utc)
    return CheckRecord(
        id=id_,
        repo=repo,
        pr_number=pr_number,
        head_sha="a" * 40,
        status=status,
        started_at=started_at,
        severity_counts=severity_counts
        or {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    )


def _make_app(
    *,
    state: Any | None = None,
    settings: Settings | None = None,
    llm_client: Any | None = None,
    manual_analyze_handler: Any | None = None,
    repos_secrets_path: Path | None = None,
    enable: bool = True,
) -> tuple[FastAPI, Any]:
    if state is None:
        state = InMemoryStateStore()
    if settings is None:
        settings = _make_settings(enable_console_ui=enable)

    app = FastAPI()
    if enable:
        router = build_console_router(
            state=state,
            settings=settings,
            llm_client=llm_client,
            manual_analyze_handler=manual_analyze_handler,
            repos_secrets_path=repos_secrets_path,
        )
        app.include_router(router)
    return app, state


# ---------------------------------------------------------------------------
# 1. Slug / ref helpers
# ---------------------------------------------------------------------------


def test_slug_and_ref_helpers_handle_edge_cases() -> None:
    """Slug — A-Z0-9_, strip trailing underscores; refs детерминированы."""
    assert slug_for_repo("alice/proj") == "ALICE_PROJ"
    assert slug_for_repo("stellar/core-api") == "STELLAR_CORE_API"
    assert slug_for_repo("a.b/c-d.e") == "A_B_C_D_E"
    assert slug_for_repo("---foo/bar---") == "FOO_BAR"
    assert vcs_token_ref_name("alice/proj") == "REPO_ALICE_PROJ_VCS_TOKEN"
    assert webhook_secret_ref_name("alice/proj") == "REPO_ALICE_PROJ_WEBHOOK_SECRET"


# ---------------------------------------------------------------------------
# 2. ENABLE_CONSOLE_UI=false → 404
# ---------------------------------------------------------------------------


def test_console_disabled_returns_404() -> None:
    """Если флаг выключен — endpoint'ов нет вовсе (404)."""
    app, _ = _make_app(enable=False)
    with TestClient(app) as client:
        for path in ("/api/console/budget", "/api/console/settings", "/api/console/repos"):
            resp = client.get(path)
            assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 3. GET /api/console/budget
# ---------------------------------------------------------------------------


def test_get_budget_returns_camel_case_snapshot() -> None:
    budget = MagicMock()
    budget.spent_rub = 12.5
    budget.limit_rub = 80.0
    budget.calls = 7
    llm_client = MagicMock()
    llm_client.budget = budget

    app, _ = _make_app(llm_client=llm_client)
    with TestClient(app) as client:
        resp = client.get("/api/console/budget")
        assert resp.status_code == 200
        data = resp.json()
        assert data["spentRub"] == 12.5
        assert data["limitRub"] == 80.0
        assert data["remainingRub"] == pytest.approx(67.5)
        assert data["callsCount"] == 7
        assert data["limitPercent"] == pytest.approx(15.625, rel=1e-3)


def test_get_budget_no_llm_returns_zeros() -> None:
    app, _ = _make_app(llm_client=None)
    with TestClient(app) as client:
        resp = client.get("/api/console/budget")
        assert resp.status_code == 200
        data = resp.json()
        assert data["spentRub"] == 0.0
        assert data["limitRub"] == 0.0
        assert data["callsCount"] == 0


# ---------------------------------------------------------------------------
# 4. GET /api/console/settings — masking
# ---------------------------------------------------------------------------


def test_get_settings_masks_secrets() -> None:
    """Response НЕ содержит ни одной строки, похожей на api_key / token / secret / password."""
    settings = _make_settings(
        polza_api_key="real-polza-key-abc123",
        openrouter_api_key="sk-or-v1-xxx",
        vcs_token="ghp_secret_token_xyz",
        webhook_secret="webhook-secret-zzz",
    )
    app, _ = _make_app(settings=settings)
    with TestClient(app) as client:
        resp = client.get("/api/console/settings")
        assert resp.status_code == 200
        text = resp.text
        # Secrets — точно не утекли.
        for leaked in (
            "real-polza-key-abc123",
            "sk-or-v1-xxx",
            "ghp_secret_token_xyz",
            "webhook-secret-zzz",
        ):
            assert leaked not in text, f"Secret leaked: {leaked!r}"
        # И в ключах нет именно секретных подстрок: apiKey / vcsToken / webhookSecret /
        # password / authorization. `maxTokens` — token COUNT, не token-value, разрешён
        # (explicit allow-list в SettingsOut, см. system_design §13.3.2).
        data = resp.json()
        forbidden_substrings = (
            "apikey",
            "vcstoken",
            "polzaapikey",
            "openrouterapikey",
            "webhooksecret",
            "password",
            "authorization",
            "storageencryptionkey",
        )
        for key in data:
            low = key.lower()
            for sub in forbidden_substrings:
                assert sub not in low, f"Secret-related key leaked: {key!r}"
        # CamelCase у ожидаемых полей.
        assert data["appEnv"] == "test"
        assert data["enableConsoleUi"] is True


# ---------------------------------------------------------------------------
# 5. GET /api/console/checks — filter / pagination
# ---------------------------------------------------------------------------


def test_get_checks_filter_by_status() -> None:
    state = InMemoryStateStore()

    async def setup() -> None:
        await state.save_check(_make_check(id_="c1", status="completed"))
        await state.save_check(_make_check(id_="c2", status="failed"))
        await state.save_check(_make_check(id_="c3", status="completed"))

    asyncio.run(setup())

    app, _ = _make_app(state=state)
    with TestClient(app) as client:
        resp = client.get("/api/console/checks", params={"status": "completed"})
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 2
        assert {it["id"] for it in items} == {"c1", "c3"}
        assert all(it["status"] == "completed" for it in items)


def test_get_checks_pagination_camel_case_fields() -> None:
    state = InMemoryStateStore()

    async def setup() -> None:
        for i in range(5):
            await state.save_check(
                _make_check(
                    id_=f"c{i}",
                    pr_number=i + 1,
                    started_at=datetime(2026, 5, 16, 10, i, tzinfo=timezone.utc),
                )
            )

    asyncio.run(setup())

    app, _ = _make_app(state=state)
    with TestClient(app) as client:
        resp = client.get("/api/console/checks", params={"limit": 2, "offset": 1})
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 2
        # camelCase ключи у каждого элемента
        first = items[0]
        assert "prNumber" in first
        assert "severityCounts" in first
        assert "startedAt" in first


# ---------------------------------------------------------------------------
# 6. GET /api/console/checks/{id} — 404 vs 200
# ---------------------------------------------------------------------------


def test_get_check_by_id_404_and_200() -> None:
    state = InMemoryStateStore()

    async def setup() -> None:
        await state.save_check(_make_check(id_="c1", status="completed"))
        await state.save_findings(
            "c1",
            [
                FindingRecord(
                    id="f1",
                    check_id="c1",
                    file="app.py",
                    line=42,
                    **{"class": "sql_injection"},
                    severity="high",
                    confidence=0.9,
                    message="SQLi",
                )
            ],
        )

    asyncio.run(setup())

    app, _ = _make_app(state=state)
    with TestClient(app) as client:
        resp = client.get("/api/console/checks/nope")
        assert resp.status_code == 404

        resp = client.get("/api/console/checks/c1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "c1"
        assert data["repository"] == "alice/proj"
        assert len(data["findings"]) == 1
        finding = data["findings"][0]
        assert finding["class"] == "sql_injection"
        assert finding["severity"] == "high"
        assert "codeContext" in finding  # alias to_camel
        assert data["skippedFiles"] == []  # MVP — empty
        assert "timeline" in data


# ---------------------------------------------------------------------------
# 7. POST /api/console/repos happy-path — нет plaintext в response
# ---------------------------------------------------------------------------


def test_post_repos_happy_path_no_plaintext_in_response(tmp_path: Path, monkeypatch) -> None:
    secrets_file = tmp_path / "repos_secrets.env"
    # Не оставляем мусор в os.environ после теста.
    monkeypatch.delenv("REPO_ALICE_PROJ_VCS_TOKEN", raising=False)
    monkeypatch.delenv("REPO_ALICE_PROJ_WEBHOOK_SECRET", raising=False)

    app, state = _make_app(repos_secrets_path=secrets_file)
    with TestClient(app) as client:
        resp = client.post(
            "/api/console/repos",
            json={
                "fullName": "alice/proj",
                "vcsProvider": "github",
                "vcsToken": "ghp_real_secret_xyz",
                "webhookSecret": "wh_real_secret_abc",
                "enabled": True,
            },
        )
        assert resp.status_code == 201, resp.text
        data = resp.json()
        # Plaintext-секретов нигде в ответе.
        text = resp.text
        assert "ghp_real_secret_xyz" not in text
        assert "wh_real_secret_abc" not in text
        # Возвращаются только refs + индикаторы.
        assert data["vcsTokenRef"] == "REPO_ALICE_PROJ_VCS_TOKEN"
        assert data["webhookSecretRef"] == "REPO_ALICE_PROJ_WEBHOOK_SECRET"
        assert data["vcsTokenSet"] is True
        assert data["webhookSecretSet"] is True
        # os.environ обновился (in-process env-патч).
        assert os.environ.get("REPO_ALICE_PROJ_VCS_TOKEN") == "ghp_real_secret_xyz"
        # Cleanup — иначе следующий тест увидит этот env.
        monkeypatch.delenv("REPO_ALICE_PROJ_VCS_TOKEN", raising=False)
        monkeypatch.delenv("REPO_ALICE_PROJ_WEBHOOK_SECRET", raising=False)


# ---------------------------------------------------------------------------
# 8. POST /api/console/repos — пишет в data/repos_secrets.env
# ---------------------------------------------------------------------------


def test_post_repos_writes_to_secrets_env_file(tmp_path: Path, monkeypatch) -> None:
    secrets_file = tmp_path / "repos_secrets.env"
    monkeypatch.delenv("REPO_STELLAR_CORE_API_VCS_TOKEN", raising=False)

    app, _ = _make_app(repos_secrets_path=secrets_file)
    with TestClient(app) as client:
        resp = client.post(
            "/api/console/repos",
            json={
                "fullName": "stellar/core-api",
                "vcsProvider": "github",
                "vcsToken": "ghp_durable_token",
                "webhookSecret": "wh_durable",
            },
        )
        assert resp.status_code == 201
        # Файл создан и содержит запись.
        assert secrets_file.exists()
        text = secrets_file.read_text(encoding="utf-8")
        assert "REPO_STELLAR_CORE_API_VCS_TOKEN" in text
        assert "REPO_STELLAR_CORE_API_WEBHOOK_SECRET" in text

    monkeypatch.delenv("REPO_STELLAR_CORE_API_VCS_TOKEN", raising=False)
    monkeypatch.delenv("REPO_STELLAR_CORE_API_WEBHOOK_SECRET", raising=False)


# ---------------------------------------------------------------------------
# 9. POST /api/console/repos — duplicate full_name → 409
# ---------------------------------------------------------------------------


def test_post_repos_duplicate_returns_409(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("REPO_DUP_REPO_VCS_TOKEN", raising=False)
    secrets_file = tmp_path / "repos_secrets.env"

    app, _ = _make_app(repos_secrets_path=secrets_file)
    with TestClient(app) as client:
        body = {
            "fullName": "dup/repo",
            "vcsProvider": "github",
            "vcsToken": "x",
            "webhookSecret": "y",
        }
        r1 = client.post("/api/console/repos", json=body)
        assert r1.status_code == 201
        r2 = client.post("/api/console/repos", json=body)
        assert r2.status_code == 409
        err = r2.json()["detail"]
        assert isinstance(err, dict) and err.get("code") == "REPO_DUPLICATE"


# ---------------------------------------------------------------------------
# 10. POST /api/console/repos — некорректный full_name → 422
# ---------------------------------------------------------------------------


def test_post_repos_invalid_full_name_returns_422(tmp_path: Path) -> None:
    app, _ = _make_app(repos_secrets_path=tmp_path / "x.env")
    with TestClient(app) as client:
        resp = client.post(
            "/api/console/repos",
            json={"fullName": "notavalidrepo", "vcsProvider": "github"},
        )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 11. PATCH /api/console/repos/{id} — toggle enabled
# ---------------------------------------------------------------------------


def test_patch_repo_toggle_enabled(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("REPO_FOO_BAR_VCS_TOKEN", raising=False)
    secrets_file = tmp_path / "repos_secrets.env"

    app, state = _make_app(repos_secrets_path=secrets_file)
    with TestClient(app) as client:
        resp = client.post(
            "/api/console/repos",
            json={
                "fullName": "foo/bar",
                "vcsProvider": "github",
                "vcsToken": "x",
                "webhookSecret": "y",
                "enabled": True,
            },
        )
        assert resp.status_code == 201
        repo_id = resp.json()["id"]

        resp = client.patch(
            f"/api/console/repos/{repo_id}",
            json={"enabled": False},
        )
        assert resp.status_code == 200
        assert resp.json()["enabled"] is False

        # И на 404 для несуществующего id.
        resp = client.patch("/api/console/repos/no-such-id", json={"enabled": True})
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 12. DELETE /api/console/repos/{id}
# ---------------------------------------------------------------------------


def test_delete_repo_404_and_204(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("REPO_DEL_REPO_VCS_TOKEN", raising=False)
    secrets_file = tmp_path / "repos_secrets.env"

    app, _ = _make_app(repos_secrets_path=secrets_file)
    with TestClient(app) as client:
        resp = client.delete("/api/console/repos/non-existent")
        assert resp.status_code == 404

        r1 = client.post(
            "/api/console/repos",
            json={
                "fullName": "del/repo",
                "vcsProvider": "github",
                "vcsToken": "x",
                "webhookSecret": "y",
            },
        )
        assert r1.status_code == 201
        repo_id = r1.json()["id"]

        r2 = client.delete(f"/api/console/repos/{repo_id}")
        assert r2.status_code == 204
        assert r2.content == b""


# ---------------------------------------------------------------------------
# 13. POST /api/console/manual/analyze — proxy → 200
# ---------------------------------------------------------------------------


def test_post_manual_analyze_proxies_and_returns_findings(tmp_path: Path) -> None:
    # Mock UI handler — возвращает dict напрямую (упрощённая proxy-схема).
    async def fake_handler(payload: dict[str, Any]) -> dict[str, Any]:
        return {
            "summary": "test summary",
            "findings": [
                {
                    "severity": "high",
                    "class": "sql_injection",
                    "file": payload["files"][0]["path"],
                    "line": 3,
                    "message": "found SQLi",
                    "confidence": 0.9,
                }
            ],
            "llm": {
                "status": "ok",
                "model": "gpt-4o-mini",
                "cost_rub": 0.1,
                "latency_ms": 250,
            },
        }

    app, _ = _make_app(manual_analyze_handler=fake_handler)
    with TestClient(app) as client:
        resp = client.post(
            "/api/console/manual/analyze",
            json={
                "files": [
                    {
                        "path": "app/views.py",
                        "code": "import sqlite3\n# more code\nx = 1",
                    }
                ]
            },
        )
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["summary"] == "test summary"
        assert len(data["findings"]) == 1
        f = data["findings"][0]
        assert f["class"] == "sql_injection"
        assert f["severity"] == "high"
        assert "codeContext" in f  # auto-extracted backend-side
        meta = data["llm"]
        assert meta["status"] == "ok"
        assert meta["costRub"] == pytest.approx(0.1)
        assert meta["latencyMs"] == 250


def test_post_manual_analyze_invalid_payload_returns_422(tmp_path: Path) -> None:
    async def fake_handler(payload):
        return {"summary": "", "findings": [], "llm": {"status": "ok", "model": "", "cost_rub": 0, "latency_ms": 0}}

    app, _ = _make_app(manual_analyze_handler=fake_handler)
    with TestClient(app) as client:
        resp = client.post("/api/console/manual/analyze", json={"files": []})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 14. GET /api/console/dashboard
# ---------------------------------------------------------------------------


def test_get_dashboard_aggregates_recent_checks() -> None:
    state = InMemoryStateStore()

    async def setup() -> None:
        for i in range(3):
            await state.save_check(
                _make_check(
                    id_=f"c{i}",
                    status="completed" if i < 2 else "failed",
                    severity_counts={
                        "critical": 0,
                        "high": 1 if i == 0 else 0,
                        "medium": 0,
                        "low": 0,
                        "info": 0,
                    },
                )
            )
        await state.upsert_repo(
            RepoConfigRecord(
                id="r1",
                full_name="alice/proj",
                vcs_provider="github",
                vcs_token_ref="REPO_ALICE_PROJ_VCS_TOKEN",
                enabled=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )

    asyncio.run(setup())

    app, _ = _make_app(state=state)
    with TestClient(app) as client:
        resp = client.get("/api/console/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert "recentChecks" in data
        assert len(data["recentChecks"]) == 3
        sev = data["findingsBySeverity"]
        assert sev["high"] == 1
        assert data["reposCount"] == 1
        assert data["successRate"] == pytest.approx(2 / 3, rel=1e-2)


# ---------------------------------------------------------------------------
# 15. Webhook resolver — DB token берётся first
# ---------------------------------------------------------------------------


def test_webhook_resolver_db_preferred_over_env(monkeypatch) -> None:
    from sunsec.webhook.repo_resolver import resolve_webhook_credentials

    state = InMemoryStateStore()
    settings = _make_settings(
        vcs_token="env_global_token",
        webhook_secret="env_global_secret",
    )
    monkeypatch.setenv("REPO_ALICE_PROJ_VCS_TOKEN", "db_specific_token")
    monkeypatch.setenv("REPO_ALICE_PROJ_WEBHOOK_SECRET", "db_specific_secret")

    async def setup_and_resolve() -> tuple:
        await state.upsert_repo(
            RepoConfigRecord(
                id="r1",
                full_name="alice/proj",
                vcs_provider="github",
                vcs_token_ref="REPO_ALICE_PROJ_VCS_TOKEN",
                webhook_secret_ref="REPO_ALICE_PROJ_WEBHOOK_SECRET",
                enabled=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )
        c1 = await resolve_webhook_credentials(
            state=state, settings=settings, full_name="alice/proj"
        )
        c2 = await resolve_webhook_credentials(
            state=state, settings=settings, full_name="other/repo"
        )
        return c1, c2

    c1, c2 = asyncio.run(setup_and_resolve())
    # Registered repo → DB-specific.
    assert c1.vcs_token == "db_specific_token"
    assert c1.webhook_secret == "db_specific_secret"
    assert c1.source == "db"
    # Not registered → env fallback.
    assert c2.vcs_token == "env_global_token"
    assert c2.webhook_secret == "env_global_secret"
    assert c2.source == "env"


def test_webhook_resolver_disabled_repo_falls_back_to_env(monkeypatch) -> None:
    from sunsec.webhook.repo_resolver import resolve_webhook_credentials

    state = InMemoryStateStore()
    settings = _make_settings(vcs_token="env_t", webhook_secret="env_s")
    monkeypatch.setenv("REPO_OFF_REPO_VCS_TOKEN", "should_not_be_used")

    async def setup_and_resolve():
        await state.upsert_repo(
            RepoConfigRecord(
                id="r2",
                full_name="off/repo",
                vcs_provider="github",
                vcs_token_ref="REPO_OFF_REPO_VCS_TOKEN",
                enabled=False,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )
        return await resolve_webhook_credentials(
            state=state, settings=settings, full_name="off/repo"
        )

    creds = asyncio.run(setup_and_resolve())
    assert creds.vcs_token == "env_t"
    assert creds.source == "env"


# ---------------------------------------------------------------------------
# 16. Startup: load_dotenv(data/repos_secrets.env) до Settings()
# ---------------------------------------------------------------------------


def test_startup_loads_repos_secrets_before_settings(tmp_path: Path, monkeypatch) -> None:
    """Симуляция рестарта: положили .env-файл → load_dotenv подгружает
    его до создания Settings() → значение доступно через os.environ."""
    from sunsec.app import _load_repos_secrets_if_present

    ref = "REPO_RESTART_TEST_VCS_TOKEN"
    monkeypatch.delenv(ref, raising=False)
    secrets_file = tmp_path / "repos_secrets.env"
    secrets_file.write_text(f"{ref}=loaded_after_restart_xyz\n", encoding="utf-8")

    assert os.environ.get(ref) is None
    ok = _load_repos_secrets_if_present(secrets_file)
    assert ok is True
    assert os.environ.get(ref) == "loaded_after_restart_xyz"
    monkeypatch.delenv(ref, raising=False)


def test_startup_no_file_returns_false(tmp_path: Path) -> None:
    from sunsec.app import _load_repos_secrets_if_present

    nope = tmp_path / "nonexistent.env"
    assert _load_repos_secrets_if_present(nope) is False


# ---------------------------------------------------------------------------
# 17. Logs do not contain plaintext secret on POST /repos
# ---------------------------------------------------------------------------


def test_post_repos_does_not_log_plaintext_secret(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    monkeypatch.delenv("REPO_LOG_TEST_VCS_TOKEN", raising=False)
    secrets_file = tmp_path / "repos_secrets.env"

    app, _ = _make_app(repos_secrets_path=secrets_file)
    with caplog.at_level("INFO", logger="sunsec.ui.console_router"):
        with TestClient(app) as client:
            resp = client.post(
                "/api/console/repos",
                json={
                    "fullName": "log/test",
                    "vcsProvider": "github",
                    "vcsToken": "PLAINTEXT_TOKEN_MUST_NOT_LEAK",
                    "webhookSecret": "PLAINTEXT_SECRET_MUST_NOT_LEAK",
                },
            )
            assert resp.status_code == 201

    log_text = "\n".join(record.getMessage() + " " + str(record.__dict__) for record in caplog.records)
    assert "PLAINTEXT_TOKEN_MUST_NOT_LEAK" not in log_text
    assert "PLAINTEXT_SECRET_MUST_NOT_LEAK" not in log_text

    monkeypatch.delenv("REPO_LOG_TEST_VCS_TOKEN", raising=False)
    monkeypatch.delenv("REPO_LOG_TEST_WEBHOOK_SECRET", raising=False)


# ---------------------------------------------------------------------------
# 18. GET /api/console/repos — listing
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 19. WebhookService — HMAC использует repo-specific secret из БД
# ---------------------------------------------------------------------------


def test_webhook_service_uses_db_secret_when_repo_registered(monkeypatch) -> None:
    """Webhook handler с зарегистрированным repo использует
    `webhook_secret` из env-переменной (по `webhook_secret_ref`),
    а не глобальный `Settings.webhook_secret`."""
    import hashlib
    import hmac
    import json

    from sunsec.contracts.storage import RepoConfigRecord
    from sunsec.state.memory import InMemoryStateStore
    from sunsec.vcs.github import GitHubAdapter
    from sunsec.webhook.service import EnqueueAnalysis, InvalidSignature, WebhookService

    state = InMemoryStateStore()
    settings = _make_settings(
        vcs_token="env_t",
        webhook_secret="env_global_secret",
    )

    db_secret = "db_specific_webhook_secret"
    monkeypatch.setenv("REPO_ALICE_PROJ_WEBHOOK_SECRET", db_secret)

    async def setup() -> None:
        await state.upsert_repo(
            RepoConfigRecord(
                id="r1",
                full_name="alice/proj",
                vcs_provider="github",
                webhook_secret_ref="REPO_ALICE_PROJ_WEBHOOK_SECRET",
                enabled=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )

    asyncio.run(setup())

    service = WebhookService(
        vcs=GitHubAdapter(token="t", api_base="https://api.github.com"),
        state=state,
        webhook_secret="env_global_secret",
        settings=settings,
    )

    # payload — pull_request opened на alice/proj
    user = {"login": "u", "id": 1}
    repo = {"full_name": "alice/proj", "owner": user}
    head = {"sha": "a" * 40, "ref": "f", "repo": repo}
    base = {"sha": "b" * 40, "ref": "main", "repo": repo}
    pr = {
        "id": 1,
        "number": 1,
        "state": "open",
        "title": "T-039 secret resolve test",
        "head": head,
        "base": base,
        "draft": False,
        "user": user,
    }
    payload = {
        "action": "opened",
        "number": 1,
        "pull_request": pr,
        "repository": repo,
        "sender": user,
    }
    body = json.dumps(payload).encode("utf-8")

    # Signature with DB secret — должно пройти HMAC.
    sig_db = "sha256=" + hmac.new(db_secret.encode(), body, hashlib.sha256).hexdigest()
    out = asyncio.run(
        service.handle(
            raw_body=body,
            headers={
                "X-Hub-Signature-256": sig_db,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "d-1",
            },
        )
    )
    assert isinstance(out, EnqueueAnalysis)

    # Signature with env-global secret — НЕ должно пройти (т.к. db_secret приоритетнее).
    sig_env = (
        "sha256="
        + hmac.new(b"env_global_secret", body, hashlib.sha256).hexdigest()
    )
    out2 = asyncio.run(
        service.handle(
            raw_body=body,
            headers={
                "X-Hub-Signature-256": sig_env,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "d-2",
            },
        )
    )
    assert isinstance(out2, InvalidSignature)

    monkeypatch.delenv("REPO_ALICE_PROJ_WEBHOOK_SECRET", raising=False)


# ---------------------------------------------------------------------------
# 20. GET /api/console/repos — listing
# ---------------------------------------------------------------------------


def test_get_repos_returns_camel_case_list(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("REPO_LIST_TEST_VCS_TOKEN", raising=False)
    secrets_file = tmp_path / "repos_secrets.env"

    app, _ = _make_app(repos_secrets_path=secrets_file)
    with TestClient(app) as client:
        r1 = client.post(
            "/api/console/repos",
            json={
                "fullName": "list/test",
                "vcsProvider": "github",
                "vcsToken": "t",
                "webhookSecret": "s",
            },
        )
        assert r1.status_code == 201

        r2 = client.get("/api/console/repos")
        assert r2.status_code == 200
        items = r2.json()
        assert len(items) == 1
        item = items[0]
        assert item["fullName"] == "list/test"
        assert "vcsTokenRef" in item
        assert "vcsTokenSet" in item

    monkeypatch.delenv("REPO_LIST_TEST_VCS_TOKEN", raising=False)
    monkeypatch.delenv("REPO_LIST_TEST_WEBHOOK_SECRET", raising=False)
