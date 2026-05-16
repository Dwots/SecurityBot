"""End-to-end smoke test для M-9 «Persistence, Console UI & Repo Onboarding».

Финальный gate-тест T-041 (QA). Проверяет полный поток:
    /ui  →  POST /api/console/repos  →  PipelineOrchestrator.process_pr
         →  SQLite (checks + findings)  →  GET /api/console/checks
         →  GET /api/console/checks/{id}  →  DELETE /api/console/repos/{id}

Запуск:
    PYTHONPATH=src .venv/bin/pytest tests/integration/test_m9_e2e_smoke.py -v

Ключевые свойства теста:
* `ENABLE_CONSOLE_UI=true` + `SUNSEC_DB_PATH=<tmp>/test_m9_e2e.db`
  (свежий файл, удаляется в фикстуре).
* `httpx.AsyncClient(ASGITransport(app))` — никакого реального TCP / GitHub /
  polza.ai / OpenRouter. 0 ₽ LLM-spend.
* LLM-вызов **замокирован** (`AsyncMock(return_value=LLMResponseSchema(...))`),
  pipeline получает 1 SQLi-finding и пишет его в SQLite.
* После прогона проверяется `vcs_token_ref` колонка `repo_configs` — реальный
  плейсхолдер `ghp_qa_test_only_not_real` НЕ должен быть в БД (только имя
  env-переменной).

Регрессионный набор: запускается через `pytest tests/ -q`, попадает в общий
счётчик passed-тестов M-9 (baseline T-039 = 259).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

# --- Skip-on-missing-deps ---------------------------------------------------
pytest.importorskip("fastapi")
pytest.importorskip("httpx")
pytest.importorskip("aiosqlite")
pytest.importorskip("pydantic")
pytest.importorskip("dotenv")

import aiosqlite  # noqa: E402
import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from sunsec.config.settings import Settings  # noqa: E402
from sunsec.contracts import (  # noqa: E402
    GitHubPullRequestEvent,
)
from sunsec.contracts.llm_response import Finding, LLMResponseSchema  # noqa: E402
from sunsec.llm.client import LLMClient  # noqa: E402
from sunsec.pipeline.orchestrator import PipelineOrchestrator  # noqa: E402
from sunsec.storage import build_storage_from_settings, run_migrations  # noqa: E402
from sunsec.storage.sqlite_store import SQLiteStateStore  # noqa: E402
from sunsec.ui.console_router import build_console_router  # noqa: E402


# ----- Helpers ---------------------------------------------------------------


def _build_event(
    *,
    repo: str = "qa-test/m9-smoke",
    pr_number: int = 1,
    head_sha: str = "h1" + "a" * 38,
    base_sha: str = "b1" + "a" * 38,
) -> GitHubPullRequestEvent:
    """Минимально-валидный GitHubPullRequestEvent для pipeline.process_pr.

    Использует computed_field-свойства `event.repo` / `event.pr_number` /
    `event.head_sha` (ADR-5).
    """
    user = {"login": "qa-bot", "id": 1}
    repo_obj = {"full_name": repo, "owner": user}
    payload = {
        "action": "opened",
        "number": pr_number,
        "pull_request": {
            "id": 1000,
            "number": pr_number,
            "state": "open",
            "title": "T-041 QA smoke PR",
            "head": {"sha": head_sha, "ref": "vuln-demo", "repo": repo_obj},
            "base": {"sha": base_sha, "ref": "main", "repo": repo_obj},
            "draft": False,
            "user": user,
        },
        "repository": repo_obj,
        "sender": user,
    }
    return GitHubPullRequestEvent.model_validate(payload)


def _pr_diff_fixture(repo: str, pr_number: int) -> Any:
    """Мини-PRDiff (raw) → проходит через DiffFilter → FilteredDiff с 1 vuln-файлом."""
    from sunsec.contracts.diff import (
        DiffFile,
        DiffHunk,
        DiffLine,
        PRDiff,
    )

    line_content = "    cursor.execute(f\"SELECT * FROM u WHERE n='{name}'\")"
    hunk = DiffHunk(
        old_start=1,
        old_lines=1,
        new_start=10,
        new_lines=1,
        lines=[
            DiffLine(
                type="added",
                old_line_no=None,
                new_line_no=10,
                content=line_content,
            )
        ],
    )
    file = DiffFile(
        path="app/views.py",
        status="modified",
        hunks=[hunk],
    )
    return PRDiff(
        repo=repo,
        pr_number=pr_number,
        head_sha="h1" + "a" * 38,
        base_sha="b1" + "a" * 38,
        files=[file],
    )


def _filtered_diff_fixture(repo: str, pr_number: int) -> Any:
    """Готовый FilteredDiff (для pass-through diff_filter)."""
    from sunsec.contracts.diff import AddedLine, FilteredDiff, FilteredDiffFile

    file = FilteredDiffFile(
        path="app/views.py",
        language="python",
        added_lines=[
            AddedLine(
                new_line_no=10,
                content="    cursor.execute(f\"SELECT * FROM u WHERE n='{name}'\")",
            )
        ],
    )
    return FilteredDiff(
        repo=repo,
        pr_number=pr_number,
        head_sha="h1" + "a" * 38,
        files=[file],
    )


# ----- Fixtures --------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Чистая SQLite-БД, удаляется автоматически по окончании теста."""
    p = tmp_path / "test_m9_e2e.db"
    if p.exists():
        p.unlink()
    return p


@pytest.fixture
def repos_secrets_path(tmp_path: Path) -> Path:
    """Подменённый `data/repos_secrets.env` (RT-012). Удаляется автоматически."""
    return tmp_path / "repos_secrets.env"


@pytest.fixture
def settings(db_path: Path) -> Settings:
    return Settings(
        app_env="test",
        enable_console_ui=True,
        sunsec_db_path=str(db_path),
        vcs_token="dummy",
        webhook_secret="dummy",
        polza_api_key="dummy",
        openrouter_api_key="dummy",
        publish_comments_enabled=False,  # без реальных VCS-вызовов
        log_format="json",
    )


@pytest.fixture
def state_store(settings: Settings) -> SQLiteStateStore:
    """Реальный `SQLiteStateStore` с применёнными миграциями."""
    state = build_storage_from_settings(settings)
    assert isinstance(state, SQLiteStateStore)
    asyncio.run(run_migrations(state.db_path))
    return state


@pytest.fixture
def app(
    settings: Settings,
    state_store: SQLiteStateStore,
    repos_secrets_path: Path,
) -> FastAPI:
    """Собирает FastAPI-app с реальным console-router'ом + SQLite-store."""
    a = FastAPI()
    router = build_console_router(
        state=state_store,
        settings=settings,
        llm_client=None,  # /budget вернёт нули — это OK для smoke
        manual_analyze_handler=None,
        repos_secrets_path=repos_secrets_path,
    )
    a.include_router(router)
    return a


# ----- Test ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_m9_e2e_smoke_full_flow(
    app: FastAPI,
    state_store: SQLiteStateStore,
    settings: Settings,
    db_path: Path,
    repos_secrets_path: Path,
) -> None:
    """Финальный e2e M-9 — 11 шагов согласно DoD T-041.

    Шаги:
      1. GET /api/console/repos → 200, [].
      2. POST /api/console/repos → 201, без plaintext-токена в response.
      3. GET /api/console/repos → 200, 1 элемент с vcsTokenSet=True.
      4. DB-check: vcs_token_ref в repo_configs = REPO_QA_TEST_M9_SMOKE_VCS_TOKEN
         (никакого плейсхолдера 'ghp_qa_test_only_not_real').
      5. Pipeline-вызов (с mocked LLM) → запись в `checks` + `findings`.
      6. GET /api/console/checks → 200, ≥1 элемент с repo=qa-test/m9-smoke.
      7. GET /api/console/checks/{id} → 200, findings[] + summary.
      8. DB-counts: checks ≥1, findings ≥1.
      9. PATCH /api/console/repos/{id} → toggle enabled.
     10. DELETE /api/console/repos/{id} → 204.
     11. GET /api/console/repos → 200, [].
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:

        # --- Step 1: empty list ---------------------------------------------
        r = await client.get("/api/console/repos")
        assert r.status_code == 200, r.text
        assert r.json() == []

        # --- Step 2: POST /repos --------------------------------------------
        token_placeholder = "ghp_qa_test_only_not_real"
        webhook_secret_plain = "sssss-qa-test-secret"
        body = {
            "fullName": "qa-test/m9-smoke",
            "vcsProvider": "github",
            "vcsToken": token_placeholder,
            "webhookSecret": webhook_secret_plain,
            "enabled": True,
        }
        r = await client.post("/api/console/repos", json=body)
        assert r.status_code == 201, r.text
        created = r.json()
        # Plaintext-токен НЕ должен быть в response.
        response_text = r.text
        assert token_placeholder not in response_text, (
            "vcs_token plaintext НЕ должен быть в response. Содержимое: " + response_text
        )
        assert webhook_secret_plain not in response_text, (
            "webhook_secret plaintext НЕ должен быть в response."
        )
        assert created["fullName"] == "qa-test/m9-smoke"
        assert created["vcsTokenSet"] is True
        assert created["webhookSecretSet"] is True
        assert created["vcsTokenRef"] == "REPO_QA_TEST_M9_SMOKE_VCS_TOKEN"
        repo_id = created["id"]

        # --- Step 3: GET /repos → 1 element ---------------------------------
        r = await client.get("/api/console/repos")
        assert r.status_code == 200
        items = r.json()
        assert len(items) == 1
        assert items[0]["fullName"] == "qa-test/m9-smoke"
        assert items[0]["vcsTokenSet"] is True

        # --- Step 4: DB-check vcs_token_ref ---------------------------------
        async with aiosqlite.connect(str(db_path)) as db:
            cur = await db.execute(
                "SELECT vcs_token_ref, webhook_secret_ref FROM repo_configs WHERE full_name=?",
                ("qa-test/m9-smoke",),
            )
            row = await cur.fetchone()
            assert row is not None
            vcs_token_ref, webhook_secret_ref = row
            assert vcs_token_ref == "REPO_QA_TEST_M9_SMOKE_VCS_TOKEN"
            assert webhook_secret_ref == "REPO_QA_TEST_M9_SMOKE_WEBHOOK_SECRET"
            # Plaintext в DB не должен встречаться.
            assert "ghp_" not in (vcs_token_ref or "")
            assert "sssss" not in (vcs_token_ref or "")

            # Дополнительно: secret в .env-файле (RT-012), а не plaintext в БД.
            assert repos_secrets_path.exists(), (
                "data/repos_secrets.env должен быть создан (RT-012 backend-fix)"
            )

        # --- Step 5: pipeline.process_pr (with mocked LLM) -------------------
        # Создаём pipeline вручную, чтобы НЕ ходить в реальный GitHub.
        event = _build_event()
        pr_diff = _pr_diff_fixture(event.repo, event.pr_number)
        filtered = _filtered_diff_fixture(event.repo, event.pr_number)

        # Mock VCS.fetch_pr_diff → PRDiff (raw, как реальный адаптер).
        vcs_mock = AsyncMock()
        vcs_mock.fetch_pr_diff = AsyncMock(return_value=pr_diff)

        # Mock LLM.analyze → 1 SQLi-finding.
        llm_response = LLMResponseSchema(
            findings=[
                Finding(
                    file="app/views.py",
                    line=10,
                    **{"class": "sql_injection"},
                    severity="high",
                    message="SQL-инъекция через f-string в cursor.execute() с пользовательским name.",
                    suggestion="cursor.execute('SELECT * FROM u WHERE n=?', (name,))",
                    confidence=0.95,
                ),
            ],
            summary="1 SQLi finding detected in app/views.py:10 (test fixture).",
        )
        llm_client_mock = AsyncMock(spec=LLMClient)
        llm_client_mock.analyze = AsyncMock(return_value=llm_response)
        # prompt_version — реальный attr (синхронный)
        type(llm_client_mock).prompt_version = property(lambda self: "test-v1")

        # diff_filter: PRDiff → FilteredDiff (фикстура).
        class _PassThroughFilter:
            def __init__(self, fd: Any) -> None:
                self._fd = fd

            def apply(self, _diff: Any) -> Any:
                return self._fd

        # fp_filter no-op
        class _PassThroughFp:
            def pre_llm_scan(self, _: Any) -> list:
                return []

            def postprocess(self, llm_findings: list, _diff: Any, _pre: list) -> list:
                return list(llm_findings)

        pipeline = PipelineOrchestrator(
            vcs=vcs_mock,
            diff_filter=_PassThroughFilter(filtered),
            llm=llm_client_mock,
            state=state_store,
            fp_filter=_PassThroughFp(),
            publisher=None,  # publish_comments_enabled=False ничего и не вызовет
        )

        await pipeline.process_pr(event)

        # --- Step 6: GET /api/console/checks --------------------------------
        r = await client.get("/api/console/checks")
        assert r.status_code == 200, r.text
        checks = r.json()
        assert len(checks) >= 1, f"expected ≥1 check, got {checks}"
        matching = [c for c in checks if c["repository"] == "qa-test/m9-smoke"]
        assert len(matching) >= 1, f"expected check for qa-test/m9-smoke, got {checks}"
        check_id = matching[0]["id"]
        # Pipeline статус — finalize success → done/completed.
        assert matching[0]["status"] in {"completed", "done", "in_progress", "received"}, (
            matching[0]["status"]
        )

        # --- Step 7: GET /api/console/checks/{id} ---------------------------
        r = await client.get(f"/api/console/checks/{check_id}")
        assert r.status_code == 200, r.text
        details = r.json()
        assert details["id"] == check_id
        # findings[] — может быть пустым (если pipeline по какой-то причине
        # не дошёл до save_findings), но в этом тесте mock-LLM вернул 1 finding.
        assert isinstance(details["findings"], list)
        assert len(details["findings"]) >= 1, (
            f"expected ≥1 finding (mock LLM returned 1), got {details['findings']}"
        )
        finding = details["findings"][0]
        assert finding["file"] == "app/views.py"
        assert finding["line"] == 10
        assert finding["class"] == "sql_injection"
        assert finding["severity"] == "high"
        assert "summary" in details
        assert isinstance(details["timeline"], list)

        # --- Step 8: DB counts ---------------------------------------------
        async with aiosqlite.connect(str(db_path)) as db:
            cur = await db.execute("SELECT COUNT(*) FROM checks")
            (checks_count,) = await cur.fetchone()
            assert checks_count >= 1, f"expected ≥1 check row, got {checks_count}"

            cur = await db.execute("SELECT COUNT(*) FROM findings")
            (findings_count,) = await cur.fetchone()
            assert findings_count >= 1, f"expected ≥1 finding row, got {findings_count}"

            cur = await db.execute("SELECT COUNT(*) FROM repo_configs")
            (repos_count,) = await cur.fetchone()
            assert repos_count == 1

        # --- Step 9: PATCH toggle enabled -----------------------------------
        r = await client.patch(
            f"/api/console/repos/{repo_id}", json={"enabled": False}
        )
        assert r.status_code == 200, r.text
        assert r.json()["enabled"] is False

        # --- Step 10: DELETE /repos/{id} ------------------------------------
        r = await client.delete(f"/api/console/repos/{repo_id}")
        assert r.status_code == 204, r.text

        # --- Step 11: GET /repos → [] ---------------------------------------
        r = await client.get("/api/console/repos")
        assert r.status_code == 200
        assert r.json() == []


@pytest.mark.asyncio
async def test_m9_e2e_smoke_ui_route_serves_console_html(
    app: FastAPI,
    settings: Settings,
) -> None:
    """`GET /ui` отдаёт реальный production-фронт (T-040), не M-6 placeholder.

    Поскольку console-router НЕ включает `/ui` (это `build_ui_router` из M-6),
    отдельно собираем app с обоими, чтобы проверить статический файл.
    """
    pytest.importorskip("fastapi")
    from fastapi import FastAPI as _FA

    from sunsec.ui.router import build_ui_router

    a = _FA()
    ui_router = build_ui_router(
        llm_client=None,
        fp_filter=None,
        diff_filter=None,
        budget=None,
    )
    a.include_router(ui_router)

    transport = httpx.ASGITransport(app=a)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        r = await client.get("/ui")
        assert r.status_code == 200
        body = r.text
        # Production-фронт T-040 (single-file с Tailwind CDN + console-нав).
        assert "<title>SunSecurityBot Console" in body, (
            "expected production index.html title, got placeholder"
        )
        # Признак, что это НЕ M-6 placeholder (M-6 был «Test UI»):
        assert "Test UI" not in body or "/api/console/" in body, (
            "expected production UI, not M-6 placeholder"
        )
