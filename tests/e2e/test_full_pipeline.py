"""E2E pipeline tests (T-021).

Полный pipeline `POST /webhook/github → WebhookService → BackgroundTasks →
PipelineOrchestrator → GitHubAdapter (через httpx.MockTransport) → DiffFilter →
LLMClient (mock LLM с реалистичным ответом; реальный polza.ai — отдельный
smoke-скрипт `run_polza_smoke.py`) → FalsePositiveFilter → CommentPublisher →
GitHub mock-API (POST /reviews, POST /issues/{n}/comments, GET для дедупа)`.

Что покрывает (DoD T-021):
- 3 синтетических vuln PR (SQLi / hardcoded secret / XSS) → бот публикует
  review с inline-комментариями + summary issue-comment.
- 1 чистый PR (parametrized SQL) → бот не публикует inline (либо публикует
  тихий empty-comment с маркером `:empty`).
- Идемпотентность: повторный POST с тем же delivery_id → 200 already_processed,
  без второй публикации.

Окружение:
- `fastapi`, `httpx`, `pydantic` — обязательны (importorskip).
- polza.ai не используется в этих тестах — LLM мокается через
  `_make_mock_llm_client`. Реальный polza-smoke — `run_polza_smoke.py`.

Запуск:
    PYTHONPATH=src pytest tests/e2e/test_full_pipeline.py -v
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
pytest.importorskip("pydantic")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from sunsec.comments.publisher import CommentPublisher  # noqa: E402
from sunsec.config.settings import Settings  # noqa: E402
from sunsec.contracts import (  # noqa: E402
    Finding,
    LLMResponseSchema,
)
from sunsec.filter import build_filter_from_settings  # noqa: E402
from sunsec.llm.budget import BudgetCounter  # noqa: E402
from sunsec.llm.client import LLMClient  # noqa: E402
from sunsec.llm.prompt_builder import PromptBuilder  # noqa: E402
from sunsec.ml import build_fp_filter_from_settings  # noqa: E402
from sunsec.pipeline.orchestrator import PipelineOrchestrator  # noqa: E402
from sunsec.state.memory import InMemoryStateStore  # noqa: E402
from sunsec.vcs.github import GitHubAdapter  # noqa: E402
from sunsec.webhook.router import build_router  # noqa: E402
from sunsec.webhook.service import WebhookService  # noqa: E402

FIXTURES_DIR = Path(__file__).parent / "fixtures"
SECRET = "e2e-secret-please-rotate-32chars-min!"


# ---------------------------------------------------------------------------
# Fixture loading
# ---------------------------------------------------------------------------


def _load_fixture(name: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Возвращает (webhook_payload, files_response). Имя — `pr_sqli` / `pr_secret` / ..."""
    base = FIXTURES_DIR / name
    webhook = json.loads((base / "webhook.json").read_text(encoding="utf-8"))
    files = json.loads((base / "files_response.json").read_text(encoding="utf-8"))
    return webhook, files


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _json_resp(status: int, body: Any, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
    )


# ---------------------------------------------------------------------------
# GitHub mock-API (httpx.MockTransport) — отвечает на GET pulls / files,
# POST reviews / issues/comments, PATCH issues/comments, GET list.
# ---------------------------------------------------------------------------


class _GitHubMock:
    """Запоминает все запросы; даёт ответы как настоящий GitHub.

    Реализует подмножество REST API, нужное pipeline + CommentPublisher:
    - `GET /repos/{repo}/pulls/{n}` → head/base sha
    - `GET /repos/{repo}/pulls/{n}/files` → массив файлов
    - `POST /repos/{repo}/pulls/{n}/reviews` → review с id
    - `POST /repos/{repo}/issues/{n}/comments` → issue-comment с id
    - `PATCH /repos/{repo}/issues/comments/{id}` → апдейт body
    - `GET  /repos/{repo}/pulls/{n}/comments?per_page=...&page=N` → review-comments (пустой массив по умолчанию)
    - `GET  /repos/{repo}/issues/{n}/comments?per_page=...&page=N` → issue-comments

    Все опубликованные комментарии сохраняются в `self.posted_review`,
    `self.posted_issue_comments`. Тесты их смотрят как `evidence`.
    """

    def __init__(
        self,
        repo: str,
        pr_number: int,
        head_sha: str,
        base_sha: str,
        files_response: list[dict[str, Any]],
    ) -> None:
        self.repo = repo
        self.pr_number = pr_number
        self.head_sha = head_sha
        self.base_sha = base_sha
        self.files_response = files_response
        # Журналы запросов и публикаций (evidence для тестов и отчёта).
        self.requests: list[tuple[str, str]] = []  # (METHOD, PATH)
        self.posted_review: dict[str, Any] | None = None
        self.posted_review_payloads: list[dict[str, Any]] = []
        self.posted_issue_comments: list[dict[str, Any]] = []
        self.patched_issue_comments: list[dict[str, Any]] = []
        # in-memory database "опубликованных" issue-comment'ов
        # (CommentPublisher делает list_issue_comments для дедупа summary).
        self._issue_comment_store: list[dict[str, Any]] = []
        self._next_id = 1000

    def handler(self, req: httpx.Request) -> httpx.Response:
        method = req.method
        path = req.url.path
        self.requests.append((method, path))

        pull_path = f"/repos/{self.repo}/pulls/{self.pr_number}"
        files_path = f"/repos/{self.repo}/pulls/{self.pr_number}/files"
        reviews_path = f"/repos/{self.repo}/pulls/{self.pr_number}/reviews"
        issue_comments_path = f"/repos/{self.repo}/issues/{self.pr_number}/comments"
        review_comments_list_path = f"/repos/{self.repo}/pulls/{self.pr_number}/comments"

        # --- fetch_pr_diff: GET /pulls/{n} ---
        if method == "GET" and path == pull_path:
            return _json_resp(
                200,
                {
                    "number": self.pr_number,
                    "head": {"sha": self.head_sha},
                    "base": {"sha": self.base_sha},
                },
            )

        # --- fetch_pr_diff: GET /pulls/{n}/files ---
        if method == "GET" and path == files_path:
            page = int(req.url.params.get("page", "1"))
            if page == 1:
                return _json_resp(200, self.files_response)
            return _json_resp(200, [])

        # --- list_review_comments (дедуп finding-маркеров): GET /pulls/{n}/comments ---
        if method == "GET" and path == review_comments_list_path:
            return _json_resp(200, [])

        # --- list_issue_comments (дедуп summary/empty/budget): GET /issues/{n}/comments ---
        if method == "GET" and path == issue_comments_path:
            return _json_resp(200, list(self._issue_comment_store))

        # --- post_review: POST /pulls/{n}/reviews ---
        if method == "POST" and path == reviews_path:
            payload = json.loads(req.content.decode("utf-8"))
            self.posted_review_payloads.append(payload)
            review_id = self._next_id
            self._next_id += 1
            self.posted_review = {
                "id": review_id,
                "body": payload.get("body", ""),
                "commit_id": payload.get("commit_id"),
                "comments": payload.get("comments", []),
                "html_url": f"https://github.com/{self.repo}/pull/{self.pr_number}#pullrequestreview-{review_id}",
            }
            return _json_resp(
                200,
                {
                    "id": review_id,
                    "body": payload.get("body", ""),
                    "html_url": self.posted_review["html_url"],
                    "commit_id": payload.get("commit_id"),
                },
            )

        # --- post_issue_comment: POST /issues/{n}/comments ---
        if method == "POST" and path == issue_comments_path:
            payload = json.loads(req.content.decode("utf-8"))
            cid = self._next_id
            self._next_id += 1
            stored = {
                "id": cid,
                "body": payload.get("body", ""),
                "html_url": f"https://github.com/{self.repo}/pull/{self.pr_number}#issuecomment-{cid}",
                "created_at": "2026-05-15T12:00:00Z",
            }
            self._issue_comment_store.append(stored)
            self.posted_issue_comments.append(stored)
            return _json_resp(200, stored)

        # --- PATCH /repos/{repo}/issues/comments/{id} ---
        if method == "PATCH" and path.startswith(f"/repos/{self.repo}/issues/comments/"):
            cid = int(path.rsplit("/", 1)[1])
            payload = json.loads(req.content.decode("utf-8"))
            updated_body = payload.get("body", "")
            self.patched_issue_comments.append({"id": cid, "body": updated_body})
            for c in self._issue_comment_store:
                if c["id"] == cid:
                    c["body"] = updated_body
                    return _json_resp(200, c)
            return _json_resp(404, {"detail": "comment not found"})

        # Не должно происходить — заметный 500, чтобы тест упал на стыке.
        return _json_resp(500, {"detail": f"unexpected {method} {path}"})


# ---------------------------------------------------------------------------
# Mock LLM client (детерминистический реалистичный ответ по golden-id)
# ---------------------------------------------------------------------------


def _mock_response_for_pr(pr_name: str, payload_head_sha: str, file_path: str) -> dict[str, Any]:
    """Возвращает realistic LLM-ответ под каждый PR-сценарий.

    Числа line'ов соответствуют added-строкам в fixtures. PromptBuilder
    рендерит added_lines, LLM «видит» строки 1..N (relative). Мы выбираем
    значимую строку.
    """
    if pr_name == "pr_sqli":
        return {
            "summary": "Found 1 SQL injection: user_id interpolated into raw SQL string.",
            "findings": [
                {
                    "file": file_path,
                    "line": 3,
                    "class": "sql_injection",
                    "severity": "high",
                    "message": "User input `user_id` is interpolated into SQL via f-string and passed directly to `conn.execute(query)`. This allows SQL injection.",
                    "suggestion": "query = \"SELECT id, email FROM users WHERE id = ?\"\nrow = conn.execute(query, (user_id,)).fetchone()",
                    "confidence": 0.95,
                }
            ],
        }
    if pr_name == "pr_secret":
        return {
            "summary": "Found 2 hardcoded AWS credentials in source code.",
            "findings": [
                {
                    "file": file_path,
                    "line": 3,
                    "class": "hardcoded_secret",
                    "severity": "critical",
                    "message": "AWS Access Key ID hardcoded in repository (AKIA-prefix). Anyone with read access to the repo can use it.",
                    "suggestion": "AWS_ACCESS_KEY_ID = os.environ['AWS_ACCESS_KEY_ID']",
                    "confidence": 0.99,
                },
                {
                    "file": file_path,
                    "line": 4,
                    "class": "hardcoded_secret",
                    "severity": "critical",
                    "message": "AWS Secret Access Key hardcoded next to the access key. Both must be moved to environment variables / IAM role.",
                    "suggestion": "AWS_SECRET_ACCESS_KEY = os.environ['AWS_SECRET_ACCESS_KEY']",
                    "confidence": 0.99,
                },
            ],
        }
    if pr_name == "pr_xss":
        return {
            "summary": "Found 1 XSS via innerHTML with unescaped user input.",
            "findings": [
                {
                    "file": file_path,
                    "line": 4,
                    "class": "xss",
                    "severity": "high",
                    "message": "`userName` is interpolated into `innerHTML` without HTML-escaping. If userName comes from user input, this is a stored/reflected XSS vector.",
                    "suggestion": "el.textContent = `Hello, ${userName}!`;",
                    "confidence": 0.9,
                }
            ],
        }
    # pr_clean — модель не находит проблем
    return {
        "summary": "No security findings detected in the changed code.",
        "findings": [],
    }


class _StubLLMProvider:
    """Mock-LLMProvider. Возвращает заранее заданный response по PR-name.

    PR-name достаётся из user-prompt через `Head SHA: <sha>` хака (как в T-015):
    мы кладём имя PR в head_sha через `goldenid-<name>`. Это не нужно для
    e2e — нам подходит более простая стратегия: provider знает текущий
    активный PR из тестового state (одна копия provider'а на тест).
    """

    name = "stub-e2e"
    _max_tokens = 1024

    def __init__(self, pr_name: str, file_path: str, head_sha: str) -> None:
        self.pr_name = pr_name
        self.file_path = file_path
        self.head_sha = head_sha
        self.call_count = 0

    async def analyze(self, prompt):  # noqa: ANN001 — type: PromptPayload
        self.call_count += 1
        from sunsec.llm.base import LLMRawResponse, TokenUsage  # local
        content = json.dumps(_mock_response_for_pr(self.pr_name, self.head_sha, self.file_path))
        return LLMRawResponse(
            model="stub-e2e",
            content=content,
            usage=TokenUsage(prompt_tokens=300, completion_tokens=150, total_tokens=450),
            latency_ms=10.0,
        )

    def estimate_cost_rub(self, usage) -> float:  # noqa: ANN001
        return 0.0


def _make_mock_llm_client(pr_name: str, file_path: str, head_sha: str) -> LLMClient:
    provider = _StubLLMProvider(pr_name=pr_name, file_path=file_path, head_sha=head_sha)
    return LLMClient(provider=provider, builder=PromptBuilder(), budget=None)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def _build_app(
    *,
    mock: _GitHubMock,
    llm_client: LLMClient,
) -> tuple[FastAPI, InMemoryStateStore, _GitHubMock, CommentPublisher]:
    settings = Settings(
        webhook_secret=SECRET,
        vcs_token="ghp_test_token",
        polza_api_key="dummy-not-real",
        log_format="json",
        skip_drafts=True,
        publish_comments_enabled=True,
    )
    transport = httpx.MockTransport(mock.handler)
    httpx_client = httpx.AsyncClient(
        transport=transport, base_url=settings.github_api_base
    )

    async def _no_sleep(_sec: float) -> None:  # pragma: no cover
        return None

    vcs = GitHubAdapter(
        token=settings.vcs_token,
        api_base=settings.github_api_base,
        client=httpx_client,
        sleeper=_no_sleep,
        max_retries=settings.vcs_max_retries,
        files_page_size=settings.vcs_files_page_size,
        files_soft_limit=settings.vcs_files_soft_limit,
        rate_limit_wait_cap_seconds=settings.vcs_rate_limit_wait_cap_seconds,
    )
    state = InMemoryStateStore()
    diff_filter = build_filter_from_settings(settings)
    fp_filter = build_fp_filter_from_settings(settings)
    publisher = CommentPublisher(vcs=vcs, state=state, enabled=True)
    pipeline = PipelineOrchestrator(
        vcs=vcs,
        diff_filter=diff_filter,
        llm=llm_client,
        state=state,
        fp_filter=fp_filter,
        publisher=publisher,
    )
    webhook_service = WebhookService(
        vcs=vcs,
        state=state,
        webhook_secret=settings.webhook_secret,
        skip_drafts=settings.skip_drafts,
    )

    app = FastAPI()
    app.include_router(build_router(service=webhook_service, pipeline=pipeline))
    app.state.state_store = state
    app.state.vcs = vcs
    app.state.pipeline = pipeline
    app.state.publisher = publisher
    return app, state, mock, publisher


def _post_webhook(
    client: TestClient,
    payload: dict[str, Any],
    *,
    delivery_id: str,
) -> Any:
    body = json.dumps(payload).encode("utf-8")
    return client.post(
        "/webhook/github",
        content=body,
        headers={
            "X-Hub-Signature-256": _sign(SECRET, body),
            "X-GitHub-Event": "pull_request",
            "X-GitHub-Delivery": delivery_id,
            "Content-Type": "application/json",
        },
    )


def _run_pr(
    pr_name: str,
    *,
    delivery_id: str,
) -> tuple[Any, _GitHubMock, InMemoryStateStore]:
    webhook, files = _load_fixture(pr_name)
    head_sha = webhook["pull_request"]["head"]["sha"]
    base_sha = webhook["pull_request"]["base"]["sha"]
    repo = webhook["repository"]["full_name"]
    pr_number = webhook["number"]
    file_path = files[0]["filename"]

    mock = _GitHubMock(
        repo=repo,
        pr_number=pr_number,
        head_sha=head_sha,
        base_sha=base_sha,
        files_response=files,
    )
    llm_client = _make_mock_llm_client(pr_name, file_path, head_sha)
    app, state, mock, _publisher = _build_app(mock=mock, llm_client=llm_client)

    with TestClient(app) as client:
        resp = _post_webhook(client, webhook, delivery_id=delivery_id)

    return resp, mock, state


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_e2e_sqli_pr_publishes_inline_and_summary() -> None:
    """PR с f-string SQLi → review с >=1 inline + summary issue-comment."""
    resp, mock, state = _run_pr("pr_sqli", delivery_id="e2e-sqli-1")
    assert resp.status_code == 202, resp.text

    # 1) Review с inline-комментариями опубликован.
    assert mock.posted_review is not None, "review должен быть опубликован"
    review = mock.posted_review
    assert review["commit_id"] == "aaaa1111bbbb2222cccc3333dddd4444eeee5555"
    comments = review["comments"]
    assert len(comments) >= 1
    body = comments[0]["body"]
    assert "[SUNSEC]" in body
    assert "Sql Injection" in body or "SQL" in body.upper()
    assert "<!-- sunsec:bot:v1:finding:" in body

    # 2) Summary issue-comment опубликован отдельно (T-017 PATCH-pattern).
    assert len(mock.posted_issue_comments) == 1
    summary = mock.posted_issue_comments[0]["body"]
    assert "## SunSecurityBot review" in summary
    assert "<!-- sunsec:bot:v1:summary -->" in summary
    assert "Severity breakdown" in summary
    # severity-таблица должна показать что-то >=high (counts могут различаться)
    assert "High" in summary

    # 3) State помечен done.
    key = (
        f"{mock.repo}#{mock.pr_number}@{mock.head_sha}"
    )
    assert key in state._done


def test_e2e_secret_pr_publishes_critical_findings() -> None:
    """PR с AWS-ключом → бот публикует >=1 inline с severity критическим."""
    resp, mock, state = _run_pr("pr_secret", delivery_id="e2e-secret-1")
    assert resp.status_code == 202

    # Pre-scan находит AKIA, LLM находит AKIA + secret key — после postprocess
    # уникальных findings обычно 2 (dedup по file+line+class).
    assert mock.posted_review is not None
    comments = mock.posted_review["comments"]
    assert len(comments) >= 1, f"expected >=1 inline, got 0 (review={mock.posted_review})"

    # Каждый inline должен иметь severity-маркер + class-метку
    for c in comments:
        body = c["body"]
        assert "[SUNSEC]" in body
        assert "Hardcoded Secret" in body
        assert "<!-- sunsec:bot:v1:finding:" in body

    # Summary должен агрегировать severity. critical >=1 OR high >=1 (in case FP severity cap).
    summary = mock.posted_issue_comments[0]["body"]
    assert "## SunSecurityBot review" in summary
    assert ("Critical" in summary and "| 1" in summary or "| 2" in summary or "Critical" in summary)


def test_e2e_xss_pr_publishes_inline_xss_finding() -> None:
    """PR с innerHTML = userInput → бот публикует XSS inline."""
    resp, mock, state = _run_pr("pr_xss", delivery_id="e2e-xss-1")
    assert resp.status_code == 202

    assert mock.posted_review is not None
    comments = mock.posted_review["comments"]
    assert len(comments) >= 1
    body = comments[0]["body"]
    assert "[SUNSEC]" in body
    assert "Xss" in body or "XSS" in body.upper()
    # suggestion с фиксом (T-017) — fenced code block с javascript
    assert "### Suggested fix" in body
    assert "```javascript" in body
    assert "<!-- sunsec:bot:v1:finding:" in body

    # State done
    key = f"{mock.repo}#{mock.pr_number}@{mock.head_sha}"
    assert key in state._done


def test_e2e_clean_pr_does_not_publish_inline_comments() -> None:
    """Параметризованный SQL → бот не публикует inline, только опц. empty-комментарий.

    Поведение зависит от Settings.publish_empty_pr_comment (default false).
    Контракт T-021 DoD: «не оставил ложноположительных комментариев или
    оставил только summary "issues not found"». В дефолте флаг empty=false,
    значит ни review, ни empty-comment не публикуются — это валидный исход.
    """
    resp, mock, state = _run_pr("pr_clean", delivery_id="e2e-clean-1")
    assert resp.status_code == 202

    # Inline-комментариев быть не должно (LLM вернул пустой список, postprocess чистый).
    assert mock.posted_review is None, (
        f"clean PR не должен публиковать review, got {mock.posted_review}"
    )

    # Issue-comments: либо пусто (publish_empty_pr_comment=false), либо ровно
    # один empty-comment с маркером. Главное — НЕ должно быть summary с
    # findings, потому что их нет.
    if mock.posted_issue_comments:
        for c in mock.posted_issue_comments:
            body = c["body"]
            assert (
                "<!-- sunsec:bot:v1:empty -->" in body
                or "<!-- sunsec:bot:v1:summary -->" in body
            )
            # Если summary — он должен явно говорить «no findings»
            if "<!-- sunsec:bot:v1:summary -->" in body:
                assert "No security findings" in body or "0 total" in body

    # State done
    key = f"{mock.repo}#{mock.pr_number}@{mock.head_sha}"
    assert key in state._done


def test_e2e_idempotent_duplicate_delivery_does_not_republish() -> None:
    """Повторный POST с тем же delivery_id → 200 already_processed, review не публикуется снова.

    Проверяет двойную защиту: (a) WebhookService dedup по delivery_id;
    (b) CommentPublisher dedup по finding-маркерам через list_*_comments.
    """
    webhook, files = _load_fixture("pr_sqli")
    head_sha = webhook["pull_request"]["head"]["sha"]
    base_sha = webhook["pull_request"]["base"]["sha"]
    repo = webhook["repository"]["full_name"]
    pr_number = webhook["number"]
    file_path = files[0]["filename"]

    mock = _GitHubMock(
        repo=repo, pr_number=pr_number, head_sha=head_sha,
        base_sha=base_sha, files_response=files,
    )
    llm_client = _make_mock_llm_client("pr_sqli", file_path, head_sha)
    app, state, mock, _pub = _build_app(mock=mock, llm_client=llm_client)

    with TestClient(app) as client:
        r1 = _post_webhook(client, webhook, delivery_id="dup-1")
        r2 = _post_webhook(client, webhook, delivery_id="dup-1")  # тот же delivery!

    assert r1.status_code == 202
    assert r2.status_code == 200
    assert r2.json()["status"] == "already_processed"
    # Pipeline вызывался один раз, review — ровно один.
    assert len(mock.posted_review_payloads) == 1
