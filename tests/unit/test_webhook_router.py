"""HTTP-уровневые тесты webhook-роутера (FastAPI TestClient).

Покрытие (по DoD T-007):
  - valid signature + 200/202 → запуск pipeline через BackgroundTasks.
  - invalid signature → 401, тело `{"detail":"invalid signature"}` без диагностики.
  - ignored action → 200 без обработки.
  - duplicate delivery_id → 200, pipeline не вызывается повторно.
  - GET /health → 200.

Если FastAPI / TestClient недоступны (нет зависимостей в окружении
оркестратора) — модуль `pytest.skip`'ит весь файл.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import List

import pytest

# Если fastapi/httpx нет — пропускаем модуль целиком.
fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient

from sunsec.contracts import GitHubPullRequestEvent
from sunsec.state.memory import InMemoryStateStore
from sunsec.vcs.github import GitHubAdapter
from sunsec.webhook.router import build_router
from sunsec.webhook.service import WebhookService

SECRET = "test-webhook-secret-please-rotate"


def _signature(secret: str, body: bytes) -> str:
    return f"sha256={hmac.new(secret.encode('utf-8'), body, hashlib.sha256).hexdigest()}"


def _payload(action: str = "opened", *, draft: bool = False, head_sha: str = "cafe" * 10) -> dict:
    user = {"login": "alice", "id": 1}
    repo = {"full_name": "alice/proj", "owner": user}
    head = {"sha": head_sha, "ref": "feature", "repo": repo}
    base = {"sha": "feedface" * 5, "ref": "main", "repo": repo}
    pr = {
        "id": 100,
        "number": 42,
        "state": "open",
        "title": "T-007 router test",
        "head": head,
        "base": base,
        "draft": draft,
        "user": user,
    }
    return {
        "action": action,
        "number": 42,
        "pull_request": pr,
        "repository": repo,
        "sender": user,
    }


class FakePipeline:
    """Pipeline-шпион: записывает все вызовы process_pr (для проверки идемпотентности)."""

    def __init__(self) -> None:
        self.calls: List[GitHubPullRequestEvent] = []

    async def process_pr(self, event: GitHubPullRequestEvent) -> None:
        self.calls.append(event)


def _build_app(*, skip_drafts: bool = True):
    from fastapi import FastAPI  # noqa: PLC0415

    vcs = GitHubAdapter(token="dummy", api_base="https://api.github.com")
    state = InMemoryStateStore()
    pipeline = FakePipeline()
    service = WebhookService(vcs=vcs, state=state, webhook_secret=SECRET, skip_drafts=skip_drafts)
    app = FastAPI()
    app.include_router(build_router(service=service, pipeline=pipeline))
    app.state.pipeline = pipeline
    app.state.state_store = state
    return app


# --- Health ---------------------------------------------------------------


def test_health_endpoint_returns_200() -> None:
    app = _build_app()
    with TestClient(app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "service": "sunsec"}


# --- Valid signature + 202 + pipeline triggered ---------------------------


def test_valid_webhook_returns_202_and_triggers_pipeline() -> None:
    app = _build_app()
    body = json.dumps(_payload(action="opened")).encode("utf-8")
    sig = _signature(SECRET, body)

    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "router-valid-1",
                "Content-Type": "application/json",
            },
        )

    assert resp.status_code == 202
    body_json = resp.json()
    assert body_json["status"] == "accepted"
    assert body_json["repo"] == "alice/proj"
    assert body_json["pr_number"] == 42

    # BackgroundTasks выполняются после ответа — TestClient ждёт их.
    assert len(app.state.pipeline.calls) == 1
    assert app.state.pipeline.calls[0].action == "opened"


# --- Invalid signature → 401, без диагностики -----------------------------


def test_invalid_signature_returns_401_without_diagnostics() -> None:
    app = _build_app()
    body = json.dumps(_payload()).encode("utf-8")

    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": "sha256=" + "0" * 64,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "router-badsig-1",
            },
        )

    assert resp.status_code == 401
    assert resp.json() == {"detail": "invalid signature"}
    # Pipeline не запускается.
    assert app.state.pipeline.calls == []


# --- Ignored event_type → 200, без обработки ------------------------------


def test_unsupported_event_type_returns_200_without_processing() -> None:
    app = _build_app()
    body = b'{"zen":"any"}'
    sig = _signature(SECRET, body)
    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "issues",
                "X-GitHub-Delivery": "router-issues-1",
            },
        )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"
    assert app.state.pipeline.calls == []


# --- Duplicate delivery_id → 200, нет повторного вызова pipeline ----------


def test_duplicate_delivery_id_does_not_retrigger_pipeline() -> None:
    app = _build_app()
    body = json.dumps(_payload(action="opened")).encode("utf-8")
    sig = _signature(SECRET, body)
    headers = {
        "X-Hub-Signature-256": sig,
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "router-dup-1",
    }

    with TestClient(app) as client:
        r1 = client.post("/webhook/github", content=body, headers=headers)
        r2 = client.post("/webhook/github", content=body, headers=headers)

    assert r1.status_code == 202
    assert r2.status_code == 200
    assert r2.json()["status"] == "already_processed"
    assert r2.json()["reason"] == "duplicate delivery_id"
    # Pipeline вызывается ровно один раз (NFR §6: «5 повторов = 1 post_review»).
    assert len(app.state.pipeline.calls) == 1


# --- Duplicate head_sha с другим delivery_id → 200, нет повторного вызова -


def test_duplicate_head_sha_does_not_retrigger_pipeline() -> None:
    app = _build_app()
    body = json.dumps(_payload(action="synchronize")).encode("utf-8")
    sig = _signature(SECRET, body)

    with TestClient(app) as client:
        r1 = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "router-headsha-a",
            },
        )
        r2 = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "router-headsha-b",
            },
        )

    assert r1.status_code == 202
    assert r2.status_code == 200
    assert r2.json()["reason"] == "head_sha already processed"
    assert len(app.state.pipeline.calls) == 1


# --- BadRequest (malformed) → 400 -----------------------------------------


def test_malformed_payload_returns_400() -> None:
    app = _build_app()
    body = b"not really {valid"
    sig = _signature(SECRET, body)

    with TestClient(app) as client:
        resp = client.post(
            "/webhook/github",
            content=body,
            headers={
                "X-Hub-Signature-256": sig,
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "router-mal-1",
            },
        )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "bad request"


# --- create_app() smoke-test (DI собирается без ошибок) -------------------


def test_create_app_initializes_with_default_settings(monkeypatch) -> None:
    """Проверяем, что app.create_app() поднимает все компоненты без падения."""
    from sunsec.app import create_app
    from sunsec.config.settings import Settings

    # Settings явно — не зависим от .env во время теста.
    settings = Settings(
        webhook_secret=SECRET,
        vcs_token="dummy",
        polza_api_key="dummy-not-real",
        log_format="json",
    )
    app = create_app(settings=settings)
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
