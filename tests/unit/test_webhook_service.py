"""Unit-тесты WebhookService (T-007, system_design §3.1).

Покрытие (по DoD T-007):
  1. Валидная подпись + opened action → EnqueueAnalysis.
  2. Невалидная подпись → InvalidSignature (роутер маппит в 401).
  3. action не в whitelist (closed) → Ignored, без запуска анализа.
  4. Повторный delivery_id → AlreadyProcessed.
  5. Повторный head_sha (тот же PR, разные delivery_id) → AlreadyProcessed.
  6. Валидный synchronize → EnqueueAnalysis (запуск анализа).
  7. Невалидный JSON / payload → BadRequest.
  8. Draft PR при SKIP_DRAFTS=true → Ignored.
  9. Event type != pull_request → Ignored.

Тесты — async (pytest-asyncio, mode=auto из pyproject.toml).
"""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from sunsec.state.memory import InMemoryStateStore
from sunsec.vcs.github import GitHubAdapter
from sunsec.webhook.service import (
    AlreadyProcessed,
    BadRequest,
    EnqueueAnalysis,
    Ignored,
    InvalidSignature,
    WebhookService,
)

SECRET = "test-webhook-secret-please-rotate"


def _signature(secret: str, body: bytes) -> str:
    """Сформировать заголовок `X-Hub-Signature-256` валидно (как делает GitHub)."""
    mac = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def _payload(action: str = "opened", *, draft: bool = False, head_sha: str = "deadbeef" * 5) -> dict:
    user = {"login": "alice", "id": 1}
    repo = {"full_name": "alice/proj", "owner": user}
    head = {"sha": head_sha, "ref": "feature", "repo": repo}
    base = {"sha": "feedface" * 5, "ref": "main", "repo": repo}
    pr = {
        "id": 100,
        "number": 42,
        "state": "open",
        "title": "T-007 webhook test",
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


def _build_service(*, skip_drafts: bool = True) -> WebhookService:
    return WebhookService(
        vcs=GitHubAdapter(token="dummy", api_base="https://api.github.com"),
        state=InMemoryStateStore(),
        webhook_secret=SECRET,
        skip_drafts=skip_drafts,
    )


# --- 1. Valid signature + opened → EnqueueAnalysis -------------------------


@pytest.mark.asyncio
async def test_valid_signature_opened_action_enqueues_analysis() -> None:
    service = _build_service()
    body = json.dumps(_payload(action="opened")).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "11111111-2222-3333-4444-555555555555",
        "content-type": "application/json",
    }

    outcome = await service.handle(raw_body=body, headers=headers)

    assert isinstance(outcome, EnqueueAnalysis)
    assert outcome.event.action == "opened"
    assert outcome.event.repo == "alice/proj"
    assert outcome.event.pr_number == 42
    assert outcome.idempotency_key == f"alice/proj#42@{'deadbeef' * 5}"
    assert outcome.delivery_id == "11111111-2222-3333-4444-555555555555"


# --- 2. Invalid signature → InvalidSignature -------------------------------


@pytest.mark.asyncio
async def test_invalid_signature_returns_invalid_signature() -> None:
    service = _build_service()
    body = json.dumps(_payload()).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": "sha256=" + "0" * 64,  # not matching
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "bad-sig-delivery",
    }

    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, InvalidSignature)


@pytest.mark.asyncio
async def test_missing_signature_header_returns_invalid_signature() -> None:
    service = _build_service()
    body = json.dumps(_payload()).encode("utf-8")
    headers = {
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "no-sig-delivery",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, InvalidSignature)


# --- 3. action not in whitelist → Ignored ---------------------------------


@pytest.mark.asyncio
async def test_ignored_action_closed_is_skipped_with_200() -> None:
    """DoD: невыбранный action ('closed', 'edited', ...) → 200 ignored, без анализа.

    Pre-check action до Pydantic-валидации, чтобы легитимные `closed`-уведомления
    от GitHub не возвращали 400 (см. service.py § «4a. Pre-check action»).
    """
    service = _build_service()
    # Делаем raw payload вручную, чтобы поля типа `state="closed"`, draft=False
    # не ломали Pydantic-валидацию — но из-за pre-check мы её и не вызовем.
    raw = _payload(action="opened")
    raw["action"] = "closed"  # action не в whitelist
    body = json.dumps(raw).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "closed-delivery",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, Ignored)
    assert outcome.reason == "action not in whitelist"
    assert outcome.detail == "closed"


@pytest.mark.asyncio
async def test_ignored_action_edited_is_skipped_with_200() -> None:
    service = _build_service()
    raw = _payload(action="opened")
    raw["action"] = "edited"
    body = json.dumps(raw).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "edited-delivery",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, Ignored)
    assert outcome.detail == "edited"


@pytest.mark.asyncio
async def test_ignored_event_type_returns_ignored() -> None:
    """Заголовок X-GitHub-Event не из whitelist → Ignored 200.

    T-019: `issue_comment` теперь обрабатывается reply-веткой; для
    проверки «непонятный event_type → Ignored» берём `push` (никогда
    не наш канал).
    """
    service = _build_service()
    body = json.dumps({"zen": "Practicality beats purity."}).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "push",  # не PR-событие и не reply-событие
        "X-GitHub-Delivery": "push-delivery",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, Ignored)
    assert outcome.reason == "unsupported event type"


@pytest.mark.asyncio
async def test_ping_event_returns_ignored_200() -> None:
    """GitHub шлёт `ping` при добавлении webhook — отвечаем 200."""
    service = _build_service()
    body = json.dumps({"zen": "Anything added dilutes everything else."}).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "ping",
        "X-GitHub-Delivery": "ping-1",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, Ignored)
    assert outcome.reason == "ping"


# --- 4. Duplicate delivery_id → AlreadyProcessed --------------------------


@pytest.mark.asyncio
async def test_duplicate_delivery_id_returns_already_processed() -> None:
    service = _build_service()
    body = json.dumps(_payload(action="opened")).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "dup-delivery-id-aaa",
    }

    first = await service.handle(raw_body=body, headers=headers)
    second = await service.handle(raw_body=body, headers=headers)

    assert isinstance(first, EnqueueAnalysis)
    assert isinstance(second, AlreadyProcessed)
    assert second.reason == "duplicate delivery_id"


# --- 5. Duplicate head_sha (другой delivery_id) → AlreadyProcessed --------


@pytest.mark.asyncio
async def test_duplicate_head_sha_with_different_delivery_returns_already_processed() -> None:
    service = _build_service()
    body = json.dumps(_payload(action="synchronize")).encode("utf-8")

    headers_v1 = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "delivery-a",
    }
    headers_v2 = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "delivery-b",  # новый id, но тот же head_sha
    }

    first = await service.handle(raw_body=body, headers=headers_v1)
    second = await service.handle(raw_body=body, headers=headers_v2)

    assert isinstance(first, EnqueueAnalysis)
    assert isinstance(second, AlreadyProcessed)
    assert second.reason == "head_sha already processed"
    assert second.idempotency_key == f"alice/proj#42@{'deadbeef' * 5}"


# --- 6. Valid synchronize → EnqueueAnalysis (DoD: запуск анализа) ---------


@pytest.mark.asyncio
async def test_valid_synchronize_action_enqueues_analysis() -> None:
    service = _build_service()
    body = json.dumps(_payload(action="synchronize")).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "sync-1",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, EnqueueAnalysis)
    assert outcome.event.action == "synchronize"


@pytest.mark.asyncio
async def test_valid_reopened_action_enqueues_analysis() -> None:
    service = _build_service()
    body = json.dumps(_payload(action="reopened")).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "reopen-1",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, EnqueueAnalysis)
    assert outcome.event.action == "reopened"


# --- 7. Malformed payload → BadRequest -------------------------------------


@pytest.mark.asyncio
async def test_malformed_json_returns_bad_request() -> None:
    service = _build_service()
    body = b"not really {valid json"
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "malformed-1",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, BadRequest)
    assert "JSON" in outcome.reason or "json" in outcome.reason


@pytest.mark.asyncio
async def test_payload_missing_required_fields_returns_bad_request() -> None:
    service = _build_service()
    body = json.dumps({"action": "opened"}).encode("utf-8")  # нет number/pr/repo/sender
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "schema-mismatch-1",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, BadRequest)
    assert outcome.reason == "payload schema mismatch"


# --- 8. Draft PR при SKIP_DRAFTS=true → Ignored ---------------------------


@pytest.mark.asyncio
async def test_draft_pr_is_ignored_when_skip_drafts_true() -> None:
    service = _build_service(skip_drafts=True)
    body = json.dumps(_payload(action="opened", draft=True)).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "draft-1",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, Ignored)
    assert "draft" in outcome.reason.lower()


@pytest.mark.asyncio
async def test_draft_pr_processed_when_skip_drafts_false() -> None:
    service = _build_service(skip_drafts=False)
    body = json.dumps(_payload(action="opened", draft=True)).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "draft-allow-1",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, EnqueueAnalysis)


@pytest.mark.asyncio
async def test_ready_for_review_processes_even_if_payload_still_says_draft() -> None:
    """`ready_for_review` = «из черновика → готов». Обрабатываем, даже если
    payload.pull_request.draft ещё `true` (GitHub иногда так шлёт)."""
    service = _build_service(skip_drafts=True)
    body = json.dumps(_payload(action="ready_for_review", draft=True)).encode("utf-8")
    headers = {
        "X-Hub-Signature-256": _signature(SECRET, body),
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": "rfr-1",
    }
    outcome = await service.handle(raw_body=body, headers=headers)
    assert isinstance(outcome, EnqueueAnalysis)
