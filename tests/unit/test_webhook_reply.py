"""Unit-тесты reply-ветки WebhookService (T-019).

Покрываем:
  1. `issue_comment.created` без @mention → Ignored.
  2. `issue_comment.created` с @mention → EnqueueReply(kind="issue").
  3. `issue_comment.created` от самого бота (sender == bot_username) → Ignored(self).
  4. `pull_request_review_comment.created` с parent — нашим → EnqueueReply(kind="inline").
  5. `pull_request_review_comment.created` с parent — НЕ нашим → Ignored.
  6. Дубль `delivery_id` → AlreadyProcessed.
  7. reply-режим выключен → Ignored.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest

from sunsec.contracts import PostedComment
from sunsec.state.memory import InMemoryStateStore
from sunsec.vcs.github import GitHubAdapter
from sunsec.webhook.service import (
    AlreadyProcessed,
    EnqueueReply,
    Ignored,
    WebhookService,
)

SECRET = "test-webhook-secret-reply"
BOT_LOGIN = "sunsec-bot"


def _signature(body: bytes) -> str:
    mac = hmac.new(SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


class _StubVCS:
    """Минимальный VCS-адаптер, возвращающий заранее заданный parent-comment."""

    def __init__(self, parent_body: str | None = "<!-- sunsec:bot:v1:finding:abcd -->\nrev-replica") -> None:
        self._parent_body = parent_body
        self.get_calls: list[tuple[str, int]] = []

    def verify_signature(self, raw_body: bytes, signature: str, secret: str) -> bool:
        expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
        return signature == f"sha256={expected}"

    async def get_review_comment(self, repo: str, comment_id: int) -> PostedComment:
        self.get_calls.append((repo, int(comment_id)))
        return PostedComment(
            id=int(comment_id),
            url=f"https://github.com/{repo}/pull/comments/{comment_id}",
            posted_at=datetime.now(timezone.utc),
            body=self._parent_body,
        )


def _build_service(
    *,
    enable_reply_mode: bool = True,
    parent_body: str | None = "<!-- sunsec:bot:v1:finding:abcd --> наша заметка",
    state: InMemoryStateStore | None = None,
) -> tuple[WebhookService, _StubVCS, InMemoryStateStore]:
    state = state or InMemoryStateStore()
    vcs = _StubVCS(parent_body=parent_body)
    svc = WebhookService(
        vcs=vcs,
        state=state,
        webhook_secret=SECRET,
        skip_drafts=True,
        bot_username=BOT_LOGIN,
        enable_reply_mode=enable_reply_mode,
    )
    return svc, vcs, state


def _issue_comment_payload(
    *,
    action: str = "created",
    body: str = "Можно подробнее почему это XSS?",
    sender_login: str = "alice",
) -> dict:
    user = {"login": sender_login, "id": 42}
    repo = {"full_name": "alice/proj", "owner": {"login": "alice", "id": 42}}
    return {
        "action": action,
        "issue": {
            "number": 7,
            "pull_request": {"url": "https://api.github.com/repos/alice/proj/pulls/7"},
        },
        "comment": {"id": 555, "body": body, "user": user},
        "repository": repo,
        "sender": user,
    }


def _review_comment_payload(
    *,
    action: str = "created",
    body: str = "А если я sanitize'ю выше — это всё ещё уязвимо?",
    in_reply_to_id: int | None = 111,
    sender_login: str = "alice",
) -> dict:
    user = {"login": sender_login, "id": 42}
    repo = {"full_name": "alice/proj", "owner": {"login": "alice", "id": 42}}
    pr_user = {"login": "alice", "id": 42}
    head = {"sha": "deadbeef" * 5, "ref": "feat", "repo": repo}
    base = {"sha": "feedface" * 5, "ref": "main", "repo": repo}
    pull_request = {
        "id": 7,
        "number": 7,
        "state": "open",
        "title": "demo",
        "head": head,
        "base": base,
        "draft": False,
        "user": pr_user,
    }
    comment = {
        "id": 222,
        "body": body,
        "path": "app/views.py",
        "user": user,
        "in_reply_to_id": in_reply_to_id,
        "pull_request_review_id": 999,
        "line": 33,
        "original_line": 33,
    }
    return {
        "action": action,
        "pull_request": pull_request,
        "comment": comment,
        "repository": repo,
        "sender": user,
    }


def _headers(event: str, body: bytes, delivery: str) -> dict[str, str]:
    return {
        "X-Hub-Signature-256": _signature(body),
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
    }


@pytest.mark.asyncio
async def test_issue_comment_without_mention_ignored() -> None:
    svc, _, _ = _build_service()
    payload = _issue_comment_payload(body="Просто комментарий без обращения")
    body = json.dumps(payload).encode("utf-8")
    outcome = await svc.handle(body, _headers("issue_comment", body, "d1"))
    assert isinstance(outcome, Ignored)
    assert outcome.reason == "not addressed to bot"


@pytest.mark.asyncio
async def test_issue_comment_with_mention_enqueues_reply() -> None:
    svc, _, _ = _build_service()
    payload = _issue_comment_payload(body=f"@{BOT_LOGIN} объясни почему high")
    body = json.dumps(payload).encode("utf-8")
    outcome = await svc.handle(body, _headers("issue_comment", body, "d2"))
    assert isinstance(outcome, EnqueueReply)
    assert outcome.kind == "issue"
    assert outcome.payload.pr_number == 7
    assert outcome.idempotency_key == "reply:alice/proj#7@555"


@pytest.mark.asyncio
async def test_issue_comment_from_bot_self_filtered() -> None:
    svc, _, _ = _build_service()
    payload = _issue_comment_payload(
        body=f"@{BOT_LOGIN} триггер от себя самого",
        sender_login=BOT_LOGIN,
    )
    body = json.dumps(payload).encode("utf-8")
    outcome = await svc.handle(body, _headers("issue_comment", body, "d3"))
    assert isinstance(outcome, Ignored)
    assert outcome.reason == "self-reply"


@pytest.mark.asyncio
async def test_pr_review_comment_with_bot_parent_enqueues_inline_reply() -> None:
    svc, vcs, _ = _build_service(
        parent_body="<!-- sunsec:bot:v1:finding:abcd --> наш inline-комментарий"
    )
    payload = _review_comment_payload(in_reply_to_id=111)
    body = json.dumps(payload).encode("utf-8")
    outcome = await svc.handle(body, _headers("pull_request_review_comment", body, "d4"))
    assert isinstance(outcome, EnqueueReply)
    assert outcome.kind == "inline"
    assert outcome.idempotency_key == "reply:alice/proj#7@222"
    assert vcs.get_calls == [("alice/proj", 111)]


@pytest.mark.asyncio
async def test_pr_review_comment_with_human_parent_ignored() -> None:
    svc, vcs, _ = _build_service(parent_body="обычное обсуждение, без маркера")
    payload = _review_comment_payload(in_reply_to_id=111)
    body = json.dumps(payload).encode("utf-8")
    outcome = await svc.handle(body, _headers("pull_request_review_comment", body, "d5"))
    assert isinstance(outcome, Ignored)
    assert outcome.reason == "not addressed to bot"
    # Запрос к VCS всё же был — чтобы проверить родителя.
    assert vcs.get_calls == [("alice/proj", 111)]


@pytest.mark.asyncio
async def test_pr_review_comment_top_level_ignored() -> None:
    """Новый top-level review-comment (без `in_reply_to_id`) — НЕ триггер."""
    svc, vcs, _ = _build_service()
    payload = _review_comment_payload(in_reply_to_id=None)
    body = json.dumps(payload).encode("utf-8")
    outcome = await svc.handle(body, _headers("pull_request_review_comment", body, "d6"))
    assert isinstance(outcome, Ignored)
    # На top-level GitHub НЕ кладёт in_reply_to_id, и мы НЕ должны дёргать API.
    assert vcs.get_calls == []


@pytest.mark.asyncio
async def test_duplicate_delivery_returns_already_processed() -> None:
    state = InMemoryStateStore()
    svc, _, _ = _build_service(state=state)
    payload = _issue_comment_payload(body=f"@{BOT_LOGIN} ?")
    body = json.dumps(payload).encode("utf-8")
    first = await svc.handle(body, _headers("issue_comment", body, "dup-1"))
    assert isinstance(first, EnqueueReply)
    second = await svc.handle(body, _headers("issue_comment", body, "dup-1"))
    assert isinstance(second, AlreadyProcessed)


@pytest.mark.asyncio
async def test_reply_mode_disabled_returns_ignored() -> None:
    svc, _, _ = _build_service(enable_reply_mode=False)
    payload = _issue_comment_payload(body=f"@{BOT_LOGIN} hi")
    body = json.dumps(payload).encode("utf-8")
    outcome = await svc.handle(body, _headers("issue_comment", body, "off-1"))
    assert isinstance(outcome, Ignored)
    assert "disabled" in outcome.reason
