"""Smoke-тесты доменных контрактов из system_design §4.

Проверяем computed_field на GitHubPullRequestEvent (ADR-5), alias для
`class` в Finding (ADR-4), и FilteredDiff.is_empty / content_hash.
"""
from __future__ import annotations

from sunsec.contracts import (
    AddedLine,
    Finding,
    FilteredDiff,
    FilteredDiffFile,
    GitHubPullRequestEvent,
    LLMResponseSchema,
)


def _make_event_payload() -> dict:
    user = {"login": "alice", "id": 1}
    repo = {"full_name": "alice/proj", "owner": user}
    head = {"sha": "deadbeef" * 5, "ref": "feature", "repo": repo}
    base = {"sha": "feedface" * 5, "ref": "main", "repo": repo}
    pr = {
        "id": 100,
        "number": 42,
        "state": "open",
        "title": "T-006 skeleton",
        "head": head,
        "base": base,
        "draft": False,
        "user": user,
    }
    return {
        "action": "opened",
        "number": 42,
        "pull_request": pr,
        "repository": repo,
        "sender": user,
    }


def test_event_exposes_repo_pr_number_head_sha_via_computed_fields() -> None:
    """ADR-5: orchestrator должен видеть event.repo / pr_number / head_sha."""
    event = GitHubPullRequestEvent.model_validate(_make_event_payload())
    assert event.repo == "alice/proj"
    assert event.pr_number == 42
    assert event.head_sha == "deadbeef" * 5

    # И эти поля сериализуются как обычные.
    dumped = event.model_dump()
    assert dumped["repo"] == "alice/proj"
    assert dumped["pr_number"] == 42
    assert dumped["head_sha"] == "deadbeef" * 5


def test_finding_uses_class_alias_per_adr4() -> None:
    """ADR-4: JSON-поле называется `class` (alias), Python-атрибут — `class_`."""
    raw = {
        "file": "app/db.py",
        "line": 17,
        "class": "sql_injection",
        "severity": "high",
        "message": "User input concatenated into raw SQL",
        "suggestion": "Use parametrized query",
        "confidence": 0.85,
    }
    f = Finding.model_validate(raw)
    assert f.class_ == "sql_injection"

    # Должна сериализоваться обратно с алиасом `class`.
    dumped = f.model_dump(by_alias=True)
    assert dumped["class"] == "sql_injection"

    # И инициализация по python-имени `class_` тоже работает (populate_by_name=True).
    f2 = Finding(
        file="x.py", line=1, class_="xss", severity="low",
        message="not really sure tbh", confidence=0.1,
    )
    assert f2.class_ == "xss"


def test_filtered_diff_is_empty_and_content_hash_stable() -> None:
    """FilteredDiff.is_empty() пуст если нет +-строк; content_hash — детерминирован."""
    files1 = [
        FilteredDiffFile(
            path="a.py",
            language="python",
            added_lines=[AddedLine(new_line_no=1, content="x = 1")],
        ),
    ]
    files2 = [
        FilteredDiffFile(
            path="a.py",
            language="python",
            added_lines=[AddedLine(new_line_no=1, content="x = 1")],
        ),
    ]
    h1 = FilteredDiff.compute_content_hash(files1)
    h2 = FilteredDiff.compute_content_hash(files2)
    assert h1 == h2 and len(h1) == 64  # sha256 hex

    fd_empty = FilteredDiff(
        repo="o/r", pr_number=1, head_sha="0" * 40, files=[],
        estimated_input_tokens=0, content_hash="",
    )
    assert fd_empty.is_empty()

    fd_full = FilteredDiff(
        repo="o/r", pr_number=1, head_sha="0" * 40, files=files1,
        estimated_input_tokens=10, content_hash=h1,
    )
    assert not fd_full.is_empty()


def test_llm_response_schema_accepts_minimal_payload() -> None:
    r = LLMResponseSchema.model_validate({
        "findings": [],
        "summary": "No findings.",
    })
    assert r.findings == []
    assert r.summary == "No findings."
