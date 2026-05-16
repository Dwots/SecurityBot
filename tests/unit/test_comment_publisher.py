"""Тесты `sunsec.comments.publisher.CommentPublisher` (T-016).

Стратегия: mock-VCS (AsyncMock) — не дёргаем GitHub. Все +-строки задаются
через `FilteredDiff` (передаётся вторым параметром в publish).

Покрываемые сценарии (DoD T-016):
- (a) happy-path: 2 findings → 1 review с 2 inline + summary.
- (b) finding не на +-строке → переезжает в general comment (fallback).
- (c) идемпотентность: повторный publish с теми же findings → НЕТ inline.
- (d) `publish_empty` идемпотентен (маркер уже есть → None).
- (e) `publish_budget_exhausted` идемпотентен.
- (f) `publish` при VCSAdapterError (auth/404/rate-limit) — НЕ валит pipeline.
- (g) `_render_inline_body` содержит маркер.
- (h) finding_hash стабилен (одинаков на одинаковом Finding).
- (i) deduped счётчик при in-batch дублях.
- (j) enabled=False → ничего не публикует.

Все async-тесты (asyncio_mode=auto в pyproject.toml).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("pydantic")

from sunsec.comments.publisher import (  # noqa: E402
    MARKER_BUDGET,
    MARKER_EMPTY,
    MARKER_SUMMARY,
    CommentPublisher,
    finding_hash,
    finding_marker,
)
from sunsec.contracts import (  # noqa: E402
    AddedLine,
    Finding,
    FilteredDiff,
    FilteredDiffFile,
    GitHubPullRequestEvent,
    PostedComment,
    PostedReview,
)
from sunsec.vcs.base import (  # noqa: E402
    AuthError,
    NotFoundError,
    RateLimitError,
    VCSAdapterError,
)


# --- helpers --------------------------------------------------------------


def _make_event(repo: str = "acme/example", pr_number: int = 7) -> GitHubPullRequestEvent:
    owner, _ = repo.split("/", 1)
    repo_payload = {
        "full_name": repo,
        "name": repo.split("/")[-1],
        "owner": {"login": owner, "id": 1},
    }
    user = {"login": "alice", "id": 2}
    return GitHubPullRequestEvent(
        action="opened",
        number=pr_number,
        repository=repo_payload,
        sender=user,
        pull_request={
            "id": 99,
            "number": pr_number,
            "state": "open",
            "title": "Test PR",
            "head": {"sha": "abc123def", "ref": "feature/x", "repo": repo_payload},
            "base": {"sha": "0000000", "ref": "main", "repo": repo_payload},
            "draft": False,
            "user": user,
        },
    )


def _make_finding(
    file: str = "src/app.py",
    line: int = 10,
    cls: str = "sql_injection",
    severity: str = "high",
    message: str = "Potential SQL injection via string concatenation.",
    confidence: float = 0.9,
    suggestion: str | None = None,
) -> Finding:
    return Finding.model_validate(
        {
            "file": file,
            "line": line,
            "class": cls,
            "severity": severity,
            "message": message,
            "confidence": confidence,
            "suggestion": suggestion,
        }
    )


def _make_filtered_diff(
    *files_and_lines: tuple[str, list[int]]
) -> FilteredDiff:
    files = [
        FilteredDiffFile(
            path=path,
            language=None,
            added_lines=[AddedLine(new_line_no=ln, content=f"line {ln}") for ln in lines],
        )
        for path, lines in files_and_lines
    ]
    return FilteredDiff(
        repo="acme/example",
        pr_number=7,
        head_sha="abc123def",
        files=files,
        estimated_input_tokens=0,
        content_hash="ch",
    )


def _make_mock_vcs() -> MagicMock:
    """Mock VCSAdapter с пустыми list_*_comments по умолчанию."""
    vcs = MagicMock()
    vcs.post_review = AsyncMock(
        return_value=PostedReview(
            review_id=12345,
            comments_posted=0,
            summary_posted=True,
            deduped=0,
            fallback_to_summary=0,
        )
    )
    vcs.post_issue_comment = AsyncMock(
        return_value=PostedComment(
            id=987,
            url="https://github.com/acme/example/pull/7#comment-987",
            posted_at=datetime.now(tz=timezone.utc),
            body=None,
        )
    )
    vcs.update_issue_comment = AsyncMock()
    vcs.list_review_comments = AsyncMock(return_value=[])
    vcs.list_issue_comments = AsyncMock(return_value=[])
    return vcs


# --- finding_hash sanity --------------------------------------------------


def test_finding_hash_stable_for_same_finding() -> None:
    f1 = _make_finding()
    f2 = _make_finding()
    assert finding_hash(f1) == finding_hash(f2)
    assert len(finding_hash(f1)) == 16


def test_finding_hash_differs_when_class_or_line_changes() -> None:
    f1 = _make_finding(line=10)
    f2 = _make_finding(line=11)
    assert finding_hash(f1) != finding_hash(f2)
    f3 = _make_finding(cls="xss", message="DOM XSS via innerHTML.")
    assert finding_hash(f1) != finding_hash(f3)


# --- happy path -----------------------------------------------------------


async def test_publish_happy_path_inline_and_summary() -> None:
    """(a) 2 findings на +-строках → 1 review с 2 inline + summary."""
    vcs = _make_mock_vcs()
    vcs.post_review = AsyncMock(
        return_value=PostedReview(
            review_id=42,
            comments_posted=2,
            summary_posted=True,
        )
    )
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10, 25]))
    findings = [
        _make_finding(line=10, message="SQLi via f-string in query()."),
        _make_finding(line=25, cls="xss", severity="medium",
                      message="Potential XSS in innerHTML assignment."),
    ]

    result = await publisher.publish(
        event=_make_event(),
        findings=findings,
        summary="Found 2 issues.",
        filtered_diff=filtered,
    )

    assert result.review_id == 42
    assert result.comments_posted == 2
    assert result.summary_posted is True
    assert result.fallback_to_summary == 0
    assert result.deduped == 0

    vcs.post_review.assert_awaited_once()
    kwargs = vcs.post_review.await_args.kwargs
    assert kwargs["repo"] == "acme/example"
    assert kwargs["pr_number"] == 7
    assert kwargs["commit_id"] == "abc123def"
    assert len(kwargs["comments"]) == 2
    # маркер finding_hash есть в body inline-комментариев
    for inline in kwargs["comments"]:
        assert "<!-- sunsec:bot:v1:finding:" in inline.body
    # T-017: summary живёт как отдельный issue-comment (с маркером :summary).
    vcs.post_issue_comment.assert_awaited_once()
    summary_body = vcs.post_issue_comment.await_args.args[2]
    assert MARKER_SUMMARY in summary_body
    # review.body — короткий лидер, не дублирует summary.
    assert MARKER_SUMMARY not in kwargs["summary"]
    # T-019 (Russian lock): review.body упоминает «сводке» вместо "summary comment".
    assert "сводке" in kwargs["summary"].lower()


# --- (b) line not in diff → fallback в summary -----------------------------


async def test_publish_finding_not_in_diff_goes_to_fallback() -> None:
    """(b) finding с line, которой нет среди +-строк → fallback в summary."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))  # line 99 — НЕТ
    findings = [
        _make_finding(line=10, message="SQLi via f-string in query()."),
        _make_finding(
            line=99,
            cls="hardcoded_secret",
            severity="critical",
            message="AWS access key id committed in source.",
        ),
    ]

    result = await publisher.publish(
        event=_make_event(),
        findings=findings,
        summary="Found 2 issues.",
        filtered_diff=filtered,
    )

    assert result.fallback_to_summary == 1
    kwargs = vcs.post_review.await_args.kwargs
    assert len(kwargs["comments"]) == 1
    assert kwargs["comments"][0].line == 10
    # T-017: fallback finding попал в отдельный summary issue-comment.
    vcs.post_issue_comment.assert_awaited_once()
    summary_body = vcs.post_issue_comment.await_args.args[2]
    assert "без привязки к diff" in summary_body
    assert "src/app.py:99" in summary_body


# --- (c) идемпотентность ---------------------------------------------------


async def test_publish_idempotent_when_finding_marker_already_present() -> None:
    """(c) повтор с теми же findings → inline пропускается по маркеру.

    T-017: post_review больше не вызывается с пустыми comments (т.к. summary
    переехал в отдельный issue-comment). Но summary всё равно публикуется
    (или обновляется через PATCH, если был).
    """
    f1 = _make_finding(line=10, message="SQLi via f-string in query().")
    fhash = finding_hash(f1)
    vcs = _make_mock_vcs()
    # Симулируем: предыдущий запуск уже опубликовал inline с этим маркером.
    vcs.list_review_comments = AsyncMock(
        return_value=[
            PostedComment(
                id=111,
                url="https://x/c/111",
                posted_at=datetime.now(tz=timezone.utc),
                body=f"old body\n{finding_marker(fhash)}",
            )
        ]
    )

    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    result = await publisher.publish(
        event=_make_event(),
        findings=[f1],
        summary="repeat",
        filtered_diff=filtered,
    )

    assert result.deduped >= 1
    # T-017: post_review НЕ вызывается с 0 inline.
    vcs.post_review.assert_not_awaited()
    # Summary всё равно должен попасть в PR (первый прогон summary не было).
    vcs.post_issue_comment.assert_awaited_once()


async def test_publish_idempotent_in_batch_duplicates() -> None:
    """(i) два одинаковых finding'а в одном batch → один inline."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    findings = [
        _make_finding(line=10, message="SQLi via f-string in query()."),
        _make_finding(line=10, message="SQLi via f-string in query()."),
    ]
    result = await publisher.publish(
        event=_make_event(),
        findings=findings,
        summary="duplicate batch",
        filtered_diff=filtered,
    )
    assert result.comments_posted == 1
    assert vcs.post_review.await_count == 1


# --- (d) publish_empty idempotent ----------------------------------------


async def test_publish_empty_creates_when_marker_absent() -> None:
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)

    posted = await publisher.publish_empty(_make_event())

    assert posted is not None
    vcs.post_issue_comment.assert_awaited_once()
    body = vcs.post_issue_comment.await_args.args[2]
    assert MARKER_EMPTY in body


async def test_publish_empty_skips_when_marker_present() -> None:
    """(d) если маркер уже опубликован — возвращает None."""
    vcs = _make_mock_vcs()
    vcs.list_issue_comments = AsyncMock(
        return_value=[
            PostedComment(
                id=222,
                url="https://x/i/222",
                posted_at=datetime.now(tz=timezone.utc),
                body=f"prev empty\n{MARKER_EMPTY}",
            )
        ]
    )
    publisher = CommentPublisher(vcs=vcs)
    posted = await publisher.publish_empty(_make_event())
    assert posted is None
    vcs.post_issue_comment.assert_not_awaited()


# --- (e) publish_budget_exhausted idempotent -----------------------------


async def test_publish_budget_exhausted_creates_when_marker_absent() -> None:
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    posted = await publisher.publish_budget_exhausted(_make_event())
    assert posted is not None
    body = vcs.post_issue_comment.await_args.args[2]
    assert MARKER_BUDGET in body


async def test_publish_budget_exhausted_skips_when_marker_present() -> None:
    vcs = _make_mock_vcs()
    vcs.list_issue_comments = AsyncMock(
        return_value=[
            PostedComment(
                id=333,
                url="https://x/i/333",
                posted_at=datetime.now(tz=timezone.utc),
                body=f"prev budget\n{MARKER_BUDGET}",
            )
        ]
    )
    publisher = CommentPublisher(vcs=vcs)
    posted = await publisher.publish_budget_exhausted(_make_event())
    assert posted is None
    vcs.post_issue_comment.assert_not_awaited()


# --- (f) publish при VCS-ошибках — НЕ валит pipeline ---------------------


@pytest.mark.parametrize(
    "exc",
    [
        AuthError("401"),
        NotFoundError("404"),
        RateLimitError("429"),
        VCSAdapterError("5xx"),
    ],
)
async def test_publish_swallows_vcs_errors_and_returns_zero_review(exc: Exception) -> None:
    vcs = _make_mock_vcs()
    vcs.post_review = AsyncMock(side_effect=exc)
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    result = await publisher.publish(
        event=_make_event(),
        findings=[_make_finding(line=10, message="SQLi via f-string in query().")],
        summary="x",
        filtered_diff=filtered,
    )
    # Не падаем: вернули пустой review.
    assert result.comments_posted == 0
    assert result.review_id == 0


async def test_publish_swallows_list_review_failures() -> None:
    """`list_review_comments` 500 → publisher всё равно публикует."""
    vcs = _make_mock_vcs()
    vcs.list_review_comments = AsyncMock(side_effect=VCSAdapterError("5xx"))
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    result = await publisher.publish(
        event=_make_event(),
        findings=[_make_finding(line=10, message="SQLi via f-string in query().")],
        summary="x",
        filtered_diff=filtered,
    )
    assert result.comments_posted == 1


# --- enabled=False — не публикует ----------------------------------------


async def test_publish_disabled_short_circuits() -> None:
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs, enabled=False)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    result = await publisher.publish(
        event=_make_event(),
        findings=[_make_finding(line=10, message="SQLi via f-string in query().")],
        summary="x",
        filtered_diff=filtered,
    )
    assert result.skipped is True
    vcs.post_review.assert_not_awaited()
    vcs.post_issue_comment.assert_not_awaited()


async def test_publish_empty_disabled_returns_none() -> None:
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs, enabled=False)
    assert await publisher.publish_empty(_make_event()) is None
    vcs.post_issue_comment.assert_not_awaited()


async def test_publish_budget_disabled_returns_none() -> None:
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs, enabled=False)
    assert await publisher.publish_budget_exhausted(_make_event()) is None
    vcs.post_issue_comment.assert_not_awaited()


# --- содержание inline-body ----------------------------------------------


async def test_inline_body_contains_severity_class_message_marker() -> None:
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    f = _make_finding(
        line=10,
        cls="hardcoded_secret",
        severity="critical",
        message="AWS access key id committed in source.",
        confidence=0.95,
        suggestion="Move to env / Secrets Manager.",
    )
    await publisher.publish(
        event=_make_event(),
        findings=[f],
        summary="",
        filtered_diff=filtered,
    )
    inline = vcs.post_review.await_args.kwargs["comments"][0]
    assert "[SUNSEC][CRITICAL]" in inline.body
    assert "Hardcoded Secret" in inline.body
    assert "AWS access key id committed" in inline.body
    assert "Move to env / Secrets Manager." in inline.body
    assert inline.body.strip().endswith("-->")  # маркер в конце


# --- soft-mode: filtered_diff не передан → all findings inline -----------


async def test_publish_without_diff_treats_all_as_valid_lines() -> None:
    """Если ни filtered_diff, ни pr_diff не переданы — все findings inline."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    f = _make_finding(line=999, message="SQLi via f-string in query().")
    result = await publisher.publish(
        event=_make_event(),
        findings=[f],
        summary="x",
    )
    assert result.comments_posted == 1
    assert result.fallback_to_summary == 0


# ==========================================================================
# T-017: summary-комментарий с агрегацией + snippet с языком файла.
# ==========================================================================


from sunsec.comments.publisher import _lang_from_path  # noqa: E402


# --- (T-017 d) snippet → fenced code block с языком ----------------------


def test_lang_from_path_python() -> None:
    assert _lang_from_path("src/app.py") == "python"
    assert _lang_from_path("api/login.pyi") == "python"


def test_lang_from_path_js_ts_variants() -> None:
    assert _lang_from_path("src/web.js") == "javascript"
    assert _lang_from_path("src/web.mjs") == "javascript"
    assert _lang_from_path("src/Counter.jsx") == "javascript"
    assert _lang_from_path("src/app.ts") == "typescript"
    assert _lang_from_path("src/Counter.tsx") == "typescript"


def test_lang_from_path_other_languages() -> None:
    assert _lang_from_path("main.go") == "go"
    assert _lang_from_path("app/user.rb") == "ruby"
    assert _lang_from_path("Foo.java") == "java"
    assert _lang_from_path("src/lib.rs") == "rust"
    assert _lang_from_path("public/index.php") == "php"
    assert _lang_from_path("scripts/deploy.sh") == "bash"
    assert _lang_from_path("queries/q.sql") == "sql"
    assert _lang_from_path("page.html") == "html"
    assert _lang_from_path("styles.css") == "css"
    assert _lang_from_path("config.yaml") == "yaml"
    assert _lang_from_path("config.yml") == "yaml"
    assert _lang_from_path("pkg.json") == "json"


def test_lang_from_path_unknown_extension_returns_empty() -> None:
    """Неизвестное расширение → пустая строка (fenced block без языка)."""
    assert _lang_from_path("src/x.xyz") == ""
    assert _lang_from_path("file.unknown") == ""
    assert _lang_from_path("") == ""


def test_lang_from_path_no_extension_handles_dockerfile() -> None:
    """Файлы без расширения: Dockerfile / Makefile → known langs; иначе ''."""
    assert _lang_from_path("Dockerfile") == "dockerfile"
    assert _lang_from_path("api/Dockerfile") == "dockerfile"
    assert _lang_from_path("Makefile") == "makefile"
    assert _lang_from_path("README") == ""


async def test_publish_inline_includes_suggested_fix_snippet_python() -> None:
    """(T-017 d) suggestion → fenced ```python block в inline body."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    f = _make_finding(
        line=10,
        message="SQLi via f-string in query().",
        suggestion="cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))",
    )
    await publisher.publish(
        event=_make_event(),
        findings=[f],
        summary="x",
        filtered_diff=filtered,
    )
    inline = vcs.post_review.await_args.kwargs["comments"][0]
    assert "### Предлагаемое исправление" in inline.body
    assert "```python" in inline.body
    assert "cursor.execute" in inline.body
    # fenced block корректно закрыт.
    assert inline.body.count("```") == 2


async def test_publish_inline_includes_suggested_fix_snippet_javascript() -> None:
    """(T-017 d) тот же snippet-рендеринг для .js → ```javascript."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/web.js", [25]))
    f = _make_finding(
        file="src/web.js",
        line=25,
        cls="xss",
        severity="high",
        message="DOM XSS via innerHTML assignment.",
        suggestion="el.textContent = userInput;",
    )
    await publisher.publish(
        event=_make_event(),
        findings=[f],
        summary="x",
        filtered_diff=filtered,
    )
    inline = vcs.post_review.await_args.kwargs["comments"][0]
    assert "### Предлагаемое исправление" in inline.body
    assert "```javascript" in inline.body
    assert "el.textContent = userInput;" in inline.body


async def test_publish_inline_skips_suggested_fix_when_none() -> None:
    """(T-017 d edge) `suggestion=None` или пустая → секция не рендерится."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    f = _make_finding(line=10, suggestion=None)
    await publisher.publish(
        event=_make_event(),
        findings=[f],
        summary="x",
        filtered_diff=filtered,
    )
    inline = vcs.post_review.await_args.kwargs["comments"][0]
    assert "Предлагаемое исправление" not in inline.body
    # Также не должно быть пустого fenced block'а.
    assert "```" not in inline.body


async def test_publish_inline_snippet_for_unknown_extension_uses_empty_lang() -> None:
    """(T-017 d edge) Файл с неизвестным расширением → fenced без языка."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/legacy.xyz", [5]))
    f = _make_finding(
        file="src/legacy.xyz",
        line=5,
        suggestion="use safe API instead",
    )
    await publisher.publish(
        event=_make_event(),
        findings=[f],
        summary="x",
        filtered_diff=filtered,
    )
    inline = vcs.post_review.await_args.kwargs["comments"][0]
    assert "### Предлагаемое исправление" in inline.body
    # `` ` `` без указания языка — три бэктика и сразу перевод строки.
    assert "```\n" in inline.body
    assert "```python" not in inline.body
    assert "```javascript" not in inline.body


# --- (T-017 b) PR с 1 finding → severity-агрегация --------------------


async def test_publish_summary_aggregates_single_finding_by_severity() -> None:
    """(T-017 b) 1 finding (severity=high) → severity-таблица с точными числами."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    await publisher.publish(
        event=_make_event(),
        findings=[_make_finding(line=10, severity="high",
                                message="SQLi via f-string in query().")],
        summary="One issue.",
        filtered_diff=filtered,
    )
    vcs.post_issue_comment.assert_awaited_once()
    summary = vcs.post_issue_comment.await_args.args[2]
    # Заголовок + LLM summary + severity-таблица + top + footer + маркер
    assert "## Ревью SunSecurityBot" in summary
    assert "Распределение по severity" in summary
    # Таблица содержит все 5 уровней с числами (icon + label.capitalize()):
    assert "Critical | 0" in summary
    assert "High     | 1" in summary
    assert "Medium   | 0" in summary
    assert "Low      | 0" in summary
    assert "Info     | 0" in summary
    # Top findings присутствуют для 1 finding.
    assert "Главные находки (показано 1 из 1)" in summary
    assert "src/app.py:10" in summary
    # Footer + commit (T-019: русские формулировки)
    assert "всего 1" in summary
    assert "привязано inline: 1" in summary
    assert "общих: 0" in summary
    assert "abc123d" in summary  # короткий head_sha
    assert MARKER_SUMMARY in summary


# --- (T-017 c) PR с >5 findings → top-K=5 + правильная агрегация ---------


async def test_publish_summary_aggregates_many_findings_top5() -> None:
    """(T-017 c) 6 findings разной severity → top-5 + точная severity-таблица."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    lines = [10, 11, 12, 13, 14, 15, 16]
    filtered = _make_filtered_diff(("src/app.py", lines))
    findings = [
        _make_finding(line=10, severity="critical",
                      message="Critical: AWS AKIA leak in source."),
        _make_finding(line=11, severity="high",
                      message="High: SQLi via f-string interpolation."),
        _make_finding(line=12, severity="high",
                      message="High: XSS via innerHTML.", cls="xss"),
        _make_finding(line=13, severity="medium",
                      message="Medium: weak JWT fallback secret."),
        _make_finding(line=14, severity="low",
                      message="Low: hardcoded test password.",
                      cls="hardcoded_secret"),
        _make_finding(line=15, severity="low",
                      message="Low: second low finding."),
        _make_finding(line=16, severity="info",
                      message="Info-level finding."),
    ]
    result = await publisher.publish(
        event=_make_event(),
        findings=findings,
        summary="Many findings.",
        filtered_diff=filtered,
    )
    assert result.comments_posted == 7
    summary = vcs.post_issue_comment.await_args.args[2]
    # Точные числа в таблице (порядок строк — critical/high/medium/low/info).
    assert "Critical | 1" in summary
    assert "High     | 2" in summary
    assert "Medium   | 1" in summary
    assert "Low      | 2" in summary
    assert "Info     | 1" in summary
    # Top-5 (не больше).
    assert "Главные находки (показано 5 из 7)" in summary
    # Top должен сортироваться по severity: critical → high → high → medium → low.
    # «Critical: AWS AKIA leak» — первое сообщение critical.
    crit_pos = summary.index("Critical: AWS AKIA")
    high_pos = summary.index("High: SQLi")
    medium_pos = summary.index("Medium: weak JWT")
    low_pos = summary.index("Low: hardcoded test password")
    assert crit_pos < high_pos < medium_pos < low_pos
    # Info НЕ попал в top-5 (5 = critical+2high+medium+low; ещё один low
    # вытеснил info за пределы top-5).
    assert "Info-level finding" not in summary
    # Footer (T-019: русские формулировки)
    assert "всего 7" in summary
    assert "привязано inline: 7" in summary


# --- (T-017 e) идемпотентность summary через PATCH update_issue_comment ---


async def test_publish_summary_updates_existing_issue_comment_via_patch() -> None:
    """(T-017 e) Повторный вызов с теми же findings — summary НЕ дублируется,
    а PATCH-обновляется через `update_issue_comment`.

    Симулируем второй прогон: list_issue_comments возвращает уже опубликованный
    summary issue-comment (с маркером :summary). Publisher должен вызвать
    update_issue_comment, а не post_issue_comment.
    """
    vcs = _make_mock_vcs()
    # GitHub помнит summary с предыдущего прогона.
    existing_summary_id = 555
    vcs.list_issue_comments = AsyncMock(
        return_value=[
            PostedComment(
                id=existing_summary_id,
                url="https://x/i/555",
                posted_at=datetime.now(tz=timezone.utc),
                body=f"old summary body\n{MARKER_SUMMARY}",
            )
        ]
    )
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    # Новая итерация: добавилось ещё одно finding на новой строке.
    # finding_hash отличается от того, что на прошлом прогоне (lines/messages
    # симулируем как новые → list_review_comments пуст по умолчанию).
    findings = [
        _make_finding(line=10, severity="high",
                      message="Updated SQLi finding for re-publish.")
    ]
    result = await publisher.publish(
        event=_make_event(),
        findings=findings,
        summary="re-run",
        filtered_diff=filtered,
    )
    assert result.summary_posted is True
    # ВАЖНО: post_issue_comment НЕ должен быть вызван (это сделало бы дубль).
    vcs.post_issue_comment.assert_not_awaited()
    # Зато update_issue_comment вызвался ровно один раз с existing_summary_id.
    vcs.update_issue_comment.assert_awaited_once()
    update_args = vcs.update_issue_comment.await_args.args
    assert update_args[0] == "acme/example"
    assert update_args[1] == existing_summary_id
    # Новое тело содержит маркер summary.
    assert MARKER_SUMMARY in update_args[2]


async def test_publish_summary_idempotent_when_all_findings_already_posted() -> None:
    """(T-017 e) Если все finding-маркеры уже опубликованы И summary уже есть,
    publisher возвращает skipped=True и не плодит ничего."""
    f1 = _make_finding(line=10, message="SQLi via f-string in query().")
    fhash = finding_hash(f1)
    vcs = _make_mock_vcs()
    # И inline-маркер, и summary уже опубликованы.
    vcs.list_review_comments = AsyncMock(
        return_value=[
            PostedComment(
                id=111,
                url="https://x/c/111",
                posted_at=datetime.now(tz=timezone.utc),
                body=f"inline\n{finding_marker(fhash)}",
            )
        ]
    )
    vcs.list_issue_comments = AsyncMock(
        return_value=[
            PostedComment(
                id=222,
                url="https://x/i/222",
                posted_at=datetime.now(tz=timezone.utc),
                body=f"summary\n{MARKER_SUMMARY}",
            )
        ]
    )
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    result = await publisher.publish(
        event=_make_event(),
        findings=[f1],
        summary="repeat",
        filtered_diff=filtered,
    )
    assert result.skipped is True
    assert result.deduped >= 1
    vcs.post_review.assert_not_awaited()
    vcs.post_issue_comment.assert_not_awaited()
    vcs.update_issue_comment.assert_not_awaited()


async def test_publish_summary_includes_severity_icons_for_all_levels() -> None:
    """(T-017 b extra) Severity-таблица содержит маркеры для всех уровней."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))
    await publisher.publish(
        event=_make_event(),
        findings=[_make_finding(line=10, severity="critical",
                                message="Critical hardcoded AWS AKIA key.")],
        summary="",
        filtered_diff=filtered,
    )
    summary = vcs.post_issue_comment.await_args.args[2]
    # Все 5 уровней в таблице — даже с нулём.
    for label in ("Critical", "High", "Medium", "Low", "Info"):
        assert label in summary
    # Маркер severity (icon — наш plain-text [CRIT]).
    assert "[CRIT]" in summary


async def test_publish_summary_fallback_findings_have_finding_marker() -> None:
    """(T-017 b extra) В секции «without diff anchor» каждый finding имеет
    свой finding-маркер — чтобы повторный publish дедупил их корректно."""
    vcs = _make_mock_vcs()
    publisher = CommentPublisher(vcs=vcs)
    filtered = _make_filtered_diff(("src/app.py", [10]))  # line 99 — НЕТ
    findings = [
        _make_finding(line=10, message="SQLi via f-string in query()."),
        _make_finding(
            line=99,
            cls="hardcoded_secret",
            severity="critical",
            message="AWS AKIA committed in source.",
        ),
    ]
    await publisher.publish(
        event=_make_event(),
        findings=findings,
        summary="",
        filtered_diff=filtered,
    )
    summary_body = vcs.post_issue_comment.await_args.args[2]
    fallback_hash = finding_hash(findings[1])
    assert "Находки без привязки к diff" in summary_body
    assert finding_marker(fallback_hash) in summary_body
