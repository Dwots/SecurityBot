"""Unit-тест интеграции `PipelineOrchestrator` с `LLMClient` (T-012).

Проверяем поведение оркестратора на трёх веточках:
- happy path: filter → llm → log `pipeline_llm_analyzed`;
- `BudgetExceeded`: pipeline ловит, log warning, НЕ падает;
- `LLMTimeout`: то же — warning + pipeline_completed без exception.
"""
from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("pydantic")

from sunsec.contracts import (  # noqa: E402
    AddedLine,
    FilteredDiff,
    FilteredDiffFile,
    GitHubPullRequestEvent,
    LLMResponseSchema,
    PRDiff,
)
from sunsec.llm.base import BudgetExceeded, LLMTimeout  # noqa: E402
from sunsec.pipeline.orchestrator import PipelineOrchestrator  # noqa: E402


def _make_event() -> GitHubPullRequestEvent:
    repo = {
        "full_name": "acme/example",
        "name": "example",
        "owner": {"login": "acme", "id": 1},
    }
    user = {"login": "alice", "id": 2}
    return GitHubPullRequestEvent(
        action="opened",
        number=7,
        repository=repo,
        sender=user,
        pull_request={
            "id": 99,
            "number": 7,
            "state": "open",
            "title": "Test PR",
            "head": {"sha": "abc123def", "ref": "feature/x", "repo": repo},
            "base": {"sha": "0000000", "ref": "main", "repo": repo},
            "draft": False,
            "user": user,
        },
    )


def _make_filtered() -> FilteredDiff:
    return FilteredDiff(
        repo="acme/example",
        pr_number=7,
        head_sha="abc123def",
        files=[
            FilteredDiffFile(
                path="x.py",
                language="python",
                added_lines=[AddedLine(new_line_no=1, content="print('hi')")],
            )
        ],
        estimated_input_tokens=10,
        content_hash="h1",
    )


def _make_pr_diff() -> PRDiff:
    return PRDiff(
        repo="acme/example",
        pr_number=7,
        head_sha="abc123def",
        base_sha="0000000",
        files=[],
    )


async def test_pipeline_calls_llm_after_filter_and_logs_analysis(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """filter → llm.analyze → log `pipeline_llm_analyzed`."""
    pr_diff = _make_pr_diff()
    filtered = _make_filtered()

    vcs = MagicMock()
    vcs.fetch_pr_diff = AsyncMock(return_value=pr_diff)

    diff_filter = MagicMock()
    diff_filter.apply = MagicMock(return_value=filtered)

    llm = MagicMock()
    llm.analyze = AsyncMock(
        return_value=LLMResponseSchema(findings=[], summary="ok")
    )

    state = MagicMock()
    state.mark_pr_done = AsyncMock()
    state.mark_pr_failed = AsyncMock()

    orch = PipelineOrchestrator(vcs=vcs, diff_filter=diff_filter, llm=llm, state=state)
    caplog.set_level(logging.INFO, logger="sunsec.pipeline.orchestrator")

    await orch.process_pr(_make_event())

    llm.analyze.assert_awaited_once_with(filtered)
    state.mark_pr_done.assert_awaited_once()
    assert any(r.message == "pipeline_llm_analyzed" for r in caplog.records)


async def test_pipeline_handles_budget_exceeded_without_crashing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`BudgetExceeded` от llm.analyze → log warning, pipeline_completed успехом."""
    vcs = MagicMock()
    vcs.fetch_pr_diff = AsyncMock(return_value=_make_pr_diff())
    diff_filter = MagicMock()
    diff_filter.apply = MagicMock(return_value=_make_filtered())
    llm = MagicMock()
    llm.analyze = AsyncMock(side_effect=BudgetExceeded("limit hit"))
    state = MagicMock()
    state.mark_pr_done = AsyncMock()
    state.mark_pr_failed = AsyncMock()

    orch = PipelineOrchestrator(vcs=vcs, diff_filter=diff_filter, llm=llm, state=state)
    caplog.set_level(logging.WARNING, logger="sunsec.pipeline.orchestrator")

    await orch.process_pr(_make_event())  # НЕ должно бросить

    assert any(
        r.message == "pipeline_llm_budget_exceeded" for r in caplog.records
    )
    state.mark_pr_done.assert_awaited_once()
    state.mark_pr_failed.assert_not_awaited()


async def test_pipeline_handles_llm_timeout_without_crashing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """`LLMTimeout` от llm.analyze → log warning, pipeline_completed."""
    vcs = MagicMock()
    vcs.fetch_pr_diff = AsyncMock(return_value=_make_pr_diff())
    diff_filter = MagicMock()
    diff_filter.apply = MagicMock(return_value=_make_filtered())
    llm = MagicMock()
    llm.analyze = AsyncMock(side_effect=LLMTimeout("timeout after retries"))
    state = MagicMock()
    state.mark_pr_done = AsyncMock()
    state.mark_pr_failed = AsyncMock()

    orch = PipelineOrchestrator(vcs=vcs, diff_filter=diff_filter, llm=llm, state=state)
    caplog.set_level(logging.WARNING, logger="sunsec.pipeline.orchestrator")

    await orch.process_pr(_make_event())

    assert any(r.message == "pipeline_llm_timeout" for r in caplog.records)
    state.mark_pr_done.assert_awaited_once()


async def test_pipeline_invokes_fp_filter_pre_and_post(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """T-013: pipeline вызывает fp.pre_llm_scan ДО LLM и fp.postprocess ПОСЛЕ."""
    vcs = MagicMock()
    vcs.fetch_pr_diff = AsyncMock(return_value=_make_pr_diff())
    diff_filter = MagicMock()
    diff_filter.apply = MagicMock(return_value=_make_filtered())
    llm = MagicMock()
    llm.analyze = AsyncMock(
        return_value=LLMResponseSchema(findings=[], summary="ok")
    )

    pre_scan_findings: list = []
    final_findings: list = []
    fp_filter = MagicMock()
    fp_filter.pre_llm_scan = MagicMock(return_value=pre_scan_findings)
    fp_filter.postprocess = MagicMock(return_value=final_findings)

    state = MagicMock()
    state.mark_pr_done = AsyncMock()
    state.mark_pr_failed = AsyncMock()

    orch = PipelineOrchestrator(
        vcs=vcs,
        diff_filter=diff_filter,
        llm=llm,
        state=state,
        fp_filter=fp_filter,
    )
    caplog.set_level(logging.INFO, logger="sunsec.pipeline.orchestrator")

    await orch.process_pr(_make_event())

    # pre_llm_scan вызван ровно один раз, до LLM
    fp_filter.pre_llm_scan.assert_called_once()
    # postprocess получил llm-findings ([]) + pre_scan
    fp_filter.postprocess.assert_called_once()
    args, _ = fp_filter.postprocess.call_args
    assert args[0] == []  # llm.findings
    # filtered diff
    assert args[2] == pre_scan_findings or args[2] is pre_scan_findings
    state.mark_pr_done.assert_awaited_once()


async def test_pipeline_fp_postprocess_runs_even_when_llm_skipped(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Если LLM не вызывался (BudgetExceeded), FP всё равно постпроцессит pre_scan."""
    vcs = MagicMock()
    vcs.fetch_pr_diff = AsyncMock(return_value=_make_pr_diff())
    diff_filter = MagicMock()
    diff_filter.apply = MagicMock(return_value=_make_filtered())
    llm = MagicMock()
    llm.analyze = AsyncMock(side_effect=BudgetExceeded("limit hit"))

    fake_pre = [{"sentinel": "pre"}]
    fp_filter = MagicMock()
    fp_filter.pre_llm_scan = MagicMock(return_value=fake_pre)
    fp_filter.postprocess = MagicMock(return_value=[])

    state = MagicMock()
    state.mark_pr_done = AsyncMock()
    state.mark_pr_failed = AsyncMock()

    orch = PipelineOrchestrator(
        vcs=vcs,
        diff_filter=diff_filter,
        llm=llm,
        state=state,
        fp_filter=fp_filter,
    )
    await orch.process_pr(_make_event())

    fp_filter.pre_llm_scan.assert_called_once()
    fp_filter.postprocess.assert_called_once()
    # llm-findings = [] (LLM упал → нет ответа), pre_scan приходит как 3-й аргумент
    args, _ = fp_filter.postprocess.call_args
    assert args[0] == []
    assert args[2] == fake_pre
