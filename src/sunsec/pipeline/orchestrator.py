"""PipelineOrchestrator — связующий слой (system_design §3.7 + v1.2.1 §12).

T-008: добавлен реальный вызов `vcs.fetch_pr_diff(repo, pr_number)` и
структурированное логирование результата (количество файлов, head/base SHA).
Дальше по цепочке (diff_filter → llm.analyze → publisher.publish) — T-009 /
T-012 / T-016.

T-038 (M-9): добавлены best-effort writes в `StateStore` durable-layer
(`save_check` / `update_check_status` / `save_findings` / `save_comments`).
Ошибка SQLite **не валит pipeline** — логируем через `log.exception(
"storage_write_failed", stage=...)` и продолжаем (§12.4).

Контракт ошибок (см. system_design §4.2):
- `NotFoundError` — тихо логируем и завершаем (PR удалён / нет доступа).
- `AuthError` — critical-лог, PR не обрабатывается. DevOps смотрит healthcheck.
- `RateLimitError` — лог counter, не падает.
- `VCSAdapterError` / прочее — лог exception, не падает.

`process_pr` НИКОГДА не бросает наружу — webhook-receiver запускает его в
BackgroundTasks, исключение там просто потеряется и не доедет до клиента.
"""
from __future__ import annotations

import logging
import secrets
import time
from datetime import datetime
from typing import Any, Optional

from sunsec.contracts import GitHubPullRequestEvent
from sunsec.contracts.storage import (
    CheckRecord,
    CommentRecord,
    FindingRecord,
)
from sunsec.llm.base import (
    BudgetExceeded,
    LLMProviderUnavailable,
    LLMTimeout,
)
from sunsec.state.base import StateStore
from sunsec.vcs.base import (
    AuthError,
    NotFoundError,
    RateLimitError,
    VCSAdapterError,
)

log = logging.getLogger(__name__)


def _generate_check_id() -> str:
    """`chk_` + 5-байтный hex (system_design §11.3.1)."""
    return f"chk_{secrets.token_hex(5)}"


def _generate_finding_id() -> str:
    return f"fnd_{secrets.token_hex(6)}"


def _generate_comment_id() -> str:
    return f"cmt_{secrets.token_hex(6)}"


def _severity_counts_from_findings(findings: list) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = getattr(f, "severity", None)
        if sev in counts:
            counts[sev] += 1
    return counts


def _build_short_summary(findings: list, llm_summary: str) -> str:
    """Короткая агрегация для CommentPublisher.publish (T-016 minimal summary).

    Полная агрегация по severity + топ-N — T-017; здесь мы передаём LLM
    summary как есть. CommentPublisher сам рендерит breakdown по severity
    (см. `_render_summary_body` в `comments/publisher.py`).
    """
    return llm_summary or ""


def idempotency_key(event: GitHubPullRequestEvent) -> str:
    """`owner/repo#42@sha` — единый ключ дедупликации.

    См. system_design §3.1 и §3.7. Содержит `head_sha`, поэтому при
    `synchronize` (новый коммит в ту же PR) ключ меняется и новый анализ
    запустится корректно.
    """
    return f"{event.repo}#{event.pr_number}@{event.head_sha}"


class PipelineOrchestrator:
    """Связывает VCSAdapter → DiffFilter → LLMClient → CommentPublisher.

    T-008: фактически делает первый шаг — `vcs.fetch_pr_diff`. Дальнейшие
    компоненты (`diff_filter` / `llm` / `publisher`) пока остаются как
    optional-зависимости и будут вызываться после T-009 / T-012 / T-016.
    """

    def __init__(
        self,
        *,
        vcs: Any = None,
        diff_filter: Any = None,
        llm: Any = None,
        publisher: Any = None,
        state: Optional[StateStore] = None,
        fp_filter: Any = None,
        fp_heuristics: Any = None,  # legacy alias — синоним fp_filter
    ) -> None:
        self._vcs = vcs
        self._filter = diff_filter
        self._llm = llm
        self._publisher = publisher
        self._state = state
        # T-013: FP-фильтр (pre_llm_scan + postprocess). Поддерживаем оба имени
        # для совместимости с T-007 wiring.
        self._fp = fp_filter if fp_filter is not None else fp_heuristics

    async def _safe_storage_call(
        self, op_name: str, coro_factory, *, stage: str, repo: str, pr_number: int
    ) -> Any:
        """Wrapper для best-effort writes (system_design §12.4).

        Ошибки StateStore не валят pipeline — логируются как `storage_write_failed`
        и проглатываются. Возвращает результат корутины или `None` при ошибке.
        """
        try:
            return await coro_factory()
        except Exception as exc:  # noqa: BLE001 — best-effort
            log.exception(
                "storage_write_failed",
                extra={
                    "operation": op_name,
                    "stage": stage,
                    "repo": repo,
                    "pr_number": pr_number,
                    "error_type": type(exc).__name__,
                },
            )
            return None

    async def process_pr(self, event: GitHubPullRequestEvent) -> None:
        """Безопасная обёртка над основной цепочкой обработки PR.

        Контракт для T-007 webhook-receiver: метод НЕ должен бросать наружу.
        Любое исключение логируем и проглатываем, чтобы не уронить background
        worker FastAPI.
        """
        key = idempotency_key(event)
        started_at = datetime.utcnow()
        t_start = time.monotonic()
        check_id = _generate_check_id()
        log.info(
            "pipeline_invoked",
            extra={
                "repo": event.repo,
                "pr_number": event.pr_number,
                "head_sha": event.head_sha,
                "action": event.action,
                "idempotency_key": key,
                "check_id": check_id,
                "stage": "start",
            },
        )

        # --- M-9: durable INSERT `checks` row (best-effort, §12.2 step 1) ---
        if self._state is not None:
            pr_url = (
                f"https://github.com/{event.repo}/pull/{event.pr_number}"
            )
            initial_record = CheckRecord(
                id=check_id,
                repo=event.repo,
                pr_number=event.pr_number,
                pr_title=getattr(event.pull_request, "title", None),
                author=(
                    getattr(event.pull_request.user, "login", None)
                    if getattr(event.pull_request, "user", None)
                    else None
                ),
                source_branch=(
                    getattr(event.pull_request.head, "ref", None)
                    if getattr(event.pull_request, "head", None)
                    else None
                ),
                target_branch=(
                    getattr(event.pull_request.base, "ref", None)
                    if getattr(event.pull_request, "base", None)
                    else None
                ),
                head_sha=event.head_sha,
                base_sha=(
                    getattr(event.pull_request.base, "sha", None)
                    if getattr(event.pull_request, "base", None)
                    else None
                ),
                action=event.action,
                status="received",
                started_at=started_at,
                pr_url=pr_url,
            )
            await self._safe_storage_call(
                "save_check",
                lambda: self._state.save_check(initial_record),
                stage="webhook_received",
                repo=event.repo,
                pr_number=event.pr_number,
            )

        pr_diff = None
        try:
            # --- Step 1: VCS fetch_pr_diff (T-008) -------------------------
            if self._vcs is not None:
                t0 = time.monotonic()
                try:
                    pr_diff = await self._vcs.fetch_pr_diff(event.repo, event.pr_number)
                except NotFoundError:
                    log.warning(
                        "pipeline_pr_not_found",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "stage": "vcs_fetch_pr_diff",
                        },
                    )
                    if self._state is not None:
                        duration_ms = int((time.monotonic() - t_start) * 1000)
                        await self._safe_storage_call(
                            "update_check_status",
                            lambda dm=duration_ms: self._state.update_check_status(
                                check_id,
                                status="skipped",
                                finished_at=datetime.utcnow(),
                                duration_ms=dm,
                            ),
                            stage="pr_not_found",
                            repo=event.repo,
                            pr_number=event.pr_number,
                        )
                    await self._finalize(key, success=True)
                    return
                except AuthError:
                    # critical — devops видит в healthcheck (T-020). НЕ пробрасываем.
                    log.critical(
                        "pipeline_auth_error",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "stage": "vcs_fetch_pr_diff",
                        },
                    )
                    await self._finalize(key, success=False)
                    return
                except RateLimitError:
                    log.warning(
                        "pipeline_rate_limited",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "stage": "vcs_fetch_pr_diff",
                        },
                    )
                    await self._finalize(key, success=False)
                    return
                except VCSAdapterError as exc:
                    log.exception(
                        "pipeline_vcs_error",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "stage": "vcs_fetch_pr_diff",
                            "error_type": type(exc).__name__,
                        },
                    )
                    await self._finalize(key, success=False)
                    return

                log.info(
                    "pipeline_diff_fetched",
                    extra={
                        "repo": event.repo,
                        "pr_number": event.pr_number,
                        "head_sha": pr_diff.head_sha,
                        "base_sha": pr_diff.base_sha,
                        "files_count": len(pr_diff.files),
                        "duration_ms": int((time.monotonic() - t0) * 1000),
                        "stage": "vcs_fetch_pr_diff",
                    },
                )

            # --- Step 2: DiffFilter (T-009) -------------------------------
            filtered = None
            if self._filter is not None and pr_diff is not None:
                t1 = time.monotonic()
                filtered = self._filter.apply(pr_diff)
                log.info(
                    "pipeline_diff_filtered",
                    extra={
                        "repo": event.repo,
                        "pr_number": event.pr_number,
                        "head_sha": pr_diff.head_sha,
                        "files_in": len(pr_diff.files),
                        "files_kept": len(filtered.files),
                        "files_excluded": len(filtered.excluded_files),
                        "estimated_input_tokens": filtered.estimated_input_tokens,
                        "duration_ms": int((time.monotonic() - t1) * 1000),
                        "stage": "diff_filter",
                    },
                )
                # --- M-9: durable UPDATE post-diff-filter (§12.2 step 3) ---
                if self._state is not None:
                    is_empty = filtered.is_empty()
                    await self._safe_storage_call(
                        "update_check_status",
                        lambda fc=len(filtered.files),
                        fs=len(filtered.excluded_files),
                        ie=is_empty: self._state.update_check_status(
                            check_id,
                            status=("skipped" if ie else "filtering"),
                            llm_status=("skipped_empty" if ie else None),
                            files_checked=fc,
                            files_skipped=fs,
                        ),
                        stage="diff_filtered",
                        repo=event.repo,
                        pr_number=event.pr_number,
                    )

            # --- Step 2.5: FP pre-LLM scan (T-013) ------------------------
            pre_scan_findings: list = []
            if self._fp is not None and filtered is not None and not filtered.is_empty():
                t_pre = time.monotonic()
                try:
                    pre_scan_findings = self._fp.pre_llm_scan(filtered)
                except Exception as exc:  # noqa: BLE001 — FP не должен валить пайплайн
                    log.exception(
                        "pipeline_fp_pre_scan_failed",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "error_type": type(exc).__name__,
                            "stage": "fp_pre_scan",
                        },
                    )
                else:
                    log.info(
                        "pipeline_fp_pre_scan",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "head_sha": event.head_sha,
                            "pre_scan_findings": len(pre_scan_findings),
                            "duration_ms": int((time.monotonic() - t_pre) * 1000),
                            "stage": "fp_pre_scan",
                        },
                    )

            # --- Step 3: LLMClient.analyze (T-012) ------------------------
            llm_response = None
            llm_status = "skipped"
            if self._llm is not None and filtered is not None and not filtered.is_empty():
                t2 = time.monotonic()
                try:
                    llm_response = await self._llm.analyze(filtered)
                    llm_status = "ok"
                    log.info(
                        "pipeline_llm_analyzed",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "head_sha": event.head_sha,
                            "findings_count": len(llm_response.findings),
                            "duration_ms": int((time.monotonic() - t2) * 1000),
                            "stage": "llm_analyze",
                        },
                    )
                except BudgetExceeded:
                    # ADR-2 kill-switch — НЕ падаем, помечаем PR как обработанный.
                    llm_status = "budget_exceeded"
                    log.warning(
                        "pipeline_llm_budget_exceeded",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "head_sha": event.head_sha,
                            "stage": "llm_analyze",
                        },
                    )
                except LLMTimeout:
                    llm_status = "timeout"
                    log.warning(
                        "pipeline_llm_timeout",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "stage": "llm_analyze",
                        },
                    )
                except LLMProviderUnavailable as exc:
                    llm_status = "provider_unavailable"
                    log.warning(
                        "pipeline_llm_provider_unavailable",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "error_type": type(exc).__name__,
                            "stage": "llm_analyze",
                        },
                    )
            elif self._llm is not None and filtered is not None and filtered.is_empty():
                llm_status = "skipped_empty"
                log.info(
                    "pipeline_llm_skipped_empty",
                    extra={
                        "repo": event.repo,
                        "pr_number": event.pr_number,
                        "stage": "llm_analyze",
                    },
                )

            # --- M-9: durable UPDATE post-LLM-analyze (§12.2 step 4) ---
            if self._state is not None and filtered is not None and not filtered.is_empty():
                llm_provider_name = (
                    getattr(self._llm._provider, "name", None)
                    if self._llm is not None and hasattr(self._llm, "_provider")
                    else None
                )
                llm_model_name = (
                    getattr(self._llm._provider, "_model_id", None)
                    if self._llm is not None and hasattr(self._llm, "_provider")
                    else None
                )
                llm_summary = (
                    llm_response.summary if llm_response is not None else None
                )
                await self._safe_storage_call(
                    "update_check_status",
                    lambda lps=llm_status,
                    lpn=llm_provider_name,
                    lpm=llm_model_name,
                    sm=llm_summary: self._state.update_check_status(
                        check_id,
                        status="analyzing",
                        llm_status=lps,
                        llm_provider=lpn,
                        llm_model=lpm,
                        summary=sm,
                    ),
                    stage="llm_analyzed",
                    repo=event.repo,
                    pr_number=event.pr_number,
                )

            # --- Step 3.5: FP postprocess (T-013) -------------------------
            # Слияние pre_scan + LLM findings, дедуп, контекстные правила,
            # confidence-фильтр. Если LLM не вызвался (timeout/budget) —
            # всё равно прогоняем postprocess поверх pre_scan_findings.
            final_findings: list = []
            if self._fp is not None and filtered is not None:
                llm_findings = (
                    llm_response.findings if llm_response is not None else []
                )
                try:
                    final_findings = self._fp.postprocess(
                        llm_findings, filtered, pre_scan_findings
                    )
                except Exception as exc:  # noqa: BLE001
                    log.exception(
                        "pipeline_fp_postprocess_failed",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "error_type": type(exc).__name__,
                            "stage": "fp_postprocess",
                        },
                    )
                    # Откатываемся на LLM-ответ без обработки.
                    final_findings = list(llm_findings) + list(pre_scan_findings)
            elif llm_response is not None:
                final_findings = list(llm_response.findings)
            else:
                final_findings = list(pre_scan_findings)

            # --- M-9: durable save findings + severity_counts (§12.2 step 5) ---
            finding_id_by_obj: dict[int, str] = {}
            if self._state is not None and final_findings:
                finding_records: list[FindingRecord] = []
                for f in final_findings:
                    fid = _generate_finding_id()
                    finding_id_by_obj[id(f)] = fid
                    finding_records.append(
                        FindingRecord(
                            id=fid,
                            check_id=check_id,
                            file=getattr(f, "file", ""),
                            line=int(getattr(f, "line", 0) or 0),
                            **{"class": getattr(f, "class_", getattr(f, "class", ""))},
                            severity=getattr(f, "severity", "info"),
                            confidence=getattr(f, "confidence", None),
                            message=getattr(f, "message", ""),
                            suggestion=getattr(f, "suggestion", None),
                            status="pending",
                        )
                    )
                severity_counts = _severity_counts_from_findings(final_findings)
                await self._safe_storage_call(
                    "save_findings",
                    lambda recs=finding_records: self._state.save_findings(
                        check_id, recs
                    ),
                    stage="findings_saved",
                    repo=event.repo,
                    pr_number=event.pr_number,
                )
                await self._safe_storage_call(
                    "update_check_status",
                    lambda fc=len(finding_records),
                    sc=severity_counts: self._state.update_check_status(
                        check_id,
                        findings_count=fc,
                        severity_counts=sc,
                    ),
                    stage="findings_counted",
                    repo=event.repo,
                    pr_number=event.pr_number,
                )

            # --- Step 4: CommentPublisher (T-016) ---------------------------
            # Publisher НИКОГДА не валит пайплайн: ошибки логируются внутри
            # CommentPublisher / GitHubAdapter. Любое неожиданное исключение
            # ловим здесь (двойная защита).
            review = None
            if self._publisher is not None:
                t4 = time.monotonic()
                try:
                    if llm_status == "budget_exceeded":
                        await self._publisher.publish_budget_exhausted(event)
                        log.info(
                            "pipeline_publisher_budget_notified",
                            extra={
                                "repo": event.repo,
                                "pr_number": event.pr_number,
                                "head_sha": event.head_sha,
                                "duration_ms": int((time.monotonic() - t4) * 1000),
                                "stage": "comment_publisher",
                            },
                        )
                    elif not final_findings:
                        await self._publisher.publish_empty(event)
                        log.info(
                            "pipeline_publisher_empty",
                            extra={
                                "repo": event.repo,
                                "pr_number": event.pr_number,
                                "head_sha": event.head_sha,
                                "duration_ms": int((time.monotonic() - t4) * 1000),
                                "stage": "comment_publisher",
                            },
                        )
                    else:
                        short_summary = _build_short_summary(
                            final_findings,
                            llm_response.summary if llm_response is not None else "",
                        )
                        review = await self._publisher.publish(
                            event,
                            final_findings,
                            short_summary,
                            pr_diff=pr_diff,
                            filtered_diff=filtered,
                        )
                        log.info(
                            "pipeline_publisher_published",
                            extra={
                                "repo": event.repo,
                                "pr_number": event.pr_number,
                                "head_sha": event.head_sha,
                                "review_id": getattr(review, "review_id", 0),
                                "inline_count": getattr(review, "comments_posted", 0),
                                "fallback_to_summary": getattr(
                                    review, "fallback_to_summary", 0
                                ),
                                "deduped": getattr(review, "deduped", 0),
                                "skipped": getattr(review, "skipped", False),
                                "duration_ms": int((time.monotonic() - t4) * 1000),
                                "stage": "comment_publisher",
                            },
                        )
                except Exception as exc:  # noqa: BLE001 — publisher НЕ валит пайплайн
                    log.exception(
                        "pipeline_publisher_failed",
                        extra={
                            "repo": event.repo,
                            "pr_number": event.pr_number,
                            "error_type": type(exc).__name__,
                            "stage": "comment_publisher",
                        },
                    )

            # --- M-9: durable save comments + final status (§12.2 step 6) ---
            if self._state is not None:
                # CommentPublisher v1 не возвращает per-comment details; пишем
                # агрегированный CommentRecord(kind=...) для аудит-трейла. Когда
                # CommentPublisher эволюционирует и начнёт возвращать список
                # PostedComment[] — этот блок расширится per-finding записями.
                summary_kind: Optional[str] = None
                if llm_status == "budget_exceeded":
                    summary_kind = "budget_exhausted"
                elif not final_findings:
                    summary_kind = "empty"
                elif review is not None and not getattr(review, "skipped", False):
                    summary_kind = "summary"

                if summary_kind is not None:
                    comment_record = CommentRecord(
                        id=_generate_comment_id(),
                        check_id=check_id,
                        kind=summary_kind,
                        posted_at=datetime.utcnow(),
                        vcs_comment_id=(
                            str(getattr(review, "review_id", "")) if review else None
                        ),
                    )
                    await self._safe_storage_call(
                        "save_comments",
                        lambda rec=comment_record: self._state.save_comments(
                            check_id, [rec]
                        ),
                        stage="comments_published",
                        repo=event.repo,
                        pr_number=event.pr_number,
                    )

                duration_ms = int((time.monotonic() - t_start) * 1000)
                final_status = "completed"
                if llm_status in {"budget_exceeded", "timeout", "provider_unavailable"}:
                    final_status = "failed"
                if (
                    filtered is not None
                    and filtered.is_empty()
                ):
                    final_status = "skipped"
                await self._safe_storage_call(
                    "update_check_status",
                    lambda st=final_status,
                    dm=duration_ms: self._state.update_check_status(
                        check_id,
                        status=st,
                        finished_at=datetime.utcnow(),
                        duration_ms=dm,
                    ),
                    stage="check_finalized",
                    repo=event.repo,
                    pr_number=event.pr_number,
                )

            await self._finalize(key, success=True)
            log.info(
                "pipeline_completed",
                extra={
                    "repo": event.repo,
                    "pr_number": event.pr_number,
                    "stage": "done",
                    "files_count": (len(pr_diff.files) if pr_diff is not None else 0),
                    "files_kept": (len(filtered.files) if filtered is not None else None),
                    "llm_status": llm_status,
                    "findings_count": (
                        len(llm_response.findings) if llm_response is not None else None
                    ),
                    "pre_scan_findings": len(pre_scan_findings) if self._fp is not None else None,
                    "final_findings": len(final_findings) if self._fp is not None else None,
                },
            )
        except Exception as exc:  # noqa: BLE001 — пайплайн ловит всё, см. §3.7
            log.exception(
                "pipeline_failed",
                extra={
                    "repo": event.repo,
                    "pr_number": event.pr_number,
                    "error_type": type(exc).__name__,
                },
            )
            if self._state is not None:
                duration_ms = int((time.monotonic() - t_start) * 1000)
                await self._safe_storage_call(
                    "update_check_status",
                    lambda dm=duration_ms: self._state.update_check_status(
                        check_id,
                        status="failed",
                        finished_at=datetime.utcnow(),
                        duration_ms=dm,
                    ),
                    stage="pipeline_failed",
                    repo=event.repo,
                    pr_number=event.pr_number,
                )
            await self._finalize(key, success=False)

    async def _finalize(self, key: str, *, success: bool) -> None:
        """Снимаем резервацию: success → `mark_pr_done`; иначе — `mark_pr_failed`."""
        if self._state is None:
            return
        try:
            if success:
                await self._state.mark_pr_done(key)
            else:
                await self._state.mark_pr_failed(key)
        except Exception:  # noqa: BLE001
            log.exception("pipeline_state_finalize_failed")
