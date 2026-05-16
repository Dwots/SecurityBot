"""CommentPublisher — публикация inline + summary комментариев в PR/MR.

Реализация system_design §3.5 + §4.7 (T-016).

Pipeline видит ровно три метода:
- `publish(event, findings, summary) -> PostedReview` — нормальный путь.
- `publish_empty(event) -> PostedComment | None` — после фильтрации не осталось
  `+`-строк, опц. публикуется тихий комментарий «нет файлов для анализа».
- `publish_budget_exhausted(event) -> PostedComment` — kill-switch ADR-2:
  пользователь должен видеть причину тишины.

Идемпотентность реализована **на стороне GitHub** через HTML-маркеры в теле
комментария:

- `<!-- sunsec:bot:v1:finding:<finding_hash> -->` — на каждый inline-finding.
- `<!-- sunsec:bot:v1:summary -->` — на общий summary-комментарий PR.
- `<!-- sunsec:bot:v1:empty -->` — для publish_empty.
- `<!-- sunsec:bot:v1:budget -->` — для publish_budget_exhausted.

Перед публикацией CommentPublisher запрашивает `list_review_comments` +
`list_issue_comments` и собирает множество уже опубликованных маркеров.
Это переживает рестарт (в отличие от in-memory StateStore, ADR-3).

`finding_hash = sha256(f"{file}|{line}|{class_}|{message[:80]}").hexdigest()[:16]`
"""
from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter
from typing import Any, Iterable, Optional

from sunsec.contracts import (
    Finding,
    FilteredDiff,
    GitHubPullRequestEvent,
    InlineComment,
    PostedComment,
    PostedReview,
)
from sunsec.vcs.base import VCSAdapterError

log = logging.getLogger(__name__)

# --- HTML-маркеры идемпотентности (system_design §4.7) ---
MARKER_VERSION = "sunsec:bot:v1"
MARKER_SUMMARY = f"<!-- {MARKER_VERSION}:summary -->"
MARKER_EMPTY = f"<!-- {MARKER_VERSION}:empty -->"
MARKER_BUDGET = f"<!-- {MARKER_VERSION}:budget -->"

# Сколько находок выводится в секцию «Top findings» summary-комментария.
# Согласовано с system_design §3.5 («список топ-5 находок»).
_TOP_N_IN_SUMMARY = 5

# Regex для извлечения finding-маркеров из тел уже опубликованных комментариев.
# Маркер finding выглядит как `<!-- sunsec:bot:v1:finding:<16-hex> -->`.
_FINDING_MARKER_RE = re.compile(
    r"<!--\s*sunsec:bot:v1:finding:([0-9a-f]{4,64})\s*-->",
    re.IGNORECASE,
)

# Маппинг расширений файла на язык подсветки в fenced code block (T-017).
# Если ключа нет — fenced block без явного языка (просто ``` ).
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rb": "ruby",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rs": "rust",
    ".php": "php",
    ".sh": "bash",
    ".bash": "bash",
    ".zsh": "bash",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "scss",
    ".less": "less",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".xml": "xml",
    ".md": "markdown",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".scala": "scala",
    ".dockerfile": "dockerfile",
    ".tf": "hcl",
    ".hcl": "hcl",
}


def finding_hash(finding: Finding) -> str:
    """sha256(`file|line|class_|message[:80]`) → first 16 hex chars.

    Стабильно при повторе анализа того же коммита (LLM в temperature=0 даёт
    одинаковые message; первые 80 символов — устойчивая префикс-зона).
    """
    raw = f"{finding.file}|{finding.line}|{finding.class_}|{finding.message[:80]}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def finding_marker(fhash: str) -> str:
    return f"<!-- {MARKER_VERSION}:finding:{fhash} -->"


# --- внутренние ошибки ---


class _InvalidLineError(Exception):
    """Finding.line не найден среди +-строк FilteredDiff. НЕ bubble — downgrade
    в summary."""


class CommentPublisher:
    """Доменный фасад поверх `VCSAdapter`. См. system_design §3.5 + §4.7.

    Параметры:
        vcs: `VCSAdapter` — Protocol; для GitHubAdapter — должен реализовать
            `post_review`, `post_issue_comment`, `update_issue_comment`,
            `list_review_comments`, `list_issue_comments`.
        state: опц. `StateStore` — НЕ обязателен, идемпотентность держится
            маркерами на стороне GitHub. Если есть — дополнительно
            регистрируем published-маркеры (in-process кэш).
        enabled: True для прод; False — комментарии не публикуются (dry-run /
            test-окружение). Берётся из `Settings.publish_comments_enabled`.
    """

    def __init__(
        self,
        vcs: Any = None,
        state: Any = None,
        *,
        enabled: bool = True,
    ) -> None:
        self._vcs = vcs
        self._state = state
        self._enabled = enabled

    # --- публичные методы (system_design §4.7) ---------------------------

    async def publish(
        self,
        event: GitHubPullRequestEvent,
        findings: list[Finding],
        summary: str,
        *,
        pr_diff: Any = None,
        filtered_diff: Optional[FilteredDiff] = None,
    ) -> PostedReview:
        """Публикует review (inline + summary) с дедупом по finding_hash.

        Args:
            event: GitHubPullRequestEvent (даёт repo / pr_number / head_sha).
            findings: список Finding после FP-фильтра. Может быть пуст —
                тогда возвращаем PostedReview(comments_posted=0,
                summary_posted=True/False по флагу `enabled`).
            summary: `LLMResponseSchema.summary` — короткое описание от LLM.
            pr_diff: опц. `PRDiff` (для line-валидации без доп. вызова API).
            filtered_diff: опц. `FilteredDiff` (более удобный источник
                added-строк — это уже +-строки). Если задан, используем его;
                иначе пытаемся извлечь +-строки из pr_diff.

        Returns:
            PostedReview: review_id (int) + счётчики. `skipped=True`, если
            все findings уже были опубликованы (повторная доставка после
            рестарта).

        НЕ бросает наружу (контракт §3.7 — publisher не валит pipeline):
        VCSAdapterError ловится, логируется как `comment_publisher_failed`
        и метод возвращает «пустой» PostedReview.
        """
        if not self._enabled:
            log.info(
                "comment_publisher_disabled",
                extra={
                    "repo": event.repo,
                    "pr_number": event.pr_number,
                    "findings_count": len(findings),
                },
            )
            return PostedReview(
                review_id=0,
                comments_posted=0,
                summary_posted=False,
                skipped=True,
            )

        repo = event.repo
        pr_number = event.pr_number
        head_sha = event.head_sha

        # Соберём множество +-строк (file, line) для line-валидации.
        added_lines = _collect_added_lines(pr_diff=pr_diff, filtered_diff=filtered_diff)

        # Подготовим формирование inline / fallback findings.
        inline_comments: list[InlineComment] = []
        fallback_findings: list[Finding] = []
        seen_hashes: set[str] = set()

        for f in findings:
            fhash = finding_hash(f)
            if fhash in seen_hashes:
                # in-batch дубль — пропускаем.
                continue
            seen_hashes.add(fhash)

            try:
                _validate_line_in_diff(f, added_lines)
            except _InvalidLineError:
                fallback_findings.append(f)
                continue

            inline_comments.append(
                InlineComment(
                    path=f.file,
                    line=f.line,
                    side="RIGHT",
                    body=_render_inline_body(f, fhash),
                    finding_hash=fhash,
                )
            )

        # --- идемпотентность на стороне GitHub --------------------------
        try:
            already_posted = await self._collect_posted_finding_hashes(repo, pr_number)
        except Exception as exc:  # noqa: BLE001 — не валим пайплайн
            log.warning(
                "comment_publisher_list_failed",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "error_type": type(exc).__name__,
                },
            )
            already_posted = set()

        # Отсеиваем уже опубликованные finding-маркеры из обеих ветвей.
        new_inline: list[InlineComment] = [
            c for c in inline_comments if c.finding_hash not in already_posted
        ]
        new_fallback: list[Finding] = [
            f for f in fallback_findings if finding_hash(f) not in already_posted
        ]
        deduped = (len(inline_comments) - len(new_inline)) + (
            len(fallback_findings) - len(new_fallback)
        )

        # --- summary issue-comment (создать или PATCH-обновить) --------
        # T-017: summary живёт как отдельный issue-comment (`<!-- ... :summary -->`),
        # а review.body — короткий лидер. Это даёт идемпотентность summary через
        # PATCH `/issues/comments/{id}` — при повторном вызове с теми же
        # findings один summary не плодится, тело перерисовывается.
        summary_body = _render_summary_body(
            findings=findings,
            summary_text=summary,
            fallback_findings=new_fallback,
            head_sha=head_sha,
        )

        # Найдём существующий summary-issue-comment, если он уже есть.
        try:
            existing_summary_id = await self._find_existing_issue_marker(
                repo, pr_number, MARKER_SUMMARY
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "comment_publisher_list_failed",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "error_type": type(exc).__name__,
                    "kind": "summary_lookup",
                },
            )
            existing_summary_id = None

        # Если нет новых inline / fallback И summary уже опубликован — skip.
        if not new_inline and not new_fallback and existing_summary_id is not None:
            log.info(
                "comment_publisher_nothing_to_publish",
                extra={"repo": repo, "pr_number": pr_number, "deduped": deduped},
            )
            return PostedReview(
                review_id=0,
                comments_posted=0,
                summary_posted=False,
                deduped=deduped,
                fallback_to_summary=0,
                skipped=True,
            )

        # --- 1) Публикация review (inline-only). Body — короткий лидер.
        review_body = _render_review_lead(
            n_total=len(findings),
            n_inline=len(new_inline),
            n_fallback=len(new_fallback),
        )
        review_id = 0
        review_summary_posted = False
        if new_inline:
            try:
                review = await self._vcs.post_review(
                    repo=repo,
                    pr_number=pr_number,
                    comments=new_inline,
                    summary=review_body,
                    marker=MARKER_SUMMARY,
                    commit_id=head_sha,
                )
                review_id = review.review_id
                review_summary_posted = review.summary_posted
            except VCSAdapterError as exc:
                log.exception(
                    "comment_publisher_post_review_failed",
                    extra={
                        "repo": repo,
                        "pr_number": pr_number,
                        "error_type": type(exc).__name__,
                        "inline_count": len(new_inline),
                        "fallback_count": len(new_fallback),
                    },
                )
                return PostedReview(
                    review_id=0,
                    comments_posted=0,
                    summary_posted=False,
                    deduped=deduped,
                    fallback_to_summary=len(new_fallback),
                    skipped=False,
                )

        # --- 2) Summary issue-comment: PATCH если есть, иначе POST.
        summary_posted = False
        try:
            if existing_summary_id is not None:
                update_fn = getattr(self._vcs, "update_issue_comment", None)
                if update_fn is not None:
                    await update_fn(repo, existing_summary_id, summary_body)
                    summary_posted = True
                    log.info(
                        "comment_publisher_summary_updated",
                        extra={
                            "repo": repo,
                            "pr_number": pr_number,
                            "comment_id": existing_summary_id,
                        },
                    )
                else:
                    # Адаптер не умеет PATCH — оставляем как есть, не плодим
                    # дубль (best-effort идемпотентность).
                    log.info(
                        "comment_publisher_summary_kept",
                        extra={
                            "repo": repo,
                            "pr_number": pr_number,
                            "comment_id": existing_summary_id,
                            "reason": "update_issue_comment_unavailable",
                        },
                    )
                    summary_posted = True
            else:
                await self._vcs.post_issue_comment(repo, pr_number, summary_body)
                summary_posted = True
                log.info(
                    "comment_publisher_summary_posted",
                    extra={"repo": repo, "pr_number": pr_number},
                )
        except VCSAdapterError as exc:
            log.exception(
                "comment_publisher_post_summary_failed",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "error_type": type(exc).__name__,
                },
            )
            summary_posted = False

        # Регистрируем published в state (если задан) — это in-process slot,
        # ускоряет повторный анализ в той же сессии. После рестарта будем
        # полагаться на GitHub-маркеры.
        if self._state is not None:
            for c in new_inline:
                try:
                    await self._state.register_posted_finding(
                        repo, pr_number, c.finding_hash
                    )
                except Exception:  # noqa: BLE001
                    pass

        # Если ни inline'ов не было, ни review.body не публиковался, но мы
        # обновили summary — это считается успехом (summary_posted=True,
        # review_id=0).
        result = PostedReview(
            review_id=review_id,
            comments_posted=len(new_inline),
            summary_posted=summary_posted or review_summary_posted,
            deduped=deduped,
            fallback_to_summary=len(new_fallback),
            skipped=False,
        )
        log.info(
            "comment_publisher_published",
            extra={
                "repo": repo,
                "pr_number": pr_number,
                "head_sha": head_sha,
                "review_id": result.review_id,
                "inline_count": result.comments_posted,
                "summary_posted": result.summary_posted,
                "deduped": result.deduped,
                "fallback_to_summary": result.fallback_to_summary,
                "summary_action": (
                    "patched" if existing_summary_id is not None else "created"
                ),
            },
        )
        return result

    async def publish_empty(
        self, event: GitHubPullRequestEvent
    ) -> Optional[PostedComment]:
        """Публикует issue-comment «не найдено уязвимостей» (идемпотентно).

        В MVP DoD T-016 требует, чтобы метод существовал и был идемпотентен.

        Фактическое поведение (см. RT-009 doc-fix, 2026-05-15):
        - метод управляется master-switch'ем `self._enabled` (= аргумент
          `enabled` конструктора, источник — `Settings.publish_comments_enabled` /
          env `PUBLISH_COMMENTS_ENABLED`, default `true` в prod);
        - если `enabled=False` → ранний `return None` без обращения к VCS;
        - если `enabled=True` → проверяется маркер `MARKER_EMPTY`
          в существующих issue-comments PR; если маркер уже есть — возвращаем
          `None` (не дублируем и не PATCH'аем — empty-комментарий без апдейта
          смысла не имеет); если нет — публикуется один новый issue-comment с
          маркером `MARKER_EMPTY` через `vcs.post_issue_comment`;
        - VCS-ошибки (`VCSAdapterError`) логируются и проглатываются — метод
          никогда не валит pipeline.

        `Settings.publish_empty_pr_comment` (default `False`) **в MVP НЕ
        прокидывается** в этот метод и его поведение не меняет. Чтобы
        полностью отключить empty-комментарии без отключения inline+summary,
        используйте один из обходных путей:
        (a) убрать вызов `publish_empty(...)` в `PipelineOrchestrator` step 4
            (там же, где «no findings» branch);
        (b) выключить master-switch `PUBLISH_COMMENTS_ENABLED=false` (но тогда
            отключатся и inline, и summary).

        Поддержка `Settings.publish_empty_pr_comment` как отдельного opt-out —
        backlog (Variant B RT-009, см. `agents/project_info/return_tickets.md`).

        Returns:
            `PostedComment` если только что опубликован новый empty-комментарий;
            `None` во всех остальных ветках (disabled / маркер уже есть /
            VCS-ошибка).
        """
        if not self._enabled:
            return None
        repo = event.repo
        pr_number = event.pr_number

        body = (
            "**SunSecurityBot:** не найдено уязвимостей по сканируемой "
            "таксономии (SQLi / hardcoded secrets / XSS) в изменённых "
            "файлах.\n\n" + MARKER_EMPTY
        )

        try:
            existing_id = await self._find_existing_issue_marker(
                repo, pr_number, MARKER_EMPTY
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "comment_publisher_list_failed",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "error_type": type(exc).__name__,
                    "kind": "empty",
                },
            )
            existing_id = None

        if existing_id is not None:
            # Маркер уже есть — повторно ничего не публикуем.
            log.info(
                "comment_publisher_empty_already_posted",
                extra={"repo": repo, "pr_number": pr_number},
            )
            return None

        try:
            posted = await self._vcs.post_issue_comment(repo, pr_number, body)
        except VCSAdapterError as exc:
            log.exception(
                "comment_publisher_post_empty_failed",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "error_type": type(exc).__name__,
                },
            )
            return None
        log.info(
            "comment_publisher_empty_posted",
            extra={"repo": repo, "pr_number": pr_number, "comment_id": posted.id},
        )
        return posted

    async def publish_budget_exhausted(
        self, event: GitHubPullRequestEvent
    ) -> Optional[PostedComment]:
        """Публикует issue-comment про исчерпание LLM-бюджета. Идемпотентно.

        Контракт §4.7 говорит «всегда публикуется» (без env-флага), потому
        что пользователь должен видеть причину тишины. Идемпотентность
        обеспечивается маркером `<!-- sunsec:bot:v1:budget -->`: если он уже
        есть — возвращаем None.
        """
        if not self._enabled:
            return None
        repo = event.repo
        pr_number = event.pr_number

        body = (
            "**SunSecurityBot:** дневной/общий LLM-бюджет исчерпан — "
            "автоматический анализ этого PR пропущен. Свяжитесь с "
            "администратором или попробуйте позже.\n\n" + MARKER_BUDGET
        )

        try:
            existing_id = await self._find_existing_issue_marker(
                repo, pr_number, MARKER_BUDGET
            )
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "comment_publisher_list_failed",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "error_type": type(exc).__name__,
                    "kind": "budget",
                },
            )
            existing_id = None

        if existing_id is not None:
            log.info(
                "comment_publisher_budget_already_posted",
                extra={"repo": repo, "pr_number": pr_number},
            )
            return None

        try:
            posted = await self._vcs.post_issue_comment(repo, pr_number, body)
        except VCSAdapterError as exc:
            log.exception(
                "comment_publisher_post_budget_failed",
                extra={
                    "repo": repo,
                    "pr_number": pr_number,
                    "error_type": type(exc).__name__,
                },
            )
            return None
        log.info(
            "comment_publisher_budget_posted",
            extra={"repo": repo, "pr_number": pr_number, "comment_id": posted.id},
        )
        return posted

    # --- helpers ----------------------------------------------------------

    async def _collect_posted_finding_hashes(
        self, repo: str, pr_number: int
    ) -> set[str]:
        """Запрашивает у GitHub существующие review/issue-комментарии PR и
        возвращает множество finding_hash, для которых уже есть маркер.

        Защищает от дублирующейся публикации после рестарта (in-memory
        StateStore пуст). Если list_*_comments не реализован у VCS-адаптера —
        мы тихо возвращаем пустое множество (Protocol есть, но кастомные
        моки в тестах могут его не покрывать).
        """
        hashes: set[str] = set()
        review_list_fn = getattr(self._vcs, "list_review_comments", None)
        issue_list_fn = getattr(self._vcs, "list_issue_comments", None)

        if review_list_fn is not None:
            try:
                review_comments = await review_list_fn(repo, pr_number)
                hashes.update(_extract_finding_hashes(review_comments))
            except VCSAdapterError as exc:
                log.warning(
                    "comment_publisher_list_review_failed",
                    extra={
                        "repo": repo,
                        "pr_number": pr_number,
                        "error_type": type(exc).__name__,
                    },
                )

        if issue_list_fn is not None:
            try:
                issue_comments = await issue_list_fn(repo, pr_number)
                hashes.update(_extract_finding_hashes(issue_comments))
            except VCSAdapterError as exc:
                log.warning(
                    "comment_publisher_list_issue_failed",
                    extra={
                        "repo": repo,
                        "pr_number": pr_number,
                        "error_type": type(exc).__name__,
                    },
                )

        return hashes

    async def _find_existing_issue_marker(
        self, repo: str, pr_number: int, marker: str
    ) -> Optional[int]:
        """Ищет ID issue-comment'а с указанным маркером (summary/empty/budget).

        Если list_issue_comments не реализован — None (как будто не нашли).
        Так мы остаёмся идемпотентными «на best-effort»: повторный комментарий
        возможен, но не критичен (хакатон-уровень).
        """
        issue_list_fn = getattr(self._vcs, "list_issue_comments", None)
        if issue_list_fn is None:
            return None
        try:
            comments = await issue_list_fn(repo, pr_number)
        except VCSAdapterError:
            return None
        for c in comments:
            if c.body and marker in c.body:
                return c.id
        return None


# --- pure-helpers (без зависимости от self) -------------------------------


def _collect_added_lines(
    *, pr_diff: Any, filtered_diff: Optional[FilteredDiff]
) -> set[tuple[str, int]]:
    """Возвращает множество `(path, new_line_no)` всех +-строк PR.

    Источники в порядке предпочтения:
      1. `filtered_diff` (точные +-строки после DiffFilter).
      2. `pr_diff` (PRDiff из VCSAdapter; берём `type=='added'`).
      3. пустое множество (тогда все finding'и пойдут в fallback).
    """
    out: set[tuple[str, int]] = set()
    if filtered_diff is not None:
        for f in filtered_diff.files:
            for ln in f.added_lines:
                out.add((f.path, ln.new_line_no))
        return out

    if pr_diff is not None and hasattr(pr_diff, "files"):
        for diff_file in pr_diff.files:
            path = getattr(diff_file, "path", None)
            if not path:
                continue
            hunks = getattr(diff_file, "hunks", None) or []
            for hunk in hunks:
                for line in getattr(hunk, "lines", []) or []:
                    if (
                        getattr(line, "type", None) == "added"
                        and getattr(line, "new_line_no", None) is not None
                    ):
                        out.add((path, int(line.new_line_no)))
    return out


def _validate_line_in_diff(
    finding: Finding, added: set[tuple[str, int]]
) -> None:
    """Бросает `_InvalidLineError`, если (file, line) — НЕ +-строка в diff.

    Если `added` пустое (не передан diff) — мы НЕ блокируем публикацию:
    предположим, что вызывающий доверяет LLM. Это «soft mode» — pipeline
    передаст filtered_diff явно, и тогда валидация заработает строго.
    """
    if not added:
        return
    if (finding.file, finding.line) not in added:
        raise _InvalidLineError(
            f"line {finding.file}:{finding.line} not in diff added lines"
        )


def _render_inline_body(finding: Finding, fhash: str) -> str:
    """Markdown-тело inline-комментария + HTML-маркер для идемпотентности.

    T-017: если `finding.suggestion` непуст — добавляем секцию «Suggested fix»
    с fenced code block; язык определяется по расширению файла через
    `_lang_from_path`. Если `suggestion=None` или пустая — секция вообще
    не рендерится (PRD приоритет 2, вес 3).
    """
    severity = finding.severity.upper()
    class_label = _class_label(finding.class_)
    confidence_pct = int(round(finding.confidence * 100))
    parts = [
        f"**[SUNSEC][{severity}] {class_label}** (уверенность {confidence_pct}%)",
        "",
        finding.message,
    ]
    snippet = (finding.suggestion or "").strip()
    if snippet:
        lang = _lang_from_path(finding.file)
        parts.extend([
            "",
            "### Предлагаемое исправление",
            f"```{lang}",
            snippet,
            "```",
        ])
    parts.extend(["", finding_marker(fhash)])
    return "\n".join(parts)


def _render_review_lead(
    *, n_total: int, n_inline: int, n_fallback: int
) -> str:
    """Короткое тело review.body (T-017): inline-комментарии + ссылка на
    summary issue-comment.

    Контекст: после T-017 сводный summary живёт как отдельный issue-comment
    (с маркером `:summary` и PATCH-able). Поэтому review.body — лишь
    короткий лидер, чтобы пользователь видел контекст внутри review'a.
    """
    if n_total == 0 and n_inline == 0:
        # Не должно вызываться (на n_inline=0 review мы не публикуем), но на
        # всякий случай возвращаем минимальный текст.
        return "**SunSecurityBot:** подробности — в общем комментарии-сводке."

    def _ru_plural(n: int, one: str, few: str, many: str) -> str:
        n_abs = abs(int(n))
        if n_abs % 10 == 1 and n_abs % 100 != 11:
            return one
        if 2 <= n_abs % 10 <= 4 and not (12 <= n_abs % 100 <= 14):
            return few
        return many

    inline_word = _ru_plural(n_inline, "находку", "находки", "находок")
    fallback_word = _ru_plural(n_fallback, "находку", "находки", "находок")

    head = (
        f"**SunSecurityBot** опубликовал {n_inline} inline-{inline_word}"
    )
    if n_fallback:
        head += (
            f" (ещё {n_fallback} {fallback_word} не удалось привязать к строке diff)"
        )
    head += "."
    parts = [
        head,
        "",
        "Полная сводка по severity — в общем комментарии-сводке этого PR.",
    ]
    return "\n".join(parts)


def _render_summary_body(
    *,
    findings: list[Finding],
    summary_text: str,
    fallback_findings: list[Finding],
    head_sha: str = "",
) -> str:
    """Сводный summary-комментарий (T-017): развёрнутая агрегация по severity.

    Структура (PRD приоритет 2 «summary с агрегацией» + system_design §3.5):
      1. Заголовок «SunSecurityBot review» + LLM-`summary`.
      2. Severity-таблица: Critical/High/Medium/Low/Info — точные числа.
      3. Top findings (до `_TOP_N_IN_SUMMARY`): `<icon> <class> at file:line — message`.
      4. Findings without diff anchor (fallback) — каждый с finding_hash маркером.
      5. Footer: `N total, N anchored inline, M general` + short commit_sha.
      6. HTML-маркер `<!-- sunsec:bot:v1:summary -->`.
    """
    n_total = len(findings)
    n_fallback = len(fallback_findings)
    n_inline = n_total - n_fallback
    counts = Counter(f.severity for f in findings)
    severity_order = ("critical", "high", "medium", "low", "info")

    lines: list[str] = []
    lines.append("## Ревью SunSecurityBot")
    lines.append("")

    if n_total == 0:
        lines.append(
            "В изменённом коде проблем безопасности не найдено "
            "(таксономия: SQL-инъекции / хардкоженые секреты / XSS)."
        )
    else:
        word = "находок"
        # 1 находка, 2/3/4 находки, 5+ находок
        if n_total % 10 == 1 and n_total % 100 != 11:
            word = "находка"
        elif 2 <= n_total % 10 <= 4 and not (12 <= n_total % 100 <= 14):
            word = "находки"
        lines.append(f"Найдено **{n_total}** {word} в изменённом коде.")

    if summary_text:
        # Доп. защита: LLMResponseSchema уже max_length=2000.
        lines.append("")
        lines.append("> " + summary_text[:2000].replace("\n", "\n> "))

    # 2) Severity-таблица — печатаем ВСЕ 5 строк (точные числа, в т.ч. нули).
    # Severity-метки оставляем латиницей (бренд CVSS / GitHub Security UI).
    lines.append("")
    lines.append("### Распределение по severity")
    lines.append("")
    lines.append("| Severity  | Кол-во |")
    lines.append("|-----------|--------|")
    for sev in severity_order:
        icon = _SEVERITY_ICON.get(sev, "")
        label = sev.capitalize()
        c = counts.get(sev, 0)
        lines.append(f"| {icon} {label:<8} | {c}      |")

    # 3) Top-N findings (по severity, затем confidence).
    top = sorted(
        findings,
        key=lambda f: (_severity_rank(f.severity), -f.confidence),
    )[:_TOP_N_IN_SUMMARY]
    if top:
        lines.append("")
        lines.append(f"### Главные находки (показано {len(top)} из {n_total})")
        lines.append("")
        for f in top:
            icon = _SEVERITY_ICON.get(f.severity, "")
            msg = f.message.replace("\n", " ").strip()
            if len(msg) > 120:
                msg = msg[:117] + "..."
            lines.append(
                f"- {icon} **{_class_label(f.class_)}** at "
                f"`{f.file}:{f.line}` — {msg}"
            )

    # 4) Fallback (не привязалось к diff-строке) — каждый с finding-маркером,
    # чтобы дедуп при повторном анализе работал и через summary.
    if fallback_findings:
        lines.append("")
        lines.append(
            f"### Находки без привязки к diff ({n_fallback})"
        )
        lines.append("")
        lines.append(
            "_LLM указал строки, которых нет в `+`-частях diff. "
            "Список ниже, без inline-привязки:_"
        )
        lines.append("")
        for f in fallback_findings:
            fhash = finding_hash(f)
            icon = _SEVERITY_ICON.get(f.severity, "")
            msg = f.message.replace("\n", " ").strip()
            if len(msg) > 200:
                msg = msg[:197] + "..."
            lines.append(
                f"- {icon} [{f.severity}] **{_class_label(f.class_)}** "
                f"at `{f.file}:{f.line}` — {msg} {finding_marker(fhash)}"
            )

    # 5) Footer: totals + commit (short sha).
    lines.append("")
    short_sha = head_sha[:7] if head_sha else ""
    footer_parts = [
        f"всего {n_total}",
        f"привязано inline: {n_inline}",
        f"общих: {n_fallback}",
    ]
    footer = "**Итого:** " + ", ".join(footer_parts) + "."
    if short_sha:
        footer += f" Проанализирован коммит `{short_sha}`."
    lines.append(footer)

    lines.append("")
    lines.append(MARKER_SUMMARY)
    return "\n".join(lines)


def _class_label(cls: str) -> str:
    """`sql_injection` → `SQL Injection`, `hardcoded_secret` → `Hardcoded Secret`."""
    return cls.replace("_", " ").title()


def _severity_rank(sev: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(sev, 99)


_SEVERITY_ICON: dict[str, str] = {
    "critical": "[CRIT]",
    "high": "[HIGH]",
    "medium": "[MED] ",
    "low": "[LOW] ",
    "info": "[INFO]",
}


def _lang_from_path(path: str) -> str:
    """`src/app.py` → `python`. Если расширение неизвестно — пустая строка
    (fenced block без указания языка, GitHub отрендерит как plain).

    T-017: маппинг покрывает MVP-набор + популярные языки. Списки расширений
    в одном источнике (`_EXT_TO_LANG` выше), чтобы расширение было точечным.
    """
    if not path:
        return ""
    # Берём последнее расширение, в нижнем регистре. Имя без расширения →
    # пробуем по basename (например, `Dockerfile` → `dockerfile`).
    lower = path.lower()
    dot = lower.rfind(".")
    if dot == -1 or dot == len(lower) - 1:
        # Без расширения — проверяем full basename'ы.
        basename = lower.rsplit("/", 1)[-1]
        if basename == "dockerfile":
            return "dockerfile"
        if basename == "makefile":
            return "makefile"
        return ""
    ext = lower[dot:]
    return _EXT_TO_LANG.get(ext, "")


def _extract_finding_hashes(comments: Iterable[PostedComment]) -> set[str]:
    """Извлекает все finding_hash маркеры из тел переданных комментариев."""
    out: set[str] = set()
    for c in comments:
        if not c.body:
            continue
        for m in _FINDING_MARKER_RE.findall(c.body):
            out.add(m.lower())
    return out


__all__ = [
    "CommentPublisher",
    "MARKER_BUDGET",
    "MARKER_EMPTY",
    "MARKER_SUMMARY",
    "finding_hash",
    "finding_marker",
    "_lang_from_path",
]
