"""DiffFilter — PRDiff → FilteredDiff (T-009).

Зачем: отбросить из diff'а файлы, которые не имеют смысла отправлять в LLM
для security-анализа — markdown/README, картинки и бинарники, lock-файлы,
служебные `.gitignore`/`.gitattributes`, авто-сгенерированные пути.

Контракт компонента — `system_design §3.3`, входной/выходной — `§4.2 / §4.3`.
Реализует PRD приоритет 2 «Бот фильтрует README.md, .gitignore, картинки»
(вес 3) и подзадачу «анализируем только изменённый код, чтобы экономить
токены» (вес —).

Поведение:

- Файлы с `status == "removed"` отбрасываются (нечего ревьюить, см. config).
- Файлы с `patch is None` (GitHub так помечает «бинарь или слишком большой»
  — см. `system_design §3.2`, T-008 пробрасывает это через `hunks == []` и
  `is_binary == True` ⇒ для нашей задачи это эквивалентно «нет diff»).
- `is_binary == True` или расширение ∈ blacklist → исключаем.
- `basename` ∈ `exclude_names` → исключаем (`.gitignore` / `LICENSE` /
  lock-файлы).
- Полный путь матчится одним из `exclude_globs` (fnmatch) → исключаем.
- Renamed-файл: используется **новый** `path` (то, что показывается в PR
  после переименования), `old_path` хранится в `detail`.
- Для оставшихся файлов в `FilteredDiff` кладутся **только `added`-строки**;
  если их нет (например, только удаления / контекст) — файл всё равно
  отбрасывается с `reason="empty_added_lines"`.

Все исключения логируются на DEBUG со структурой `{path, reason, detail}`
и аккумулируются в `FilteredDiff.excluded_files` для будущего summary
(T-017). Stats возвращаются вызывающему через `apply_with_stats(...)` —
удобно для метрик и теста.

`DiffFilter` — pure-функция (без побочных эффектов кроме логов), не
бросает наружу.
"""
from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from typing import Optional

from sunsec.contracts import (
    AddedLine,
    DiffFile,
    ExcludeReason,
    ExcludedFile,
    FilteredDiff,
    FilteredDiffFile,
    PRDiff,
)
from sunsec.filter.config import FilterConfig

log = logging.getLogger(__name__)


# --- Language hint (для подсветки snippet'а в T-017 summary) ---------------

_LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin", ".kts": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".rs": "rust",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".cxx": "cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".sh": "bash", ".bash": "bash", ".zsh": "bash",
    ".yml": "yaml", ".yaml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".sql": "sql",
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "scss",
    ".vue": "vue",
}


def _detect_language(path: str) -> Optional[str]:
    _, ext = os.path.splitext(path.lower())
    return _LANG_BY_EXT.get(ext)


# --- Stats ------------------------------------------------------------------


@dataclass(frozen=True)
class FilterStats:
    """Агрегация по результатам фильтрации (для логов / summary)."""

    input_files: int = 0
    kept_files: int = 0
    excluded_files: int = 0
    by_reason: dict[str, int] = field(default_factory=dict)

    def as_log_dict(self) -> dict[str, object]:
        return {
            "files_in": self.input_files,
            "files_kept": self.kept_files,
            "files_excluded": self.excluded_files,
            "by_reason": dict(self.by_reason),
        }


# --- DiffFilter -------------------------------------------------------------


class DiffFilter:
    """Применяет фильтрацию к `PRDiff`. Иммутабелен, потокобезопасен."""

    def __init__(self, config: Optional[FilterConfig] = None) -> None:
        self._cfg = config or FilterConfig.default()

    # ----- public API -------------------------------------------------------

    def apply(self, diff: PRDiff) -> FilteredDiff:
        """PRDiff → FilteredDiff. Логирует summary на INFO («N kept, M excluded»)."""
        filtered, stats = self.apply_with_stats(diff)
        log.info(
            "diff_filter_summary",
            extra={
                "repo": diff.repo,
                "pr_number": diff.pr_number,
                "head_sha": diff.head_sha,
                **stats.as_log_dict(),
            },
        )
        return filtered

    def apply_with_stats(self, diff: PRDiff) -> tuple[FilteredDiff, FilterStats]:
        kept: list[FilteredDiffFile] = []
        excluded: list[ExcludedFile] = []
        by_reason: dict[str, int] = {}

        for f in diff.files:
            decision = self._classify(f)
            if decision is not None:
                reason, detail = decision
                excluded.append(ExcludedFile(path=f.path, reason=reason, detail=detail))
                by_reason[reason] = by_reason.get(reason, 0) + 1
                log.debug(
                    "diff_filter_excluded",
                    extra={
                        "repo": diff.repo,
                        "pr_number": diff.pr_number,
                        "path": f.path,
                        "reason": reason,
                        "detail": detail,
                    },
                )
                continue

            added = self._collect_added_lines(f)
            if not added and self._cfg.drop_empty_added_lines:
                excluded.append(
                    ExcludedFile(
                        path=f.path,
                        reason="empty_added_lines",
                        detail="no '+' lines after parse",
                    )
                )
                by_reason["empty_added_lines"] = by_reason.get("empty_added_lines", 0) + 1
                log.debug(
                    "diff_filter_excluded",
                    extra={
                        "repo": diff.repo,
                        "pr_number": diff.pr_number,
                        "path": f.path,
                        "reason": "empty_added_lines",
                    },
                )
                continue

            kept.append(
                FilteredDiffFile(
                    path=f.path,
                    language=_detect_language(f.path),
                    added_lines=added,
                )
            )

        content_hash = FilteredDiff.compute_content_hash(kept)
        estimated_tokens = sum(
            sum(max(1, len(line.content) // 4) for line in ff.added_lines)
            for ff in kept
        )
        result = FilteredDiff(
            repo=diff.repo,
            pr_number=diff.pr_number,
            head_sha=diff.head_sha,
            files=kept,
            estimated_input_tokens=estimated_tokens,
            content_hash=content_hash,
            excluded_files=excluded,
        )
        stats = FilterStats(
            input_files=len(diff.files),
            kept_files=len(kept),
            excluded_files=len(excluded),
            by_reason=by_reason,
        )
        return result, stats

    # ----- internals --------------------------------------------------------

    def _classify(self, f: DiffFile) -> Optional[tuple[ExcludeReason, Optional[str]]]:
        """None → файл проходит. Кортеж → отброс (reason, detail).

        Порядок (важен для информативности reason'а): сначала имя/расширение/
        glob — это даёт читабельный reason (`markdown`, `binary_ext`,
        `lock_file`). Только если по path ничего не сматчилось — fallback на
        `no_patch` (бинарь / large file без extension-маркера).
        """
        path = f.path

        # 1) Renamed → берём новое имя (это `f.path`); old_path — в detail
        #    (полезно для дебага, но фильтруем именно по новому).
        rename_detail = f.old_path if f.status == "renamed" and f.old_path else None

        # 2) Удалённый файл — нет смысла анализировать.
        if self._cfg.drop_removed_files and f.status == "removed":
            return ("removed_file", _join_detail(rename_detail, "status=removed"))

        # 3) Имя файла (basename) — `.gitignore`, lock-файлы, LICENSE.
        basename = os.path.basename(path)
        if basename in self._cfg.exclude_names:
            reason = self._reason_for_name(basename)
            return (reason, _join_detail(rename_detail, f"name={basename}"))

        # 4) Расширение (case-insensitive).
        ext = _file_ext(path)
        if ext and ext in self._cfg.exclude_extensions:
            reason = self._reason_for_extension(ext)
            return (reason, _join_detail(rename_detail, f"ext={ext}"))

        # 5) Glob-маски (fnmatch). Тестируем и полный path, и basename — это
        #    покрывает оба стиля (`vendor/**` и `*.min.js`).
        for pattern in self._cfg.exclude_globs:
            if _glob_match(path, pattern):
                return (
                    "glob_excluded",
                    _join_detail(rename_detail, f"glob={pattern}"),
                )

        # 6) GitHub помечает бинарь / large file как `patch == null` → у нас
        #    в T-008 это конвертируется в `is_binary=True` + `hunks=[]`.
        #    Это fallback после name/ext: если path ничего не сказал, но
        #    GitHub явно отметил бинарь — режем как `no_patch`.
        if self._cfg.drop_no_patch and (f.is_binary or not f.hunks):
            if f.is_binary:
                return ("no_patch", _join_detail(rename_detail, "binary or too large"))
            return ("no_patch", _join_detail(rename_detail, "no hunks in patch"))

        return None

    def _collect_added_lines(self, f: DiffFile) -> list[AddedLine]:
        added: list[AddedLine] = []
        for hunk in f.hunks:
            for ln in hunk.lines:
                if ln.type == "added" and ln.new_line_no is not None:
                    added.append(AddedLine(new_line_no=ln.new_line_no, content=ln.content))
        return added

    # ----- reason helpers (детализация для DEBUG-логов и summary) -----------

    @staticmethod
    def _reason_for_name(basename: str) -> ExcludeReason:
        lower = basename.lower()
        if lower.endswith(".lock") or lower in _LOCK_FILE_NAMES:
            return "lock_file"
        return "name_excluded"

    @staticmethod
    def _reason_for_extension(ext: str) -> ExcludeReason:
        if ext in _MARKDOWN_EXT:
            return "markdown"
        if ext in _BINARY_EXT:
            return "binary_ext"
        # Прочие исключённые расширения (если кастомные) → glob-маска по смыслу.
        return "binary_ext"


# --- module-level helpers ---------------------------------------------------


# Сабсеты для классификации причины — чтобы summary читался по-человечески.
_MARKDOWN_EXT: frozenset[str] = frozenset({".md", ".txt", ".rst", ".adoc"})

_BINARY_EXT: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico",
    ".tiff", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".flac", ".ogg", ".webm",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".wasm",
    ".pyc", ".pyo", ".pyd",
    ".o", ".a", ".lib", ".obj",
    ".jpeg2000", ".jp2",
})

_LOCK_FILE_NAMES: frozenset[str] = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "pipfile.lock", "poetry.lock", "uv.lock",
    "gemfile.lock", "cargo.lock", "composer.lock", "go.sum", "bun.lockb",
    "mix.lock", "podfile.lock", "berksfile.lock",
})


def _file_ext(path: str) -> Optional[str]:
    """Расширение в lowercase с ведущей точкой. None — нет расширения."""
    _, ext = os.path.splitext(path)
    if not ext:
        return None
    return ext.lower()


def _glob_match(path: str, pattern: str) -> bool:
    """fnmatch-обёртка. Дополнительно проверяем basename для `*.min.js`-стиля.

    fnmatch.fnmatch(`vendor/lib/x.go`, `vendor/**`) — `True`, т.к. `*` в
    fnmatch покрывает `/`. Это нам подходит (мы используем `**` как явное
    выражение интенции — «любая глубина»).
    """
    if fnmatch.fnmatchcase(path, pattern):
        return True
    base = os.path.basename(path)
    if fnmatch.fnmatchcase(base, pattern):
        return True
    return False


def _join_detail(*parts: Optional[str]) -> Optional[str]:
    """Аккуратно склеивает части detail (None пропускает)."""
    cleaned = [p for p in parts if p]
    if not cleaned:
        return None
    return "; ".join(cleaned)
