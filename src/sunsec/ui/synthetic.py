"""Сборка `FilteredDiff` из сырого кода для UI (T-023, `tmp/gui_plan.md §4`).

Семантика: трактуем КАЖДУЮ строку файла как `added` — как будто это новый
файл в PR. Это даёт LLM полный контекст и достаточно для smoke-теста
«увидит ли LLM уязвимость». Реальный patch-parsing покрыт unit-тестами
`tests/unit/test_patch_parser.py` — здесь это намеренное упрощение.

Контракты НЕ меняются: возвращается стандартный `FilteredDiff` из
`sunsec.contracts`, который дальше идёт в `FalsePositiveFilter.pre_llm_scan`
и `LLMClient.analyze` без модификаций.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from sunsec.contracts import AddedLine, FilteredDiff, FilteredDiffFile


# Расширение → язык для подсказки LLM. Если расширение не известно — None,
# LLM сама разберётся (поле опциональное в `FilteredDiffFile`).
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".rb": "ruby",
    ".php": "php",
    ".go": "go",
    ".rs": "rust",
    ".cs": "csharp",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".c": "c",
    ".h": "c",
    ".hpp": "cpp",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "bash",
    ".bash": "bash",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".vue": "vue",
    ".svelte": "svelte",
}


def guess_lang_by_ext(path: str) -> Optional[str]:
    """Подсказка LLM по расширению. None — если не угадали (поле опциональное)."""
    if not path:
        return None
    _, ext = os.path.splitext(path)
    if not ext:
        return None
    return _EXT_TO_LANG.get(ext.lower())


@dataclass(frozen=True)
class FileIn:
    """Внутренняя модель файла из UI. Pydantic-валидация — на роутере."""

    path: str
    code: str
    language: Optional[str] = None


def synthetic_filtered_diff(files: list[FileIn]) -> FilteredDiff:
    """Превращает список UI-файлов в `FilteredDiff` (см. `tmp/gui_plan.md §4`).

    - Каждая строка файла → `AddedLine(new_line_no=i+1, content=line)`.
    - Пустые файлы (code == "") дают `FilteredDiffFile` с пустым `added_lines` —
      это валидно и потом отрабатывается short-circuit'ом `FilteredDiff.is_empty()`
      внутри `LLMClient.analyze` (см. `src/sunsec/llm/client.py`).
    - `language` берётся из ввода или `guess_lang_by_ext`. Если оба пусты — None.
    - `repo="ui-local/playground"`, `pr_number=0`, `head_sha="ui-synthetic"` —
      синтетические маркеры, чтобы логи и метрики ясно отделяли UI-вызовы
      от реальных PR.
    - `estimated_input_tokens = total_chars // 4` — те же ~4 chars/token, что
      использует `DiffFilter` (см. `src/sunsec/filter/diff_filter.py`).
    - `content_hash` — `FilteredDiff.compute_content_hash` (тот же sha256
      по `(path, line_no, content)`, что и в обычном пайплайне).
    """
    fd_files: list[FilteredDiffFile] = []
    total_chars = 0
    for f in files:
        added: list[AddedLine] = []
        if f.code:
            for i, line in enumerate(f.code.splitlines()):
                added.append(AddedLine(new_line_no=i + 1, content=line))
                total_chars += len(line)
        fd_files.append(
            FilteredDiffFile(
                path=f.path,
                language=f.language or guess_lang_by_ext(f.path),
                added_lines=added,
            )
        )

    return FilteredDiff(
        repo="ui-local/playground",
        pr_number=0,
        head_sha="ui-synthetic",
        files=fd_files,
        estimated_input_tokens=total_chars // 4,
        content_hash=FilteredDiff.compute_content_hash(fd_files),
        excluded_files=[],
    )


__all__ = ["FileIn", "guess_lang_by_ext", "synthetic_filtered_diff"]
