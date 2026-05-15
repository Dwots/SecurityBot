"""Diff-контракты (system_design §4.2, §4.3).

PRDiff — выход VCSAdapter.fetch_pr_diff.
FilteredDiff — выход DiffFilter (только +-строки, релевантные файлы).
"""
from __future__ import annotations

import hashlib
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


# --- PRDiff (raw, system_design §4.2) ---

class DiffLine(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["context", "added", "removed"]
    old_line_no: Optional[int]
    new_line_no: Optional[int]
    content: str


class DiffHunk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    lines: list[DiffLine]


class DiffFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    status: Literal["added", "modified", "removed", "renamed"]
    old_path: Optional[str] = None
    is_binary: bool = False
    hunks: list[DiffHunk]


class PRDiff(BaseModel):
    model_config = ConfigDict(extra="forbid")
    repo: str
    pr_number: int
    head_sha: str
    base_sha: str
    files: list[DiffFile]


# --- FilteredDiff (system_design §4.3) ---

class AddedLine(BaseModel):
    model_config = ConfigDict(extra="forbid")
    new_line_no: int
    content: str


class FilteredDiffFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    language: Optional[str] = None
    added_lines: list[AddedLine]


ExcludeReason = Literal[
    "markdown",
    "binary_ext",
    "lock_file",
    "no_patch",
    "glob_excluded",
    "name_excluded",
    "removed_file",
    "empty_added_lines",
]


class ExcludedFile(BaseModel):
    """Запись об отброшенном файле (для агрегации и summary-комментария).

    Используется `DiffFilter` (T-009) и `CommentPublisher.summary` (T-017),
    чтобы пользователь видел в PR причину пропуска (`"Excluded: 3 markdown,
    2 lock, 1 binary"`).
    """

    model_config = ConfigDict(extra="forbid")
    path: str
    reason: ExcludeReason
    detail: Optional[str] = None


class FilteredDiff(BaseModel):
    """Пост-фильтр (+ -строки, релевантные файлы). См. system_design §4.3.

    `excluded_files` — расширение T-009: список того, что отбросил
    `DiffFilter` (с причиной). Не ломает совместимость — поле опционально,
    по умолчанию пустой список.
    """

    model_config = ConfigDict(extra="forbid")
    repo: str
    pr_number: int
    head_sha: str
    files: list[FilteredDiffFile]
    estimated_input_tokens: int = 0
    content_hash: str = ""
    excluded_files: list[ExcludedFile] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(f.added_lines for f in self.files)

    @staticmethod
    def compute_content_hash(files: list[FilteredDiffFile]) -> str:
        """sha256 от отсортированного [(path, new_line_no, content)] — ключ LLM-кэша."""
        rows: list[str] = []
        for f in sorted(files, key=lambda x: x.path):
            for ln in f.added_lines:
                rows.append(f"{f.path}\x00{ln.new_line_no}\x00{ln.content}")
        h = hashlib.sha256("\n".join(rows).encode("utf-8"))
        return h.hexdigest()
