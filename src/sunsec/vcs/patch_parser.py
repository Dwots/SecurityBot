"""Парсер unified-diff patches GitHub Files API.

GitHub Files API возвращает для каждого файла поле `patch` со стандартным
unified-diff'ом (см. https://docs.github.com/en/rest/pulls/pulls#list-pull-requests-files).
Этот модуль превращает текст patch'а в структурированный `list[DiffHunk]`
из контракта `PRDiff` (system_design §4.2), сохраняя line-numbers, чтобы
T-009 (filter) и T-016 (inline comments) могли работать с конкретными
`new_line_no` / `old_line_no`.

Формат hunk header: ``@@ -<old_start>[,<old_lines>] +<new_start>[,<new_lines>] @@ [section]``
Где `<old_lines>` / `<new_lines>` могут отсутствовать (значит 1).

Префиксы строк:
- ``+`` — added (только в new)
- ``-`` — removed (только в old)
- (space) — context (есть и там и там)
- ``\\`` — "No newline at end of file" — игнорируем (не строка кода)
"""
from __future__ import annotations

import re
from typing import Iterable

from sunsec.contracts import DiffHunk, DiffLine

_HUNK_HEADER_RE = re.compile(
    r"^@@\s+-(?P<old_start>\d+)(?:,(?P<old_lines>\d+))?"
    r"\s+\+(?P<new_start>\d+)(?:,(?P<new_lines>\d+))?\s+@@"
)


def parse_patch(patch: str | None) -> list[DiffHunk]:
    """Превращает GitHub `patch` в `list[DiffHunk]`.

    Никогда не бросает — на любую структурную странность возвращает то, что
    удалось распарсить (best-effort: лучше потерять hunk, чем уронить pipeline
    из-за edge-case формата). Пустой / None `patch` → `[]`.
    """
    if not patch:
        return []

    hunks: list[DiffHunk] = []
    current_header: re.Match[str] | None = None
    current_lines: list[DiffLine] = []
    cur_old_no: int | None = None
    cur_new_no: int | None = None

    def _flush() -> None:
        if current_header is None:
            return
        hunks.append(
            DiffHunk(
                old_start=int(current_header.group("old_start")),
                old_lines=int(current_header.group("old_lines") or 1),
                new_start=int(current_header.group("new_start")),
                new_lines=int(current_header.group("new_lines") or 1),
                lines=list(current_lines),
            )
        )

    for raw in _iter_lines(patch):
        m = _HUNK_HEADER_RE.match(raw)
        if m is not None:
            # начинается новый hunk — закрываем предыдущий
            _flush()
            current_header = m
            current_lines = []
            cur_old_no = int(m.group("old_start"))
            cur_new_no = int(m.group("new_start"))
            continue

        if current_header is None:
            # текст до первого hunk header'а (diff-метаданные) — пропускаем
            continue

        if not raw:
            # пустая строка внутри patch'а — трактуем как context "" (редко, но бывает)
            current_lines.append(
                DiffLine(
                    type="context",
                    old_line_no=cur_old_no,
                    new_line_no=cur_new_no,
                    content="",
                )
            )
            if cur_old_no is not None:
                cur_old_no += 1
            if cur_new_no is not None:
                cur_new_no += 1
            continue

        prefix = raw[0]
        body = raw[1:]

        if prefix == "+":
            current_lines.append(
                DiffLine(
                    type="added",
                    old_line_no=None,
                    new_line_no=cur_new_no,
                    content=body,
                )
            )
            if cur_new_no is not None:
                cur_new_no += 1
        elif prefix == "-":
            current_lines.append(
                DiffLine(
                    type="removed",
                    old_line_no=cur_old_no,
                    new_line_no=None,
                    content=body,
                )
            )
            if cur_old_no is not None:
                cur_old_no += 1
        elif prefix == " ":
            current_lines.append(
                DiffLine(
                    type="context",
                    old_line_no=cur_old_no,
                    new_line_no=cur_new_no,
                    content=body,
                )
            )
            if cur_old_no is not None:
                cur_old_no += 1
            if cur_new_no is not None:
                cur_new_no += 1
        elif prefix == "\\":
            # "\ No newline at end of file" — служебный маркер, не строка
            continue
        else:
            # неожиданный префикс — best-effort: трактуем как context, чтобы
            # не потерять смещение line-numbers
            current_lines.append(
                DiffLine(
                    type="context",
                    old_line_no=cur_old_no,
                    new_line_no=cur_new_no,
                    content=raw,
                )
            )
            if cur_old_no is not None:
                cur_old_no += 1
            if cur_new_no is not None:
                cur_new_no += 1

    _flush()
    return hunks


def _iter_lines(patch: str) -> Iterable[str]:
    # `splitlines` без `keepends` — нам не нужны `\n` в `content`. GitHub
    # отдаёт patch с `\n` разделителем; на `\r\n` Windows-репо тоже работает.
    return patch.splitlines()


__all__ = ["parse_patch"]
