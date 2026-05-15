"""Тесты `sunsec.vcs.patch_parser.parse_patch` (T-008).

Парсер должен:
- корректно сохранять line-numbers для added/removed/context;
- поддерживать hunk header без `,N` (значит 1);
- игнорировать "\\ No newline at end of file";
- толерантно вести себя при битом / пустом patch'е.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from sunsec.vcs.patch_parser import parse_patch  # noqa: E402


def test_parse_patch_simple_single_hunk_preserves_line_numbers() -> None:
    patch = (
        "@@ -1,3 +1,4 @@\n"
        " a\n"
        "-b\n"
        "+B\n"
        "+C\n"
        " d\n"
    )
    hunks = parse_patch(patch)
    assert len(hunks) == 1
    h = hunks[0]
    assert h.old_start == 1 and h.new_start == 1
    assert h.old_lines == 3 and h.new_lines == 4
    types = [(ln.type, ln.old_line_no, ln.new_line_no, ln.content) for ln in h.lines]
    assert types == [
        ("context", 1, 1, "a"),
        ("removed", 2, None, "b"),
        ("added", None, 2, "B"),
        ("added", None, 3, "C"),
        ("context", 3, 4, "d"),
    ]


def test_parse_patch_multiple_hunks() -> None:
    patch = (
        "@@ -1,2 +1,2 @@\n"
        " a\n"
        "-b\n"
        "+B\n"
        "@@ -10 +10 @@\n"  # без `,N` — значит 1
        "-old\n"
        "+new\n"
    )
    hunks = parse_patch(patch)
    assert len(hunks) == 2
    assert hunks[0].new_start == 1 and hunks[0].new_lines == 2
    assert hunks[1].old_start == 10 and hunks[1].old_lines == 1
    assert hunks[1].new_start == 10 and hunks[1].new_lines == 1
    assert hunks[1].lines[0].type == "removed" and hunks[1].lines[0].old_line_no == 10
    assert hunks[1].lines[1].type == "added" and hunks[1].lines[1].new_line_no == 10


def test_parse_patch_ignores_no_newline_marker() -> None:
    patch = (
        "@@ -1 +1 @@\n"
        "-a\n"
        "\\ No newline at end of file\n"
        "+b\n"
        "\\ No newline at end of file\n"
    )
    hunks = parse_patch(patch)
    assert len(hunks) == 1
    assert len(hunks[0].lines) == 2  # маркеры '\\' пропущены


def test_parse_patch_empty_and_none() -> None:
    assert parse_patch(None) == []
    assert parse_patch("") == []


def test_parse_patch_skips_lines_before_first_hunk_header() -> None:
    # GitHub Files API обычно не присылает заголовки 'diff --git', но мы
    # хотим устойчивости к ним.
    patch = (
        "diff --git a/x b/x\n"
        "index abc..def 100644\n"
        "--- a/x\n"
        "+++ b/x\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )
    hunks = parse_patch(patch)
    assert len(hunks) == 1
    assert hunks[0].lines[0].type == "removed"
    assert hunks[0].lines[1].type == "added"
