"""Unit-тесты для `sunsec.ui.synthetic` (T-023 опциональный).

Покрытие: построение `FilteredDiff` для `.py` / `.jsx` / файлов без расширения,
вычисление `estimated_input_tokens`, `content_hash` и `language`-эвристики.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from sunsec.contracts import FilteredDiff  # noqa: E402
from sunsec.ui.synthetic import (  # noqa: E402
    FileIn,
    guess_lang_by_ext,
    synthetic_filtered_diff,
)


def test_guess_lang_by_ext_known_extensions():
    assert guess_lang_by_ext("a.py") == "python"
    assert guess_lang_by_ext("b.jsx") == "javascript"
    assert guess_lang_by_ext("c.ts") == "typescript"
    assert guess_lang_by_ext("d.go") == "go"


def test_guess_lang_by_ext_unknown_or_missing():
    assert guess_lang_by_ext("Dockerfile") is None
    assert guess_lang_by_ext("README") is None
    assert guess_lang_by_ext("") is None
    assert guess_lang_by_ext("script.unknown") is None


def test_synthetic_filtered_diff_python_file_basic():
    code = (
        "def f(x):\n"
        "    return x * 2\n"
        "y = f(10)\n"
    )
    fd = synthetic_filtered_diff([FileIn(path="a.py", code=code)])

    assert isinstance(fd, FilteredDiff)
    assert fd.repo == "ui-local/playground"
    assert fd.pr_number == 0
    assert fd.head_sha == "ui-synthetic"
    assert len(fd.files) == 1

    f0 = fd.files[0]
    assert f0.path == "a.py"
    assert f0.language == "python"
    # каждая строка → одна AddedLine с new_line_no = i+1
    assert [al.new_line_no for al in f0.added_lines] == [1, 2, 3]
    assert f0.added_lines[0].content == "def f(x):"
    assert f0.added_lines[2].content == "y = f(10)"

    # estimated_input_tokens = total_chars // 4
    total_chars = sum(len(line) for line in code.splitlines())
    assert fd.estimated_input_tokens == total_chars // 4

    # content_hash непустой sha256 hex (64 chars)
    assert fd.content_hash and len(fd.content_hash) == 64


def test_synthetic_filtered_diff_jsx_explicit_language_overrides_extension():
    fd = synthetic_filtered_diff(
        [FileIn(path="Foo.jsx", code="const a = 1;\n", language="typescript")]
    )
    assert fd.files[0].language == "typescript"  # явный язык побеждает эвристику


def test_synthetic_filtered_diff_no_extension_yields_none_language():
    fd = synthetic_filtered_diff([FileIn(path="Dockerfile", code="FROM alpine\n")])
    assert fd.files[0].language is None
    # added_lines всё равно собираются
    assert fd.files[0].added_lines[0].content == "FROM alpine"


def test_synthetic_filtered_diff_empty_code_produces_empty_added_lines():
    fd = synthetic_filtered_diff([FileIn(path="empty.py", code="")])
    assert fd.files[0].added_lines == []
    assert fd.is_empty() is True


def test_synthetic_filtered_diff_multiple_files_independent_numbering():
    fd = synthetic_filtered_diff(
        [
            FileIn(path="a.py", code="x = 1\n"),
            FileIn(path="b.jsx", code="const y = 2;\nexport y;\n"),
        ]
    )
    assert len(fd.files) == 2
    assert [al.new_line_no for al in fd.files[0].added_lines] == [1]
    assert [al.new_line_no for al in fd.files[1].added_lines] == [1, 2]
    assert fd.files[0].language == "python"
    assert fd.files[1].language == "javascript"
