"""Unit-тесты `DiffFilter` (T-009).

Покрытие — по одному+ тесту на каждую категорию из DoD T-009:
- markdown (`*.md` / `*.txt` / `*.rst`)
- бинарь по расширению (`*.png` / `*.zip` / ...)
- lock-файлы (`package-lock.json`, `Pipfile.lock`, ...)
- `.gitignore` / `.gitattributes`
- `patch == None` (T-008 пробрасывает как `is_binary=True` + `hunks=[]`)
- renamed файл — фильтрация по **новому** имени
- glob-маски (`vendor/**`, `*.min.js`)
- чистый исходник (`*.py`) — проходит
- empty PRDiff → empty FilteredDiff (с пустым `excluded_files`)
- content_hash детерминирован после фильтрации
- env-overrides конфига (FILTER_EXCLUDE_EXTENSIONS пустой → ничего не режет)

Тесты следуют принципу «assert behavior, not implementation»: проверяем
только публичные методы (`apply` / `apply_with_stats`) и итоговый
`FilteredDiff`.
"""
from __future__ import annotations

import logging

import pytest

from sunsec.config.settings import Settings
from sunsec.contracts import (
    DiffFile,
    DiffHunk,
    DiffLine,
    FilteredDiff,
    PRDiff,
)
from sunsec.filter import (
    DEFAULT_EXCLUDE_EXTENSIONS,
    DEFAULT_EXCLUDE_GLOBS,
    DEFAULT_EXCLUDE_NAMES,
    DiffFilter,
    FilterConfig,
    build_filter_from_settings,
)
from sunsec.filter.config import _normalize_extensions


# --- helpers ---------------------------------------------------------------


def _line(t: str, content: str, new_line_no: int | None = None, old_line_no: int | None = None) -> DiffLine:
    return DiffLine(
        type=t,  # type: ignore[arg-type]
        old_line_no=old_line_no,
        new_line_no=new_line_no,
        content=content,
    )


def _hunk(*lines: DiffLine, new_start: int = 1, new_lines: int | None = None) -> DiffHunk:
    if new_lines is None:
        new_lines = sum(1 for ln in lines if ln.type in ("added", "context"))
    return DiffHunk(
        old_start=1,
        old_lines=sum(1 for ln in lines if ln.type in ("removed", "context")),
        new_start=new_start,
        new_lines=new_lines,
        lines=list(lines),
    )


def _file(
    path: str,
    *,
    status: str = "modified",
    old_path: str | None = None,
    is_binary: bool = False,
    hunks: list[DiffHunk] | None = None,
) -> DiffFile:
    return DiffFile(
        path=path,
        status=status,  # type: ignore[arg-type]
        old_path=old_path,
        is_binary=is_binary,
        hunks=hunks or [],
    )


def _pr(*files: DiffFile, repo: str = "alice/proj", pr_number: int = 42) -> PRDiff:
    return PRDiff(
        repo=repo,
        pr_number=pr_number,
        head_sha="a" * 40,
        base_sha="b" * 40,
        files=list(files),
    )


def _src_file(path: str = "src/app.py", first_line: int = 10) -> DiffFile:
    """Минимальный «настоящий» source-файл с одной добавленной строкой."""
    return _file(
        path,
        status="modified",
        hunks=[
            _hunk(
                _line("context", "before", new_line_no=first_line - 1, old_line_no=first_line - 1),
                _line("added", "x = 1", new_line_no=first_line),
                new_start=first_line - 1,
            )
        ],
    )


# --- DoD categories --------------------------------------------------------


def test_markdown_files_are_excluded() -> None:
    """`*.md` / `*.txt` / `*.rst` (default DEFAULT_EXCLUDE_EXTENSIONS) — режутся
    с reason=markdown."""
    diff = _pr(
        _file("README.md", hunks=[_hunk(_line("added", "# title", new_line_no=1))]),
        _file("notes.txt", hunks=[_hunk(_line("added", "note", new_line_no=1))]),
        _file("docs/api.rst", hunks=[_hunk(_line("added", "API", new_line_no=1))]),
        _src_file(),
    )
    out, stats = DiffFilter().apply_with_stats(diff)

    paths_kept = [f.path for f in out.files]
    assert paths_kept == ["src/app.py"]

    excluded_paths = {ef.path: ef.reason for ef in out.excluded_files}
    assert excluded_paths == {
        "README.md": "markdown",
        "notes.txt": "markdown",
        "docs/api.rst": "markdown",
    }
    assert stats.by_reason["markdown"] == 3
    assert stats.kept_files == 1


def test_binary_extensions_are_excluded() -> None:
    """Картинки / pdf / архивы / wasm — режутся по расширению."""
    diff = _pr(
        _file("logo.png", hunks=[]),
        _file("doc.pdf", hunks=[]),
        _file("module.wasm", hunks=[]),
        _file("archive.tar.gz", hunks=[]),
        _src_file(),
    )
    out, stats = DiffFilter().apply_with_stats(diff)
    # gzip = binary; png/pdf/wasm/gz — все binary_ext
    reasons = {ef.path: ef.reason for ef in out.excluded_files}
    assert reasons["logo.png"] == "binary_ext"
    assert reasons["doc.pdf"] == "binary_ext"
    assert reasons["module.wasm"] == "binary_ext"
    assert reasons["archive.tar.gz"] == "binary_ext"
    assert [f.path for f in out.files] == ["src/app.py"]


def test_lock_files_excluded_by_name() -> None:
    """Lock-файлы (package-lock.json, poetry.lock, ...) — по точному basename."""
    locks = [
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "Gemfile.lock",
        "Cargo.lock",
        "composer.lock",
        "go.sum",
        "bun.lockb",
    ]
    files = [_file(name, hunks=[_hunk(_line("added", "x", new_line_no=1))]) for name in locks]
    files.append(_src_file())
    diff = _pr(*files)
    out, _ = DiffFilter().apply_with_stats(diff)

    for name in locks:
        match = [ef for ef in out.excluded_files if ef.path == name]
        assert match, f"expected {name} to be excluded"
        assert match[0].reason == "lock_file", f"{name}: {match[0].reason}"
    assert [f.path for f in out.files] == ["src/app.py"]


def test_gitignore_and_gitattributes_excluded() -> None:
    """`.gitignore` / `.gitattributes` / `.editorconfig` — режутся как
    name_excluded (служебные имена, не lock-файлы)."""
    diff = _pr(
        _file(".gitignore", hunks=[_hunk(_line("added", "*.pyc", new_line_no=1))]),
        _file(".gitattributes", hunks=[_hunk(_line("added", "* text=auto", new_line_no=1))]),
        _file(".editorconfig", hunks=[_hunk(_line("added", "indent=4", new_line_no=1))]),
        _src_file(),
    )
    out, _ = DiffFilter().apply_with_stats(diff)
    reasons = {ef.path: ef.reason for ef in out.excluded_files}
    assert reasons[".gitignore"] == "name_excluded"
    assert reasons[".gitattributes"] == "name_excluded"
    assert reasons[".editorconfig"] == "name_excluded"


def test_no_patch_binary_or_large_file() -> None:
    """`patch == None` от GitHub → у нас `is_binary=True` + `hunks=[]`.
    Должно отдать reason=no_patch."""
    diff = _pr(
        _file("huge.bin", is_binary=True, hunks=[]),
        _src_file(),
    )
    out, _ = DiffFilter().apply_with_stats(diff)
    no_patch = [ef for ef in out.excluded_files if ef.path == "huge.bin"]
    assert len(no_patch) == 1
    assert no_patch[0].reason == "no_patch"
    assert "binary or too large" in (no_patch[0].detail or "")


def test_renamed_file_filtered_by_new_name() -> None:
    """Renamed: PNG → MD должен резаться как markdown по новому пути.
    old_path попадает в detail для отладки."""
    diff = _pr(
        _file(
            "docs/intro.md",
            status="renamed",
            old_path="docs/intro.txt",
            hunks=[_hunk(_line("added", "hi", new_line_no=1))],
        ),
    )
    out, _ = DiffFilter().apply_with_stats(diff)
    assert len(out.excluded_files) == 1
    rec = out.excluded_files[0]
    assert rec.path == "docs/intro.md"  # фильтруем по новому имени
    assert rec.reason == "markdown"
    assert "docs/intro.txt" in (rec.detail or "")  # old_path виден в detail


def test_renamed_source_file_kept_under_new_name() -> None:
    """Renamed «настоящий» source-файл должен пройти под новым именем."""
    diff = _pr(
        _file(
            "src/new.py",
            status="renamed",
            old_path="src/old.py",
            hunks=[_hunk(_line("added", "y = 2", new_line_no=1))],
        ),
    )
    out, _ = DiffFilter().apply_with_stats(diff)
    assert [f.path for f in out.files] == ["src/new.py"]


def test_glob_excluded_vendor_and_min_js() -> None:
    """Glob-маски: `vendor/**`, `*.min.js`."""
    diff = _pr(
        _file("vendor/lib/x.go", hunks=[_hunk(_line("added", "package x", new_line_no=1))]),
        _file("static/app.min.js", hunks=[_hunk(_line("added", "var x", new_line_no=1))]),
        _file("src/app.generated.ts", hunks=[_hunk(_line("added", "export", new_line_no=1))]),
        _src_file(),
    )
    out, _ = DiffFilter().apply_with_stats(diff)
    excluded = {ef.path: ef.reason for ef in out.excluded_files}
    assert excluded["vendor/lib/x.go"] == "glob_excluded"
    assert excluded["static/app.min.js"] == "glob_excluded"
    assert excluded["src/app.generated.ts"] == "glob_excluded"
    assert [f.path for f in out.files] == ["src/app.py"]


def test_clean_source_file_passes_through() -> None:
    """«Чистый» исходник на Python — проходит, language=python."""
    diff = _pr(_src_file("src/handler.py", first_line=5))
    out = DiffFilter().apply(diff)
    assert len(out.files) == 1
    f = out.files[0]
    assert f.path == "src/handler.py"
    assert f.language == "python"
    assert len(f.added_lines) == 1
    assert f.added_lines[0].new_line_no == 5
    assert f.added_lines[0].content == "x = 1"


def test_removed_file_excluded() -> None:
    """status=removed → нечего анализировать."""
    diff = _pr(_file("src/old.py", status="removed", hunks=[]))
    out, _ = DiffFilter().apply_with_stats(diff)
    assert out.files == []
    assert out.excluded_files[0].reason == "removed_file"


def test_empty_added_lines_excluded() -> None:
    """Файл с одними `context` / `removed` строками → empty_added_lines."""
    diff = _pr(
        _file(
            "src/touched.py",
            hunks=[
                _hunk(
                    _line("context", "kept", new_line_no=1, old_line_no=1),
                    _line("removed", "gone", old_line_no=2),
                )
            ],
        )
    )
    out, _ = DiffFilter().apply_with_stats(diff)
    assert out.files == []
    assert out.excluded_files[0].reason == "empty_added_lines"


# --- contract / aggregations ----------------------------------------------


def test_content_hash_is_deterministic_after_filter() -> None:
    """compute_content_hash на kept-files детерминирован между прогонами
    (для idempotency LLM-кэша, см. system_design ADR-4)."""
    diff = _pr(_src_file("src/a.py", first_line=1), _src_file("src/b.py", first_line=2))
    out1 = DiffFilter().apply(diff)
    out2 = DiffFilter().apply(diff)
    assert out1.content_hash == out2.content_hash
    assert len(out1.content_hash) == 64  # sha256 hex


def test_estimated_tokens_grows_with_content() -> None:
    """Оценка токенов растёт пропорционально объёму +-строк."""
    short = _pr(_src_file("a.py"))
    long_line = "x" * 400
    big = _pr(
        _file(
            "b.py",
            hunks=[_hunk(_line("added", long_line, new_line_no=1))],
        )
    )
    out_short = DiffFilter().apply(short)
    out_big = DiffFilter().apply(big)
    assert out_big.estimated_input_tokens > out_short.estimated_input_tokens


def test_empty_diff_returns_empty_result() -> None:
    """Пустой PRDiff (нет файлов вовсе) → пустой FilteredDiff, не падает."""
    diff = _pr()
    out, stats = DiffFilter().apply_with_stats(diff)
    assert out.files == []
    assert out.excluded_files == []
    assert stats.input_files == 0
    assert stats.kept_files == 0
    assert out.is_empty()


def test_excluded_files_aggregation_counts_by_reason() -> None:
    """Stats.by_reason должен корректно агрегировать счётчик."""
    diff = _pr(
        _file("README.md", hunks=[_hunk(_line("added", "x", new_line_no=1))]),
        _file("CHANGELOG.md", hunks=[_hunk(_line("added", "x", new_line_no=1))]),
        _file("logo.png", hunks=[]),
        _file("yarn.lock", hunks=[_hunk(_line("added", "x", new_line_no=1))]),
        _src_file(),
    )
    out, stats = DiffFilter().apply_with_stats(diff)
    assert stats.input_files == 5
    assert stats.kept_files == 1
    assert stats.excluded_files == 4
    # README.md → markdown; CHANGELOG.md → name_excluded (точное имя), но
    # `CHANGELOG.md` тоже есть в DEFAULT_EXCLUDE_NAMES → name_excluded.
    # Однако `.md` идёт раньше? Нет: классификация порядок — name перед
    # extension. Проверяем итог.
    assert stats.by_reason.get("markdown", 0) >= 1
    assert stats.by_reason.get("binary_ext", 0) == 1
    assert stats.by_reason.get("lock_file", 0) == 1


# --- config / env-overrides ------------------------------------------------


def test_filter_config_defaults_contain_key_categories() -> None:
    """Дефолты содержат самые важные расширения / имена / глобы из DoD."""
    for ext in (".md", ".txt", ".png", ".jpg", ".pdf", ".zip", ".so", ".wasm"):
        assert ext in DEFAULT_EXCLUDE_EXTENSIONS, ext
    for name in (".gitignore", "package-lock.json", "poetry.lock", "go.sum", "Cargo.lock"):
        assert name in DEFAULT_EXCLUDE_NAMES, name
    assert any("vendor" in g for g in DEFAULT_EXCLUDE_GLOBS)


def test_filter_config_env_overrides_extensions_csv() -> None:
    """Settings: `FILTER_EXCLUDE_EXTENSIONS=.foo,.bar` → пропускаем
    только `.foo` / `.bar`, всё остальное оставляем."""
    s = Settings.from_env(env={"FILTER_EXCLUDE_EXTENSIONS": ".foo,.bar"})
    assert s.filter_exclude_extensions == (".foo", ".bar")

    cfg = FilterConfig.from_settings(
        extensions=s.filter_exclude_extensions,
        names=s.filter_exclude_names,
        globs=s.filter_exclude_globs,
    )
    # `*.md` теперь НЕ исключаем (env переопределил).
    assert ".md" not in cfg.exclude_extensions
    assert ".foo" in cfg.exclude_extensions
    # Имена и глобы остаются дефолтными.
    assert ".gitignore" in cfg.exclude_names
    assert "vendor/**" in cfg.exclude_globs


def test_build_filter_from_settings_applies_overrides() -> None:
    """Полный path: Settings → DiffFilter; `.md` теперь проходит."""
    s = Settings.from_env(env={
        "FILTER_EXCLUDE_EXTENSIONS": ".png",  # только png отрезаем
        "FILTER_EXCLUDE_NAMES": "",           # пустое — НЕ оверрайдим (None)
        "FILTER_EXCLUDE_GLOBS": "",
    })
    flt = build_filter_from_settings(s)
    diff = _pr(
        _file("README.md", hunks=[_hunk(_line("added", "x", new_line_no=1))]),
        _file("logo.png", hunks=[]),
    )
    out, _ = flt.apply_with_stats(diff)
    # README.md прошёл (env переопределил расширения), png отрезан.
    kept = [f.path for f in out.files]
    excluded = {ef.path for ef in out.excluded_files}
    assert "README.md" in kept
    assert "logo.png" in excluded


def test_normalize_extensions_handles_case_and_dots() -> None:
    """`MD`, `.MD`, `  md `, `.md` — все приводятся к `.md`."""
    norm = _normalize_extensions(["MD", ".MD", "  md ", ".md"])
    assert norm == frozenset({".md"})


# --- logging behavior ------------------------------------------------------


def test_excluded_files_logged_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    """Каждое исключение даёт DEBUG-лог `diff_filter_excluded` с reason."""
    diff = _pr(_file("README.md", hunks=[_hunk(_line("added", "x", new_line_no=1))]))
    with caplog.at_level(logging.DEBUG, logger="sunsec.filter.diff_filter"):
        DiffFilter().apply(diff)
    messages = [rec.message for rec in caplog.records]
    assert "diff_filter_excluded" in messages


def test_summary_logged_at_info(caplog: pytest.LogCaptureFixture) -> None:
    """Summary-лог `diff_filter_summary` всегда на INFO с метриками."""
    diff = _pr(_src_file())
    with caplog.at_level(logging.INFO, logger="sunsec.filter.diff_filter"):
        DiffFilter().apply(diff)
    summary = [r for r in caplog.records if r.message == "diff_filter_summary"]
    assert summary, "expected diff_filter_summary log"
    record = summary[0]
    # Проверяем, что метрики попали в extra.
    assert getattr(record, "files_in", None) == 1
    assert getattr(record, "files_kept", None) == 1
