"""FilterConfig — дефолты и фабрика конфига `DiffFilter` (T-009).

Списки расширений / имён / glob-масок вынесены сюда, чтобы их видел и
`Settings.from_env` (CSV в env), и unit-тесты (без необходимости поднимать
полный `Settings`). Источники:

- `system_design §3.3` (рекомендованный blacklist).
- `tracking_table T-009` (минимальный список расширений и lock-файлов).
- `requirements/prd.md` приоритет 2 «фильтрует README.md, .gitignore, картинки».

ВНИМАНИЕ: все расширения хранятся **строго lowercase, с ведущей точкой**
(`.md`, не `md`). Сравнение проводится приведённым к lowercase.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional


# --- Defaults ---------------------------------------------------------------

#: Markdown / plain text — по умолчанию мы их пропускаем (PRD #6).
#: Переопределяется `FILTER_EXCLUDE_EXTENSIONS=.md,.txt` или `=` (пустой → ничего).
DEFAULT_EXCLUDE_EXTENSIONS: frozenset[str] = frozenset({
    # markdown / text / docs
    ".md", ".txt", ".rst", ".adoc",
    # images / vector
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".ico", ".tiff",
    # PDFs / archives
    ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    # fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # media
    ".mp3", ".mp4", ".mov", ".avi", ".wav", ".flac", ".ogg", ".webm",
    # binaries / compiled
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".wasm",
    ".pyc", ".pyo", ".pyd",
    ".o", ".a", ".lib", ".obj",
    # legacy / extra image
    ".jpeg2000", ".jp2",
})

#: Файлы-имена, которые исключаем целиком (точное совпадение `basename`).
DEFAULT_EXCLUDE_NAMES: frozenset[str] = frozenset({
    ".gitignore", ".gitattributes", ".gitmodules", ".editorconfig",
    "LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "NOTICE",
    "CHANGELOG", "CHANGELOG.md", "CHANGELOG.rst",
    # lock-файлы (точные имена; глобы — для редких типа `*.lock`)
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "uv.lock",
    "Gemfile.lock", "Cargo.lock", "composer.lock", "go.sum", "bun.lockb",
    "mix.lock", "Podfile.lock", "Berksfile.lock",
})

#: Glob-маски (fnmatch-style). Применяются к полному `path`.
#: NB: `vendor/**` в fnmatch покрывает любые уровни вложенности (`**` ⇒ `*`),
#: но для соответствия gitignore-семантике мы дополнительно тестируем
#: `vendor/*` и подкаталоги через recursion в `DiffFilter`.
DEFAULT_EXCLUDE_GLOBS: tuple[str, ...] = (
    "vendor/**",
    "node_modules/**",
    "dist/**",
    "build/**",
    "*.generated.*",
    "*.min.js",
    "*.min.css",
    "*.map",                # source-maps
    "**/__pycache__/**",
    "**/.next/**",
    "**/.nuxt/**",
    "**/.venv/**",
)


# --- Config object ----------------------------------------------------------


@dataclass(frozen=True)
class FilterConfig:
    """Иммутабельный конфиг `DiffFilter`. Создаётся через `from_settings` /
    `default` / напрямую (для тестов)."""

    exclude_extensions: frozenset[str] = DEFAULT_EXCLUDE_EXTENSIONS
    exclude_names: frozenset[str] = DEFAULT_EXCLUDE_NAMES
    exclude_globs: tuple[str, ...] = DEFAULT_EXCLUDE_GLOBS

    # Поведенческие флаги (явные, чтобы не плодить «магические» инварианты).
    drop_no_patch: bool = True            # `patch == None` от GitHub
    drop_removed_files: bool = True       # status == "removed" → нечего анализировать
    drop_empty_added_lines: bool = True   # после фильтрации hunks нет `+`-строк

    @classmethod
    def default(cls) -> "FilterConfig":
        return cls()

    @classmethod
    def from_settings(
        cls,
        *,
        extensions: Optional[Iterable[str]] = None,
        names: Optional[Iterable[str]] = None,
        globs: Optional[Iterable[str]] = None,
    ) -> "FilterConfig":
        """Принимает переопределения из `Settings` (None → дефолт).

        Все расширения нормализуются: lowercase + ведущая точка.
        """
        return cls(
            exclude_extensions=(
                _normalize_extensions(extensions)
                if extensions is not None
                else DEFAULT_EXCLUDE_EXTENSIONS
            ),
            exclude_names=(
                frozenset(n.strip() for n in names if n.strip())
                if names is not None
                else DEFAULT_EXCLUDE_NAMES
            ),
            exclude_globs=(
                tuple(g.strip() for g in globs if g.strip())
                if globs is not None
                else DEFAULT_EXCLUDE_GLOBS
            ),
        )


def _normalize_extensions(items: Iterable[str]) -> frozenset[str]:
    """`'.MD'`, `'md'`, `'  .Md '` → все приведутся к `'.md'`."""
    out: set[str] = set()
    for raw in items:
        if raw is None:
            continue
        s = str(raw).strip().lower()
        if not s:
            continue
        if not s.startswith("."):
            s = "." + s
        out.add(s)
    return frozenset(out)
