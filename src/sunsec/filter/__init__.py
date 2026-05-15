"""DiffFilter — фильтрация diff'а до релевантных для security-анализа +-строк.

Публичный API (T-009):
- `DiffFilter` — основной класс, `.apply(PRDiff) -> FilteredDiff`.
- `FilterConfig` — иммутабельный конфиг (списки расширений / имён / глобов).
- `FilterStats` — агрегация по результатам фильтрации (для логов / summary).
- `build_filter_from_settings(settings) -> DiffFilter` — фабрика.
"""
from sunsec.filter.config import (
    DEFAULT_EXCLUDE_EXTENSIONS,
    DEFAULT_EXCLUDE_GLOBS,
    DEFAULT_EXCLUDE_NAMES,
    FilterConfig,
)
from sunsec.filter.diff_filter import DiffFilter, FilterStats


def build_filter_from_settings(settings) -> DiffFilter:  # type: ignore[no-untyped-def]
    """Сборка `DiffFilter` из `Settings` (env-overrides → FilterConfig).

    Сигнатура без аннотации, чтобы не тащить циклический импорт
    `sunsec.config.settings` в `sunsec.filter.config`.
    """
    cfg = FilterConfig.from_settings(
        extensions=settings.filter_exclude_extensions,
        names=settings.filter_exclude_names,
        globs=settings.filter_exclude_globs,
    )
    return DiffFilter(cfg)


__all__ = [
    "DiffFilter",
    "FilterConfig",
    "FilterStats",
    "DEFAULT_EXCLUDE_EXTENSIONS",
    "DEFAULT_EXCLUDE_NAMES",
    "DEFAULT_EXCLUDE_GLOBS",
    "build_filter_from_settings",
]
