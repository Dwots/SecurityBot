"""Исключения persistence-слоя (system_design v1.2.1 §11.5).

`StorageError` — общий базовый класс; маппится HTTP-router'ом (T-039) на
соответствующие статусы (`StorageConflictError` → 409,
`StorageNotFoundError` → 404).
"""
from __future__ import annotations


class StorageError(Exception):
    """Общая ошибка persistence-слоя."""


class StorageConflictError(StorageError):
    """UNIQUE constraint violation (например, дубликат `repo_configs.full_name`)."""


class StorageNotFoundError(StorageError):
    """Запрошенная запись не найдена (для PATCH/DELETE routes)."""


__all__ = [
    "StorageError",
    "StorageConflictError",
    "StorageNotFoundError",
]
