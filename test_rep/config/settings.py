"""Application settings — clean baseline.

Этот файл — пример ПРАВИЛЬНОЙ работы с конфигурацией: все секретные
значения читаются из env через `os.environ.get` с дефолтами для local
dev. Никаких production-секретов в коде нет.

SunSecurityBot НЕ должен оставлять inline-комментарии в этом файле.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    """Конфигурация приложения."""

    debug: bool
    db_path: str
    log_level: str
    jwt_secret: str  # читается из env; см. JWT_SECRET ниже
    cors_origin: str


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Загрузить настройки из env.

    Все секреты — из env. Дефолты для local dev без production-values.
    """
    return Settings(
        debug=os.environ.get("APP_DEBUG", "false").lower() == "true",
        db_path=os.environ.get("APP_DB_PATH", "./demo.sqlite3"),
        log_level=os.environ.get("APP_LOG_LEVEL", "INFO"),
        # clean: env-getter; production должен установить переменную
        jwt_secret=os.environ["JWT_SECRET"] if os.environ.get("JWT_SECRET") else "",
        cors_origin=os.environ.get("APP_CORS_ORIGIN", "http://localhost:3000"),
    )
