"""Структурированный JSON-логгер на stdlib `logging` (без внешних зависимостей).

Если установлен `structlog` — он может быть подключён позднее; для каркаса
используем минимальную stdlib-реализацию: один Formatter, JSON-вывод, hook
маскирующий extra и аргументы.

Использование:

    from sunsec.logging_ext import configure_logging, get_logger
    configure_logging(level="INFO", fmt="json")
    log = get_logger(__name__)
    log.info("pipeline_started", extra={"repo": "owner/r", "pr": 1, "api_key": "sk-..."})
    # api_key в выводе будет заменён на ***REDACTED***
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from sunsec.logging_ext.redaction import (
    REDACTED_PLACEHOLDER,
    redact_mapping,
    redact_value,
)

# Стандартные атрибуты `logging.LogRecord`, которые НЕ являются user-extra
# и должны быть отфильтрованы при сериализации.
_STD_LOGRECORD_ATTRS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "asctime", "taskName",
})


class _RedactingJSONFormatter(logging.Formatter):
    """JSON-formatter с маскированием sensitive-полей в extra и аргументах."""

    def format(self, record: logging.LogRecord) -> str:
        # Базовый payload.
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Маскируем message — на случай, если в строку попал bearer-токен.
        payload["msg"] = redact_value(payload["msg"])

        # Достаём extra-поля.
        extras: dict[str, Any] = {}
        for k, v in record.__dict__.items():
            if k in _STD_LOGRECORD_ATTRS or k.startswith("_"):
                continue
            extras[k] = v
        if extras:
            payload.update(redact_mapping(extras))

        # Stack / exception — маскируем как строку (часто туда попадают
        # Authorization-заголовки из tracebacks внешних SDK).
        if record.exc_info:
            exc_text = self.formatException(record.exc_info)
            payload["exc_text"] = redact_value(exc_text)
        if record.stack_info:
            payload["stack"] = redact_value(record.stack_info)

        try:
            return json.dumps(payload, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            # На случай несериализуемых объектов в extra — fallback на str().
            safe = {k: (v if isinstance(v, (str, int, float, bool, type(None))) else str(v))
                    for k, v in payload.items()}
            return json.dumps(safe, ensure_ascii=False)


class _RedactingTextFormatter(logging.Formatter):
    """Текстовый человекочитаемый формат — для локальной отладки."""

    def __init__(self) -> None:
        super().__init__(fmt="%(asctime)s %(levelname)s %(name)s | %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        record.msg = redact_value(record.getMessage())
        record.args = ()  # уже отрендерили в getMessage
        extras: dict[str, Any] = {}
        for k, v in record.__dict__.items():
            if k in _STD_LOGRECORD_ATTRS or k.startswith("_"):
                continue
            extras[k] = v
        base = super().format(record)
        if extras:
            redacted = redact_mapping(extras)
            tail = " ".join(f"{k}={v}" for k, v in redacted.items())
            return f"{base} | {tail}"
        return base


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Настраивает корневой логгер. Идемпотентна.

    Args:
        level: DEBUG / INFO / WARNING / ERROR / CRITICAL.
        fmt: "json" (default) или "text".
    """
    root = logging.getLogger()
    # Сносим существующие handlers, чтобы избежать дублирования при повторном вызове.
    for h in list(root.handlers):
        root.removeHandler(h)

    handler = logging.StreamHandler(stream=sys.stdout)
    if fmt.lower() == "text":
        handler.setFormatter(_RedactingTextFormatter())
    else:
        handler.setFormatter(_RedactingJSONFormatter())
    root.addHandler(handler)

    level_num = getattr(logging, level.upper(), logging.INFO)
    root.setLevel(level_num)

    # Шум сторонних библиотек на WARNING.
    for noisy in ("urllib3", "httpx", "httpcore", "openai"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Удобная обёртка."""
    return logging.getLogger(name)


__all__ = [
    "configure_logging",
    "get_logger",
    "REDACTED_PLACEHOLDER",
]
