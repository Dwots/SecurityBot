"""Структурированный JSON-логгер с маскированием секретов.

system_design §9 + ml_instructions_polza §4 — hard requirement: ключи и токены
никогда не должны попадать в логи (в т.ч. в exception tracebacks).
"""
from sunsec.logging_ext.redaction import (
    SENSITIVE_KEY_PATTERN,
    REDACTED_PLACEHOLDER,
    redact_mapping,
    redact_value,
)
from sunsec.logging_ext.setup import configure_logging, get_logger

__all__ = [
    "SENSITIVE_KEY_PATTERN",
    "REDACTED_PLACEHOLDER",
    "configure_logging",
    "get_logger",
    "redact_mapping",
    "redact_value",
]
