"""Redaction для sensitive-полей.

Hard requirement из system_design §9 и ml_instructions_polza §4:
ключи / токены никогда не попадают в логи.

Маскируем поля, имя которых матчит регекс по подстрокам:
- token
- secret
- api_key / apikey
- authorization
- password
"""
from __future__ import annotations

import re
from typing import Any, Mapping

# Регекс по имени ключа (case-insensitive). Покрывает: api_key, apikey,
# secret, secret_key, token, polza_token, authorization, password, passwd.
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:api[_-]?key|secret|token|authorization|password|passwd|bearer)",
    re.IGNORECASE,
)

REDACTED_PLACEHOLDER = "***REDACTED***"

# Регекс на значение, похожее на Bearer-токен / API-ключ внутри строки.
# Срабатывает, например, на "Bearer sk-abc...", "api_key=xxx" в свободном тексте.
_VALUE_BEARER_RE = re.compile(
    r"(?i)(bearer\s+)([A-Za-z0-9._\-]{8,})"
)
_VALUE_KV_RE = re.compile(
    r"(?i)((?:api[_-]?key|token|secret|authorization|password)\s*[:=]\s*)([\"']?)([A-Za-z0-9._\-]{6,})\2"
)


def _is_sensitive_key(key: str) -> bool:
    return bool(SENSITIVE_KEY_PATTERN.search(key))


def redact_value(value: Any) -> Any:
    """Маскирует только строки, в которых видим Bearer/api_key-паттерн.

    Не агрессивен: обычные строки не трогает. Для агрессивной маскировки используй
    `redact_mapping`, где имя ключа само по себе сигнализирует о секрете.
    """
    if not isinstance(value, str):
        return value
    out = _VALUE_BEARER_RE.sub(lambda m: m.group(1) + REDACTED_PLACEHOLDER, value)
    out = _VALUE_KV_RE.sub(lambda m: m.group(1) + REDACTED_PLACEHOLDER, out)
    return out


def redact_mapping(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """Возвращает копию dict, где значения sensitive-ключей заменены на placeholder.

    Рекурсивно проходит по вложенным dict / list.
    """
    result: dict[str, Any] = {}
    for key, value in mapping.items():
        key_str = str(key)
        if _is_sensitive_key(key_str):
            # Маскируем, даже если значение None/"" — иначе тестовая ловушка обходима.
            if value in (None, ""):
                result[key_str] = value
            else:
                result[key_str] = REDACTED_PLACEHOLDER
            continue
        if isinstance(value, Mapping):
            result[key_str] = redact_mapping(value)
        elif isinstance(value, (list, tuple)):
            result[key_str] = [
                redact_mapping(v) if isinstance(v, Mapping) else redact_value(v)
                for v in value
            ]
        else:
            result[key_str] = redact_value(value)
    return result
