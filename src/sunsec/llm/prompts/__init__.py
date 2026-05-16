"""Загрузчик системного промпта v1.2.0 + reply-промпт v1.0.0.

Источник истины — `system_v1.md` (review) и `reply_system.md` (диалог).

История версий (review):
- v1.0.0 (T-011, 2026-05-14) — initial SQLi/secrets/XSS.
- v1.1.0 (T-032, 2026-05-16) — Server-side template XSS sub-section.
- v1.2.0 (2026-05-16) — Force RUSSIAN-only for human-facing fields
  (`message`, `summary`, prose inside `suggestion`). Canonical empty
  summary localized.

`PROMPT_VERSION` уходит в `PromptPayload.system` и в cache-key — мажорный
bump инвалидирует кэш by design.

`EMPTY_SUMMARY` — единая каноническая строка для пустых findings. Должна
ОДНОВРЕМЕННО присутствовать (а) в системном промпте, (б) в `LLMClient`-
фолбеке, (в) в тестовых фикстурах. Меняем здесь — меняется везде.
"""
from __future__ import annotations

from pathlib import Path

PROMPT_VERSION = "1.2.0"
REPLY_PROMPT_VERSION = "1.0.0"
EMPTY_SUMMARY = "В diff не обнаружено проблем безопасности."

_PROMPT_FILE = Path(__file__).resolve().parent / "system_v1.md"
_REPLY_PROMPT_FILE = Path(__file__).resolve().parent / "reply_system.md"


def _load_system_prompt_v1() -> str:
    """Читает текст промпта из .md при первом обращении.

    Файл коммитится вместе с пакетом, поэтому путь стабилен. На любой
    ошибке IO — поднимаем исключение, потому что без промпта LLMClient
    бесполезен.
    """
    return _PROMPT_FILE.read_text(encoding="utf-8")


def _load_reply_prompt_v1() -> str:
    """Reply-промпт для диалога в комментариях PR (T-019)."""
    return _REPLY_PROMPT_FILE.read_text(encoding="utf-8")


# Eager-load: ловим отсутствие файла на импорте, а не на первом запросе PR.
SYSTEM_PROMPT_V1: str = _load_system_prompt_v1()
REPLY_SYSTEM_PROMPT_V1: str = _load_reply_prompt_v1()


__all__ = [
    "PROMPT_VERSION",
    "SYSTEM_PROMPT_V1",
    "REPLY_PROMPT_VERSION",
    "REPLY_SYSTEM_PROMPT_V1",
    "EMPTY_SUMMARY",
]
