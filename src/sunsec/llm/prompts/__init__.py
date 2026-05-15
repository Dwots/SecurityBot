"""Загрузчик системного промпта v1.0.0.

Источник истины — `system_v1.md` (этот же каталог), скопировано из
`agents/artifacts/ml/system_prompt.md` (T-011, Раздел A) без модификаций.

`PROMPT_VERSION` версионирует промпт и (через T-012) уходит в:
- `PromptPayload.system` — пейлоад провайдеру;
- cache-key `LLMResponseCache` (system_design §3.6) — мажорный bump
  инвалидирует кэш by design.
"""
from __future__ import annotations

from pathlib import Path

PROMPT_VERSION = "1.0.0"
_PROMPT_FILE = Path(__file__).resolve().parent / "system_v1.md"


def _load_system_prompt_v1() -> str:
    """Читает текст промпта из .md при первом обращении.

    Файл коммитится вместе с пакетом, поэтому путь стабилен. На любой
    ошибке IO — поднимаем исключение, потому что без промпта LLMClient
    бесполезен.
    """
    return _PROMPT_FILE.read_text(encoding="utf-8")


# Eager-load: ловим отсутствие файла на импорте, а не на первом запросе PR.
SYSTEM_PROMPT_V1: str = _load_system_prompt_v1()


__all__ = ["PROMPT_VERSION", "SYSTEM_PROMPT_V1"]
