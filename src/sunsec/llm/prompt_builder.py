"""PromptBuilder — компонует system + user сообщение для polza.ai.

См. system_design §3.4: `LLMClient` использует `PromptBuilder.build(filtered_diff)`
для получения `PromptPayload`, который затем уходит транспортному
`LLMProvider.analyze(payload)`.

Render diff: для каждого `FilteredDiffFile.path` → один блок:

    --- file: path/to/file.py ---
    L<line>: <content>
    L<line>: <content>

Этот формат — компромисс между «полным unified diff» (который пришлось
бы реконструировать из `+` строк, теряя контекст) и «только added_lines»
(дёшево, но без явного указания line_no). Префикс `L<n>:` помогает LLM
вернуть правильный `line` в `Finding`.

Версия промпта (`PROMPT_VERSION` из `llm.prompts`) подмешивается в
текст `system` инструкции как хвостовой комментарий — это нужно, чтобы
при апгрейде промпта старый кэш `LLMResponseCache` был автоматически
инвалидирован (хеш меняется вместе с текстом).
"""
from __future__ import annotations

from typing import Any, Optional

from sunsec.contracts import FilteredDiff, LLMResponseSchema  # noqa: F401 (re-export)
from sunsec.contracts.llm_response import LLM_JSON_SCHEMA
from sunsec.llm.base import PromptPayload
from sunsec.llm.prompts import PROMPT_VERSION, SYSTEM_PROMPT_V1


class PromptBuilder:
    """Stateless билдер промпта (FilteredDiff → PromptPayload)."""

    def __init__(
        self,
        *,
        system_prompt: str = SYSTEM_PROMPT_V1,
        prompt_version: str = PROMPT_VERSION,
        use_json_schema: bool = False,
    ) -> None:
        self._system = system_prompt
        self._version = prompt_version
        self._use_json_schema = bool(use_json_schema)

    @property
    def prompt_version(self) -> str:
        return self._version

    def build(self, filtered: FilteredDiff) -> PromptPayload:
        """FilteredDiff → PromptPayload (готов для `LLMProvider.analyze`)."""
        user = self._render_user_message(filtered)
        response_schema: Optional[dict[str, Any]] = None
        response_format = "json_object"
        if self._use_json_schema:
            response_schema = LLM_JSON_SCHEMA
            response_format = "json_schema"
        return PromptPayload(
            system=self._system,
            user=user,
            response_schema=response_schema,
            response_format=response_format,
        )

    # --- render helpers ---

    def _render_user_message(self, filtered: FilteredDiff) -> str:
        header = (
            f"Repo: {filtered.repo}\n"
            f"PR: #{filtered.pr_number}\n"
            f"Head SHA: {filtered.head_sha}\n"
            f"Files changed: {len(filtered.files)}\n"
        )
        parts: list[str] = [header.rstrip(), ""]
        if not filtered.files or filtered.is_empty():
            parts.append("# (no added lines after filtering)")
            return "\n".join(parts)

        for f in filtered.files:
            if not f.added_lines:
                continue
            parts.append(f"--- file: {f.path} ---")
            for ln in f.added_lines:
                # Сохраняем оригинальный contents, обрезаем хвостовые \r.
                content = ln.content.rstrip("\r")
                parts.append(f"L{ln.new_line_no}: {content}")
            parts.append("")  # пустая строка между файлами

        return "\n".join(parts).rstrip() + "\n"


__all__ = ["PromptBuilder", "PROMPT_VERSION", "SYSTEM_PROMPT_V1"]
