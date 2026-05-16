"""LLMClient — доменный фасад (system_design §3.4).

Контракт: `FilteredDiff → LLMResponseSchema`.

Цепочка:
1. `PromptBuilder.build(filtered)` → `PromptPayload`.
2. `BudgetCounter.check_and_reserve(estimated_cost)` — kill-switch (ADR-2).
   Estimate: `prompt_tokens` ≈ `FilteredDiff.estimated_input_tokens`,
   `completion_tokens` ≈ Settings.llm_max_tokens (worst-case).
3. `provider.analyze(payload)` → `LLMRawResponse` (raw JSON-строка).
4. Парсер: `LLMResponseSchema.model_validate_json(raw.content)`.
   - При битом JSON → возвращаем пустой `LLMResponseSchema` с
     `summary="LLM response parse error — skipped."` (системное сообщение).
   - Невалидные `findings` (отдельные элементы) — отбрасываем поэлементно
     с логом `llm_finding_invalid`.
5. `BudgetCounter.commit(actual_cost)`; метрика `llm_call_completed`.

Контракты ошибок:
- `BudgetExceeded` — пробрасываем вверх, оркестратор обрабатывает.
- `LLMTimeout` / `LLMProviderUnavailable` — также пробрасываем; пайплайн
  логирует и возвращает пустой комментарий (T-016).
- Любая ValidationError на корневой схеме → empty response (НЕ исключение).

Безопасность:
- Никаких `repr(provider)` / `repr(client._provider)` с подмешанным
  ключом в логи. В extra идут только домен-поля (model, tokens, cost).
"""
from __future__ import annotations

import json
import logging
import time
from typing import Any

from pydantic import ValidationError

from sunsec.contracts import FilteredDiff, Finding, LLMResponseSchema
from sunsec.llm.base import (
    BudgetExceeded,
    LLMParseError,
    LLMProvider,
    LLMProviderUnavailable,
    LLMTimeout,
    PromptPayload,
)
from sunsec.llm.budget import BudgetCounter
from sunsec.llm.prompt_builder import PromptBuilder
from sunsec.llm.prompts import EMPTY_SUMMARY

log = logging.getLogger(__name__)


def _empty_response(summary: str = "LLM response unavailable — analysis skipped.") -> LLMResponseSchema:
    return LLMResponseSchema(findings=[], summary=summary)


class LLMClient:
    """Доменный фасад polza.ai (FilteredDiff → LLMResponseSchema)."""

    def __init__(
        self,
        *,
        provider: LLMProvider,
        builder: PromptBuilder | None = None,
        budget: BudgetCounter | None = None,
    ) -> None:
        self._provider = provider
        self._builder = builder or PromptBuilder()
        self._budget = budget

    @property
    def prompt_version(self) -> str:
        return self._builder.prompt_version

    @property
    def budget(self) -> BudgetCounter | None:
        """Публичный доступ к BudgetCounter (T-023 / `tmp/gui_plan.md §9`).

        Используется UI-роутером `build_ui_router` для отдачи `/api/ui/budget`
        без обращения к приватному полю `_budget`. Возвращает `None`, если
        LLM-клиент инициализирован без счётчика (например, polza.ai ключ
        не задан и `app.py` собрал клиент без бюджета).

        Контракт: read-only. Менять состояние счётчика снаружи нельзя —
        это сделает только сам `LLMClient` через `check_and_reserve` /
        `commit` / `release`.
        """
        return self._budget

    async def analyze(self, filtered: FilteredDiff) -> LLMResponseSchema:
        """Вызывает polza.ai и парсит ответ в `LLMResponseSchema`.

        Контракт ошибок — см. модуль-docstring. Кратко:
        - `BudgetExceeded` → raise (kill-switch).
        - `LLMTimeout` / `LLMProviderUnavailable` → raise.
        - Любые проблемы парсинга → `LLMResponseSchema(findings=[], summary=...)`.
        """
        if filtered.is_empty():
            # Дешёвый short-circuit — LLM ничего не увидит, не тратим бюджет.
            log.info(
                "llm_call_skipped_empty_diff",
                extra={"repo": filtered.repo, "pr_number": filtered.pr_number},
            )
            return LLMResponseSchema(
                findings=[],
                summary=EMPTY_SUMMARY,
            )

        payload = self._builder.build(filtered)

        # --- бюджет: резервируем worst-case (estimated_input + max_output) ---
        estimated_cost = self._estimate_cost(filtered, payload)
        reservation_id: int | None = None
        if self._budget is not None:
            reservation_id = self._budget.check_and_reserve(estimated_cost)

        t0 = time.monotonic()
        raw = None
        try:
            try:
                raw = await self._provider.analyze(payload)
            except (LLMTimeout, LLMProviderUnavailable):
                if self._budget is not None and reservation_id is not None:
                    self._budget.release(reservation_id)
                raise

            actual_cost = self._provider.estimate_cost_rub(raw.usage)
            response = self._parse_response(raw.content, filtered=filtered)

            if self._budget is not None and reservation_id is not None:
                self._budget.commit(actual_cost, reservation_id)

            self._log_call_completed(
                filtered=filtered,
                raw_model=raw.model,
                prompt_tokens=raw.usage.prompt_tokens,
                completion_tokens=raw.usage.completion_tokens,
                cost_rub=actual_cost,
                latency_ms=raw.latency_ms or (time.monotonic() - t0) * 1000.0,
                findings_count=len(response.findings),
            )
            return response
        except BudgetExceeded:
            # Не должны попасть сюда (check_and_reserve кинул выше),
            # но на всякий случай — откатываем резерв.
            if self._budget is not None and reservation_id is not None:
                self._budget.release(reservation_id)
            raise

    # --- helpers ---

    def _estimate_cost(self, filtered: FilteredDiff, payload: PromptPayload) -> float:
        """Worst-case оценка для kill-switch (резервации).

        Приближение токенов:
        - input: `filtered.estimated_input_tokens` (заполняет DiffFilter)
          + длина системного промпта / 4 (приближение 1 token ≈ 4 chars).
        - output: текущий `llm_max_tokens` — это потолок, который мы дали SDK.

        Это намеренная переоценка: лучше зарезервировать чуть больше и
        потом скорректировать через `commit`, чем пробить лимит.
        """
        input_tokens = int(filtered.estimated_input_tokens or 0) + max(
            1, len(payload.system) // 4
        )
        output_tokens = self._provider_max_output_tokens()
        usage_like = type("U", (), {"prompt_tokens": input_tokens, "completion_tokens": output_tokens})()
        try:
            return float(self._provider.estimate_cost_rub(usage_like))  # type: ignore[arg-type]
        except Exception:  # noqa: BLE001
            # Fallback: считаем по нулю, чтобы не блокировать вызов из-за бага в провайдере.
            return 0.0

    def _provider_max_output_tokens(self) -> int:
        # У всех наших провайдеров поле `_max_tokens` — приватное; не
        # хотим жёстко завязываться. Если не нашли — берём дефолт 2048.
        return int(getattr(self._provider, "_max_tokens", 2048))

    def _parse_response(
        self,
        content: str,
        *,
        filtered: FilteredDiff,
    ) -> LLMResponseSchema:
        """Жёсткий парсер: невалидный JSON → empty; невалидные findings → drop."""
        content = (content or "").strip()
        if not content:
            log.warning(
                "llm_response_empty",
                extra={"repo": filtered.repo, "pr_number": filtered.pr_number},
            )
            return _empty_response("LLM returned empty response — skipped.")

        # Сначала: парсим как dict, затем валидируем findings поэлементно.
        # Это нужно, чтобы 1 битая находка не убивала весь ответ.
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            log.warning(
                "llm_response_json_decode_error",
                extra={
                    "repo": filtered.repo,
                    "pr_number": filtered.pr_number,
                    "error": str(exc),
                    "content_length": len(content),
                },
            )
            return _empty_response("LLM response invalid JSON — skipped.")

        if not isinstance(data, dict):
            log.warning(
                "llm_response_not_object",
                extra={
                    "repo": filtered.repo,
                    "pr_number": filtered.pr_number,
                    "type": type(data).__name__,
                },
            )
            return _empty_response("LLM response not a JSON object — skipped.")

        # Поэлементно валидируем findings.
        raw_findings = data.get("findings") or []
        valid_findings: list[Finding] = []
        for idx, item in enumerate(raw_findings):
            if not isinstance(item, dict):
                log.info(
                    "llm_finding_invalid",
                    extra={
                        "repo": filtered.repo,
                        "pr_number": filtered.pr_number,
                        "index": idx,
                        "reason": "not_dict",
                    },
                )
                continue
            try:
                f = Finding.model_validate(item)
            except ValidationError as exc:
                log.info(
                    "llm_finding_invalid",
                    extra={
                        "repo": filtered.repo,
                        "pr_number": filtered.pr_number,
                        "index": idx,
                        "errors_count": len(exc.errors()),
                    },
                )
                continue
            valid_findings.append(f)

        summary = data.get("summary")
        if not isinstance(summary, str):
            summary = EMPTY_SUMMARY if not valid_findings else ""
        # Жёсткий cap на summary (даже если LLM проигнорировал) — Pydantic откажет.
        if len(summary) > 2000:
            summary = summary[:2000]

        try:
            return LLMResponseSchema(findings=valid_findings, summary=summary)
        except ValidationError as exc:
            log.warning(
                "llm_response_root_validation_error",
                extra={
                    "repo": filtered.repo,
                    "pr_number": filtered.pr_number,
                    "errors_count": len(exc.errors()),
                },
            )
            return _empty_response("LLM response schema invalid — skipped.")

    def _log_call_completed(
        self,
        *,
        filtered: FilteredDiff,
        raw_model: str,
        prompt_tokens: int,
        completion_tokens: int,
        cost_rub: float,
        latency_ms: float,
        findings_count: int,
    ) -> None:
        budget_remaining: Any = None
        budget_spent: Any = None
        if self._budget is not None:
            budget_remaining = round(
                max(0.0, self._budget.limit_rub - self._budget.spent_rub), 6
            )
            budget_spent = round(self._budget.spent_rub, 6)
        log.info(
            "llm_call_completed",
            extra={
                "provider": getattr(self._provider, "name", "unknown"),
                "model": raw_model,
                "prompt_tokens": int(prompt_tokens),
                "completion_tokens": int(completion_tokens),
                "cost_rub": round(float(cost_rub), 6),
                "latency_ms": int(latency_ms),
                "findings_count": int(findings_count),
                "prompt_version": self.prompt_version,
                "repo": filtered.repo,
                "pr_number": filtered.pr_number,
                "head_sha": filtered.head_sha,
                "budget_spent_rub": budget_spent,
                "budget_remaining_rub": budget_remaining,
            },
        )

    def __repr__(self) -> str:  # без секретов — `LLMClient(provider=polza, ...)`
        provider_name = getattr(self._provider, "name", "unknown")
        budget_repr = repr(self._budget) if self._budget is not None else "None"
        return (
            f"LLMClient(provider={provider_name!r}, "
            f"prompt_version={self.prompt_version!r}, budget={budget_repr})"
        )


__all__ = ["LLMClient", "_empty_response", "LLMParseError"]
