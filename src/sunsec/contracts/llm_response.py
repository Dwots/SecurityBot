"""LLMResponseSchema — канонический контракт ответа LLM.

ИСТОЧНИК ИСТИНЫ: `agents/artifacts/researcher/vuln_taxonomy.md §8 / §8.5`
(зафиксировано ADR-4 в system_design.md).

ВНИМАНИЕ: старые поля `vuln_type` / `suggested_fix` — deprecated, не использовать.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


VulnClass = Literal["sql_injection", "hardcoded_secret", "xss"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    """Одна находка LLM. Поле `class` через alias (Python keyword)."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    file: str = Field(..., description="Путь файла как в FilteredDiffFile.path")
    line: int = Field(..., ge=1, description="new_line_no в FilteredDiff")
    class_: VulnClass = Field(..., alias="class")
    severity: Severity
    message: str = Field(..., min_length=10, max_length=500)
    suggestion: Optional[str] = None
    confidence: float = Field(..., ge=0.0, le=1.0)


class LLMResponseSchema(BaseModel):
    """Корневой ответ LLM. Pipeline видит ТОЛЬКО этот тип после парсера."""

    model_config = ConfigDict(extra="ignore")

    findings: list[Finding] = Field(default_factory=list)
    summary: str = Field(..., max_length=2000)


# JSON Schema для response_format / tool_use (передаётся в LLM в T-011/T-012).
LLM_JSON_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer", "minimum": 1},
                    "class": {
                        "type": "string",
                        "enum": ["sql_injection", "hardcoded_secret", "xss"],
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                    },
                    "message": {"type": "string", "minLength": 10, "maxLength": 500},
                    "suggestion": {"type": ["string", "null"]},
                    "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                },
                "required": ["file", "line", "class", "severity", "message", "confidence"],
            },
        },
        "summary": {"type": "string", "maxLength": 2000},
    },
    "required": ["findings", "summary"],
}
