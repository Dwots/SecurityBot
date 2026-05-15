"""ML-слой SunSecurityBot — постпроцессинг находок LLM.

T-013: `FalsePositiveFilter` — двухступенчатый фильтр (pre-LLM + post-LLM)
для снижения false positives и детерминированного детектора секретов.

См. спецификацию: `agents/artifacts/ml/false_positive_filter.md`.
"""
from sunsec.ml.false_positive_filter import (
    FalsePositiveFilter,
    FPFilterConfig,
    build_fp_filter_from_settings,
)

__all__ = [
    "FalsePositiveFilter",
    "FPFilterConfig",
    "build_fp_filter_from_settings",
]
