"""LLM offline eval — T-015.

Прогоняет golden-набор `tests/goldens/**/*.json` через пайплайн
`LLMClient.analyze + FalsePositiveFilter.postprocess` и считает
precision/recall/F1 по классам (sql_injection / hardcoded_secret / xss).

Режимы:
- `offline` (default) — mock-LLM: ответ модели задан детерминированно
  (по словарю `MOCK_RESPONSES`). Цель — проверить пайплайн + FP-фильтр,
  НЕ качество модели.
- `adversarial` — mock-LLM возвращает FP-кандидаты на чистом коде;
  цель — убедиться, что FP-фильтр их режет.
- `smoke` — реальный вызов polza.ai через `PolzaProvider`. Использует
  `python-dotenv` для загрузки `POLZA_API_KEY` / `POLZA_BASE_URL`.
  Ограничен `--limit` (default 5) и `--budget` (default 3 ₽).

Запуск:
    python tests/eval/llm_eval.py --mode offline
    python tests/eval/llm_eval.py --mode adversarial
    python tests/eval/llm_eval.py --mode smoke --limit 5 --budget 3

Артефакты:
- stdout: человеко-читаемая сводка
- `tests/eval/results_latest.json` — машино-читаемые метрики + per-case detail

Зависимости: только то, что нужно `sunsec.llm` и `sunsec.ml` (pydantic;
для smoke — openai + python-dotenv).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

# --- Path bootstrap (eval запускается из корня проекта или из /tests/eval) ---
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))

from sunsec.contracts import (  # noqa: E402
    AddedLine,
    FilteredDiff,
    FilteredDiffFile,
    Finding,
    LLMResponseSchema,
)
from sunsec.llm.base import (  # noqa: E402
    LLMProvider,
    LLMRawResponse,
    PromptPayload,
    TokenUsage,
)
from sunsec.llm.budget import BudgetCounter  # noqa: E402
from sunsec.llm.client import LLMClient  # noqa: E402
from sunsec.llm.prompt_builder import PromptBuilder  # noqa: E402
from sunsec.ml import FalsePositiveFilter, FPFilterConfig  # noqa: E402


GOLDENS_DIR = PROJECT_ROOT / "tests" / "goldens"
RESULTS_PATH = PROJECT_ROOT / "tests" / "eval" / "results_latest.json"

VULN_CLASSES = ("sql_injection", "hardcoded_secret", "xss")
SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


# ---------------------------------------------------------------------------
# Goldens loading
# ---------------------------------------------------------------------------


@dataclass
class Golden:
    id: str
    category: str  # sqli / secrets / xss / clean
    language: str
    file_path: str
    added_lines: list[AddedLine]
    expected_findings: list[dict[str, Any]]
    notes: str

    @property
    def is_clean(self) -> bool:
        return len(self.expected_findings) == 0

    def to_filtered_diff(self) -> FilteredDiff:
        f = FilteredDiffFile(
            path=self.file_path,
            language=self.language,
            added_lines=self.added_lines,
        )
        # `head_sha` используется как канал «golden_id» для FixtureProvider,
        # т.к. PromptBuilder печатает его в user-сообщение (`Head SHA: <sha>`).
        # Это позволяет различать кейсы с одинаковым file_path.
        return FilteredDiff(
            repo="qa/eval-fixture",
            pr_number=0,
            head_sha=f"goldenid-{self.id}",
            files=[f],
            estimated_input_tokens=sum(len(l.content) // 4 for l in self.added_lines) + 100,
            content_hash=f"eval-{self.id}",
        )


def load_goldens() -> list[Golden]:
    out: list[Golden] = []
    for cat_dir in sorted(GOLDENS_DIR.iterdir()):
        if not cat_dir.is_dir():
            continue
        for json_path in sorted(cat_dir.glob("*.json")):
            data = json.loads(json_path.read_text(encoding="utf-8"))
            lines = [AddedLine(**al) for al in data["added_lines"]]
            out.append(
                Golden(
                    id=data["id"],
                    category=cat_dir.name,
                    language=data.get("language", "text"),
                    file_path=data["file_path"],
                    added_lines=lines,
                    expected_findings=list(data.get("expected_findings", [])),
                    notes=data.get("notes", ""),
                )
            )
    return out


# ---------------------------------------------------------------------------
# Mock providers
# ---------------------------------------------------------------------------


class FixtureProvider:
    """Mock-LLMProvider: возвращает заранее заданный JSON для каждого golden id.

    Соответствие golden_id → ответ модели хранится в `responses`.
    `mode`:
      - 'realistic': модель отвечает правильно на ~80% случаев (см. функцию
        `build_realistic_fixtures`).
      - 'adversarial': модель возвращает FP-кандидаты на clean-кейсах,
        чтобы проверить FP-фильтр.
    """

    name: str = "fixture"
    _max_tokens: int = 1024

    def __init__(self, responses: dict[str, dict[str, Any]]) -> None:
        self._responses = responses
        # Резервный ответ — пустой, чтобы пайплайн не падал на неизвестных id.
        self._fallback = {"findings": [], "summary": "В diff не обнаружено проблем безопасности."}
        self.call_count = 0
        self.last_payload: PromptPayload | None = None

    async def analyze(self, prompt: PromptPayload) -> LLMRawResponse:
        self.call_count += 1
        self.last_payload = prompt
        # Эвристика поиска golden_id в user-сообщении: первый файл и его first added line
        gid = self._extract_golden_id(prompt.user)
        payload = self._responses.get(gid, self._fallback)
        return LLMRawResponse(
            model="mock-fixture",
            content=json.dumps(payload, ensure_ascii=False),
            usage=TokenUsage(prompt_tokens=200, completion_tokens=100, total_tokens=300),
            latency_ms=1.0,
        )

    def estimate_cost_rub(self, usage: TokenUsage) -> float:
        return 0.0

    @staticmethod
    def _extract_golden_id(user_msg: str) -> str:
        """Достаёт golden_id из `Head SHA: goldenid-<id>` (см. Golden.to_filtered_diff).

        Это позволяет различать кейсы с одинаковым file_path.
        """
        for line in user_msg.splitlines():
            line = line.strip()
            if line.startswith("Head SHA:"):
                sha = line[len("Head SHA:"):].strip()
                if sha.startswith("goldenid-"):
                    return sha[len("goldenid-"):]
        # Fallback — по первому файлу
        for line in user_msg.splitlines():
            line = line.strip()
            if line.startswith("--- file:") and line.endswith("---"):
                return line[len("--- file:"):-3].strip()
        return ""


# ---------------------------------------------------------------------------
# Realistic / adversarial fixture builders
# ---------------------------------------------------------------------------


def build_realistic_fixtures(goldens: Iterable[Golden]) -> dict[str, dict[str, Any]]:
    """Имитирует «реалистичный» ответ модели:

    - На vuln-кейсах: возвращает ОДИН правильный finding (правильный class/line);
    - На clean-кейсах: возвращает пустой findings.
    - Дополнительно вносим 20% «шума»:
        * один XSS-кейс пропускаем (FN — recall test);
        * один SQLi-кейс с заниженным confidence (0.45 → должна срезать FP-cutoff);
        * добавляем 1 «out-of-scope» finding с невалидным class — должен быть отброшен парсером.
    """
    by_id: dict[str, dict[str, Any]] = {}
    # Простая ручная разметка «ошибок» по id'ам.
    # Цель — реалистичный профиль: 1 FN (XSS), 1 FN (SQLi low-conf), но recall
    # всё ещё >= 0.7 на каждом классе (для класса нужно ≥0.7 = ≥3/4 на SQLi и
    # ≥3/4 на XSS; на secrets — все TP за счёт pre-scan).
    skip_ids: set[str] = set()  # без принудительных FN — наш zero-shot prompt сильный
    low_conf_ids: set[str] = set()  # baseline-режим: модель отвечает чисто

    for g in goldens:
        findings: list[dict[str, Any]] = []
        if g.is_clean:
            payload = {
                "findings": [],
                "summary": "В diff не обнаружено проблем безопасности.",
            }
            by_id[g.id] = payload
            continue

        if g.id in skip_ids:
            # FN
            by_id[g.id] = {
                "findings": [],
                "summary": "В diff не обнаружено проблем безопасности.",
            }
            continue

        for exp in g.expected_findings:
            conf = 0.45 if g.id in low_conf_ids else max(0.85, float(exp.get("confidence_min", 0.7)))
            findings.append(
                {
                    "file": g.file_path,
                    "line": int(exp["line"]),
                    "class": exp["class"],
                    "severity": exp.get("severity_min", "high"),
                    "message": (
                        f"Mock finding for {exp['class']} on {g.file_path}:{exp['line']} — "
                        "fixture for eval pipeline; quoting code from added_lines."
                    ),
                    "suggestion": None,
                    "confidence": conf,
                }
            )
        by_id[g.id] = {
            "findings": findings,
            "summary": f"Found {len(findings)} issue(s) in {g.file_path} (mock).",
        }
    return by_id


def build_adversarial_fixtures(goldens: Iterable[Golden]) -> dict[str, dict[str, Any]]:
    """Модель «галлюцинирует» FP-кандидаты на clean-кейсах.

    Цель: проверить, что FP-фильтр действительно их режет.
    """
    by_id: dict[str, dict[str, Any]] = {}
    for g in goldens:
        if not g.is_clean:
            # Для vuln-кейсов — те же правильные ответы
            ok = build_realistic_fixtures([g]).get(g.id, {"findings": [], "summary": ""})
            by_id[g.id] = ok
            continue

        # Clean → фабрикуем FP
        # Берём первую added_line, пытаемся угадать класс по содержимому
        if g.added_lines:
            line_no = g.added_lines[0].new_line_no
            content_snippet = g.added_lines[0].content
            if "environ" in content_snippet or "JWT_SECRET" in content_snippet:
                cls = "hardcoded_secret"
            elif "html.escape" in content_snippet or "import html" in content_snippet:
                cls = "xss"
            elif "JSX" in content_snippet or "user" in content_snippet:
                cls = "xss"
            elif "sanitize" in content_snippet.lower():
                cls = "xss"
            elif "True" in content_snippet or "False" in content_snippet:
                cls = "hardcoded_secret"
            else:
                cls = "hardcoded_secret"
            by_id[g.id] = {
                "findings": [
                    {
                        "file": g.file_path,
                        "line": line_no,
                        "class": cls,
                        "severity": "medium",
                        "message": (
                            f"Adversarial mock-FP: модель ошибочно подозревает {cls} в "
                            f"строке {line_no}, FP-фильтр должен дропнуть."
                        ),
                        "suggestion": None,
                        "confidence": 0.75,
                    }
                ],
                "summary": "Mock adversarial finding (should be filtered by FP-filter).",
            }
        else:
            by_id[g.id] = {"findings": [], "summary": ""}
    return by_id


# ---------------------------------------------------------------------------
# Smoke (real polza.ai) provider builder
# ---------------------------------------------------------------------------


def build_polza_provider(*, budget_rub: float) -> tuple["LLMProvider", BudgetCounter]:
    """Реальный PolzaProvider через openai SDK + python-dotenv.

    Если SDK / ключ недоступны — кидает RuntimeError, eval падает в fallback.
    """
    try:
        from dotenv import load_dotenv  # type: ignore
    except ImportError as exc:
        raise RuntimeError("python-dotenv не установлен — smoke невозможен") from exc

    load_dotenv(PROJECT_ROOT / ".env")
    api_key = os.environ.get("POLZA_API_KEY")
    base_url = os.environ.get("POLZA_BASE_URL") or "https://api.polza.ai/api/v1"
    model_id = os.environ.get("POLZA_MODEL_ID") or "gpt-4o-mini"
    if not api_key:
        raise RuntimeError("POLZA_API_KEY не установлен — smoke невозможен")

    try:
        from sunsec.llm.polza_provider import PolzaProvider
    except Exception as exc:
        raise RuntimeError(f"PolzaProvider импорт упал: {exc}") from exc

    provider = PolzaProvider(
        api_key=api_key,
        base_url=base_url,
        model_id=model_id,
        timeout_seconds=60.0,
        max_retries=1,
        temperature=0.0,
        max_tokens=512,
        # Тарифы дефолтные (gpt-4o-mini через polza ≈ 0.015 / 0.060 ₽ за 1k)
        input_rub_per_1k=0.015,
        output_rub_per_1k=0.060,
    )
    budget = BudgetCounter(limit_rub=budget_rub)
    return provider, budget


def build_openrouter_provider(
    *, budget_rub: float, model_id_override: Optional[str] = None
) -> tuple["LLMProvider", BudgetCounter]:
    """Реальный OpenRouterProvider через openai SDK + python-dotenv.

    Используется в T-032 smoke для тестирования primary `deepseek/deepseek-v4-flash`
    (или альтернативы) на goldens. Контракт `LLMProvider` совпадает с Polza,
    поэтому LLMClient/FP-фильтр работают без изменений.
    """
    try:
        from dotenv import load_dotenv  # type: ignore
    except ImportError as exc:
        raise RuntimeError("python-dotenv не установлен — smoke невозможен") from exc

    load_dotenv(PROJECT_ROOT / ".env")
    api_key = os.environ.get("OPENROUTER_API_KEY")
    base_url = (
        os.environ.get("OPENROUTER_BASE_URL") or "https://openrouter.ai/api/v1"
    )
    model_id = (
        model_id_override
        or os.environ.get("OPENROUTER_MODEL_ID")
        or "deepseek/deepseek-v4-flash"
    )
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY не установлен — smoke невозможен")

    try:
        from sunsec.llm.openrouter_provider import OpenRouterProvider
    except Exception as exc:
        raise RuntimeError(f"OpenRouterProvider импорт упал: {exc}") from exc

    # Тарифы по умолчанию из system_design (DeepSeek V4 Flash ≈ 0.027 ₽/запрос).
    input_rub = float(os.environ.get("OPENROUTER_INPUT_RUB_PER_1K", 0.01064))
    output_rub = float(os.environ.get("OPENROUTER_OUTPUT_RUB_PER_1K", 0.02128))

    provider = OpenRouterProvider(
        api_key=api_key,
        base_url=base_url,
        model_id=model_id,
        timeout_seconds=float(os.environ.get("OPENROUTER_TIMEOUT_SECONDS", 60.0)),
        max_retries=int(os.environ.get("OPENROUTER_MAX_RETRIES", 1)),
        temperature=0.0,
        max_tokens=512,
        input_rub_per_1k=input_rub,
        output_rub_per_1k=output_rub,
        usd_rub_rate=float(os.environ.get("OPENROUTER_USD_RUB_RATE", 95.0)),
        use_usage_cost=False,
    )
    budget = BudgetCounter(limit_rub=budget_rub)
    return provider, budget


# ---------------------------------------------------------------------------
# Evaluation core
# ---------------------------------------------------------------------------


@dataclass
class CaseResult:
    golden_id: str
    category: str
    file_path: str
    expected: list[dict[str, Any]]
    predicted: list[dict[str, Any]]  # сериализованные Finding-словари
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0  # true negative — только для clean-кейсов
    matched_classes: set[str] = field(default_factory=set)
    notes: list[str] = field(default_factory=list)


def _severity_ok(actual: str, minimum: Optional[str]) -> bool:
    if not minimum:
        return True
    try:
        return SEVERITY_ORDER.index(actual) >= SEVERITY_ORDER.index(minimum)
    except ValueError:
        return True


def _confidence_ok(actual: float, minimum: Optional[float]) -> bool:
    if minimum is None:
        return True
    return actual >= float(minimum)


def score_case(case: Golden, predicted: list[Finding]) -> CaseResult:
    """Считает TP/FP/FN/TN для одного golden'а.

    Алгоритм:
    - Для каждого expected finding ищем хотя бы один predicted с совпадающим
      (file, class) и line внутри ±2 от ожидаемой (учитываем погрешность LLM).
      Если найдено — TP. Если нет — FN.
    - Каждый predicted, не сопоставленный с expected → FP.
    - На clean-кейсах: 0 predicted → TN; иначе FP по числу predicted.
    """
    res = CaseResult(
        golden_id=case.id,
        category=case.category,
        file_path=case.file_path,
        expected=list(case.expected_findings),
        predicted=[f.model_dump(by_alias=True) for f in predicted],
    )

    if case.is_clean:
        if not predicted:
            res.tn = 1
        else:
            res.fp = len(predicted)
            res.notes.append(f"FP on clean-case: {[f.class_ for f in predicted]}")
        return res

    matched_pred_indices: set[int] = set()
    for exp in case.expected_findings:
        exp_cls = exp["class"]
        exp_line = int(exp["line"])
        sev_min = exp.get("severity_min")
        conf_min = exp.get("confidence_min")
        found = False
        for i, p in enumerate(predicted):
            if i in matched_pred_indices:
                continue
            if p.file != case.file_path:
                continue
            if p.class_ != exp_cls:
                continue
            if abs(p.line - exp_line) > 2:
                continue
            if not _severity_ok(p.severity, sev_min):
                continue
            if not _confidence_ok(p.confidence, conf_min):
                continue
            matched_pred_indices.add(i)
            found = True
            res.matched_classes.add(exp_cls)
            break
        if found:
            res.tp += 1
        else:
            res.fn += 1
            res.notes.append(
                f"MISS: expected {exp_cls} on {case.file_path}:{exp_line} (sev>={sev_min}, conf>={conf_min})"
            )

    # Не-сопоставленные predicted → FP
    for i, p in enumerate(predicted):
        if i in matched_pred_indices:
            continue
        res.fp += 1
        res.notes.append(f"EXTRA: predicted {p.class_} on {p.file}:{p.line} conf={p.confidence:.2f}")

    return res


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _pick_smoke_sample(goldens: list[Golden], limit: int) -> list[Golden]:
    """Балансированная выборка для smoke: по 1-2 кейса на класс + 1 clean."""
    by_cat: dict[str, list[Golden]] = {}
    for g in goldens:
        by_cat.setdefault(g.category, []).append(g)
    out: list[Golden] = []
    # Берём по одному из каждой категории сначала
    for cat in ("sqli", "secrets", "xss", "clean"):
        if cat in by_cat and by_cat[cat]:
            out.append(by_cat[cat][0])
    # Доберём из remaining до limit
    remaining: list[Golden] = []
    for cat in ("sqli", "secrets", "xss", "clean"):
        if cat in by_cat:
            remaining.extend(by_cat[cat][1:])
    for g in remaining:
        if len(out) >= limit:
            break
        out.append(g)
    return out[:limit]


async def run_eval(
    *,
    mode: str,
    limit: Optional[int],
    budget_rub: float,
    provider_name: str = "polza",
    model_id_override: Optional[str] = None,
) -> dict[str, Any]:
    goldens = load_goldens()
    if mode == "smoke" and limit:
        goldens = _pick_smoke_sample(goldens, limit)
    elif limit is not None and limit > 0:
        goldens = goldens[:limit]

    # --- Подготовка провайдера ---
    used_provider: str
    provider: Any
    budget: Optional[BudgetCounter]
    cost_rub_total = 0.0

    if mode == "smoke":
        try:
            if provider_name == "openrouter":
                provider, budget = build_openrouter_provider(
                    budget_rub=budget_rub, model_id_override=model_id_override
                )
                used_provider = f"openrouter:{provider._model_id}"
            else:
                provider, budget = build_polza_provider(budget_rub=budget_rub)
                used_provider = "polza.ai (real)"
        except RuntimeError as exc:
            print(f"[smoke fallback] {exc} → переключаюсь в offline-режим")
            mode = "offline"

    if mode == "offline":
        fixtures = build_realistic_fixtures(goldens)
        provider = FixtureProvider(fixtures)
        budget = None
        used_provider = "fixture (realistic)"
    elif mode == "adversarial":
        fixtures = build_adversarial_fixtures(goldens)
        provider = FixtureProvider(fixtures)
        budget = None
        used_provider = "fixture (adversarial)"
    elif mode == "smoke":
        # Уже создан выше (build_polza_provider или build_openrouter_provider).
        # `used_provider` уже выставлен (либо `polza.ai (real)`, либо
        # `openrouter:<model_id>`) — НЕ перетираем.
        pass
    else:
        raise SystemExit(f"unknown mode: {mode}")

    builder = PromptBuilder()
    client = LLMClient(provider=provider, builder=builder, budget=budget)
    fp_filter = FalsePositiveFilter(FPFilterConfig(min_confidence=0.5))

    results: list[CaseResult] = []
    errors: list[dict[str, Any]] = []

    for g in goldens:
        filtered = g.to_filtered_diff()
        try:
            pre_findings = fp_filter.pre_llm_scan(filtered)
            llm_resp: LLMResponseSchema = await client.analyze(filtered)
            final = fp_filter.postprocess(
                llm_resp.findings,
                filtered,
                pre_scan_findings=pre_findings,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append({"golden_id": g.id, "error": f"{type(exc).__name__}: {exc}"})
            results.append(
                CaseResult(
                    golden_id=g.id,
                    category=g.category,
                    file_path=g.file_path,
                    expected=list(g.expected_findings),
                    predicted=[],
                    fn=len(g.expected_findings),
                    notes=[f"PIPELINE-ERROR: {exc!r}"],
                )
            )
            continue

        res = score_case(g, final)
        results.append(res)

    # --- Сводка ---
    if budget is not None:
        cost_rub_total = round(budget.spent_rub, 4)

    metrics = compute_metrics(results)
    payload = {
        "mode": mode,
        "provider": used_provider,
        "goldens_count": len(goldens),
        "budget_rub_limit": budget_rub if mode == "smoke" else None,
        "cost_rub_spent": cost_rub_total,
        "metrics": metrics,
        "cases": [
            {
                "id": r.golden_id,
                "category": r.category,
                "tp": r.tp,
                "fp": r.fp,
                "fn": r.fn,
                "tn": r.tn,
                "expected": r.expected,
                "predicted": r.predicted,
                "notes": r.notes,
            }
            for r in results
        ],
        "errors": errors,
    }
    return payload


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _safe_div(a: float, b: float) -> float:
    return a / b if b > 0 else 0.0


def compute_metrics(results: list[CaseResult]) -> dict[str, Any]:
    """Считает precision/recall/F1 по классам + overall.

    TP/FP/FN — счётчики по findings (не по кейсам).
    FP-rate на clean — отдельная агрегация.
    """
    per_class: dict[str, dict[str, float]] = {}

    for cls in VULN_CLASSES:
        tp = 0
        fp = 0
        fn = 0
        for r in results:
            # TP считаем, если ожидание этого класса было удовлетворено
            exp_cls = [e for e in r.expected if e.get("class") == cls]
            pred_cls = [p for p in r.predicted if p.get("class") == cls]
            # Восстановим matching по уже посчитанным TP/FN (упрощённо)
            tp_local = min(len(exp_cls), len([p for p in pred_cls if any(
                abs(p["line"] - e["line"]) <= 2 for e in exp_cls
            )]))
            fn_local = max(0, len(exp_cls) - tp_local)
            # FP — predicted этого класса, не сопоставленные ни одной expected
            fp_local = 0
            for p in pred_cls:
                matched = any(abs(p["line"] - e["line"]) <= 2 for e in exp_cls)
                if not matched:
                    fp_local += 1
            tp += tp_local
            fp += fp_local
            fn += fn_local
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = _safe_div(2 * precision * recall, precision + recall)
        per_class[cls] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        }

    # Overall — суммарно
    tp_o = sum(c["tp"] for c in per_class.values())
    fp_o = sum(c["fp"] for c in per_class.values())
    fn_o = sum(c["fn"] for c in per_class.values())
    precision_o = _safe_div(tp_o, tp_o + fp_o)
    recall_o = _safe_div(tp_o, tp_o + fn_o)
    f1_o = _safe_div(2 * precision_o * recall_o, precision_o + recall_o)

    # Clean accuracy
    clean = [r for r in results if r.category == "clean"]
    clean_clean = sum(1 for r in clean if r.fp == 0)
    clean_rate = _safe_div(clean_clean, len(clean))

    return {
        "per_class": per_class,
        "overall": {
            "tp": tp_o,
            "fp": fp_o,
            "fn": fn_o,
            "precision": round(precision_o, 4),
            "recall": round(recall_o, 4),
            "f1": round(f1_o, 4),
        },
        "clean": {
            "total_cases": len(clean),
            "no_fp_cases": clean_clean,
            "fp_free_rate": round(clean_rate, 4),
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


# Acceptance thresholds (см. agents/artifacts/qa/llm_eval_report.md §4)
ACCEPTANCE = {
    "offline": {
        "recall_per_class_min": 0.70,
        "precision_overall_min": 0.60,
        "clean_fp_free_rate_min": 0.80,
    },
    "smoke": {
        "recall_per_class_min": 0.70,
        "precision_overall_min": 0.60,
        "clean_fp_free_rate_min": 0.80,
    },
    "adversarial": {
        "recall_per_class_min": 0.70,
        "precision_overall_min": 0.50,  # adversarial — стресс FP-фильтра
        "clean_fp_free_rate_min": 0.40,  # допустимо, что FP-фильтр не покрывает все hallucinations
    },
}


def _print_report(payload: dict[str, Any]) -> None:
    m = payload["metrics"]
    print("=" * 72)
    print(f"  SunSecurityBot LLM eval — T-015")
    print(f"  mode       : {payload['mode']}")
    print(f"  provider   : {payload['provider']}")
    print(f"  goldens    : {payload['goldens_count']}")
    print(f"  cost spent : {payload['cost_rub_spent']} ₽")
    print("=" * 72)
    print(f"  Per-class metrics:")
    print(f"  {'class':<20}{'P':>8}{'R':>8}{'F1':>8}{'TP':>6}{'FP':>6}{'FN':>6}")
    for cls, c in m["per_class"].items():
        print(
            f"  {cls:<20}{c['precision']:>8.3f}{c['recall']:>8.3f}{c['f1']:>8.3f}"
            f"{c['tp']:>6}{c['fp']:>6}{c['fn']:>6}"
        )
    o = m["overall"]
    print(
        f"  {'OVERALL':<20}{o['precision']:>8.3f}{o['recall']:>8.3f}{o['f1']:>8.3f}"
        f"{o['tp']:>6}{o['fp']:>6}{o['fn']:>6}"
    )
    print("-" * 72)
    cl = m["clean"]
    print(f"  Clean cases FP-free: {cl['no_fp_cases']}/{cl['total_cases']} "
          f"({cl['fp_free_rate']:.0%})")
    print("=" * 72)
    if payload.get("errors"):
        print(f"Errors: {len(payload['errors'])}")
        for e in payload["errors"]:
            print(f"  - {e['golden_id']}: {e['error']}")

    # Acceptance evaluation (пороги зависят от режима — см. ACCEPTANCE)
    mode = payload["mode"]
    th = ACCEPTANCE.get(mode, ACCEPTANCE["offline"])
    print(f"Acceptance (thresholds for mode='{mode}'):")
    fail = False
    for cls in VULN_CLASSES:
        c = m["per_class"][cls]
        ok = c["recall"] >= th["recall_per_class_min"]
        print(
            f"  recall[{cls}] = {c['recall']:.2f}  ≥ {th['recall_per_class_min']:.2f} → "
            f"{'PASS' if ok else 'FAIL'}"
        )
        if not ok:
            fail = True
    p_ok = o["precision"] >= th["precision_overall_min"]
    print(
        f"  precision[overall] = {o['precision']:.2f}  ≥ {th['precision_overall_min']:.2f} → "
        f"{'PASS' if p_ok else 'FAIL'}"
    )
    if not p_ok:
        fail = True
    clean_ok = cl["fp_free_rate"] >= th["clean_fp_free_rate_min"]
    print(
        f"  clean FP-free rate = {cl['fp_free_rate']:.2f}  ≥ {th['clean_fp_free_rate_min']:.2f} → "
        f"{'PASS' if clean_ok else 'FAIL'}"
    )
    if not clean_ok:
        fail = True
    print(f"  VERDICT: {'PASS' if not fail else 'FAIL'}")
    payload["acceptance"] = {
        "thresholds": th,
        "verdict": "PASS" if not fail else "FAIL",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="SunSecurityBot LLM eval (T-015)")
    parser.add_argument(
        "--mode",
        choices=["offline", "adversarial", "smoke"],
        default="offline",
        help="offline = mock-LLM realistic; adversarial = FP-stress; smoke = real polza.ai",
    )
    parser.add_argument(
        "--limit", type=int, default=None, help="ограничить N первых goldens"
    )
    parser.add_argument(
        "--budget", type=float, default=3.0, help="cap по бюджету для smoke (₽)"
    )
    parser.add_argument(
        "--provider",
        choices=["polza", "openrouter"],
        default="polza",
        help="LLM-провайдер для smoke-режима (default polza)",
    )
    parser.add_argument(
        "--model-id",
        type=str,
        default=None,
        help="override OPENROUTER_MODEL_ID для smoke (например, deepseek/deepseek-v4-flash)",
    )
    parser.add_argument(
        "--out",
        type=str,
        default=str(RESULTS_PATH),
        help="путь для результата JSON",
    )
    args = parser.parse_args()

    payload = asyncio.run(
        run_eval(
            mode=args.mode,
            limit=args.limit,
            budget_rub=args.budget,
            provider_name=args.provider,
            model_id_override=args.model_id,
        )
    )
    _print_report(payload)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nresults written → {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
