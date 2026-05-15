"""Реальный polza.ai smoke для T-021 e2e.

Прогоняет 4 fixture PR через полный pipeline с **реальным** LLMClient (polza.ai
gpt-4o-mini). VCS остаётся мок через `httpx.MockTransport`, чтобы не зависеть
от GitHub API. CommentPublisher публикует в этот же мок — мы наблюдаем
финальный body review / issue-comment, как будто это настоящий GitHub.

Запуск:
    PYTHONPATH=src python tests/e2e/run_polza_smoke.py

Бюджет: при отсутствии `POLZA_API_KEY` или ошибке инициализации — fallback на
mock-LLM (smoke degrade, не валим выполнение). Реальный расход — печатается
в конце; ожидаемая стоимость ~0.05–0.10 ₽ на PR (gpt-4o-mini через polza.ai).

Артефакт: `tests/e2e/results_smoke.json` — машино-читаемый результат всех 4
прогонов (severity, inline_count, fallback_count, cost_rub).
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
if str(Path(__file__).parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).parent))

from test_full_pipeline import (  # noqa: E402  — sibling import
    FIXTURES_DIR,
    SECRET,
    _GitHubMock,
    _build_app,
    _load_fixture,
    _post_webhook,
    _make_mock_llm_client,
)
from sunsec.llm.budget import BudgetCounter  # noqa: E402
from sunsec.llm.client import LLMClient  # noqa: E402
from sunsec.llm.prompt_builder import PromptBuilder  # noqa: E402

PR_SCENARIOS = ["pr_sqli", "pr_secret", "pr_xss", "pr_clean"]
SMOKE_BUDGET_RUB = 10.0  # cap для T-021


def _build_real_polza_client(*, budget: BudgetCounter) -> tuple[LLMClient | None, str]:
    """Реальный polza.ai LLMClient. Возвращает (client, used_provider_label)."""
    try:
        from dotenv import load_dotenv  # type: ignore
    except ImportError:
        return None, "no python-dotenv"

    load_dotenv(PROJECT_ROOT / ".env")
    api_key = os.environ.get("POLZA_API_KEY", "")
    base_url = os.environ.get("POLZA_BASE_URL", "https://api.polza.ai/api/v1")
    model_id = os.environ.get("POLZA_MODEL_ID", "gpt-4o-mini")
    if not api_key:
        return None, "no POLZA_API_KEY in .env"

    try:
        from sunsec.llm.polza_provider import PolzaProvider
    except Exception as exc:  # noqa: BLE001
        return None, f"PolzaProvider import failed: {exc}"

    provider = PolzaProvider(
        api_key=api_key,
        base_url=base_url,
        model_id=model_id,
        timeout_seconds=60.0,
        max_retries=2,
        temperature=0.0,
        max_tokens=1024,
        input_rub_per_1k=0.015,
        output_rub_per_1k=0.060,
    )
    client = LLMClient(provider=provider, builder=PromptBuilder(), budget=budget)
    return client, f"polza.ai {model_id}"


async def _run_one_real_pr(pr_name: str, *, llm_client: LLMClient) -> dict[str, Any]:
    webhook, files = _load_fixture(pr_name)
    head_sha = webhook["pull_request"]["head"]["sha"]
    base_sha = webhook["pull_request"]["base"]["sha"]
    repo = webhook["repository"]["full_name"]
    pr_number = webhook["number"]
    file_path = files[0]["filename"]

    mock = _GitHubMock(
        repo=repo, pr_number=pr_number, head_sha=head_sha,
        base_sha=base_sha, files_response=files,
    )
    app, state, mock, _pub = _build_app(mock=mock, llm_client=llm_client)

    from fastapi.testclient import TestClient
    t0 = time.monotonic()
    with TestClient(app) as client:
        resp = _post_webhook(client, webhook, delivery_id=f"smoke-{pr_name}")
    elapsed = time.monotonic() - t0

    review = mock.posted_review
    summary = mock.posted_issue_comments[0] if mock.posted_issue_comments else None
    review_inline = (review or {}).get("comments", []) if review else []

    return {
        "pr_name": pr_name,
        "file_path": file_path,
        "http_status": resp.status_code,
        "elapsed_seconds": round(elapsed, 2),
        "review_posted": review is not None,
        "inline_count": len(review_inline),
        "inline_bodies": [c["body"] for c in review_inline][:3],
        "summary_posted": summary is not None,
        "summary_body": (summary["body"] if summary else None),
        "github_requests_count": len(mock.requests),
        "github_paths": list({p for _, p in mock.requests}),
    }


async def main() -> int:
    budget = BudgetCounter(limit_rub=SMOKE_BUDGET_RUB)
    real_client, label = _build_real_polza_client(budget=budget)

    used_provider = label
    if real_client is None:
        print(f"[smoke fallback] {label} → используем mock-LLM")
        # Fallback: каждое из PR будет использовать свой mock-client
        real_client = None

    print(f"=== T-021 polza.ai smoke ({used_provider}) ===")
    print(f"Budget cap: {SMOKE_BUDGET_RUB} ₽")
    results: list[dict[str, Any]] = []
    errors: list[str] = []

    for pr in PR_SCENARIOS:
        try:
            if real_client is None:
                webhook, files = _load_fixture(pr)
                file_path = files[0]["filename"]
                head_sha = webhook["pull_request"]["head"]["sha"]
                client_for_pr = _make_mock_llm_client(pr, file_path, head_sha)
            else:
                client_for_pr = real_client
            r = await _run_one_real_pr(pr, llm_client=client_for_pr)
            results.append(r)
            print(
                f"  {pr:<12} HTTP {r['http_status']}  "
                f"inline={r['inline_count']}  summary={'Y' if r['summary_posted'] else 'N'}  "
                f"t={r['elapsed_seconds']}s"
            )
        except Exception as exc:  # noqa: BLE001
            err = f"{pr}: {type(exc).__name__}: {exc}"
            errors.append(err)
            print(f"  ERROR: {err}")

    spent = round(budget.spent_rub, 4) if real_client is not None else 0.0
    payload = {
        "provider": used_provider,
        "budget_cap_rub": SMOKE_BUDGET_RUB,
        "cost_rub_spent": spent,
        "results": results,
        "errors": errors,
        "real_polza_used": real_client is not None,
    }
    out_path = PROJECT_ROOT / "tests" / "e2e" / "results_smoke.json"
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print()
    print(f"Real polza.ai used: {payload['real_polza_used']}")
    print(f"Total spent: {spent} ₽ / cap {SMOKE_BUDGET_RUB} ₽")
    print(f"Results saved → {out_path}")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
