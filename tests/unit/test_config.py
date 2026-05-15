"""Unit-тесты конфига (T-006 DoD)."""
from __future__ import annotations

import pytest

from sunsec.config.settings import Settings


def test_settings_from_env_picks_required_values() -> None:
    """`Settings.from_env(env=...)` берёт VCS_TOKEN / POLZA_API_KEY / WEBHOOK_SECRET / LOG_LEVEL."""
    s = Settings.from_env(env={
        "VCS_TOKEN": "test-token-vcs-123",
        "WEBHOOK_SECRET": "test-secret-webhook-xyz",
        "POLZA_API_KEY": "test-token-polza-456",
        "LOG_LEVEL": "debug",
        "POLZA_BUDGET_LIMIT_RUB": "12.5",
    })

    assert s.vcs_token == "test-token-vcs-123"
    assert s.webhook_secret == "test-secret-webhook-xyz"
    assert s.polza_api_key == "test-token-polza-456"
    assert s.log_level == "DEBUG"  # нормализовано в upper-case
    assert s.polza_budget_limit_rub == pytest.approx(12.5)


def test_settings_defaults_when_env_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    """Если env пуст — Settings строится с дефолтами, без exception."""
    # Сносим все возможные переменные.
    for name in [
        "VCS_TOKEN", "GITHUB_TOKEN", "WEBHOOK_SECRET", "POLZA_API_KEY",
        "LLM_API_KEY", "POLZA_BASE_URL", "POLZA_MODEL_ID",
        "POLZA_BUDGET_LIMIT_RUB", "LOG_LEVEL", "LOG_FORMAT",
        "ALLOW_DIRECT_FALLBACK", "PUBLISH_EMPTY_PR_COMMENT", "SKIP_DRAFTS",
    ]:
        monkeypatch.delenv(name, raising=False)

    # Подменяем env в `from_env` напрямую — чтобы .env-файл проекта не повлиял.
    s = Settings.from_env(env={})

    assert s.vcs_token == ""
    assert s.polza_api_key == ""
    assert s.polza_base_url == "https://polza.ai/api/v1"
    assert s.polza_model_id == "gpt-4o-mini"
    assert s.polza_budget_limit_rub == pytest.approx(80.0)
    assert s.log_level == "INFO"
    assert s.log_format == "json"
    assert s.vcs_provider == "github"
    assert s.llm_provider == "polza"
    assert s.allow_direct_fallback is False
    assert s.skip_drafts is True


def test_settings_repr_redacts_secrets() -> None:
    """`repr(Settings)` не печатает значения секретных полей."""
    s = Settings.from_env(env={
        "VCS_TOKEN": "ghp_super_secret_pat",
        "WEBHOOK_SECRET": "hmac-very-secret",
        "POLZA_API_KEY": "sk-polza-leaked-key-1234",
    })

    rep = repr(s)
    # Сами секреты НЕ должны попасть в repr.
    assert "ghp_super_secret_pat" not in rep
    assert "hmac-very-secret" not in rep
    assert "sk-polza-leaked-key-1234" not in rep
    # Placeholder есть.
    assert "***REDACTED***" in rep
    # Несекретные поля видны как обычно.
    assert "polza_model_id='gpt-4o-mini'" in rep or "polza_model_id=\"gpt-4o-mini\"" in rep


def test_settings_log_level_validation_rejects_garbage() -> None:
    """Невалидный LOG_LEVEL приводит к pydantic ValidationError."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings.from_env(env={"LOG_LEVEL": "TRACE"})


def test_settings_bool_parsing() -> None:
    """`ALLOW_DIRECT_FALLBACK=true|1|yes` → True; иначе False."""
    s_true = Settings.from_env(env={"ALLOW_DIRECT_FALLBACK": "true"})
    s_one = Settings.from_env(env={"ALLOW_DIRECT_FALLBACK": "1"})
    s_yes = Settings.from_env(env={"ALLOW_DIRECT_FALLBACK": "YES"})
    s_off = Settings.from_env(env={"ALLOW_DIRECT_FALLBACK": "off"})
    s_unset = Settings.from_env(env={})

    assert s_true.allow_direct_fallback is True
    assert s_one.allow_direct_fallback is True
    assert s_yes.allow_direct_fallback is True
    assert s_off.allow_direct_fallback is False
    assert s_unset.allow_direct_fallback is False


def test_legacy_env_aliases_supported() -> None:
    """`GITHUB_TOKEN` и `LLM_API_KEY` поддерживаются как алиасы."""
    s = Settings.from_env(env={
        "GITHUB_TOKEN": "test-token-from-github-alias",
        "LLM_API_KEY": "test-token-from-llm-alias",
    })
    assert s.vcs_token == "test-token-from-github-alias"
    assert s.polza_api_key == "test-token-from-llm-alias"
