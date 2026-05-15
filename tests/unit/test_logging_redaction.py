"""Unit-тесты маскирования секретов в логгере (T-006 DoD: hard-requirement из system_design §9)."""
from __future__ import annotations

import io
import json
import logging

from sunsec.logging_ext import (
    REDACTED_PLACEHOLDER,
    configure_logging,
    get_logger,
    redact_mapping,
    redact_value,
)
from sunsec.logging_ext.setup import _RedactingJSONFormatter


# ---------- pure-function level: redact_mapping / redact_value ----------


def test_redact_mapping_hides_token_secret_api_key_authorization_password() -> None:
    """Все четыре класса ключей маскируются по подстроке."""
    src = {
        "VCS_TOKEN": "ghp_secret_value",
        "polza_api_key": "sk-polza-xxx",
        "webhook_secret": "hmac-very-secret",
        "Authorization": "Bearer abc.def.ghi",
        "password": "p@ssw0rd",
        "user_id": 42,
        "repo": "owner/repo",
    }
    out = redact_mapping(src)

    assert out["VCS_TOKEN"] == REDACTED_PLACEHOLDER
    assert out["polza_api_key"] == REDACTED_PLACEHOLDER
    assert out["webhook_secret"] == REDACTED_PLACEHOLDER
    assert out["Authorization"] == REDACTED_PLACEHOLDER
    assert out["password"] == REDACTED_PLACEHOLDER
    # Несекретные поля сохраняются.
    assert out["user_id"] == 42
    assert out["repo"] == "owner/repo"


def test_redact_value_hides_bearer_in_freeform_text() -> None:
    """Bearer-токен внутри произвольной строки тоже маскируется."""
    raw = "GET /repos failed: 401 Authorization: Bearer ghp_super_secret_value_123"
    out = redact_value(raw)
    assert "ghp_super_secret_value_123" not in out
    assert REDACTED_PLACEHOLDER in out


def test_redact_mapping_nested_dict() -> None:
    """Вложенный dict рекурсивно маскируется."""
    src = {
        "request": {
            "headers": {
                "Authorization": "Bearer secret-1",
                "X-Request-Id": "abc",
            },
        },
        "api_key": "sk-leak",
    }
    out = redact_mapping(src)
    assert out["request"]["headers"]["Authorization"] == REDACTED_PLACEHOLDER
    assert out["request"]["headers"]["X-Request-Id"] == "abc"
    assert out["api_key"] == REDACTED_PLACEHOLDER


# ---------- end-to-end: configure_logging → write → parse JSON ----------


def _capture_logs() -> tuple[logging.Logger, io.StringIO]:
    """Возвращает (logger, stream) с подключённым _RedactingJSONFormatter."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_RedactingJSONFormatter())
    logger = logging.getLogger("sunsec.test.redaction")
    # Снос предыдущих handlers (тесты идут в одном процессе).
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, buf


def test_logger_redacts_extra_with_token_field() -> None:
    """logger.info(..., extra={"api_key": "..."}) не должен оставить ключ в выводе."""
    logger, buf = _capture_logs()
    logger.info(
        "pipeline_started",
        extra={
            "repo": "owner/repo",
            "pr_number": 7,
            "polza_api_key": "sk-polza-leaked-1234567890",
            "vcs_token": "ghp_leaked_value",
        },
    )
    line = buf.getvalue().strip()
    payload = json.loads(line)

    assert payload["msg"] == "pipeline_started"
    assert payload["repo"] == "owner/repo"
    assert payload["pr_number"] == 7
    assert payload["polza_api_key"] == REDACTED_PLACEHOLDER
    assert payload["vcs_token"] == REDACTED_PLACEHOLDER
    # Гарантируем, что нигде в выводе нет утечки.
    assert "sk-polza-leaked-1234567890" not in line
    assert "ghp_leaked_value" not in line


def test_logger_redacts_bearer_token_in_message() -> None:
    """Bearer-токен в самой строке сообщения тоже маскируется."""
    logger, buf = _capture_logs()
    logger.warning("auth failed: Authorization: Bearer sk-leaked-xyz-9999")

    line = buf.getvalue().strip()
    payload = json.loads(line)
    assert "sk-leaked-xyz-9999" not in line
    assert REDACTED_PLACEHOLDER in payload["msg"]


def test_logger_redacts_exception_traceback_with_authorization() -> None:
    """logger.exception(...) маскирует Authorization в traceback / exc text."""
    logger, buf = _capture_logs()
    try:
        # Эмулируем ошибку, в которой Authorization мог бы попасть в текст.
        raise RuntimeError("Bearer sk-token-in-exc-9876543210 was rejected by gateway")
    except RuntimeError:
        logger.exception("llm_call_failed")

    line = buf.getvalue().strip()
    # Должно быть JSON-ом.
    payload = json.loads(line)
    assert payload["level"] == "ERROR"
    assert "sk-token-in-exc-9876543210" not in line
    assert "exc_text" in payload
    assert REDACTED_PLACEHOLDER in payload["exc_text"]


def test_configure_logging_idempotent_and_json_default() -> None:
    """configure_logging можно вызывать многократно, дефолт — JSON."""
    configure_logging(level="DEBUG", fmt="json")
    configure_logging(level="INFO", fmt="json")  # повторно
    root = logging.getLogger()
    assert root.level == logging.INFO
    # Ровно один handler на корне после второго вызова.
    assert len(root.handlers) == 1
    # Это — JSON formatter.
    assert isinstance(root.handlers[0].formatter, _RedactingJSONFormatter)

    # Get_logger возвращает обычный stdlib logger.
    log = get_logger("sunsec.smoke")
    assert isinstance(log, logging.Logger)
