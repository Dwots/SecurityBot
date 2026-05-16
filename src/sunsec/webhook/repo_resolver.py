"""Repo registry resolver (T-039, system_design v1.2.1 §11.4 / §12.3).

При входящем webhook'е по `payload.repository.full_name` определяем
эффективные `vcs_token` / `webhook_secret`:

  1. Если в БД зарегистрирован репо (`repo_configs.full_name=full_name`)
     и `enabled=1`:
       a) `token = os.environ.get(repo.vcs_token_ref) or settings.vcs_token`
       b) `secret = os.environ.get(repo.webhook_secret_ref) or settings.webhook_secret`
       c) лог `webhook_repo_resolved_from_db` (без значений!)
  2. Иначе (репо не в БД / `enabled=0` / repo без `*_ref`):
       a) `token = settings.vcs_token` / `secret = settings.webhook_secret`
       b) лог `webhook_repo_resolved_from_env` (M-2/M-7 backward-compat)

Контракт безопасности:
- значения `token` / `secret` НИКОГДА не попадают в лог-записи (extra=…).
- Логируется только `vcs_token_ref` / `webhook_secret_ref` имя (это не
  секрет — это имя env-переменной, в `.env.example` встречается).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from sunsec.config import Settings
    from sunsec.state.base import StateStore

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResolvedCredentials:
    """Резолвленные credentials для одного входящего webhook'а."""

    vcs_token: str
    webhook_secret: str
    source: str  # "db" | "env" | "mixed"
    repo_full_name: Optional[str] = None


async def resolve_webhook_credentials(
    *,
    state: "StateStore",
    settings: "Settings",
    full_name: Optional[str],
) -> ResolvedCredentials:
    """Резолвит `(vcs_token, webhook_secret)` для входящего webhook'а.

    Args:
        state: `StateStore` (in-memory или SQLite — оба поддерживают
            `get_repo_by_full_name`).
        settings: глобальный `Settings` — fallback на `.env` значения.
        full_name: `payload.repository.full_name` — может быть None,
            если payload ещё не распарсен (тогда сразу fallback на env).

    Returns:
        `ResolvedCredentials` — c полем `source` для аудита.
    """
    fallback_token = str(settings.vcs_token or "")
    fallback_secret = str(settings.webhook_secret or "")

    if not full_name:
        log.info(
            "webhook_repo_resolved_from_env",
            extra={"reason": "no_full_name"},
        )
        return ResolvedCredentials(
            vcs_token=fallback_token,
            webhook_secret=fallback_secret,
            source="env",
            repo_full_name=None,
        )

    repo = None
    try:
        repo = await state.get_repo_by_full_name(full_name)
    except Exception as exc:  # noqa: BLE001 — best-effort, lookup-error → fallback
        log.warning(
            "webhook_repo_lookup_failed",
            extra={
                "repo": full_name,
                "error_type": type(exc).__name__,
            },
        )
        repo = None

    if repo is None or not getattr(repo, "enabled", False):
        log.info(
            "webhook_repo_resolved_from_env",
            extra={
                "repo": full_name,
                "reason": "not_registered" if repo is None else "disabled",
            },
        )
        return ResolvedCredentials(
            vcs_token=fallback_token,
            webhook_secret=fallback_secret,
            source="env",
            repo_full_name=full_name,
        )

    token = ""
    secret = ""
    token_source = "fallback"
    secret_source = "fallback"

    if repo.vcs_token_ref:
        env_token = os.environ.get(repo.vcs_token_ref, "")
        if env_token:
            token = env_token
            token_source = "db_ref"
    if not token:
        token = fallback_token

    if repo.webhook_secret_ref:
        env_secret = os.environ.get(repo.webhook_secret_ref, "")
        if env_secret:
            secret = env_secret
            secret_source = "db_ref"
    if not secret:
        secret = fallback_secret

    if token_source == "db_ref" and secret_source == "db_ref":
        source = "db"
    elif token_source == "db_ref" or secret_source == "db_ref":
        source = "mixed"
    else:
        source = "env"

    log.info(
        "webhook_repo_resolved_from_db",
        extra={
            "repo": full_name,
            "vcs_token_ref": repo.vcs_token_ref,
            "webhook_secret_ref": repo.webhook_secret_ref,
            "source": source,
            "token_source": token_source,
            "secret_source": secret_source,
        },
    )

    return ResolvedCredentials(
        vcs_token=token,
        webhook_secret=secret,
        source=source,
        repo_full_name=full_name,
    )


__all__ = ["ResolvedCredentials", "resolve_webhook_credentials"]
