"""VCS-адаптеры. GitHub primary (ADR-1)."""
from sunsec.vcs.base import (
    AuthError,
    NotFoundError,
    RateLimitError,
    VCSAdapter,
    VCSAdapterError,
)
from sunsec.vcs.github import GitHubAdapter
from sunsec.vcs.patch_parser import parse_patch

__all__ = [
    "VCSAdapter",
    "VCSAdapterError",
    "AuthError",
    "NotFoundError",
    "RateLimitError",
    "GitHubAdapter",
    "parse_patch",
]
