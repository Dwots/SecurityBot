"""Pydantic-модели GitHub webhook payload (system_design §4.1, ADR-5).

`GitHubPullRequestEvent` несёт computed_field'ы `repo` / `pr_number` / `head_sha`
— это единственный публичный доступ из pipeline (ADR-5).
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, computed_field


class UserPayload(BaseModel):
    """GitHub user (sender, owner, PR author)."""

    model_config = ConfigDict(extra="allow")
    login: str
    id: int


class RepositoryPayload(BaseModel):
    """GitHub repository (минимум полей, нужных pipeline)."""

    model_config = ConfigDict(extra="allow")
    full_name: str  # "owner/repo"
    owner: UserPayload


class GitRefPayload(BaseModel):
    """Git ref (head / base) внутри PR."""

    model_config = ConfigDict(extra="allow")
    sha: str
    ref: str
    repo: RepositoryPayload


class PullRequestPayload(BaseModel):
    """Тело PR из GitHub webhook payload."""

    model_config = ConfigDict(extra="allow")
    id: int
    number: int
    state: Literal["open", "closed"]
    title: str
    head: GitRefPayload
    base: GitRefPayload
    draft: bool
    user: UserPayload


class InstallationPayload(BaseModel):
    """GitHub App installation (в MVP не используется)."""

    model_config = ConfigDict(extra="allow")
    id: int


class GitHubPullRequestEvent(BaseModel):
    """Вход WebhookReceiver. См. system_design §4.1 + ADR-5.

    Pipeline-код обращается ИСКЛЮЧИТЕЛЬНО к computed-полям `repo`, `pr_number`,
    `head_sha`. Прямое чтение `event.repository.full_name` — антипаттерн.
    """

    model_config = ConfigDict(extra="allow")

    action: Literal["opened", "synchronize", "reopened", "ready_for_review"]
    number: int
    pull_request: PullRequestPayload
    repository: RepositoryPayload
    sender: UserPayload
    installation: Optional[InstallationPayload] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def repo(self) -> str:
        """Каноническая строка `owner/repo` (из `repository.full_name`)."""
        return self.repository.full_name

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pr_number(self) -> int:
        """Алиас к `number` (PR-номер на корне payload'а)."""
        return self.number

    @computed_field  # type: ignore[prop-decorator]
    @property
    def head_sha(self) -> str:
        """SHA HEAD-коммита PR — используется в idempotency-ключе."""
        return self.pull_request.head.sha
