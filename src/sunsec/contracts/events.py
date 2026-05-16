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


# ---------------------------------------------------------------------------
# Reply-mode (T-019, post-MVP): issue_comment / pull_request_review_comment.
# Эти события приходят, когда пользователь отвечает на комментарий бота в
# обсуждении PR. Бот распознаёт их, дергает LLM-диалог и публикует ответ.
# ---------------------------------------------------------------------------


class IssuePullRequestRef(BaseModel):
    """Под-объект `issue.pull_request` (его наличие = issue это PR-issue).

    Минимально нужен `url` — но мы держим `extra=allow`, чтобы GitHub мог
    добавлять поля без поломки парсинга.
    """

    model_config = ConfigDict(extra="allow")
    url: str


class IssueRefPayload(BaseModel):
    """Объект `issue` в `issue_comment` событиях."""

    model_config = ConfigDict(extra="allow")
    number: int
    pull_request: Optional[IssuePullRequestRef] = None


class IssueCommentPayload(BaseModel):
    """Тело комментария в `issue_comment` событии."""

    model_config = ConfigDict(extra="allow")
    id: int
    body: str
    user: UserPayload


class GitHubIssueCommentEvent(BaseModel):
    """`issue_comment` webhook (GitHub шлёт его и для обычных issues, и для PR).

    Триггер reply-режима: только если `is_pull_request == True` И в теле
    комментария есть `@<BOT_USERNAME>`. Сам фильтр живёт в `WebhookService`.
    """

    model_config = ConfigDict(extra="allow")

    action: Literal["created", "edited", "deleted"]
    issue: IssueRefPayload
    comment: IssueCommentPayload
    repository: RepositoryPayload
    sender: UserPayload

    @computed_field  # type: ignore[prop-decorator]
    @property
    def repo(self) -> str:
        return self.repository.full_name

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pr_number(self) -> int:
        return self.issue.number

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_pull_request(self) -> bool:
        """`True`, если комментарий оставлен в PR (а не в обычной issue)."""
        return self.issue.pull_request is not None


class ReviewCommentPayload(BaseModel):
    """Тело комментария в `pull_request_review_comment` событии.

    Поля threading'а — `in_reply_to_id` (на чей комментарий это ответ) и
    `pull_request_review_id` (к какому review относится).
    """

    model_config = ConfigDict(extra="allow")
    id: int
    body: str
    path: str
    user: UserPayload
    in_reply_to_id: Optional[int] = None
    pull_request_review_id: Optional[int] = None
    line: Optional[int] = None
    original_line: Optional[int] = None


class GitHubPullRequestReviewCommentEvent(BaseModel):
    """`pull_request_review_comment` webhook — inline-комментарий в PR diff."""

    model_config = ConfigDict(extra="allow")

    action: Literal["created", "edited", "deleted"]
    pull_request: PullRequestPayload
    comment: ReviewCommentPayload
    repository: RepositoryPayload
    sender: UserPayload

    @computed_field  # type: ignore[prop-decorator]
    @property
    def repo(self) -> str:
        return self.repository.full_name

    @computed_field  # type: ignore[prop-decorator]
    @property
    def pr_number(self) -> int:
        return self.pull_request.number

    @computed_field  # type: ignore[prop-decorator]
    @property
    def head_sha(self) -> str:
        return self.pull_request.head.sha
