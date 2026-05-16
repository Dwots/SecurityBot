"""Доменные контракты SunSecurityBot.

Соответствие system_design.md §4. Эти модели — единственный источник истины
для входов/выходов между компонентами (WebhookReceiver → VCSAdapter → DiffFilter
→ LLMClient → CommentPublisher). Backend и ML импортируют ровно эти классы.
"""

from sunsec.contracts.events import (
    GitHubPullRequestEvent,
    GitRefPayload,
    PullRequestPayload,
    RepositoryPayload,
    UserPayload,
)
from sunsec.contracts.diff import (
    AddedLine,
    DiffFile,
    DiffHunk,
    DiffLine,
    ExcludeReason,
    ExcludedFile,
    FilteredDiff,
    FilteredDiffFile,
    PRDiff,
)
from sunsec.contracts.llm_response import (
    Finding,
    LLMResponseSchema,
    Severity,
    VulnClass,
)
from sunsec.contracts.comments import (
    InlineComment,
    PostedComment,
    PostedReview,
)
from sunsec.contracts.storage import (
    CheckRecord,
    CommentRecord,
    FindingRecord,
    RepoConfigRecord,
)

__all__ = [
    # events
    "GitHubPullRequestEvent",
    "GitRefPayload",
    "PullRequestPayload",
    "RepositoryPayload",
    "UserPayload",
    # diff
    "AddedLine",
    "DiffFile",
    "DiffHunk",
    "DiffLine",
    "ExcludeReason",
    "ExcludedFile",
    "FilteredDiff",
    "FilteredDiffFile",
    "PRDiff",
    # llm
    "Finding",
    "LLMResponseSchema",
    "Severity",
    "VulnClass",
    # comments
    "InlineComment",
    "PostedComment",
    "PostedReview",
    # storage (M-9)
    "CheckRecord",
    "CommentRecord",
    "FindingRecord",
    "RepoConfigRecord",
]
