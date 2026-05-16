"""VCSAdapter Protocol — единственный публичный контракт для pipeline.

См. system_design §3.2 + §4.2 + §4.7.

Реализация GitHubAdapter — задача T-008 (fetch_pr_diff) + T-016 (post_review /
post_issue_comment / list_*_comments / update_issue_comment / verify_signature).
"""
from __future__ import annotations

from typing import Optional, Protocol

from sunsec.contracts import (
    InlineComment,
    PostedComment,
    PostedReview,
    PRDiff,
)


class VCSAdapterError(Exception):
    """Базовый класс ошибок VCS-адаптера."""


class AuthError(VCSAdapterError):
    """401/403 — токен невалиден / истёк."""


class NotFoundError(VCSAdapterError):
    """404 — PR удалён / нет доступа."""


class RateLimitError(VCSAdapterError):
    """429 — лимиты API исчерпаны (SDK обычно ретраит сам)."""


class VCSAdapter(Protocol):
    """Изолирует pipeline от конкретного VCS-провайдера.

    Все методы — async, кроме `verify_signature` (быстрая synchronous HMAC).
    """

    def verify_signature(self, raw_body: bytes, signature_header: str, secret: str) -> bool:
        """HMAC-проверка подписи webhook'а."""
        ...

    async def fetch_pr_diff(self, repo: str, pr_number: int) -> PRDiff:
        """Возвращает структурированный diff PR."""
        ...

    async def post_inline_comment(
        self,
        repo: str,
        pr_number: int,
        comment: InlineComment,
    ) -> PostedComment:
        ...

    async def post_summary_comment(
        self,
        repo: str,
        pr_number: int,
        body: str,
        marker: str,
    ) -> PostedComment:
        ...

    async def post_review(
        self,
        repo: str,
        pr_number: int,
        comments: list[InlineComment],
        summary: str,
        marker: str,
        commit_id: Optional[str] = None,
    ) -> PostedReview:
        """Один HTTP-вызов: POST /repos/{repo}/pulls/{n}/reviews с массивом
        `comments[]` (inline) и `body` (summary). Тело summary включает
        `marker` (HTML-комментарий идемпотентности). `commit_id` — sha PR HEAD,
        нужен GitHub-у для привязки inline-комментариев к строкам diff.
        """
        ...

    async def update_issue_comment(
        self,
        repo: str,
        comment_id: int,
        body: str,
    ) -> PostedComment:
        """PATCH /repos/{repo}/issues/comments/{id} — апдейт текста ранее
        опубликованного general-комментария (используется для идемпотентного
        обновления summary/empty/budget-маркеров)."""
        ...

    async def list_review_comments(
        self, repo: str, pr_number: int
    ) -> list[PostedComment]:
        """GET /repos/{repo}/pulls/{n}/comments — все review-comments PR
        (inline). Используется CommentPublisher'ом для проверки маркеров
        finding_hash перед публикацией (защита от дубликатов после рестарта).
        В `body` каждого `PostedComment` должен лежать сырой `body` из GitHub,
        чтобы можно было искать HTML-маркер."""
        ...

    async def list_issue_comments(
        self, repo: str, pr_number: int
    ) -> list[PostedComment]:
        """GET /repos/{repo}/issues/{n}/comments — все обычные PR-комментарии
        (включая summary / empty / budget). См. `list_review_comments`."""
        ...

    async def set_status_check(
        self,
        repo: str,
        commit_sha: str,
        state: str,
        description: str,
        context: str,
    ) -> None:
        """Для T-018 (block merge). В MVP — заглушка."""
        ...

    # --- Reply mode (T-019) ---

    async def reply_to_review_comment(
        self,
        repo: str,
        pr_number: int,
        in_reply_to_id: int,
        body: str,
    ) -> PostedComment:
        """POST /repos/{owner}/{repo}/pulls/{pull_number}/comments/{comment_id}/replies
        — публикует ответ в той же ветке (thread) inline-комментариев, без
        отдельного review-объекта. Используется в reply-режиме (T-019).
        """
        ...

    async def get_review_comment(
        self,
        repo: str,
        comment_id: int,
    ) -> PostedComment:
        """GET /repos/{owner}/{repo}/pulls/comments/{comment_id} — забирает
        один review-comment по id. Нужен для определения, является ли
        родительский комментарий нашим (проверка маркера / автора).
        """
        ...
