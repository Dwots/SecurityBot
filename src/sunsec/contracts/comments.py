"""Примитивы CommentPublisher ↔ VCSAdapter (system_design §4.5 / §4.7)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict


class InlineComment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    line: int
    side: Literal["RIGHT"] = "RIGHT"
    body: str
    finding_hash: str


class PostedComment(BaseModel):
    """Доменный примитив возврата от VCSAdapter.

    `body` (T-016) — сырой текст комментария, как он лежит в GitHub. Нужен
    `CommentPublisher`'у для поиска HTML-маркеров идемпотентности при
    рестарте процесса (in-memory state пуст, GitHub остался).
    """

    model_config = ConfigDict(extra="forbid")
    id: int
    url: str
    posted_at: datetime
    body: Optional[str] = None


class PostedReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    review_id: int
    comments_posted: int
    summary_posted: bool
    deduped: int = 0
    fallback_to_summary: int = 0
    # T-016: если все findings уже опубликованы при предыдущем прогоне и
    # CommentPublisher ничего нового не отправил, поле выставляется в True.
    # Pipeline считает такой результат успехом.
    skipped: bool = False
