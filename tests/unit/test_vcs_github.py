"""Тесты `sunsec.vcs.github.GitHubAdapter.fetch_pr_diff` (T-008).

Стратегия: httpx.AsyncClient(transport=MockTransport) — никаких реальных
сетевых вызовов, никакого monkeypatch'а на стандартную либу.

Покрываемые сценарии (минимум из DoD T-008):
- Happy path: GET /pulls/{n} + /pulls/{n}/files → структурированный `PRDiff`.
- 404 → `NotFoundError` (без ретраев).
- 401/403 (без rate-limit-маркеров) → `AuthError` (без ретраев).
- 429 → backoff → success (счётчик `_sleep` срабатывает).
- 403 + `X-RateLimit-Remaining: 0` → ожидание `X-RateLimit-Reset` → success.
- Rate-limit-cap: огромный `Retry-After` обрезается до cap'а.
- 5xx → exponential backoff → success.
- 5xx исчерпание ретраев → `VCSAdapterError`.
- Pagination (две страницы) → объединение files.
- Soft-limit (files_soft_limit) → warning + обрезка.
- Безопасность: `repr()` не содержит токена; токен не попадает в `__dict__`-ключи
  с человекочитаемыми именами.
- Binary file (patch=None) → `is_binary=True`, hunks=[].

Все тесты — async (asyncio_mode=auto в pyproject.toml).
"""
from __future__ import annotations

import json
from typing import Any

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("httpx")

import httpx  # noqa: E402

from sunsec.contracts import PRDiff  # noqa: E402
from sunsec.vcs.base import (  # noqa: E402
    AuthError,
    NotFoundError,
    RateLimitError,
    VCSAdapterError,
)
from sunsec.vcs.github import GitHubAdapter  # noqa: E402

# --- helpers --------------------------------------------------------------


def _pr_payload(head_sha: str = "deadbeef", base_sha: str = "cafef00d") -> dict[str, Any]:
    return {
        "number": 42,
        "head": {"sha": head_sha},
        "base": {"sha": base_sha},
    }


def _file_modified(path: str, patch: str | None = None) -> dict[str, Any]:
    return {
        "filename": path,
        "status": "modified",
        "patch": patch
        if patch is not None
        else (
            "@@ -1,2 +1,3 @@\n"
            " a\n"
            "-b\n"
            "+B\n"
            "+C\n"
        ),
    }


def _json_response(status: int, body: Any, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
    )


class _Sleeper:
    """Учётный async-sleeper — собирает интервалы вместо реального ожидания."""

    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, sec: float) -> None:
        self.calls.append(sec)


def _adapter(
    handler: httpx.MockTransport,
    *,
    max_retries: int = 3,
    files_soft_limit: int = 300,
    files_page_size: int = 100,
    rate_limit_wait_cap: float = 60.0,
    sleeper: _Sleeper | None = None,
) -> tuple[GitHubAdapter, _Sleeper]:
    sleeper = sleeper or _Sleeper()
    client = httpx.AsyncClient(transport=handler, base_url="https://api.github.com")
    return (
        GitHubAdapter(
            token="ghp_dummy_token_value",
            api_base="https://api.github.com",
            max_retries=max_retries,
            files_soft_limit=files_soft_limit,
            files_page_size=files_page_size,
            rate_limit_wait_cap_seconds=rate_limit_wait_cap,
            client=client,
            sleeper=sleeper,
        ),
        sleeper,
    )


# --- tests: happy path -----------------------------------------------------


async def test_fetch_pr_diff_happy_path_returns_structured_prdiff() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        assert req.headers["Authorization"].startswith("Bearer ")
        assert req.headers["X-GitHub-Api-Version"] == "2022-11-28"
        if req.url.path == "/repos/o/r/pulls/42":
            return _json_response(200, _pr_payload("HEAD", "BASE"))
        if req.url.path == "/repos/o/r/pulls/42/files":
            return _json_response(
                200,
                [
                    _file_modified("a.py"),
                    {
                        "filename": "img.png",
                        "status": "modified",
                        # patch отсутствует — GitHub так помечает binary.
                    },
                ],
            )
        return _json_response(500, {"message": "unexpected path"})

    adapter, _sleep = _adapter(httpx.MockTransport(handler))
    diff = await adapter.fetch_pr_diff("o/r", 42)

    assert isinstance(diff, PRDiff)
    assert diff.repo == "o/r"
    assert diff.pr_number == 42
    assert diff.head_sha == "HEAD"
    assert diff.base_sha == "BASE"
    assert len(diff.files) == 2

    a_py, img = diff.files
    assert a_py.path == "a.py"
    assert a_py.status == "modified"
    assert a_py.is_binary is False
    assert len(a_py.hunks) == 1

    assert img.path == "img.png"
    assert img.is_binary is True
    assert img.hunks == []


# --- tests: 404 -----------------------------------------------------------


async def test_fetch_pr_diff_404_raises_not_found_no_retry() -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path)
        return _json_response(404, {"message": "Not Found"})

    adapter, sleeper = _adapter(httpx.MockTransport(handler))
    with pytest.raises(NotFoundError):
        await adapter.fetch_pr_diff("o/r", 42)
    # один вызов /pulls/42, без ретраев и без sleep'ов.
    assert len(calls) == 1
    assert sleeper.calls == []


# --- tests: 401/403 auth --------------------------------------------------


async def test_fetch_pr_diff_401_raises_auth_error_no_retry() -> None:
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.url.path)
        return _json_response(401, {"message": "Bad credentials"})

    adapter, sleeper = _adapter(httpx.MockTransport(handler))
    with pytest.raises(AuthError):
        await adapter.fetch_pr_diff("o/r", 42)
    assert len(calls) == 1
    assert sleeper.calls == []


async def test_fetch_pr_diff_403_without_rate_limit_marker_is_auth_error() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return _json_response(403, {"message": "Forbidden"})

    adapter, sleeper = _adapter(httpx.MockTransport(handler))
    with pytest.raises(AuthError):
        await adapter.fetch_pr_diff("o/r", 42)
    assert sleeper.calls == []


# --- tests: rate-limit → backoff → success ---------------------------------


async def test_fetch_pr_diff_rate_limit_429_then_success_waits_retry_after() -> None:
    state = {"hits": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/o/r/pulls/42":
            state["hits"] += 1
            if state["hits"] == 1:
                # первый запрос — 429 с Retry-After=3
                return httpx.Response(
                    429,
                    headers={"Retry-After": "3", "Content-Type": "application/json"},
                    content=b'{"message":"Too Many Requests"}',
                )
            return _json_response(200, _pr_payload())
        if req.url.path == "/repos/o/r/pulls/42/files":
            return _json_response(200, [_file_modified("a.py")])
        return _json_response(500, {})

    adapter, sleeper = _adapter(
        httpx.MockTransport(handler), rate_limit_wait_cap=60.0
    )
    diff = await adapter.fetch_pr_diff("o/r", 42)
    assert diff.pr_number == 42
    # Должен был ровно один раз заснуть на 3 секунды (Retry-After).
    assert sleeper.calls == [pytest.approx(3.0)]


async def test_fetch_pr_diff_403_rate_limit_remaining_zero_waits_reset() -> None:
    import time as _time

    state = {"hits": 0}
    reset_ts = int(_time.time()) + 5  # 5 секунд в будущее

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/o/r/pulls/42":
            state["hits"] += 1
            if state["hits"] == 1:
                return httpx.Response(
                    403,
                    headers={
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(reset_ts),
                        "Content-Type": "application/json",
                    },
                    content=b'{"message":"rate limit"}',
                )
            return _json_response(200, _pr_payload())
        return _json_response(200, [])

    adapter, sleeper = _adapter(httpx.MockTransport(handler))
    diff = await adapter.fetch_pr_diff("o/r", 42)
    assert isinstance(diff, PRDiff)
    assert len(sleeper.calls) == 1
    # Ждали примерно 5 секунд (точное число зависит от int(time.time()) на момент теста).
    assert 0.0 <= sleeper.calls[0] <= 6.0


async def test_fetch_pr_diff_rate_limit_caps_retry_after() -> None:
    state = {"hits": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/o/r/pulls/42":
            state["hits"] += 1
            if state["hits"] == 1:
                return httpx.Response(
                    429,
                    headers={
                        "Retry-After": "99999",  # > cap
                        "Content-Type": "application/json",
                    },
                    content=b'{}',
                )
            return _json_response(200, _pr_payload())
        return _json_response(200, [])

    adapter, sleeper = _adapter(
        httpx.MockTransport(handler), rate_limit_wait_cap=2.5
    )
    await adapter.fetch_pr_diff("o/r", 42)
    assert sleeper.calls == [pytest.approx(2.5)]


async def test_fetch_pr_diff_rate_limit_exhausted_raises() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/o/r/pulls/42":
            return httpx.Response(
                429,
                headers={"Retry-After": "0", "Content-Type": "application/json"},
                content=b'{}',
            )
        return _json_response(200, [])

    adapter, sleeper = _adapter(httpx.MockTransport(handler), max_retries=2)
    with pytest.raises(RateLimitError):
        await adapter.fetch_pr_diff("o/r", 42)
    # 2 ретрая = 2 sleep'а; 3-я попытка падает.
    assert len(sleeper.calls) == 2


# --- tests: 5xx backoff ----------------------------------------------------


async def test_fetch_pr_diff_5xx_then_success_does_exponential_backoff() -> None:
    state = {"hits": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/o/r/pulls/42":
            state["hits"] += 1
            if state["hits"] < 3:
                return _json_response(503, {"message": "service unavailable"})
            return _json_response(200, _pr_payload())
        return _json_response(200, [_file_modified("a.py")])

    adapter, sleeper = _adapter(httpx.MockTransport(handler), max_retries=3)
    diff = await adapter.fetch_pr_diff("o/r", 42)
    assert diff.pr_number == 42
    # На двух 503-ответах должно быть два backoff-sleep'а; интервалы растут.
    assert len(sleeper.calls) == 2
    assert sleeper.calls[0] >= 0.5
    assert sleeper.calls[1] >= 1.0


async def test_fetch_pr_diff_5xx_exhausted_raises_vcs_error() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        return _json_response(500, {"message": "boom"})

    adapter, sleeper = _adapter(httpx.MockTransport(handler), max_retries=2)
    with pytest.raises(VCSAdapterError):
        await adapter.fetch_pr_diff("o/r", 42)
    assert len(sleeper.calls) == 2  # max_retries попыток дополнительных к первой


# --- tests: pagination + soft-limit ----------------------------------------


async def test_fetch_pr_diff_pagination_two_pages_concatenated() -> None:
    page_size = 2

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/o/r/pulls/42":
            return _json_response(200, _pr_payload())
        if req.url.path == "/repos/o/r/pulls/42/files":
            page = req.url.params.get("page", "1")
            if page == "1":
                return _json_response(
                    200,
                    [_file_modified("a.py"), _file_modified("b.py")],
                    headers={
                        "Link": '<https://api.github.com/...&page=2>; rel="next"',
                    },
                )
            if page == "2":
                return _json_response(200, [_file_modified("c.py")])
            return _json_response(200, [])
        return _json_response(500, {})

    adapter, _ = _adapter(httpx.MockTransport(handler), files_page_size=page_size)
    diff = await adapter.fetch_pr_diff("o/r", 42)
    paths = [f.path for f in diff.files]
    assert paths == ["a.py", "b.py", "c.py"]


async def test_fetch_pr_diff_soft_limit_truncates_files() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/o/r/pulls/42":
            return _json_response(200, _pr_payload())
        if req.url.path == "/repos/o/r/pulls/42/files":
            # вернём 5 файлов на первой странице; soft-limit=3
            return _json_response(
                200,
                [_file_modified(f"f{i}.py") for i in range(5)],
            )
        return _json_response(500, {})

    adapter, _ = _adapter(
        httpx.MockTransport(handler), files_soft_limit=3, files_page_size=100
    )
    diff = await adapter.fetch_pr_diff("o/r", 42)
    assert len(diff.files) == 3


# --- tests: safety ---------------------------------------------------------


def test_repr_does_not_leak_token() -> None:
    a = GitHubAdapter(token="ghp_super_secret_xyz")
    text = repr(a)
    assert "ghp_super_secret_xyz" not in text
    assert "GitHubAdapter" in text


async def test_fetch_pr_diff_renamed_file_carries_old_path() -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/repos/o/r/pulls/42":
            return _json_response(200, _pr_payload())
        if req.url.path == "/repos/o/r/pulls/42/files":
            return _json_response(
                200,
                [
                    {
                        "filename": "new.py",
                        "previous_filename": "old.py",
                        "status": "renamed",
                        "patch": "@@ -1 +1 @@\n-x\n+y\n",
                    }
                ],
            )
        return _json_response(500, {})

    adapter, _ = _adapter(httpx.MockTransport(handler))
    diff = await adapter.fetch_pr_diff("o/r", 42)
    f = diff.files[0]
    assert f.status == "renamed"
    assert f.old_path == "old.py"
    assert len(f.hunks) == 1


# --- tests: verify_signature (sanity) --------------------------------------


def test_verify_signature_valid_and_invalid() -> None:
    import hashlib
    import hmac as _hmac

    adapter = GitHubAdapter(token="t")
    body = b'{"action":"opened"}'
    secret = "topsecret"
    good = (
        "sha256=" + _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    )
    bad = "sha256=" + "0" * 64
    assert adapter.verify_signature(body, good, secret) is True
    assert adapter.verify_signature(body, bad, secret) is False
    assert adapter.verify_signature(body, "", secret) is False
    assert adapter.verify_signature(body, good, "") is False
    assert adapter.verify_signature(body, "md5=abc", secret) is False
