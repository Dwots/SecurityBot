"""Тесты FalsePositiveFilter (T-013).

Покрытие:
- Pre-LLM scan: реальные секреты ловятся (AWS AKIA, GitHub PAT, JWT, PEM);
  placeholders / тестовые пути / hash — не флагятся.
- Postprocess: 10 эталонных FP-кейсов из vuln_taxonomy.md §6 (≥80% должны
  отфильтровываться). Реальные позитивные кейсы — НЕ должны падать.

Метрика DoD: на 10 явных FP-кейсах ≥80% (=8) дропаются.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic")

from sunsec.contracts import (  # noqa: E402
    AddedLine,
    FilteredDiff,
    FilteredDiffFile,
    Finding,
)
from sunsec.ml import FalsePositiveFilter, FPFilterConfig  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _filtered(files: list[tuple[str, list[tuple[int, str]]]]) -> FilteredDiff:
    """Удобный конструктор: [(path, [(line, content), ...]), ...]."""
    fd_files = [
        FilteredDiffFile(
            path=path,
            language=None,
            added_lines=[AddedLine(new_line_no=ln, content=c) for ln, c in lines],
        )
        for path, lines in files
    ]
    return FilteredDiff(
        repo="acme/test",
        pr_number=1,
        head_sha="deadbeef",
        files=fd_files,
        estimated_input_tokens=10,
        content_hash="hash",
    )


def _finding(
    file: str,
    line: int,
    cls: str,
    *,
    severity: str = "high",
    message: str = "Potential issue detected here.",
    confidence: float = 0.85,
) -> Finding:
    return Finding.model_validate(
        {
            "file": file,
            "line": line,
            "class": cls,
            "severity": severity,
            "message": message,
            "suggestion": None,
            "confidence": confidence,
        }
    )


@pytest.fixture
def fp() -> FalsePositiveFilter:
    return FalsePositiveFilter()


# ---------------------------------------------------------------------------
# Pre-LLM scan: positive cases (должны ловиться без LLM)
# ---------------------------------------------------------------------------


class TestPreLLMScan:
    def test_aws_access_key_caught_in_real_code(self, fp: FalsePositiveFilter) -> None:
        diff = _filtered([
            ("src/aws_client.py", [
                (5, 'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"'),
            ])
        ])
        # ВНИМАНИЕ: AKIAIOSFODNN7EXAMPLE — официальный AWS test-pattern
        # (см. AWS docs), он содержит EXAMPLE, попадёт в placeholder-фильтр.
        # Тестируем на безопасном fake-вариант
        diff = _filtered([
            ("src/aws_client.py", [
                (5, 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'),
            ])
        ])
        result = fp.pre_llm_scan(diff)
        assert len(result) == 1
        assert result[0].class_ == "hardcoded_secret"
        assert result[0].severity == "critical"
        assert result[0].confidence >= 0.9

    def test_github_pat_caught(self, fp: FalsePositiveFilter) -> None:
        diff = _filtered([
            ("config.py", [
                (3, 'TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901"'),
            ])
        ])
        result = fp.pre_llm_scan(diff)
        assert len(result) == 1
        assert result[0].class_ == "hardcoded_secret"
        assert result[0].severity == "critical"

    def test_private_key_pem_caught(self, fp: FalsePositiveFilter) -> None:
        diff = _filtered([
            ("ssl/key.pem", [
                (1, "-----BEGIN RSA PRIVATE KEY-----"),
            ])
        ])
        result = fp.pre_llm_scan(diff)
        assert len(result) == 1
        assert result[0].severity == "critical"

    def test_env_example_with_real_looking_key_skipped(
        self, fp: FalsePositiveFilter
    ) -> None:
        """В .env.example даже похожий на ключ паттерн — placeholder."""
        diff = _filtered([
            (".env.example", [
                (1, 'OPENAI_API_KEY=sk-REPLACE-ME-WITH-YOUR-KEY'),
            ])
        ])
        result = fp.pre_llm_scan(diff)
        assert len(result) == 0

    def test_test_path_with_short_dummy_skipped(
        self, fp: FalsePositiveFilter
    ) -> None:
        diff = _filtered([
            ("tests/conftest.py", [
                (10, 'mock_token = "ghp_fake12345"'),  # < 36 char чтобы regex не сработал
            ])
        ])
        result = fp.pre_llm_scan(diff)
        # Даже если бы regex поймал — placeholder marker "fake" должен отбросить
        assert len(result) == 0

    def test_high_entropy_secret_in_real_code_caught(
        self, fp: FalsePositiveFilter
    ) -> None:
        diff = _filtered([
            ("src/config.py", [
                (1, 'API_TOKEN = "P9kL3mQ7rT5xY1zB8nW2vU6cF4dG0hJsA"'),
            ])
        ])
        result = fp.pre_llm_scan(diff)
        assert len(result) >= 1
        assert result[0].class_ == "hardcoded_secret"


# ---------------------------------------------------------------------------
# Postprocess: 10+ FP cases (DoD ≥80%)
# ---------------------------------------------------------------------------


class TestPostprocessFalsePositives:
    """10 канонических FP-кейсов из vuln_taxonomy.md §6 + 3 позитива."""

    # ----- FP cases -----

    def test_fp1_parametrized_sql_dropped(self, fp: FalsePositiveFilter) -> None:
        """SQLi с явной параметризацией (cursor.execute(sql, (uid,))) → drop."""
        diff = _filtered([
            ("api/users.py", [
                (10, 'def get_user(conn, uid):'),
                (11, '    return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()'),
            ])
        ])
        ll = [_finding("api/users.py", 11, "sql_injection")]
        out = fp.postprocess(ll, diff, [])
        assert out == [], "Parametrized SQL must be dropped"

    def test_fp2_orm_filter_dropped(self, fp: FalsePositiveFilter) -> None:
        """ORM .objects.filter() → drop."""
        diff = _filtered([
            ("api/models.py", [
                (5, 'def filter_users(role):'),
                (6, '    return User.objects.filter(role=role, is_active=True)'),
            ])
        ])
        ll = [_finding("api/models.py", 6, "sql_injection")]
        out = fp.postprocess(ll, diff, [])
        assert out == [], "ORM filter must be dropped"

    def test_fp3_env_getter_for_secret_dropped(self, fp: FalsePositiveFilter) -> None:
        """SECRET_KEY = os.environ['DJANGO_SECRET_KEY'] → drop."""
        diff = _filtered([
            ("settings.py", [
                (3, 'SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]'),
            ])
        ])
        ll = [_finding("settings.py", 3, "hardcoded_secret")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_fp4_env_example_placeholder_dropped(
        self, fp: FalsePositiveFilter
    ) -> None:
        """TOKEN=REPLACE_ME в .env.example → drop."""
        diff = _filtered([
            (".env.example", [
                (1, 'API_TOKEN="REPLACE_ME_WITH_REAL_TOKEN"'),
            ])
        ])
        ll = [_finding(".env.example", 1, "hardcoded_secret")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_fp5_test_path_dummy_dropped(self, fp: FalsePositiveFilter) -> None:
        """mock_token='fake-token-xxx' в tests/test_*.py → drop."""
        diff = _filtered([
            ("tests/test_api.py", [
                (10, 'mock_token = "fake-token-xxx"'),
            ])
        ])
        ll = [_finding("tests/test_api.py", 10, "hardcoded_secret")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_fp6_jsx_safe_mustache_dropped(self, fp: FalsePositiveFilter) -> None:
        """JSX {userInput} без dangerouslySetInnerHTML → drop."""
        diff = _filtered([
            ("Comment.tsx", [
                (3, 'export const Comment = ({ html }) => ('),
                (4, '  <div className="comment">{html}</div>'),
                (5, ');'),
            ])
        ])
        ll = [_finding("Comment.tsx", 4, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_fp7_bleach_sanitizer_dropped(self, fp: FalsePositiveFilter) -> None:
        """bleach.clean(raw) рядом → drop xss."""
        diff = _filtered([
            ("views.py", [
                (10, 'cleaned = bleach.clean(raw_html, tags=ALLOWED)'),
                (11, 'return HttpResponse(cleaned)'),
            ])
        ])
        ll = [_finding("views.py", 11, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_fp8_bcrypt_hash_dropped(self, fp: FalsePositiveFilter) -> None:
        """password = '$2b$12$...' — bcrypt hash, не plain secret → drop."""
        diff = _filtered([
            ("models.py", [
                (5, 'password = "$2b$12$KIXxPfnK4ihFqp8tWnfM5O.K5kHnvK3T5L8H7K4tWqWvU2tNxYZqK"'),
            ])
        ])
        ll = [_finding("models.py", 5, "hardcoded_secret")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_fp9_secret_like_name_with_bool_value_dropped(
        self, fp: FalsePositiveFilter
    ) -> None:
        """is_secret_enabled = True → drop."""
        diff = _filtered([
            ("config.py", [
                (5, 'is_secret_enabled = True'),
            ])
        ])
        ll = [_finding("config.py", 5, "hardcoded_secret")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_fp10_duplicates_deduplicated(self, fp: FalsePositiveFilter) -> None:
        """Два одинаковых finding'а на (file,line,class) → один."""
        diff = _filtered([
            ("auth.py", [
                (12, 'q = f"SELECT * FROM users WHERE id = {user_id}"'),
                (13, 'return conn.execute(q).fetchone()'),
            ])
        ])
        ll = [
            _finding("auth.py", 12, "sql_injection", confidence=0.9),
            _finding("auth.py", 12, "sql_injection", confidence=0.7,
                     message="Same finding from another scan path."),
        ]
        out = fp.postprocess(ll, diff, [])
        assert len(out) == 1
        # При дедупликации — взяли finding с большей confidence
        assert out[0].confidence == 0.9

    # ----- Positive cases (НЕ должны падать) -----

    def test_pos11_real_aws_key_kept(self, fp: FalsePositiveFilter) -> None:
        """AKIA*** в реальном файле — НЕ фильтруется + pre_llm_scan ловит."""
        diff = _filtered([
            ("src/aws_client.py", [
                (5, 'AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"'),
            ])
        ])
        pre = fp.pre_llm_scan(diff)
        assert len(pre) == 1
        out = fp.postprocess([], diff, pre)
        assert len(out) == 1
        assert out[0].severity == "critical"

    def test_pos12_real_github_pat_kept(self, fp: FalsePositiveFilter) -> None:
        diff = _filtered([
            ("config.py", [
                (3, 'GH_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901"'),
            ])
        ])
        pre = fp.pre_llm_scan(diff)
        assert len(pre) == 1
        out = fp.postprocess([], diff, pre)
        assert len(out) == 1

    def test_pos13_real_sqli_kept(self, fp: FalsePositiveFilter) -> None:
        """f-string SQL без параметризации → НЕ фильтруется."""
        diff = _filtered([
            ("auth.py", [
                (12, 'q = f"SELECT * FROM users WHERE id = {user_id}"'),
                (13, 'return conn.execute(q).fetchone()'),
            ])
        ])
        ll = [_finding("auth.py", 12, "sql_injection")]
        out = fp.postprocess(ll, diff, [])
        assert len(out) == 1
        assert out[0].class_ == "sql_injection"


# ---------------------------------------------------------------------------
# Дополнительные правила (граничные кейсы)
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_finding_outside_added_lines_dropped(
        self, fp: FalsePositiveFilter
    ) -> None:
        """LLM сослался на строку, которой нет в added — drop (PRD «только изменённый код»)."""
        diff = _filtered([
            ("a.py", [(10, "x = 1")]),
        ])
        ll = [_finding("a.py", 99, "sql_injection")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_low_confidence_dropped(self, fp: FalsePositiveFilter) -> None:
        """confidence < 0.5 → drop по умолчанию."""
        diff = _filtered([
            ("a.py", [(10, 'q = f"SELECT * FROM x WHERE id = {y}"')]),
        ])
        ll = [_finding("a.py", 10, "sql_injection", confidence=0.3)]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_low_confidence_threshold_configurable(self) -> None:
        """min_confidence можно понизить."""
        fp_low = FalsePositiveFilter(FPFilterConfig(min_confidence=0.2))
        diff = _filtered([
            ("a.py", [(10, 'q = f"SELECT * FROM x WHERE id = {y}"')]),
        ])
        ll = [_finding("a.py", 10, "sql_injection", confidence=0.3)]
        out = fp_low.postprocess(ll, diff, [])
        assert len(out) == 1

    def test_comment_only_line_dropped(self, fp: FalsePositiveFilter) -> None:
        diff = _filtered([
            ("a.py", [(10, '# password = "abc123"  TODO move to env')]),
        ])
        ll = [_finding("a.py", 10, "hardcoded_secret")]
        out = fp.postprocess(ll, diff, [])
        assert out == []

    def test_innerHTML_xss_kept(self, fp: FalsePositiveFilter) -> None:
        """Реальный XSS через innerHTML — НЕ фильтруется (нет sanitizer)."""
        diff = _filtered([
            ("static/search.js", [
                (2, "const q = new URLSearchParams(location.search).get('q');"),
                (3, "document.getElementById('label').innerHTML = 'You searched: ' + q;"),
            ])
        ])
        ll = [_finding("static/search.js", 3, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert len(out) == 1

    def test_pre_scan_and_llm_findings_deduplicated(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Если pre-scan и LLM нашли тот же секрет — итог 1 finding."""
        diff = _filtered([
            ("config.py", [
                (3, 'TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345678901"'),
            ])
        ])
        pre = fp.pre_llm_scan(diff)
        assert len(pre) == 1
        ll = [_finding("config.py", 3, "hardcoded_secret", severity="high",
                       confidence=0.8)]
        out = fp.postprocess(ll, diff, pre)
        assert len(out) == 1
        # pre-scan имеет confidence 0.98 → должна победить
        assert out[0].confidence >= 0.9
        assert out[0].severity == "critical"

    def test_xss_with_sanitizer_in_window(self, fp: FalsePositiveFilter) -> None:
        diff = _filtered([
            ("comp.tsx", [
                (1, "import DOMPurify from 'dompurify';"),
                (2, "const sanitized = DOMPurify.sanitize(raw);"),
                (3, "el.innerHTML = sanitized;"),
            ])
        ])
        ll = [_finding("comp.tsx", 3, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert out == []


# ---------------------------------------------------------------------------
# RT-006: counter-examples — overly broad `escape(`/`sanitize(` НЕ должны
# глушить реальный XSS, известные XSS-санитайзеры — всё ещё работают.
# ---------------------------------------------------------------------------


class TestXssSanitizerWhitelistRT006:
    """Регресс по RT-006 (Auditor T-014 gate).

    До патча `_XSS_SANITIZER_PATTERNS` содержал `\\bescape\\s*\\(` и
    `\\bsanitize\\s*\\(` — слишком общие regex. Они ошибочно совпадали с
    `re.escape(...)` (Python regex-helper), JS legacy `escape(...)`
    (URL-encoding, НЕ HTML-escape) и `sanitize_filename(...)` (paths).
    В `_check_xss` окно ±2 строки — посторонний escape/sanitize в окне →
    `xss_sanitizer_present` → drop реального XSS (false negative,
    критично для PRD «поиск уязвимостей»).

    Эти тесты фиксируют:
      • реальный XSS НЕ дропается из-за постороннего `re.escape` /
        JS legacy `escape` / `sanitize_filename` в окне;
      • known-санитайзеры (`DOMPurify.sanitize`, `bleach.clean`,
        `html.escape`) всё ещё дропают XSS.
    """

    def test_xss_kept_with_unrelated_escape_in_window(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Counter-example #1 (RT-006): `re.escape` в окне НЕ маркирует
        finding как «sanitizer present».
        """
        diff = _filtered([
            ("static/render.js", [
                (10, "const pattern = re.escape(some_regex);"),
                (11, "el.innerHTML = userInput;"),
            ])
        ])
        ll = [_finding("static/render.js", 11, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert len(out) == 1, (
            "XSS должен остаться: re.escape — regex-helper, не HTML-санитайзер"
        )
        assert out[0].class_ == "xss"

    def test_xss_kept_with_js_legacy_escape_in_window(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Counter-example #2 (RT-006): JS legacy `escape()` — URL-encoding,
        не HTML-escape. Не должен дропать XSS.
        """
        diff = _filtered([
            ("static/app.js", [
                (20, "const url = escape(userInput);"),
                (21, "target.innerHTML = data;"),
            ])
        ])
        ll = [_finding("static/app.js", 21, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert len(out) == 1, (
            "XSS должен остаться: JS legacy escape() — URL-encoding"
        )
        assert out[0].class_ == "xss"

    def test_xss_kept_with_unrelated_sanitize_filename_in_window(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Counter-example #3 (RT-006): `sanitize_filename()` для путей —
        не HTML-санитайзер. Не должен дропать XSS.
        """
        diff = _filtered([
            ("server/upload.py", [
                (30, "path = sanitize_filename(name)"),
                (31, "element.innerHTML = input"),
            ])
        ])
        ll = [_finding("server/upload.py", 31, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert len(out) == 1, (
            "XSS должен остаться: sanitize_filename — для путей, не HTML"
        )
        assert out[0].class_ == "xss"

    # ----- Регрессия: known sanitizers всё ещё работают -----

    def test_xss_dropped_with_dompurify_in_window(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Регресс RT-006: `DOMPurify.sanitize` — known sanitizer, drop ok."""
        diff = _filtered([
            ("comp.tsx", [
                (5, "clean = DOMPurify.sanitize(userInput);"),
                (6, "el.innerHTML = clean;"),
            ])
        ])
        ll = [_finding("comp.tsx", 6, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert out == [], "DOMPurify.sanitize должен по-прежнему дропать XSS"

    def test_xss_dropped_with_html_escape_in_window(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Регресс RT-006: `html.escape` — known Python stdlib HTML-escape."""
        diff = _filtered([
            ("server/views.py", [
                (40, "safe = html.escape(userInput)"),
                (41, "response.body = '<div>' + safe + '</div>'"),
                (42, "el.innerHTML = response.body"),
            ])
        ])
        ll = [_finding("server/views.py", 42, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert out == [], "html.escape должен по-прежнему дропать XSS"

    def test_xss_dropped_with_bleach_clean_in_window(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Регресс RT-006: `bleach.clean` — known Python HTML-санитайзер."""
        diff = _filtered([
            ("server/views.py", [
                (50, "cleaned = bleach.clean(user_html)"),
                (51, "response = HttpResponse(cleaned)"),
            ])
        ])
        ll = [_finding("server/views.py", 51, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert out == [], "bleach.clean должен по-прежнему дропать XSS"

    def test_xss_dropped_with_lodash_escape_in_window(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Регресс RT-006: `_.escape` — Lodash/Underscore HTML-escape."""
        diff = _filtered([
            ("static/render.js", [
                (60, "const safe = _.escape(userInput);"),
                (61, "el.innerHTML = safe;"),
            ])
        ])
        ll = [_finding("static/render.js", 61, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert out == [], "_.escape (Lodash) должен по-прежнему дропать XSS"

    def test_xss_dropped_with_sanitize_html_camelcase_in_window(
        self, fp: FalsePositiveFilter
    ) -> None:
        """Регресс RT-006: `sanitizeHtml(...)` — npm `sanitize-html`."""
        diff = _filtered([
            ("static/render.js", [
                (70, "const safe = sanitizeHtml(rawHtml);"),
                (71, "container.innerHTML = safe;"),
            ])
        ])
        ll = [_finding("static/render.js", 71, "xss")]
        out = fp.postprocess(ll, diff, [])
        assert out == [], "sanitizeHtml() должен по-прежнему дропать XSS"


# ---------------------------------------------------------------------------
# Финальная сводка: метрика покрытия 10 FP-кейсов (DoD ≥80%)
# ---------------------------------------------------------------------------


def test_fp_coverage_metric_at_least_80_percent() -> None:
    """Суммарная метрика: на 10 эталонных FP-кейсах ≥80% (=8) дропаются.

    Этот тест дублирует логику отдельных тестов выше, но считает агрегат —
    его прогон фиксирует DoD-метрику T-013 в одном assert'е (читается легко).
    """
    fp = FalsePositiveFilter()

    cases: list[tuple[str, FilteredDiff, list[Finding], bool]] = []

    # 1) Parametrized SQL
    d = _filtered([("a.py", [
        (1, 'cursor.execute("SELECT * FROM t WHERE id = ?", (uid,))'),
    ])])
    cases.append(("parametrized_sql", d, [_finding("a.py", 1, "sql_injection")], True))

    # 2) ORM
    d = _filtered([("b.py", [
        (1, "User.objects.filter(role=role)"),
    ])])
    cases.append(("orm", d, [_finding("b.py", 1, "sql_injection")], True))

    # 3) env getter
    d = _filtered([("c.py", [(1, 'KEY = os.environ["X"]')])])
    cases.append(("env_getter", d, [_finding("c.py", 1, "hardcoded_secret")], True))

    # 4) .env.example placeholder
    d = _filtered([(".env.example", [(1, "TOKEN=YOUR_KEY_HERE")])])
    cases.append(("env_example", d, [_finding(".env.example", 1, "hardcoded_secret")], True))

    # 5) tests/ dummy
    d = _filtered([("tests/test_a.py", [(1, 'tok = "fake-xxx-test"')])])
    cases.append(("tests_dummy", d, [_finding("tests/test_a.py", 1, "hardcoded_secret")], True))

    # 6) JSX safe
    d = _filtered([("C.tsx", [(1, '<div className="x">{html}</div>')])])
    cases.append(("jsx_safe", d, [_finding("C.tsx", 1, "xss")], True))

    # 7) sanitizer
    d = _filtered([("v.py", [
        (1, "cleaned = bleach.clean(html)"),
        (2, "return cleaned"),
    ])])
    cases.append(("sanitizer", d, [_finding("v.py", 2, "xss")], True))

    # 8) bcrypt hash
    d = _filtered([("m.py", [
        (1, 'pw = "$2b$12$AbCdEfGhIjKlMnOpQrStUvWxYz012345678901234567890123"'),
    ])])
    cases.append(("bcrypt_hash", d, [_finding("m.py", 1, "hardcoded_secret")], True))

    # 9) secret-like name + bool
    d = _filtered([("c.py", [(1, "is_token_enabled = True")])])
    cases.append(("bool_value", d, [_finding("c.py", 1, "hardcoded_secret")], True))

    # 10) duplicate
    d = _filtered([("a.py", [(1, 'q = f"SELECT * FROM x WHERE id = {y}"')])])
    dup_ll = [
        _finding("a.py", 1, "sql_injection", confidence=0.9),
        _finding("a.py", 1, "sql_injection", confidence=0.7),
    ]
    cases.append(("duplicate", d, dup_ll, True))  # ожидаем 1 на выходе

    drop_count = 0
    fp_total = 0
    for name, diff, ll, expected_drop in cases:
        if name == "duplicate":
            out = fp.postprocess(ll, diff, [])
            # Считаем «дроп» как «количество финдингов сократилось»
            if len(out) < len(ll):
                drop_count += 1
            fp_total += 1
            continue
        out = fp.postprocess(ll, diff, [])
        fp_total += 1
        if not out:
            drop_count += 1

    coverage = drop_count / fp_total
    assert coverage >= 0.8, (
        f"FP coverage {coverage:.0%} < 80% (DoD T-013). "
        f"Dropped {drop_count}/{fp_total}."
    )
