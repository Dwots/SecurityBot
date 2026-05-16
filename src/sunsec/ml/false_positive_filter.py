"""FalsePositiveFilter — T-013.

Двухступенчатый фильтр для снижения false positives + детерминированный
секрет-детектор.

Pipeline integration (см. `pipeline/orchestrator.py`):

    pre_findings  = fp.pre_llm_scan(filtered_diff)       # детерминированный pre-pass
    llm_response  = await llm.analyze(filtered_diff)     # дорогой LLM-вызов
    final         = fp.postprocess(
                        llm_response.findings,
                        filtered_diff,
                        pre_scan_findings=pre_findings,
                    )

Источник истины правил: `agents/artifacts/researcher/vuln_taxonomy.md`
(§3.3 anti-signals SQLi, §4.3 anti-signals secrets, §5.3 anti-signals XSS,
§6 — 15 FP-паттернов с целевым покрытием ≥80% по DoD T-013).

Контракты НЕ ломаются: на вход/выход — `Finding` / `LLMResponseSchema` /
`FilteredDiff` из `sunsec.contracts`. См. system_design §3.5 / §4.3 / §4.4.
"""
from __future__ import annotations

import logging
import math
import os
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

from sunsec.contracts import (
    AddedLine,
    FilteredDiff,
    FilteredDiffFile,
    Finding,
    Severity,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Конфигурация
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FPFilterConfig:
    """Параметры FalsePositiveFilter. Получаются из Settings или дефолтов."""

    min_confidence: float = 0.5
    """Порог отсечения: finding с confidence < min_confidence → drop (§6 #?)."""

    skip_llm_if_prescan_found: bool = False
    """Если pre-scan нашёл ≥1 секрет — можно ли пропустить LLM. По умолчанию НЕТ
    (экономия слабая, теряем SQLi/XSS-сигнал). См. system_design §3.5."""

    entropy_min: float = 4.0
    """Shannon-entropy порог для энтропийных эвристик. 4.0 — типичное значение
    для случайных base64/hex-токенов >=20 символов."""

    entropy_min_length: int = 24
    """Минимальная длина строки, по которой смотрим энтропию."""

    # Пути, которые считаем тестовыми / примерами / документацией.
    # Используются и в pre_llm_scan (не флагим там секреты), и в postprocess
    # (cap severity / drop для hardcoded_secret).
    test_path_patterns: tuple[str, ...] = (
        r"(?i)(^|/)tests?(/|$)",
        r"(?i)/__tests__(/|$)",
        r"(?i)_test\.[a-z0-9]+$",
        r"(?i)\.test\.[a-z0-9]+$",
        r"(?i)\.spec\.[a-z0-9]+$",
        r"(?i)(^|/)spec(/|$)",
        r"(?i)/fixtures?(/|$)",
        r"(?i)/conftest\.py$",
        r"(?i)(^|/)examples?(/|$)",
        r"(?i)/samples?(/|$)",
        r"(?i)/seeds?(/|$)",
        r"(?i)/migrations?(/|$)",
    )

    example_filename_patterns: tuple[str, ...] = (
        r"(?i)\.env\.example$",
        r"(?i)\.env\.sample$",
        r"(?i)\.env\.template$",
        r"(?i)docker-compose\.example\.[ya]ml$",
        r"(?i)config\.example\.[a-z]+$",
    )


# ---------------------------------------------------------------------------
# Известные secret-паттерны (vuln_taxonomy §4.2 п.4)
# ---------------------------------------------------------------------------

# (название, severity по умолчанию, confidence для pre-scan, regex)
_KNOWN_SECRET_PATTERNS: tuple[tuple[str, Severity, float, re.Pattern[str]], ...] = (
    # AWS access keys — критично всегда (§4.4 HC-3)
    ("aws_access_key_id", "critical", 0.98, re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    # GitHub PAT family (ghp/gho/ghu/ghs/ghr_…)
    ("github_pat", "critical", 0.98, re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    # Slack tokens
    ("slack_token", "high", 0.95, re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    # Stripe live + test
    ("stripe_secret", "critical", 0.97, re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("stripe_test", "medium", 0.92, re.compile(r"\bsk_test_[0-9A-Za-z]{16,}\b")),
    # Google API keys
    ("google_api_key", "high", 0.95, re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # OpenAI legacy + project keys (sk-… ≥ 32 chars)
    ("openai_key", "critical", 0.95, re.compile(r"\bsk-(?:proj-)?[0-9A-Za-z_\-]{20,}\b")),
    # Generic JWT (eyJ…header.payload.signature)
    ("jwt", "medium", 0.7, re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    # Private key headers (PEM)
    ("private_key_pem", "critical", 0.99, re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
)


# Placeholder/dummy-маркеры в значении секрета (§4.3 anti-signals)
_PLACEHOLDER_MARKERS: frozenset[str] = frozenset({
    "your_", "your-", "<your", "yourkey", "yourkeyhere",
    "replace", "replaceme", "replace_me", "replace-me",
    "changeme", "change_me", "change-me",
    "example", "fake", "dummy", "placeholder", "redacted",
    "xxx", "xxxx", "xxxxx", "xxxxxxxx",
    "todo", "tbd",
    "test1234", "test-token", "test_token", "testkey",
    "secretsecret", "topsecret", "p@ssw0rd",
})


# Хеш-префиксы — это НЕ plain-секреты (§6 #12)
_HASH_PREFIXES: tuple[str, ...] = (
    "$2a$", "$2b$", "$2y$",  # bcrypt
    "$argon2", "$pbkdf2",
    "hash:", "bcrypt:", "sha256:", "sha512:", "md5:",
)


# ORM-вызовы (vuln_taxonomy §3.3 anti-signals SQLi, §6 #5)
_ORM_SAFE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p) for p in (
        r"\.objects\.filter\s*\(",
        r"\.objects\.get\s*\(",
        r"\.objects\.create\s*\(",
        r"\.objects\.exclude\s*\(",
        r"\.objects\.all\s*\(",
        r"session\.query\s*\(",
        r"select\s*\(.+?\)\s*\.where\s*\(",
        r"\.where\s*\(",   # SQLAlchemy 2.x select().where(Model.col == x)
        r"\.find_by\s*\(",  # ActiveRecord
        r"Prisma\.[a-zA-Z_]+\.findMany",
    )
)


# Параметризация — `?`, `%s`, `$N`, `:name` + явный tuple/dict params
_PARAMETRIZED_SQL_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p) for p in (
        # cursor.execute("... WHERE id = ?", (uid,))
        r"\bexecute\s*\([^)]*\?\s*[^)]*\)\s*,\s*\(",
        # cursor.execute("... %s", (uid,))
        r"\bexecute\s*\([^)]*%s[^)]*\)\s*,\s*[\(\[]",
        # cursor.execute("... %(name)s", {"name": uid})
        r"\bexecute\s*\([^)]*%\([a-zA-Z_][a-zA-Z0-9_]*\)s[^)]*\)\s*,\s*\{",
        # pool.query("... $1 $2", [a, b])
        r"\b(?:query|execute)\s*\([^)]*\$\d+[^)]*\)\s*,\s*\[",
        # text("... :name") + execute(stmt, {"name": x})
        r"\btext\s*\(\s*[\"'][^\"']*:[a-zA-Z_][a-zA-Z0-9_]*",
    )
)


# Опасные SQL API (vuln_taxonomy §3.2)
_SQL_EXEC_API_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p) for p in (
        r"\.execute\s*\(",
        r"\.executemany\s*\(",
        r"\.query\s*\(",
        r"\.raw\s*\(",
        r"\bcursor\.execute\s*\(",
        r"pool\.query\s*\(",
        r"db\.exec\s*\(",
    )
)


# XSS sanitizers (vuln_taxonomy §5.3) — whitelist KNOWN санитайзеров.
# ВАЖНО (RT-006, 2026-05-15): не использовать общие regex вида `\bescape\s*\(`
# или `\bsanitize\s*\(` — они ловят `re.escape(...)` (Python regex-helper),
# JS legacy `escape(...)` (URL-encoding, не HTML-escape), `sanitize_filename(...)`
# (paths) и т.п., из-за чего реальный XSS на соседней строке ошибочно
# квалифицируется как «sanitizer present» и дропается. Список ниже —
# узкие паттерны конкретных HTML-санитайзеров / escape-функций.
_XSS_SANITIZER_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p) for p in (
        # JS — известные библиотеки санитизации
        r"\bDOMPurify\.sanitize\s*\(",
        r"\bsanitizeHtml\s*\(",                     # sanitize-html (camelCase API)
        r"\bsanitize_html\s*\(",                    # snake_case binding
        r"\bsanitize-?html\b",                      # имя пакета / namespace
        # JS — известные HTML-escape хелперы (узко по имени модуля/неймспейса)
        r"\b_\.escape\s*\(",                        # Underscore.js / Lodash
        r"\bv\.escape\s*\(",                        # Vue helper
        # Python — известные HTML-escape / sanitize
        r"\bhtml\.escape\s*\(",                     # stdlib `html.escape`
        r"\bmarkupsafe\.escape\b",                  # MarkupSafe (lowercase import)
        r"\bMarkupSafe\.escape\b",                  # MarkupSafe (CapWord импорт)
        r"\bbleach\.clean\s*\(",                    # bleach (Mozilla)
        # DOM API — безопасная вставка текста
        r"\btextContent\s*=",
        r"\binnerText\s*=",
        r"\bcreateTextNode\s*\(",
    )
)


# Опасные XSS API
_XSS_DANGEROUS_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p) for p in (
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"dangerouslySetInnerHTML",
        r"\bdocument\.write\s*\(",
        r"\bv-html\b",
        r"\{\{\{[^}]+\}\}\}",  # mustache triple-brace
        r"\|\s*safe\b",
        r"mark_safe\s*\(",
        r"\bMarkup\s*\(",
        # T-032 (RT-011): server-side template XSS — explicit unsafe markers.
        # Jinja2/Django `{% autoescape false/off %}` block disables auto-escape
        # for `{{ var }}` inside; treat as dangerous within the window.
        r"\{%\s*autoescape\s+(?:false|off)\s*%\}",
        # Mako `${ x | n }` — `n` filter disables default escape.
        r"\$\{\s*[^}]+\|\s*n\s*\}",
        # Go html/template type conversions that bypass context-aware escape.
        r"\btemplate\.(?:HTML|JS|HTMLAttr|URL)\s*\(",
        # Twig (PHP) `{{ var | raw }}`.
        r"\|\s*raw\b",
        # ERB / Rails `.html_safe` and `<%= raw ... %>`.
        r"\.html_safe\b",
        r"<%=\s*raw\b",
    )
)


# Env-getters (§4.3 anti-signals): чтение из env — не секрет.
_ENV_GETTER_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p) for p in (
        r"os\.environ(?:\.get)?\s*[\[\(]",
        r"os\.getenv\s*\(",
        r"process\.env\.[A-Za-z_]",
        r"Deno\.env\.get\s*\(",
        r"viper\.GetString\s*\(",
        r"config\.get\s*\(",
        r"settings\.[A-Za-z_]",
    )
)


# ---------------------------------------------------------------------------
# Утилиты
# ---------------------------------------------------------------------------


def _shannon_entropy(s: str) -> float:
    """Битовая Shannon-энтропия строки. Для случайных base64-токенов >= 4."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _looks_like_placeholder(value: str) -> bool:
    """Есть ли в значении явный placeholder-маркер?"""
    if not value:
        return True
    low = value.lower()
    for m in _PLACEHOLDER_MARKERS:
        if m in low:
            return True
    return False


def _looks_like_hash(value: str) -> bool:
    """Хеш — не секрет per se (§6 #12)."""
    for p in _HASH_PREFIXES:
        if value.startswith(p):
            return True
    return False


def _is_test_path(path: str, cfg: FPFilterConfig) -> bool:
    """Path содержит /tests/, /examples/, *_test.py, и т.п."""
    for pat in cfg.test_path_patterns:
        if re.search(pat, path):
            return True
    return False


def _is_example_file(path: str, cfg: FPFilterConfig) -> bool:
    """Файл вида `.env.example`, `docker-compose.example.yml`."""
    base = os.path.basename(path)
    for pat in cfg.example_filename_patterns:
        if re.search(pat, base):
            return True
    return False


def _strip_comments_line(line: str) -> str:
    """Грубое снятие inline-комментариев. Достаточно для FP-эвристик."""
    # Очень аккуратно — не парсим строки, только обрезаем по символу.
    for marker in ("//", "#", "--"):
        idx = line.find(marker)
        if idx >= 0:
            return line[:idx]
    return line


def _line_in_added(line_no: int, file_added: list[AddedLine]) -> bool:
    return any(al.new_line_no == line_no for al in file_added)


def _find_added_content(line_no: int, file_added: list[AddedLine]) -> Optional[str]:
    for al in file_added:
        if al.new_line_no == line_no:
            return al.content
    return None


def _file_added_lines(filtered: FilteredDiff, path: str) -> list[AddedLine]:
    for f in filtered.files:
        if f.path == path:
            return list(f.added_lines)
    return []


def _file_record(filtered: FilteredDiff, path: str) -> Optional[FilteredDiffFile]:
    for f in filtered.files:
        if f.path == path:
            return f
    return None


def _context_window(
    file_added: list[AddedLine],
    *,
    line_no: int,
    radius: int = 3,
) -> str:
    """Возвращает текст +-`radius` строк вокруг line_no для контекстных проверок."""
    parts: list[str] = []
    for al in file_added:
        if abs(al.new_line_no - line_no) <= radius:
            parts.append(al.content)
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# FalsePositiveFilter
# ---------------------------------------------------------------------------


class FalsePositiveFilter:
    """Двухступенчатый FP-фильтр (см. модуль-docstring).

    Семантика:
    - `pre_llm_scan(filtered)` — детерминированный pre-pass: regex по known
      secret prefixes (AKIA, ghp_, sk_live, AIza, eyJ, PEM-headers). Возвращает
      findings ДО LLM-вызова — экономия токенов + надёжность для очевидных
      случаев. По пути test/example значения с placeholder-маркерами или
      низкой энтропией — не флагит (snippet pre-scan не должен сам быть FP).

    - `postprocess(llm_findings, filtered, pre_scan_findings)`:
      1. слияние pre+llm с дедупом по `(file, line, class)` (lower-cased path);
      2. отбрасывание findings вне added-lines (PRD «только изменённый код»);
      3. правила по классу (sql_injection / xss / hardcoded_secret) из §6
         vuln_taxonomy;
      4. confidence-фильтр `< min_confidence`.

    Каждое отбрасывание логируется на DEBUG с reason. Итоговая сводка — INFO
    `fp_filter_applied`.
    """

    def __init__(self, config: Optional[FPFilterConfig] = None) -> None:
        self._cfg = config or FPFilterConfig()

    @property
    def config(self) -> FPFilterConfig:
        return self._cfg

    # ----------------------------------------------------------------- pre

    def pre_llm_scan(self, filtered: FilteredDiff) -> list[Finding]:
        """Детерминированный regex-скан known-secret patterns по added-lines.

        Возвращает findings, которые потом сольются с LLM-ответом в `postprocess`.
        НЕ флагит секреты в тестовых/примерных путях и явные placeholder-строки.
        """
        out: list[Finding] = []
        seen: set[tuple[str, int]] = set()  # (path, line)

        for f in filtered.files:
            in_test_path = _is_test_path(f.path, self._cfg)
            in_example_file = _is_example_file(f.path, self._cfg)

            for al in f.added_lines:
                content = al.content
                for pat_name, sev, conf, regex in _KNOWN_SECRET_PATTERNS:
                    m = regex.search(content)
                    if not m:
                        continue
                    matched = m.group(0)
                    # Placeholder / dummy в тестах / .env.example — skip
                    if (in_test_path or in_example_file) and (
                        _looks_like_placeholder(matched) or len(matched) < 20
                    ):
                        log.debug(
                            "fp_pre_scan_skip_test_placeholder",
                            extra={
                                "file": f.path,
                                "line": al.new_line_no,
                                "pattern": pat_name,
                            },
                        )
                        continue
                    if _looks_like_placeholder(content):
                        log.debug(
                            "fp_pre_scan_skip_placeholder_marker",
                            extra={
                                "file": f.path,
                                "line": al.new_line_no,
                                "pattern": pat_name,
                            },
                        )
                        continue
                    if _looks_like_hash(content.strip()):
                        log.debug(
                            "fp_pre_scan_skip_hash_value",
                            extra={"file": f.path, "line": al.new_line_no},
                        )
                        continue

                    key = (f.path, al.new_line_no)
                    if key in seen:
                        continue
                    seen.add(key)

                    # cap severity до low для тестовых путей (см. §7.2 #1)
                    final_sev: Severity = "low" if (in_test_path or in_example_file) else sev

                    msg = (
                        f"Hardcoded secret matches pattern '{pat_name}'. "
                        f"Detected by deterministic pre-LLM scan."
                    )
                    out.append(
                        Finding.model_validate(
                            {
                                "file": f.path,
                                "line": al.new_line_no,
                                "class": "hardcoded_secret",
                                "severity": final_sev,
                                "message": msg,
                                "suggestion": None,
                                "confidence": conf,
                            }
                        )
                    )
                    break  # одна находка на (file, line), не дублируем

                # Высокоэнтропийный токен без known-prefix — мягкий сигнал,
                # confidence ниже; постпроцесс может cap'нуть.
                else:
                    self._maybe_flag_entropy(f.path, al, in_test_path or in_example_file, out, seen)

        log.info(
            "fp_pre_scan_completed",
            extra={
                "repo": filtered.repo,
                "pr_number": filtered.pr_number,
                "pre_scan_findings": len(out),
            },
        )
        return out

    def _maybe_flag_entropy(
        self,
        path: str,
        al: AddedLine,
        in_test_or_example: bool,
        out: list[Finding],
        seen: set[tuple[str, int]],
    ) -> None:
        """Энтропийная эвристика для незакрытых паттернов.

        Запускается ТОЛЬКО на присвоениях с подозрительным именем переменной
        (password/secret/token/key/auth). Без этого условия — слишком шумно
        на минифицированных файлах, base64-блобах и т.п. (минифицированные
        отсекаются T-009 filter, но всё равно подстраховываемся).
        """
        cfg = self._cfg
        content = al.content
        # Имя-маркер: ищем подстроку без жёсткого word-boundary, т.к. в идентификаторах
        # типа API_TOKEN / DJANGO_SECRET_KEY `_` не считается границей слова в re.
        if not re.search(
            r"(?i)(passwo?rd|secret|token|api[_-]?key|access[_-]?key|auth|bearer)",
            content,
        ):
            return

        # извлекаем строковый литерал
        m = re.search(r"""['"]([^'"]{8,})['"]""", content)
        if not m:
            return
        value = m.group(1)
        if _looks_like_placeholder(value) or _looks_like_hash(value):
            return
        if len(value) < cfg.entropy_min_length:
            return
        ent = _shannon_entropy(value)
        if ent < cfg.entropy_min:
            return

        # Тестовый/example файл — низкий уровень и низкая confidence.
        sev: Severity = "low" if in_test_or_example else "medium"
        key = (path, al.new_line_no)
        if key in seen:
            return
        seen.add(key)
        out.append(
            Finding.model_validate(
                {
                    "file": path,
                    "line": al.new_line_no,
                    "class": "hardcoded_secret",
                    "severity": sev,
                    "message": (
                        f"High-entropy string literal (entropy={ent:.2f}) assigned to a "
                        f"secret-like variable. Detected by deterministic entropy heuristic."
                    ),
                    "suggestion": None,
                    "confidence": 0.6,
                }
            )
        )

    # ----------------------------------------------------------- postprocess

    def postprocess(
        self,
        llm_findings: Iterable[Finding],
        filtered: FilteredDiff,
        pre_scan_findings: Optional[Iterable[Finding]] = None,
    ) -> list[Finding]:
        """Слияние + дедуп + контекстные правила + confidence-фильтр.

        НЕ модифицирует входные объекты — все правки делаются через
        `Finding.model_copy(update=...)`.
        """
        pre = list(pre_scan_findings or [])
        llm = list(llm_findings or [])

        # 1) Слияние с дедупом по (path, line, class). Pre-findings приоритетны:
        # их confidence обычно выше, и мы не хотим, чтобы LLM их "размывал".
        merged: dict[tuple[str, int, str], Finding] = {}
        for f in pre + llm:
            key = (f.file, f.line, f.class_)
            if key in merged:
                # Берём ту, у кого confidence выше
                if f.confidence > merged[key].confidence:
                    merged[key] = f
                continue
            merged[key] = f

        candidates = list(merged.values())

        kept: list[Finding] = []
        dropped: list[tuple[Finding, str]] = []

        for f in candidates:
            reason = self._evaluate(f, filtered)
            if reason is None:
                kept.append(f)
            elif reason.startswith("CAP:"):
                # Особый случай: не дропаем, понижаем severity.
                _, new_sev = reason.split(":", 1)
                kept.append(f.model_copy(update={"severity": new_sev}))
                log.debug(
                    "fp_postprocess_severity_capped",
                    extra={
                        "file": f.file,
                        "line": f.line,
                        "class": f.class_,
                        "from": f.severity,
                        "to": new_sev,
                    },
                )
            else:
                dropped.append((f, reason))
                log.debug(
                    "fp_postprocess_dropped",
                    extra={
                        "file": f.file,
                        "line": f.line,
                        "class": f.class_,
                        "reason": reason,
                    },
                )

        log.info(
            "fp_filter_applied",
            extra={
                "repo": filtered.repo,
                "pr_number": filtered.pr_number,
                "pre_llm_findings": len(pre),
                "llm_findings": len(llm),
                "merged_count": len(candidates),
                "dropped_count": len(dropped),
                "final_findings": len(kept),
                "min_confidence": self._cfg.min_confidence,
            },
        )
        return kept

    # ----- internals ---

    def _evaluate(self, f: Finding, filtered: FilteredDiff) -> Optional[str]:
        """Возвращает None (keep), reason-строку (drop) или `CAP:<severity>`.

        Порядок проверок важен: сначала кардинальные (line не в added-lines),
        потом по классу, потом confidence-cutoff.
        """
        added = _file_added_lines(filtered, f.file)

        # (1) finding должен быть на added-line. PRD: «только изменённый код».
        if not _line_in_added(f.line, added):
            return "line_not_in_added_lines"

        content = _find_added_content(f.line, added) or ""

        # (2) если строка — целиком комментарий → drop (§6 #9).
        stripped = content.lstrip()
        if stripped.startswith(("#", "//", "--", "/*", "*", '"""', "'''")):
            return "comment_only_line"

        # (3) class-specific anti-signals
        cls = f.class_
        if cls == "sql_injection":
            r = self._check_sql_injection(content, added, f.line)
            if r is not None:
                return r
        elif cls == "xss":
            r = self._check_xss(content, added, f.line)
            if r is not None:
                return r
        elif cls == "hardcoded_secret":
            r = self._check_hardcoded_secret(content, f.file)
            if r is not None:
                return r

        # (4) Confidence cutoff.
        if f.confidence < self._cfg.min_confidence:
            return f"low_confidence<{self._cfg.min_confidence}"

        return None

    def _check_sql_injection(
        self, content: str, added: list[AddedLine], line_no: int
    ) -> Optional[str]:
        # ORM в области → §6 #5
        window = _context_window(added, line_no=line_no, radius=2)
        for p in _ORM_SAFE_PATTERNS:
            if p.search(window):
                return "sql_orm_safe_pattern"
        # Параметризованный SQL → §6 #4
        for p in _PARAMETRIZED_SQL_PATTERNS:
            if p.search(window):
                return "sql_parametrized"
        # Полностью статическая SQL-строка (§6 #13)
        if _has_sql_keyword(content) and not _has_dynamic_substitution(content):
            # ещё должен быть exec-API чтобы это было хоть как-то релевантно
            if any(p.search(window) for p in _SQL_EXEC_API_PATTERNS):
                if not _has_dynamic_substitution(window):
                    return "sql_static_no_interpolation"
        return None

    def _check_xss(
        self, content: str, added: list[AddedLine], line_no: int
    ) -> Optional[str]:
        window = _context_window(added, line_no=line_no, radius=2)
        # Sanitizer на месте — drop (§5.3, §6 #6).
        for p in _XSS_SANITIZER_PATTERNS:
            if p.search(window):
                return "xss_sanitizer_present"
        # На строке нет ни одного «опасного» XSS-API — drop как ложный сигнал.
        if not any(p.search(window) for p in _XSS_DANGEROUS_PATTERNS):
            # JSX `{userInput}` без dangerouslySetInnerHTML → drop (§6 #6).
            if re.search(r"<[A-Za-z][^>]*>\s*\{[^}]+\}", window):
                return "xss_jsx_safe_mustache"
            # Mustache `{{ var }}` без `| safe` — auto-escape (§6 #14).
            if re.search(r"\{\{\s*[^}|]+?\s*\}\}", window) and "| safe" not in window:
                return "xss_template_autoescape"
            return "xss_no_dangerous_sink"
        return None

    def _check_hardcoded_secret(self, content: str, path: str) -> Optional[str]:
        stripped_content = _strip_comments_line(content)

        # env-getter → не секрет (§4.3, §6 #3)
        for p in _ENV_GETTER_PATTERNS:
            if p.search(stripped_content):
                return "secret_env_getter"

        # Извлекаем литерал
        lit_match = re.search(r"""['"]([^'"]*)['"]""", stripped_content)
        rhs_literal = lit_match.group(1) if lit_match else ""

        # Имя похоже на секрет, но значение — bool/int/None (§6 #11).
        # `\b` не работает с `_` в идентификаторах (is_secret_enabled / API_TOKEN),
        # поэтому используем substring-поиск с (?i).
        if re.search(r"(?i)(passwo?rd|secret|token|api[_-]?key|access[_-]?key|auth|bearer)", stripped_content):
            rhs_match = re.search(r"=\s*([^#;\n]+)", stripped_content)
            if rhs_match:
                rhs = rhs_match.group(1).strip().rstrip(",").rstrip(")")
                if rhs in {"True", "False", "None", "null", "true", "false", "nil"}:
                    return "secret_bool_value"
                # Чистый int/float
                if re.fullmatch(r"-?\d+(?:\.\d+)?", rhs):
                    return "secret_numeric_value"

        # Hash/salt в коде (§6 #12)
        if _looks_like_hash(rhs_literal.strip()):
            return "secret_hash_value"

        # Path в тестах / примерах:
        if _is_example_file(path, self._cfg):
            # .env.example — cap до low ИЛИ drop если placeholder
            if _looks_like_placeholder(rhs_literal):
                return "secret_placeholder_in_example"
            return "CAP:low"

        if _is_test_path(path, self._cfg):
            # тесты — dummy / низкая энтропия → drop
            if _looks_like_placeholder(rhs_literal):
                return "secret_placeholder_in_tests"
            if rhs_literal and len(rhs_literal) < 16:
                return "secret_short_value_in_tests"
            if rhs_literal and _shannon_entropy(rhs_literal) < 3.0:
                return "secret_low_entropy_in_tests"
            return "CAP:low"

        # Phantom-placeholder в любом контексте: явный мусор
        if rhs_literal and _looks_like_placeholder(rhs_literal):
            return "secret_placeholder_value"

        return None


# ---------------------------------------------------------------------------
# Helpers (module-level)
# ---------------------------------------------------------------------------


_SQL_KEYWORDS = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|GRANT|CREATE TABLE)\b",
    re.IGNORECASE,
)


def _has_sql_keyword(s: str) -> bool:
    return bool(_SQL_KEYWORDS.search(s))


_DYNAMIC_SUBST = re.compile(
    r"(?:%s|%\([a-zA-Z_]\w*\)s|\{[^}]*\}|\bf['\"]|\.format\s*\(|\+\s*['\"]|'\s*\+|\"\s*\+)"
)


def _has_dynamic_substitution(s: str) -> bool:
    return bool(_DYNAMIC_SUBST.search(s))


# ---------------------------------------------------------------------------
# DI factory
# ---------------------------------------------------------------------------


def build_fp_filter_from_settings(settings) -> FalsePositiveFilter:
    """Фабрика для DI в `app.py`. Читает поля из Settings, без env-доступа."""
    cfg = FPFilterConfig(
        min_confidence=float(getattr(settings, "fp_min_confidence", 0.5)),
        skip_llm_if_prescan_found=bool(
            getattr(settings, "fp_skip_llm_if_prescan_found", False)
        ),
    )
    return FalsePositiveFilter(config=cfg)


__all__ = [
    "FalsePositiveFilter",
    "FPFilterConfig",
    "build_fp_filter_from_settings",
]
