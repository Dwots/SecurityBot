# SunSecurityBot

**AI-ревьюер безопасности кода для GitHub Pull Request'ов.** Слушает webhook
`pull_request` / `pull_request_review_comment` / `issue_comment`, выкачивает
diff, отдаёт фильтрованный код в LLM (polza.ai / OpenRouter — DeepSeek V4
Flash / Qwen3 Coder / MiMo V2 Pro), пост-фильтрует ложные срабатывания и
публикует **inline-комментарии** на конкретные строки + **summary** в PR
conversation. Поддерживает **диалог** — отвечает на reply'и и `@mention`.

Полное ТЗ — `requirements/prd.md`. Архитектура (ADR-1..ADR-7) —
`agents/artifacts/architect/system_design.md`. Маршрут сдачи и
демо-сценарии — `demo/README.md`.

---

## Что умеет (для сдачи)

- **Поиск трёх классов уязвимостей в PR:** SQL-инъекции (f-string /
  `.format()` / `%`), hardcoded secrets (AWS / Stripe / GitHub PAT / OpenAI
  / JWT / DB connection strings), XSS (Jinja2 `|safe` / `autoescape false`
  + DOM-XSS в JS).
- **Inline-комментарии** с указанием строки, severity, CWE и предложением
  фикса; **summary-комментарий** на русском для PR-автора.
- **Reply-режим (T-019):** бот ведёт диалог — отвечает на reply на свой
  inline-комментарий и на `@<BOT_USERNAME>` в PR conversation.
- **Multi-provider LLM:** `polza.ai` (gpt-4o-mini, baseline) и
  `OpenRouter` (DeepSeek V4 Flash primary, Qwen3 Coder free, MiMo V2 Pro
  fallback) — переключается одной env-переменной `LLM_PROVIDER`. У
  каждого провайдера независимый бюджет-kill-switch.
- **FalsePositiveFilter (T-013):** pre-scan регексами (entropy + known
  prefixes) + post-filter LLM-находок по confidence-threshold.
- **Console UI (M-9):** локальная панель управления — регистрация репо
  (`/api/console/repos`), история чек-ов, бюджет, manual analyze. Под
  флагом `ENABLE_CONSOLE_UI=true`.
- **Sandbox Test UI (M-6):** одностраничник для проверки LLM-пайплайна
  без GitHub-webhook. Под флагом `ENABLE_TEST_UI=true`.
- **SQLite-персистенс (M-9, ADR-6):** история PR'ов, findings,
  опубликованных комментариев и реестр репо — durable между
  рестартами контейнера. Файл `./data/sunsec.db`.
- **Безопасность:** все секреты только в env, JSON-логгер с маской
  `token`/`secret`/`api_key`/`authorization`/`password`, HMAC-валидация
  webhook'а, `Settings.__repr__` маскирует sensitive-поля.

---

## Стек

- **Python 3.11+** (CI прогоняется на 3.11–3.14)
- **FastAPI + Uvicorn** — HTTP webhook receiver, REST API, статический UI
- **Pydantic v2** — контракты компонентов (см. `system_design.md §4`)
- **`openai` SDK** с подменённым `base_url` — единый клиент для polza.ai
  и OpenRouter
- **`aiosqlite` + raw SQL** — persistence (без ORM/Alembic, ADR-6)
- **`cachetools.TTLCache`** — in-memory idempotency / dedup
- **structlog-style JSON-логи** на stdlib + redaction-фильтр
- **vanilla HTML + Tailwind CDN + Iconify** — Console UI (без сборки)

---

## Структура каталогов

```
src/sunsec/
├── app.py                  # FastAPI application factory
├── __main__.py             # python -m sunsec → uvicorn
├── config/                 # Settings (pydantic-settings), безопасный repr
├── contracts/              # Pydantic-модели всех компонентов
├── logging_ext/            # JSON-логгер + маскирование секретов
├── webhook/                # /webhook/github + /health + HMAC + reply-режим
├── vcs/                    # VCSAdapter Protocol + GitHubAdapter (diff/comments)
├── filter/                 # DiffFilter (PRDiff → FilteredDiff, по ext/name/glob)
├── llm/                    # LLMProvider + PolzaProvider + OpenRouterProvider + Budget
├── ml/                     # FalsePositiveFilter (pre-scan + confidence post-filter)
├── comments/               # CommentPublisher (inline + summary + empty + budget)
├── storage/                # SQLite store (M-9): checks/findings/comments/repos
├── ui/                     # Test UI (M-6) + Console UI (M-9) routers + static
└── pipeline/               # PipelineOrchestrator — связующий слой webhook → publish

demo/                       # 5 сценариев для live-демо (см. demo/README.md)
presa/                      # Презентация
tests/unit                  # 19 файлов (≈216 тестов)
tests/integration           # pipeline M-2 + M-9 e2e smoke
tests/e2e                   # full pipeline + polza smoke (живой LLM)
tests/goldens               # фикстуры для регресса промпта
agents/                     # артефакты проектирования (Architect/Researcher/QA)
data/                       # SQLite + repos_secrets.env (gitignored)
```

---

## Быстрый старт — Docker (рекомендуется для сдачи)

```bash
# 1) Конфиг
cp .env.example .env
# Минимально заполнить:
#   VCS_TOKEN=ghp_...                   (GitHub PAT с repo-scope)
#   WEBHOOK_SECRET=<long-random>        (HMAC для X-Hub-Signature-256)
#   LLM_PROVIDER=openrouter             (или polza)
#   OPENROUTER_API_KEY=sk-or-v1-...     (для openrouter)
#   POLZA_API_KEY=...                   (для polza)
#   ENABLE_CONSOLE_UI=true              (открыть Console UI)
#   SUNSEC_DB_PATH=./data/sunsec.db     (durable persistence)

# 2) Сборка и запуск
docker compose up -d --build

# 3) Проверка
curl http://localhost:8000/health
# → {"status":"ok","service":"sunsec"}

# 4) Открыть Console UI
open http://localhost:8000/ui      # выбор репо / история / бюджет

docker compose logs -f sunsec      # live-логи pipeline'а
docker compose down                # остановить
```

> **Важно:** single-process, single-replica (ADR-3). `--scale sunsec=N>1`
> запрещён — состояние (бюджет, idempotency, dedup) хранится в памяти
> процесса + SQLite на volume. Healthcheck встроен в `Dockerfile`,
> multi-stage build, runtime-юзер не-root. Подробности —
> `agents/artifacts/devops/deployment.md`.

## Быстрый старт — локально (без Docker)

```bash
cp .env.example .env                # см. выше
make dev                            # установит runtime + pytest/ruff/mypy
make run                            # uvicorn на HOST:PORT из .env
curl http://localhost:8000/health
```

---

## Демо для жюри / экспертов

Пять готовых сценариев в `demo/`, каждый — отдельный PR в `remote_test_rep`:

| Сценарий              | Что покажет бот                                                | Ожидаемое              |
|-----------------------|----------------------------------------------------------------|------------------------|
| `01_sqli_login`       | 3 SQL-инъекции (f-string / `.format()` / `%`), auth-bypass     | 3× critical SQLi       |
| `02_hardcoded_keys`   | AWS / Stripe / GitHub / OpenAI / JWT / DB connection string    | 6× hardcoded_secret    |
| `03_xss_jinja2`       | Jinja2 `\|safe` и `autoescape false` на user-input             | 2× high XSS            |
| `04_clean_baseline`   | Параметризованные SQL, `os.environ`, `html.escape`             | 0 findings, рус. summary |
| `05_mixed_pr`         | Stripe live key + 2 SQLi + Sentry DSN + GitHub PAT             | ~5 findings, разные классы |

Запуск (требует поднятый бот + туннель до GitHub):

```bash
demo/scripts/new_pr.sh 01_sqli_login    # создаст бранч, PR, дождётся webhook
```

Полный сценарий показа — `demo/README.md`. Презентация — `presa/presentation.zip`.

---

## Тесты / линт / типы

```bash
make test       # pytest: 19 файлов unit + integration + e2e (~216 тестов)
make lint       # ruff check
make format     # ruff format
make typecheck  # mypy (strict mode на src/)
```

Где смотреть:
- `tests/unit/` — компонентные тесты всех модулей (config, redaction,
  webhook, vcs, filter, llm/polza, llm/openrouter, fp-filter, comments,
  sqlite_store, ui-router, console-router, reply-mode, ...).
- `tests/integration/test_m9_e2e_smoke.py` — Console UI + persistence
  end-to-end (без сети).
- `tests/e2e/run_polza_smoke.py` — живой smoke против polza.ai (требует
  `POLZA_API_KEY`).
- `tests/goldens/` — фикстуры регресса промпта (SQLi / secrets / XSS /
  clean / mixed).

---

## Console UI (M-9, control plane)

Под флагом `ENABLE_CONSOLE_UI=true` поднимается админ-панель — порт
`tmp/front.html` в `src/sunsec/ui/static/`, без сборки.

Views:
- **Dashboard** — последние чек-и, статусы, totals.
- **Checks History** — список PR'ов с findings + переход в детали.
- **Check Details** — все findings одного PR + опубликованные комментарии.
- **Settings** — runtime-конфиг (бюджеты, провайдер).
- **Budget** — текущий расход polza.ai + OpenRouter.
- **Repos** — онбординг репо: `full_name` + `vcs_token` + `webhook_secret`
  → бот начинает обрабатывать webhook'и без перезапуска. Токены пишутся
  в gitignored `data/repos_secrets.env` (durable, RT-012 fix) + в
  `os.environ` процесса.

REST API под Mock-контракт фронта:

```
GET    /api/console/dashboard       # totals + last checks
GET    /api/console/checks          # history (filter/paginate)
GET    /api/console/checks/{id}     # findings + comments
GET    /api/console/budget          # polza + openrouter
GET    /api/console/settings        # runtime config
POST   /api/console/repos           # register repo
GET    /api/console/repos           # list
DELETE /api/console/repos/{id}      # unregister
POST   /api/console/manual/analyze  # ad-hoc анализ кода
```

> **Безопасность (R-13 HIGH, system_design §11.7):** MVP не имеет
> authn. `/api/console/*` НЕ выставлять в публичную сеть без
> middleware (basic-auth / JWT / VPN). Single-user dev-режим.

## Test UI / sandbox (M-6, dev only)

Под флагом `ENABLE_TEST_UI=true` поднимается изолированная страница
для ручной проверки бота **без поднятия webhook + ngrok + реального
PR**. Закорачивает пайплайн: сырой код → `DiffFilter` (synthetic-helper)
→ `LLMClient` → `FalsePositiveFilter` → рендер findings.

```bash
ENABLE_TEST_UI=true
HOST=127.0.0.1            # ВАЖНО: bind на localhost
make run
open http://localhost:8000/ui
```

Endpoints: `GET /ui`, `POST /api/ui/analyze`, `GET /api/ui/budget`,
`GET /api/ui/examples` (4 встроенных примера: SQLi / secret / XSS / clean).

---

## Безопасность

- **Секреты только в env** (`.env` в `.gitignore`, шаблон в `.env.example`).
- **JSON-логгер** маскирует `token` / `secret` / `api_key` /
  `authorization` / `password` и в `extra`, и в exception tracebacks
  (`src/sunsec/logging_ext/redaction.py`).
- **HMAC-валидация webhook'а** — `X-Hub-Signature-256`, constant-time
  compare, отбой при ошибке.
- **Бюджет-kill-switch:** `POLZA_BUDGET_LIMIT_RUB` (default 80 ₽) и
  `OPENROUTER_BUDGET_LIMIT_RUB` (default 50 ₽) — независимые корзины.
  При превышении `BudgetExceeded` → бот не зовёт LLM и публикует
  «бюджет исчерпан» в PR.
- **Anti-loop reply-режима:** self-filter по `BOT_USERNAME` — бот не
  отвечает на свои же комментарии.
- **`Settings.__repr__`** маскирует sensitive-поля — безопасно
  логировать конфиг целиком.
- **Docker:** runtime-юзер не-root, healthcheck, multi-stage build.

---

## Лицензия / контакты

Проект разработан для хакатона в составе Черемша.
