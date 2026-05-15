# SunSecurityBot

ИИ-ревьюер кода (DevSecOps) для PR/MR. Принимает webhook GitHub, выкачивает diff,
отправляет в LLM (polza.ai) для поиска уязвимостей (SQLi / hardcoded secrets / XSS),
публикует inline-комментарии и summary в исходном PR.

Полное ТЗ — `requirements/prd.md`. Архитектура — `agents/artifacts/architect/system_design.md`.

## Стек

- Python 3.11+ (тестируется на 3.11–3.14)
- FastAPI + Uvicorn (HTTP webhook receiver)
- Pydantic v2 (контракты компонентов)
- `openai` SDK с подменённым `base_url` (polza.ai)
- structlog-style JSON-логи на stdlib (sensitive-маска)
- in-memory state store (`cachetools.TTLCache`); SQLite — post-MVP

## Структура каталогов

```
src/sunsec/
├── __init__.py
├── __main__.py             # python -m sunsec
├── app.py                  # FastAPI application factory
├── config/                 # Settings, env-loader, безопасный repr
├── contracts/              # Pydantic-модели всех компонентов (system_design §4)
├── logging_ext/            # JSON-логгер + маскирование секретов
├── webhook/                # FastAPI router /webhook/github + /health
├── vcs/                    # VCSAdapter Protocol + GitHubAdapter
├── filter/                 # DiffFilter (PRDiff → FilteredDiff)
├── llm/                    # LLMProvider Protocol + LLMClient + BudgetCounter
├── comments/               # CommentPublisher Protocol (publish / empty / budget)
├── state/                  # StateStore Protocol + InMemoryStateStore
└── pipeline/               # PipelineOrchestrator (связующий слой)

tests/unit/                 # pytest-набор для T-006 (конфиг + redaction)
scripts/run.sh              # Альтернатива `make run`
.env.example                # Пример конфига (реальный .env — в .gitignore)
Makefile                    # make install / run / test / lint / typecheck
pyproject.toml              # Зависимости + ruff/mypy/pytest-конфиги
requirements.txt            # Runtime-зависимости
requirements-dev.txt        # + dev
```

## Запуск локально

1) Клонировать репозиторий, создать `.env`:
   ```bash
   cp .env.example .env
   # отредактировать: VCS_TOKEN, WEBHOOK_SECRET, POLZA_API_KEY
   ```
2) Установить зависимости:
   ```bash
   make install        # runtime
   make dev            # runtime + dev (pytest, ruff, mypy)
   ```
3) Запустить сервис:
   ```bash
   make run            # uvicorn на HOST:PORT из .env (default 0.0.0.0:8000)
   # или: ./scripts/run.sh
   ```
4) Проверить:
   ```bash
   curl http://localhost:8000/health
   # {"status": "ok", "service": "sunsec"}
   ```

## Тесты / линт / типы

```bash
make test       # pytest (юнит-тесты конфига и редакции логов)
make lint       # ruff check
make format     # ruff format
make typecheck  # mypy
```

## Docker

Контейнеризованная сборка (T-020). Single-process, single-replica (ADR-3, in-memory state).

```bash
# 1) Конфиг
cp .env.example .env   # заполнить VCS_TOKEN / WEBHOOK_SECRET / POLZA_API_KEY

# 2) Сборка и запуск
docker compose up -d --build

# 3) Проверка
curl http://localhost:8000/health
# → {"status":"ok","service":"sunsec"}

docker compose logs -f sunsec      # tail логов
docker compose ps                  # статус (ожидается `running (healthy)`)
docker compose down                # остановить
```

Подробности (multi-stage build, healthcheck, troubleshooting, ngrok-каркас для
webhook-проверки, единственная-реплика constraint) — `agents/artifacts/devops/deployment.md`.

**Важно:** `--scale sunsec=N` (`N > 1`) запрещён — состояние (бюджет polza.ai,
idempotency, dedup) живёт в памяти процесса. См. ADR-3.

## Test UI (dev only)

Под флагом `ENABLE_TEST_UI=true` поднимается изолированная страница для
ручной проверки бота без поднятия GitHub-webhook + ngrok + реального PR.
Закорачивает пайплайн на самом ценном участке: сырой код → `DiffFilter`
(точнее — synthetic-helper, см. `tmp/gui_plan.md §4`) → `LLMClient`
(polza.ai) → `FalsePositiveFilter` → рендер findings.

```bash
# 1) В .env
ENABLE_TEST_UI=true
HOST=127.0.0.1            # ВАЖНО: bind на localhost, не открывать наружу
POLZA_API_KEY=<твой-ключ> # без него UI работает, но видны только pre-scan findings

# 2) Запуск
make run

# 3) В браузере
open http://localhost:8000/ui
```

Что внутри:

- `GET /ui` — одностраничный HTML (фронт T-024 — vanilla JS, без сборки).
- `POST /api/ui/analyze` — анализ кода: pre-scan + polza.ai + FP-postprocess.
- `GET /api/ui/budget` — текущий бюджет polza.ai (server-side, ключ не уходит на фронт).
- `GET /api/ui/examples` — 4 встроенных примера (SQLi / hardcoded secret / XSS / clean).

**Защита:** по умолчанию `ENABLE_TEST_UI=false`. В prod НЕ включать — UI
даёт прямой доступ к polza.ai без HMAC-проверки GitHub-webhook. Bind на
`127.0.0.1` обязателен в dev (иначе UI станет открытым endpoint'ом
в локальной сети).

## Безопасность

- Все секреты — через env (`.env` в `.gitignore`). См. `.env.example`.
- Логгер маскирует поля `token` / `secret` / `api_key` / `authorization` / `password` —
  и в `extra`, и в exception tracebacks. См. `src/sunsec/logging_ext/redaction.py`.
- Бюджет polza.ai контролируется `POLZA_BUDGET_LIMIT_RUB` (default 80 ₽).
  Kill-switch — `BudgetExceeded` в `LLMClient` (полностью включится в T-012).
- `Settings.__repr__` маскирует sensitive-поля — безопасно логировать конфиг целиком.

## Статус задач

Этот каркас — задача T-006 milestone M-2. Дальнейшие задачи:
- T-007 — webhook endpoint + HMAC-валидация
- T-008 — GitHub diff fetch
- T-009 — DiffFilter (полная фильтрация)
- T-011 / T-012 — ML-слой (промпт + polza.ai client)
- T-016 / T-017 — публикация inline + summary комментариев

Источник истины по задачам — `agents/project_info/tracking_table.md`.
