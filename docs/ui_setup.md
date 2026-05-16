# Настройка UI-конфига

В SunSecurityBot два независимых UI, оба выключены по умолчанию и включаются
отдельными env-флагами. Конфиг читается из `.env` через `Settings.from_env`
(`src/sunsec/config/settings.py`).

| UI            | Флаг                 | Endpoints                       | Назначение                              |
|---------------|----------------------|---------------------------------|-----------------------------------------|
| Test UI       | `ENABLE_TEST_UI`     | `GET /ui`, `/api/ui/*`          | Dev-sandbox для ручного прогона LLM     |
| Console UI    | `ENABLE_CONSOLE_UI`  | `/api/console/*` + расширенный `/ui` | Control plane (history / budget / repos) |

Оба UI **нельзя выставлять в публичную сеть без auth** (system_design v1.2.1
§11.7 R-13). В dev — `HOST=127.0.0.1`.

---

## 1. Подготовка `.env`

```bash
cd SunSecurityBot
cp .env.example .env
```

Минимум, который должен быть заполнен для работы UI:

```dotenv
HOST=127.0.0.1            # обязательно для dev — не светить наружу
PORT=8000

# LLM (без ключа Test UI работает, но видны только pre-scan findings)
LLM_PROVIDER=polza
POLZA_API_KEY=<your-polza-key>
POLZA_BUDGET_LIMIT_RUB=80
```

---

## 2. Test UI (M-6, T-023)

Изолированный sandbox: «сырой код → synthetic FilteredDiff → LLM (polza.ai)
→ FalsePositiveFilter → findings».

### Включение

```dotenv
ENABLE_TEST_UI=true
HOST=127.0.0.1
POLZA_API_KEY=<your-polza-key>
```

### Запуск и проверка

```bash
make run
# открыть в браузере
xdg-open http://localhost:8000/ui
```

Endpoints:
- `GET /ui` — одностраничный HTML (vanilla JS, без сборки).
- `POST /api/ui/analyze` — анализ кода (pre-scan + LLM + FP-postprocess).
- `GET  /api/ui/budget` — текущий бюджет polza.ai (ключ не уходит на фронт).
- `GET  /api/ui/examples` — 4 встроенных примера (SQLi / secret / XSS / clean).

Лимиты в `src/sunsec/ui/router.py`: суммарный размер `code` ≤ 50 KB → 413,
до 50 файлов в запросе.

---

## 3. Console UI (M-9, T-039 / T-040)

Control plane бота: история ревью, бюджеты обоих провайдеров, настройки,
управление подключёнными репозиториями, ручной запуск анализа.

### Включение

```dotenv
ENABLE_CONSOLE_UI=true
HOST=127.0.0.1
SUNSEC_DB_PATH=./data/sunsec.db   # SQLite для durable layer (ADR-6)
```

Если `SUNSEC_DB_PATH` пустой или `:memory:` — используется `InMemoryStateStore`
(история не переживает рестарт).

### Запуск

```bash
make run
xdg-open http://localhost:8000/ui
```

Endpoints (`/api/console/*`): `budget`, `settings`, `checks[*]`, `repos[*]`,
`manual/analyze`, `dashboard`.

### Секреты репозиториев

Токены, регистрируемые через `POST /api/console/repos`, сохраняются в
gitignored `data/repos_secrets.env` (RT-012). На startup `app.py` подгружает
файл через `load_dotenv("data/repos_secrets.env", override=False)` **до**
инициализации Settings. В production держать `data/` на persistent volume.

---

## 4. Совместное использование

Флаги независимы — можно включить оба одновременно:

```dotenv
ENABLE_TEST_UI=true
ENABLE_CONSOLE_UI=true
```

`/ui` тогда отдаёт расширенный HTML Console UI, а `/api/ui/*` остаются
доступны для sandbox-сценария.

---

## 5. Production-чеклист

Перед выкаткой UI в любую сеть, кроме `127.0.0.1`:

- [ ] Поднят reverse proxy с auth (basic-auth / JWT / VPN).
- [ ] `WEBHOOK_SECRET`, `VCS_TOKEN`, `POLZA_API_KEY` / `OPENROUTER_API_KEY` —
      из секрет-стора, не из `.env` в образе.
- [ ] `SUNSEC_DB_PATH` указывает на persistent volume.
- [ ] Бюджетные лимиты выставлены: `POLZA_BUDGET_LIMIT_RUB`,
      `OPENROUTER_BUDGET_LIMIT_RUB`.
- [ ] `PUBLISH_COMMENTS_ENABLED=true` — только если бот действительно должен
      постить в GitHub.

---

## 6. Troubleshooting

| Симптом                                | Проверить                                                        |
|----------------------------------------|------------------------------------------------------------------|
| `GET /ui` → 404                        | `ENABLE_TEST_UI` / `ENABLE_CONSOLE_UI` не выставлены в `true`    |
| `/api/ui/analyze` → `llm.status=budget_exceeded` | `POLZA_BUDGET_LIMIT_RUB` исчерпан — поднять или сбросить counter |
| `/api/ui/analyze` → `llm.status=unavailable`     | `POLZA_API_KEY` пустой/невалидный                                |
| История в `/api/console/*` теряется после рестарта | `SUNSEC_DB_PATH` не задан или равен `:memory:`                   |
| UI открывается с другой машины         | `HOST=0.0.0.0` — выставить `127.0.0.1` или закрыть фаерволом     |

Источники: `src/sunsec/config/settings.py`, `.env.example`, `README.md`
(раздел «Test UI»), `tmp/archive/gui_plan.md`.
