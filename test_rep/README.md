# test_rep — demo-репо для live e2e SunSecurityBot

## 1. Что это

Это **мини-проект на Python+FastAPI**, в который **намеренно встроены
синтетические уязвимости** для проверки боевого пайплайна
SunSecurityBot (PR webhook → GitHub Adapter → diff-filter → pre-scan →
LLM (polza.ai) → FP-filter → inline-комментарии на PR).

Сценарий использования:

1. Скопируй содержимое `test_rep/` в **отдельный публичный
   GitHub-репозиторий** (например `sunsec-demo-target`).
2. Подключи webhook этого репо к локальному SunSecurityBot
   (см. `agents/artifacts/devops/test_rep_setup.md`).
3. Создавай PR'ы, меняющие отдельные файлы (см. §3 «Ожидаемый ответ»).
4. Проверь, что бот публикует inline-комментарии в соответствии с §3.

> **Это НЕ продакшен-код.** Не запускай его как реальный сервис.
> Уязвимости намеренные, секреты — синтетические (см. §5).

## 2. Маппинг файлов на классы уязвимостей

Источник классов — `agents/artifacts/researcher/vuln_taxonomy.md`.
Номера строк актуальны на момент создания файлов (могут сдвинуться
при последующих редактах — пересмотри перед e2e-прогоном).

| Файл                              | Строка | Class               | Severity | Description                                                                                                                  | Каналом ловится |
|-----------------------------------|--------|---------------------|----------|------------------------------------------------------------------------------------------------------------------------------|-----------------|
| `app/views.py`                    | 33     | `sql_injection`     | high     | f-string SQL `SELECT … WHERE name LIKE '%{q}%'` в `/search` (user-input через `Query`)                                       | LLM             |
| `app/views.py`                    | 53–54  | `sql_injection`     | critical | `.format()` SQL в `/login` (auth-bypass через `' OR '1'='1`)                                                                 | LLM             |
| `config/secrets.py`               | 16     | `hardcoded_secret`  | critical | Hardcoded AWS access key id (`AKIA…`, 20 chars) — ловится pre-scan regex `aws_access_key_id`                                 | pre-scan        |
| `config/secrets.py`               | 17     | `hardcoded_secret`  | medium*  | AWS secret access key (40 base64-chars) — entropy heuristic (`length≥24`, `entropy≥4.0`); LLM в постпроцессе апгрейдит до critical | pre-scan + LLM  |
| `config/secrets.py`               | 22     | `hardcoded_secret`  | critical | Hardcoded GitHub PAT (`ghp_…`, 40 chars) — ловится pre-scan regex `github_pat`                                               | pre-scan        |
| `config/secrets.py`               | 26     | `hardcoded_secret`  | critical | Hardcoded Stripe live key (`sk_live_…`, 32 chars) — ловится pre-scan regex `stripe_secret`                                   | pre-scan        |
| `config/secrets.py`               | 30–32  | `hardcoded_secret`  | critical | JWT-токен сервисного аккаунта (HS256). Multi-line — pre-scan regex не ловит, видит LLM по имени `SERVICE_JWT` + `eyJ…`-структуре | LLM             |
| `app/templates/profile.html`      | 17     | `xss`               | high     | Jinja2 `{{ user.bio \| safe }}` отключает auto-escape для user-input — stored XSS                                            | LLM             |

> `*` — entropy-heuristic ставит severity=medium для L17; LLM (после
> постпроцесса) обычно повышает до critical (это второй ключ к AWS-аккаунту).

**Итого:** 8 vuln-точек в **3 классах** уязвимостей (sql_injection ×2,
hardcoded_secret ×5, xss ×1). Покрывает все три обязательных класса
из PRD «Критерии оценки» #3 + соответствует DoD T-028 «≥3 уязвимости
разных классов» с запасом.

### Clean-baseline файлы (НЕ должны порождать findings)

| Файл                  | Почему clean                                                                                  |
|-----------------------|-----------------------------------------------------------------------------------------------|
| `app/main.py`         | FastAPI bootstrap, без SQL / user-input / секретов                                            |
| `app/db.py`           | Все SQL-запросы — параметризованы через `?`-плейсхолдеры sqlite3                              |
| `config/settings.py`  | Все секреты читаются из `os.environ.get` (env-getter, vuln_taxonomy §6 #3 anti-signal)        |

## 3. Ожидаемый ответ SunSecurityBot

При прогоне **полного PR** (все 8 файлов test_rep) бот должен:

**Inline-комментарии (≥1 на каждую уязвимость):**

- `app/views.py:33` — 1 × `sql_injection` / **high** (LLM): «SQL-запрос
  собран через f-string с user-input `q` — возможна SQL-инъекция.»
- `app/views.py:53` — 1 × `sql_injection` / **critical** (LLM):
  «Auth-роут /login строит SQL через `.format()` — возможен auth bypass.»
- `config/secrets.py:16` — 1 × `hardcoded_secret` / **critical**
  (pre-scan, `aws_access_key_id`).
- `config/secrets.py:17` — 1 × `hardcoded_secret` / **medium** (pre-scan
  entropy) ИЛИ **critical** (LLM, AWS secret pair с L16).
- `config/secrets.py:22` — 1 × `hardcoded_secret` / **critical**
  (pre-scan, `github_pat`).
- `config/secrets.py:26` — 1 × `hardcoded_secret` / **critical**
  (pre-scan, `stripe_secret`).
- `config/secrets.py:30` — 1 × `hardcoded_secret` / **critical** (LLM,
  multi-line JWT, ловится по `eyJ…` структуре).
- `app/templates/profile.html:17` — 1 × `xss` / **high** (LLM,
  Jinja2 `| safe`).

**Summary-комментарий (issue-level) с маркером
`<!-- sunsec:bot:v1:summary -->`:** агрегированная severity-таблица
(критических: ≥4, high: ≥2, medium: 0..1, low: 0, info: 0).

**Clean-файлы — 0 inline-комментариев:**

- `app/main.py` — 0 findings
- `app/db.py` — 0 findings (контрольный пример параметризованного SQL)
- `config/settings.py` — 0 findings (env-getter паттерн)
- `requirements.txt`, `README.md` — обычно отфильтровываются по
  расширению / language-detect (T-009 filtered_diff).

**Granular PR'ы (рекомендованный сценарий e2e):** делать N узких PR'ов,
по 1–2 файла каждый — так точнее видно поведение бота:

1. PR-1 (sqli): `app/views.py` only → ожидание 2 inline (L33, L53).
2. PR-2 (secret): `config/secrets.py` only → ожидание 5 inline (L16, L17, L22, L26, L29).
3. PR-3 (xss): `app/templates/profile.html` only → ожидание 1 inline (L18).
4. PR-4 (clean): `app/db.py` + `config/settings.py` only → ожидание
   summary «no findings» / 0 inline.

## 4. Чем `test_rep/` отличается от `tests/e2e/fixtures/pr_*`

| Параметр                  | `tests/e2e/fixtures/pr_*`             | `test_rep/` (этот репо)               |
|---------------------------|---------------------------------------|---------------------------------------|
| LLM                       | mock (детерминированный stub)         | реальный polza.ai (gpt-4o-mini)       |
| Локация                   | внутри проекта SunSecurityBot         | внешний GitHub-репо (пользователь публикует) |
| GitHub Adapter            | mock через `respx`                    | боевой GitHub REST API через PAT      |
| Webhook                   | синтетический payload в pytest        | реальный webhook от GitHub → ngrok    |
| Расход бюджета polza.ai   | 0 ₽                                   | ~0.05 ₽/PR × 4 PR ≈ 0.2 ₽             |
| Назначение                | unit-стабильность пайплайна           | финальный live-acceptance (T-029)     |

## 5. Дисклеймер про секреты

Все «уязвимые» значения в `config/secrets.py` — **синтетические**:

- `AWS_ACCESS_KEY_ID = "AKIA4OIUTCX4SHV81WG1"` — случайно сгенерирован,
  не существует в реальном AWS-аккаунте.
- `AWS_SECRET_ACCESS_KEY` — random base64 (40 chars), не соответствует
  ни одному live access key.
- `GITHUB_PERSONAL_ACCESS_TOKEN = "ghp_…"` — random base62 (36 chars),
  не выпускался GitHub'ом.
- `STRIPE_SECRET_KEY = "sk_live_…"` — random base62 (24 chars),
  не зарегистрирован в Stripe.
- `SERVICE_JWT` — HS256 header/payload base64-url, signature random
  base62; не подписан настоящим секретом, ни один сервис его не
  валидирует.

**Безопасно для публичного репо.** Риск только в том, что кто-то
увидит эти значения и попробует их использовать — что не сработает
ни в одном live-сервисе. **НЕ используй их в реальных приложениях** —
если случайно подставишь, любой запрос вернёт `Unauthorized`.

> Дополнительно: значения НЕ содержат подстрок-маркеров
> (`example`, `fake`, `dummy`, `sample`, `changeme`, `your_`,
> `replace`, `placeholder`, `redacted`, `xxx`, …) — это критично для
> корректного срабатывания FP-фильтра SunSecurityBot (см.
> `agents/artifacts/qa/T-025_report.md §6 RT-010 follow-up`).
