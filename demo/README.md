# SunSecurityBot — демо для хакатона

Папка содержит готовые сценарии для live-демонстрации работы бота
перед экспертами. Файлы лежат отдельно от тестового репо и копируются
в `remote_test_rep` только в момент создания PR.

## Сценарии

| Папка                          | Что покажет бот                                                                          | Ожидаемое              |
|--------------------------------|-------------------------------------------------------------------------------------------|------------------------|
| `01_sqli_login`                | SQL-инъекции через f-string / `.format()` / `%` (3 SQLi в одном файле, auth-bypass)       | 3× critical SQLi       |
| `02_hardcoded_keys`            | AWS / Stripe / GitHub / OpenAI / multi-line JWT / DB connection string с паролем          | 6× hardcoded_secret    |
| `03_xss_jinja2`                | Jinja2 `\|safe` и `{% autoescape false %}` на user-input + negative example в footer       | 2× high XSS            |
| `04_clean_baseline`            | Параметризованные SQL, `os.environ`, `html.escape` — чистый PR                            | 0 findings, русская сводка |
| `05_mixed_pr`                  | Смесь: Stripe live key + 2 SQLi + Sentry DSN с паролем + GitHub PAT (в двух файлах PR)     | ~5 findings, разные классы |

## Как запустить (вручную)

```bash
cd /home/artwox/orchestrAI/XackatonChaos/SunSecurityBot
demo/scripts/new_pr.sh 01_sqli_login
```

Скрипт сам:
1. Сделает новый бранч `demo/<сценарий>-<timestamp>` от `origin/main`.
2. Скопирует файлы сценария в `remote_test_rep`.
3. Закоммитит и запушит.
4. Откроет PR через GitHub REST API.
5. Через 5–10 секунд бот получит `pull_request opened` webhook и
   опубликует inline-комментарии + summary.

## Как мне (Claude) запустить по команде

Скажите одну из фраз:
- **«PR 1»** или **«SQLi»** → `01_sqli_login`
- **«PR 2»** или **«секреты»** → `02_hardcoded_keys`
- **«PR 3»** или **«XSS»** → `03_xss_jinja2`
- **«PR 4»** или **«clean»** → `04_clean_baseline`
- **«PR 5»** или **«mixed»** → `05_mixed_pr`
- **«всё подряд»** → запущу все 5 PR с паузой 30 с

Я подтвержу созданный PR URL, дождусь `pipeline_completed` в логе и
скажу, что бот опубликовал. Все ваши и friend's reply'и в PR ловит
работающий монитор — я вижу события в реальном времени.

## Если что-то пошло не так

- **PR создался, но бот молчит** → туннель умер. Проверьте:
  ```bash
  curl https://9ab4c15b8f932d.lhr.life/health
  ```
  Если 503 — поднимите туннель заново (см. `help.md §3`) и
  **Reinstall Webhook** через `http://localhost:8000/ui`.
- **«Webhook → 401»** → `WEBHOOK_SECRET` в `.env` не совпадает с
  тем, что в GitHub-настройках hook'а. Реинсталл через UI лечит.
- **«PR creation failed: 403»** → у токена нет `repo` scope.
