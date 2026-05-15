# SunSecurityBot — production Dockerfile (T-020).
#
# Multi-stage build:
#   1) `builder` — устанавливает runtime-зависимости в /root/.local (--user).
#   2) `runtime` — копирует только установленные пакеты и исходники,
#      запускается под non-root юзером `sunsec`.
#
# Источники истины:
#   - agents/artifacts/architect/system_design.md ADR-3 (single-process, in-memory state)
#   - agents/artifacts/planner/ml_instructions_polza.md §4 (запреты: ключ в логи / .env в образ)
#
# Целевой размер итогового образа: < 500 MB.
# Оценка: python:3.11-slim (~125 MB) + site-packages (~150 MB)
#         + sources (~2 MB) ≈ 280 MB.

# ─── Stage 1: builder ─────────────────────────────────────────────────────────
FROM python:3.11.10-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# requirements.txt отдельным слоем — лучше кэшируется, чем COPY всего репо.
COPY requirements.txt ./

# `--user` ставит в /root/.local — переносится в runtime stage без системного pip.
RUN pip install --user --no-cache-dir -r requirements.txt

# ─── Stage 2: runtime ────────────────────────────────────────────────────────
FROM python:3.11.10-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/src \
    PATH=/home/sunsec/.local/bin:$PATH \
    APP_ENV=prod \
    HOST=0.0.0.0 \
    PORT=8000

# Не ставим curl/wget — healthcheck использует Python stdlib (см. HEALTHCHECK).
# Создаём non-root юзера (UID/GID 10001 — за пределами привычных system-ids).
RUN groupadd --system --gid 10001 sunsec \
 && useradd  --system --uid 10001 --gid sunsec --create-home --shell /bin/bash sunsec

WORKDIR /app

# Перенос установленных пакетов из builder в HOME юзера sunsec.
# chown — чтобы не оставлять /home/sunsec/.local от root'а.
COPY --from=builder --chown=sunsec:sunsec /root/.local /home/sunsec/.local

# Исходники приложения.
COPY --chown=sunsec:sunsec src/ /app/src/

USER sunsec

EXPOSE 8000

# Healthcheck без curl: используем urllib из stdlib.
# interval=30s/timeout=5s/retries=3 — повторяет docker-compose, чтобы образ
# был самодостаточен (compose-конфиг переопределяет, но образ работает и без него).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)" \
    || exit 1

# Запуск через __main__.py: модуль читает HOST/PORT из Settings (.env / env) и
# поднимает uvicorn. Это полностью совпадает с `make run` и упрощает поведение
# в dev/prod (одна точка входа, одна конфигурация).
CMD ["python", "-m", "sunsec"]
