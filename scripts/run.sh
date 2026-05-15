#!/usr/bin/env bash
# Альтернатива `make run`: запускает сервис из текущего venv.
set -euo pipefail

cd "$(dirname "$0")/.."

# Подгружаем .env, если есть (через `set -a` чтобы переменные ушли в окружение).
if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

exec python -m sunsec
