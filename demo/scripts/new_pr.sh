#!/usr/bin/env bash
# Создаёт демо-PR в `remote_test_rep` из сценария demo/scenarios/<name>.
# Использование (изнутри SunSecurityBot/):
#   demo/scripts/new_pr.sh 01_sqli_login
#   demo/scripts/new_pr.sh 02_hardcoded_keys
#   demo/scripts/new_pr.sh 03_xss_jinja2
#   demo/scripts/new_pr.sh 04_clean_baseline
#   demo/scripts/new_pr.sh 05_mixed_pr
#
# Использует только git + curl (без gh CLI). VCS_TOKEN берётся из .env
# SunSecurityBot/.env по дефолту, можно переопределить env VCS_TOKEN=...
set -euo pipefail

SCENARIO="${1:-}"
if [ -z "$SCENARIO" ]; then
  echo "Usage: $0 <scenario>"
  echo "Доступные:"
  ls "$(dirname "$0")/../scenarios"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO_DIR="$SCRIPT_DIR/../scenarios/$SCENARIO"
REPO_DIR="${TEST_REPO_DIR:-/home/artwox/orchestrAI/XackatonChaos/remote_test_rep}"
SUNSEC_DIR="${SUNSEC_DIR:-/home/artwox/orchestrAI/XackatonChaos/SunSecurityBot}"
REPO_SLUG="${REPO_SLUG:-DTYUI1/remote_test_rep}"

[ -d "$SCENARIO_DIR" ] || { echo "Сценарий не найден: $SCENARIO_DIR" >&2; exit 1; }
[ -d "$REPO_DIR" ]     || { echo "Тестового репо нет: $REPO_DIR" >&2; exit 1; }

# Подтянуть VCS_TOKEN из .env, если не задан в окружении.
if [ -z "${VCS_TOKEN:-}" ] && [ -f "$SUNSEC_DIR/.env" ]; then
  VCS_TOKEN="$(grep -E '^VCS_TOKEN=' "$SUNSEC_DIR/.env" | head -1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
fi
[ -n "${VCS_TOKEN:-}" ] || { echo "VCS_TOKEN не найден" >&2; exit 1; }

BRANCH="demo/${SCENARIO}-$(date +%s)"
TITLE="demo: $SCENARIO"
BODY="Live demo PR for SunSecurityBot. Scenario: \`$SCENARIO\`. Branch: \`$BRANCH\`."

cd "$REPO_DIR"
git fetch origin main >/dev/null 2>&1
git checkout -B "$BRANCH" origin/main >/dev/null 2>&1
rsync -a "$SCENARIO_DIR/" ./
git add -A
git commit -m "$TITLE" >/dev/null
git push -u origin "$BRANCH" >/dev/null 2>&1

# Создаём PR через GitHub REST API.
RESP=$(curl -sS -X POST "https://api.github.com/repos/$REPO_SLUG/pulls" \
  -H "Authorization: Bearer $VCS_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  -d "$(python3 -c "import json,sys; print(json.dumps({'title':'$TITLE','head':'$BRANCH','base':'main','body':'$BODY'}))")")

PR_URL=$(printf '%s' "$RESP" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('html_url',''))")
PR_NUM=$(printf '%s' "$RESP" | python3 -c "import json,sys;d=json.load(sys.stdin);print(d.get('number',''))")

if [ -z "$PR_URL" ]; then
  echo "PR creation failed. Response:" >&2
  printf '%s\n' "$RESP" >&2
  exit 1
fi

echo "PR #$PR_NUM создан: $PR_URL"
echo "Бранч: $BRANCH"
