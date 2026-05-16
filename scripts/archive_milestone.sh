#!/usr/bin/env bash
# archive_milestone.sh — переносит закрытый milestone из tracking_table.md в tracking_table_archive.md.
#
# Что переносится:
#   - Все строки таблицы `## Tasks` для T-XXX, у которых milestone = <M-N>
#   - Соответствующие DoD-блоки `### T-XXX: ...` целиком (от заголовка до следующего `### T-` или `## `)
#
# Что НЕ трогается:
#   - `## Milestones` overview (короткая таблица, остаётся)
#   - Шапка с «Последнее обновление» (это Planner'а ответственность)
#   - decisions_log.md / planning_notes.md (другие файлы)
#
# Безопасность:
#   - Идемпотентность: повторный запуск на пустом M-N даёт «ничего не перенесено»
#   - Атомарность: tracking_table.md заменяется через временный файл + mv
#   - --dry-run: только показывает, что было бы перенесено
#
# Usage:
#   scripts/archive_milestone.sh M-N [--dry-run]
#
# Examples:
#   scripts/archive_milestone.sh M-7
#   scripts/archive_milestone.sh M-7 --dry-run

set -euo pipefail

MILESTONE="${1:-}"
MODE="${2:-}"

if [[ -z "$MILESTONE" || ! "$MILESTONE" =~ ^M-[0-9]+$ ]]; then
  cat <<'USAGE' >&2
Usage: scripts/archive_milestone.sh M-N [--dry-run]
Example: scripts/archive_milestone.sh M-7
USAGE
  exit 2
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TT="$PROJECT_ROOT/agents/project_info/tracking_table.md"
TTA="$PROJECT_ROOT/agents/project_info/tracking_table_archive.md"
DATE="$(date +%Y-%m-%d)"

if [[ ! -f "$TT" ]]; then
  echo "error: $TT not found" >&2
  exit 1
fi
if [[ ! -f "$TTA" ]]; then
  echo "error: $TTA not found — сначала сделай первичную архивацию вручную" >&2
  exit 1
fi

# 1. Найти T-XXX, принадлежащие закрытому milestone (по столбцу Milestone в Tasks-таблице)
TASK_IDS=$(awk -v m="$MILESTONE" '
  /^\| T-[0-9]+ +\|/ {
    n = split($0, cols, "|")
    if (n < 4) next
    tid = cols[2]; mid = cols[3]
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", tid)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", mid)
    if (mid == m) print tid
  }
' "$TT")

if [[ -z "$TASK_IDS" ]]; then
  echo "Ничего не найдено для $MILESTONE в Tasks-таблице $TT."
  echo "Возможно, уже архивирован. Проверь $TTA."
  exit 0
fi

TASK_COUNT=$(printf '%s\n' "$TASK_IDS" | wc -l | tr -d ' ')
echo "Найдено в $MILESTONE: $TASK_COUNT задач"
printf '%s\n' "$TASK_IDS" | sed 's/^/  /'

if [[ "$MODE" == "--dry-run" ]]; then
  echo ""
  echo "(--dry-run: ничего не пишу)"
  exit 0
fi

# 2. Собрать набор ID для awk (в виде пар key=1 в associative array)
IDS_FOR_AWK=$(printf '%s\n' "$TASK_IDS" | tr '\n' ',' | sed 's/,$//')

# 3. Извлечь Tasks-строки и DoD-блоки в архив
TMP_ARCH_APPEND="$(mktemp)"
TMP_NEW_TT="$(mktemp)"
trap 'rm -f "$TMP_ARCH_APPEND" "$TMP_NEW_TT"' EXIT

# 3a. Архивный блок (заголовок + строки таблицы + DoD)
{
  echo ""
  echo "---"
  echo ""
  echo "## Закрыт $DATE: $MILESTONE"
  echo ""
  echo "Перенесено задач: $TASK_COUNT  ($(printf '%s' "$TASK_IDS" | tr '\n' ' '))"
  echo ""
  echo "### Tasks-строки"
  echo ""

  # Заголовок Tasks-таблицы из tracking_table.md (первая строка `| ID ...` и сразу за ней `|--`)
  awk '
    /^\| ID +\| Milestone/ && !seen { print; getline sep; print sep; seen=1; exit }
  ' "$TT"

  # Сами T-строки для нашего milestone — в порядке появления в файле
  awk -v m="$MILESTONE" '
    /^\| T-[0-9]+ +\|/ {
      n = split($0, cols, "|")
      if (n < 4) next
      mid = cols[3]
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", mid)
      if (mid == m) print
    }
  ' "$TT"

  echo ""
  echo "### Definition of Done"
  echo ""

  # DoD-блоки: захватываем от `### T-XXX:` (если T-XXX в наборе) до следующего `### T-NNN:` или `## `
  awk -v ids_str="$IDS_FOR_AWK" '
    BEGIN {
      n = split(ids_str, arr, ",")
      for (i = 1; i <= n; i++) id_set[arr[i]] = 1
      capture = 0
    }
    /^### T-[0-9]+:/ {
      match($0, /T-[0-9]+/)
      cur = substr($0, RSTART, RLENGTH)
      capture = (cur in id_set) ? 1 : 0
    }
    /^## / { capture = 0 }
    capture { print }
  ' "$TT"
} > "$TMP_ARCH_APPEND"

# 3b. Новый tracking_table.md — без Tasks-строк и DoD-блоков для закрытого milestone
awk -v ids_str="$IDS_FOR_AWK" -v m="$MILESTONE" '
  BEGIN {
    n = split(ids_str, arr, ",")
    for (i = 1; i <= n; i++) id_set[arr[i]] = 1
    skip_dod = 0
  }
  # Пропуск Tasks-строк закрытого milestone
  /^\| T-[0-9]+ +\|/ {
    cn = split($0, cols, "|")
    if (cn >= 4) {
      tid = cols[2]; mid = cols[3]
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", tid)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", mid)
      if (mid == m) next
    }
  }
  # Пропуск DoD-блоков закрытых задач (по T-ID)
  /^### T-[0-9]+:/ {
    match($0, /T-[0-9]+/)
    cur = substr($0, RSTART, RLENGTH)
    skip_dod = (cur in id_set) ? 1 : 0
  }
  /^## / { skip_dod = 0 }
  !skip_dod { print }
' "$TT" > "$TMP_NEW_TT"

# 4. Применить: сначала append в архив, затем атомарный rename main файла
LINES_BEFORE=$(wc -l < "$TT")
ARCH_LINES_BEFORE=$(wc -l < "$TTA")

cat "$TMP_ARCH_APPEND" >> "$TTA"
mv "$TMP_NEW_TT" "$TT"
trap - EXIT
rm -f "$TMP_ARCH_APPEND"

LINES_AFTER=$(wc -l < "$TT")
ARCH_LINES_AFTER=$(wc -l < "$TTA")

# 5. Сводка
echo ""
echo "✅ $MILESTONE архивирован."
echo "  tracking_table.md:         $LINES_BEFORE → $LINES_AFTER строк (-$((LINES_BEFORE - LINES_AFTER)))"
echo "  tracking_table_archive.md: $ARCH_LINES_BEFORE → $ARCH_LINES_AFTER строк (+$((ARCH_LINES_AFTER - ARCH_LINES_BEFORE)))"
echo "  Перенесено: $TASK_COUNT задач — $(printf '%s' "$TASK_IDS" | tr '\n' ',' | sed 's/,$/\n/')"
