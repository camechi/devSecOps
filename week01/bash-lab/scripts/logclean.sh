#!/usr/bin/env bash
# logclean.sh – Remove log files older than 30 days (safe + dry-run first)
set -euo pipefail

LOGDIR="${1:-/var/log}"
DAYS=30
DRY_RUN=${DRY_RUN:-true}

find "$LOGDIR" -type f -name "*.log" -mtime +$DAYS -print0 | while IFS= read -r -d '' file; do
    if [[ "$DRY_RUN" == "true" ]]; then
        echo "[DRY-RUN] Would delete: $file"
    else
        rm -f "$file" && echo "Deleted: $file"
    fi
done

[[ "$DRY_RUN" == "true" ]] && echo "Run with DRY_RUN=false to actually delete"