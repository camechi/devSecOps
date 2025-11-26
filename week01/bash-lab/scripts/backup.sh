#!/usr/bin/env bash
# backup.sh – Create timestamped tar.gz backup of a directory
set -euo pipefail

TARGET="${1:-$HOME}"
TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
BACKUP_FILE="backup_${TIMESTAMP}.tar.gz"

tar --create --gzip --preserve-permissions --file="$BACKUP_FILE" "$TARGET" 2>/dev/null

echo "Backup created: $(pwd)/$BACKUP_FILE"
echo "Size: $(du -h "$BACKUP_FILE" | cut -f1)"