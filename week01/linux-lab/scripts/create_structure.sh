#!/usr/bin/env bash
# create_structure.sh – Week 1 Day 1 (final fixed version for ~/devSecOps)

set -euo pipefail

BASE="$HOME/devSecOps"
WEEK01="$BASE/week01"

echo "Creating DevSecOps structure in $BASE ..."

mkdir -p "$BASE"

# Week 1 detailed structure
mkdir -p "$WEEK01/linux-lab"/{exercises,notes,scripts,cheatsheets}
mkdir -p "$WEEK01/bash-lab"/{scripts,notes}
mkdir -p "$WEEK01/git-lab"

# Future weeks – using bash brace expansion (safe, no printf octal issue)
for week in $(seq -w 2 12); do
    mkdir -p "$BASE/week$week"
done

# READMEs
cat > "$WEEK01/README.md" << 'EOF'
# Week 01 – Linux, Bash & Secure Git
Completed: Linux fundamentals, Bash scripting, signed Git workflow
EOF

cat > "$BASE/README.md" << 'EOF'
# DevSecOps Black Belt Journey – 2025/2026
Location: ~/devSecOps (symlinked to Windows C:\Users\camechi\Development\devSecOps)
Start: Monday, November 23, 2025
Capstone: Week 12 – February 14, 2026
EOF

# Move this script into place
chmod +x "$0"
mv -f "$0" "$WEEK01/linux-lab/scripts/create_structure.sh" 2>/dev/null || true

echo "Done! Your structure:"
tree "$BASE" -L 3 | head -n 40
echo "..."