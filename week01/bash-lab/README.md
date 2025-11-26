# Week 01 – Bash Lab

## Scripts

| Script       | Purpose                                                                 | Usage Example                          |
|--------------|-------------------------------------------------------------------------|----------------------------------------|
| `backup.sh`  | Creates a timestamped compressed backup of a directory (default: $HOME) | `./backup.sh /etc`                     |
| `sysinfo.sh` | Displays formatted system information (CPU, RAM, disk, uptime, etc.)    | `./sysinfo.sh`                         |
| `logclean.sh`| Safely removes *.log files older than 30 days (dry-run by default)      | `DRY_RUN=false ./logclean.sh /var/log` |

All scripts are `shellcheck`-clean and follow best practices (`set -euo pipefail`).

Script,Purpose,Usage Example
backup.sh,Creates a timestamped compressed backup of a directory (default: $HOME),./backup.sh /etc
sysinfo.sh,"Displays formatted system information (CPU, RAM, disk, uptime, etc.)",./sysinfo.sh
logclean.sh,Safely removes *.log files older than 30 days (dry-run by default),DRY_RUN=false ./logclean.sh /var/log
devsecops-tools.sh,"Idempotent installer for DevSecOps tools (Trivy, Checkov, etc.)",./devsecops-tools.sh -v