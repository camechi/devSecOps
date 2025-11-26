#!/usr/bin/env bash
# sysinfo.sh – Display system information in a clean format
set -euo pipefail

uptime_fmt=$(uptime -p | sed 's/up //')

echo "System Information – $(date '+%Y-%m-%d %H:%M:%S')"
echo "Hostname      : $(hostname)"
echo "Uptime        : $uptime_fmt"
echo "CPU           : $(lscpu | grep 'Model name' | awk -F: '{print $2}' | xargs)"
echo "Cores         : $(nproc)"
echo "Load average  : $(cat /proc/loadavg | cut -d' ' -f1-3)"
echo "Memory        : $(free -h | awk 'NR==2{printf "%s/%s (%s used)", $3,$2,$4}')"
echo "Disk usage    : $(df -h / | awk 'NR==2{printf "%s/%s (%s used)", $3,$2,$5}')"
echo "Kernel        : $(uname -r)"