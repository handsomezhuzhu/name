#!/usr/bin/env bash
# 三字母域名扫描 + 自动推送 GitHub
# 由 cron 调用。扫描完成生成 domains.json + data.js,然后 commit + push。

set -euo pipefail
cd /root/name-scan

# 运行扫描
python3 scan.py > /tmp/name_scan.log 2>&1 || {
    echo "❌ 域名扫描失败"
    tail -20 /tmp/name_scan.log
    exit 1
}

# 检查是否有变更
if ! git diff --quiet HEAD; then
    git add -A
    git commit -m "scan: 三字母域名更新 $(date '+%Y-%m-%d %H:%M')" || true
    git push origin main 2>&1 || {
        echo "❌ push 失败"
        exit 1
    }
    echo "✅ 已推送更新到 GitHub (Action 会自动部署)"
else
    echo "ℹ️ 无变更,未推送"
fi
