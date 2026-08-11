#!/usr/bin/env bash
# 三字母域名扫描 + 自动推送 GitHub
# 由 cron 调用。扫描完成生成 domains.json + data.js,然后 commit + push。
# 看门狗模式: 无变更时静默(输出空),有变更时输出扫描摘要。

set -uo pipefail
cd /root/name-scan

# 运行扫描(捕获输出但不打印,避免污染交付)
SCAN_OUT=$(python3 scan.py 2>&1)
SCAN_EXIT=$?

# 判断是否真正完成(找到"扫描完成")
if [ $SCAN_EXIT -ne 0 ] || ! echo "$SCAN_OUT" | grep -q "扫描完成"; then
    echo "❌ 域名扫描失败"
    echo "$SCAN_OUT" | tail -15
    exit 1
fi

# 提取摘要行
SUMMARY=$(echo "$SCAN_OUT" | grep -A20 "【三字母" | tail -20)

# 检查是否有变更
if ! git diff --quiet HEAD; then
    git add -A
    git commit -m "scan: 三字母域名更新 $(date '+%Y-%m-%d %H:%M')" >/dev/null 2>&1 || true
    if ! git push origin main >/dev/null 2>&1; then
        echo "❌ push 失败"
        echo "$SUMMARY"
        exit 1
    fi
    # 有变更:输出摘要(非空 -> 会推送)
    echo "$SUMMARY"
else
    # 无变更:静默(空输出 -> 不推送)
    exit 0
fi
