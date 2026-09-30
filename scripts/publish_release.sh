#!/bin/bash
# 等 gh release create 跑完 → 检查附件 → 把草稿发布出去
# （gh 创建的 Release 是草稿状态，草稿别人下载不了）
cd /Users/kangyx/secforge || exit 1
PID="$1"
echo "[$(date +%H:%M:%S)] 等待上传进程 $PID 结束…"
while kill -0 "$PID" 2>/dev/null; do sleep 10; done
echo "[$(date +%H:%M:%S)] 上传进程已结束"

echo "--- 附件状态 ---"
gh release view data-latest --json assets --jq '.assets[] | "\(.name)  \(.size) 字节  \(.state)"'

CAT=$(gh release view data-latest --json assets --jq '.assets[] | select(.name=="catalog.sqlite") | .size')
VUL=$(gh release view data-latest --json assets --jq '.assets[] | select(.name=="vulndb.sqlite") | .size')
echo "catalog.sqlite = ${CAT:-缺失}   vulndb.sqlite = ${VUL:-缺失}"

if [ -z "$CAT" ] || [ -z "$VUL" ]; then
  echo "!! 有附件没传完，不发布。需要重传："
  echo "   gh release upload data-latest catalog/catalog.sqlite vulndb/vulndb.sqlite --clobber"
  exit 1
fi

echo "--- 发布（取消草稿）---"
gh release edit data-latest --draft=false 2>&1 | tail -3
gh release view data-latest --json isDraft,tagName,url --jq '"草稿: \(.isDraft)  标签: \(.tagName)  地址: \(.url)"'

echo "--- 匿名下载测试（不带凭证，模拟陌生人）---"
curl -sL -o /dev/null -w "catalog.sqlite  HTTP %{http_code}  下载 %{size_download} 字节\n" \
  "https://github.com/kangyx-2024/secforge/releases/download/data-latest/catalog.sqlite"
echo "[$(date +%H:%M:%S)] 完成"
