#!/bin/bash
# 获取工具库和漏洞库。
#
# 仓库里不含数据库（vulndb.sqlite 127MB，超过 GitHub 单文件 100MB 硬上限）。
# 这个脚本先试着从 Release 附件下载现成的库；下载不到就打印自己构建的命令。
#
# 用法:  bash scripts/fetch_data.sh
set -e
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
REPO="${SECFORGE_REPO:-kangyx-2024/secforge}"
TAG="${SECFORGE_DATA_TAG:-data-latest}"

CATALOG="$ROOT/catalog/catalog.sqlite"
VULNDB="$ROOT/vulndb/vulndb.sqlite"

echo "工具箱根目录: $ROOT"
echo

need_catalog=1; [ -s "$CATALOG" ] && need_catalog=0
need_vulndb=1;  [ -s "$VULNDB"  ] && need_vulndb=0
if [ $need_catalog -eq 0 ] && [ $need_vulndb -eq 0 ]; then
  echo "两个数据库都已经在了："
  ls -lh "$CATALOG" "$VULNDB"
  exit 0
fi

echo "① 试着从 Release 下载现成的数据库（$REPO $TAG）..."
ok=0
if command -v gh >/dev/null 2>&1 && gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  mkdir -p catalog vulndb
  [ $need_catalog -eq 1 ] && gh release download "$TAG" --repo "$REPO" -p 'catalog.sqlite' -O "$CATALOG" && ok=1
  [ $need_vulndb  -eq 1 ] && gh release download "$TAG" --repo "$REPO" -p 'vulndb.sqlite'  -O "$VULNDB"  && ok=1
else
  echo "   （没有 Release 附件，或者你还没装/登录 gh）"
fi

if [ $ok -eq 1 ]; then
  echo
  echo "下载完成："
  ls -lh "$CATALOG" "$VULNDB" 2>/dev/null
  exit 0
fi

echo
cat <<'EOF'
② 本地自己构建（需要 gh CLI 已登录 —— GitHub 搜索 API 有速率限制）

   python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

   # 工具库：爬 GitHub → 过滤噪音（约 30-60 分钟，默认能爬到 8000+ 个仓库）
   .venv/bin/python catalog/scrape_github.py --pages 2 --min-stars 30
   .venv/bin/python catalog/refine_catalog.py

   # 漏洞库：微软 MSRC + CISA KEV + ExploitDB（约 1-2 小时）
   .venv/bin/python vulndb/build_vulndb.py --from 2016-Jan

   # 补 CVSS / severity / CWE 评分（下 NVD 年度 feed，约 20 分钟）
   .venv/bin/python vulndb/fill_cvss_nvd.py

   之后再跑一次本脚本会认出数据库已存在。
EOF
