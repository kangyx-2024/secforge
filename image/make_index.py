#!/usr/bin/env python3
"""只重新生成 tools_index.json / 更新 vulndb.sqlite, 不动 Dockerfile。

为什么需要它: Dockerfile 里 COPY 这两个文件放在最后几层, 只改数据文件再
docker build 时前面对 apt/go/pip 的重层全部命中缓存, 几秒就能重建。
如果改动了 Dockerfile 文本(哪怕只是注释里的数字), 缓存整体失效, 又要重装 20 分钟。

用法:
  python3 make_index.py            # 刷新工具索引 + 把最新 vulndb 拷进来
  python3 make_index.py --rebuild  # 顺便重新 docker build
"""
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CATALOG = os.path.join(ROOT, "catalog", "catalog.sqlite")
VULNDB = os.path.join(ROOT, "vulndb", "vulndb.sqlite")

ap = argparse.ArgumentParser()
ap.add_argument("--min-stars", type=int, default=100)
ap.add_argument("--rebuild", action="store_true")
ap.add_argument("--tag", default="secforge/kali:standard")
a = ap.parse_args()

if not os.path.exists(CATALOG):
    sys.exit(f"! 没有 {CATALOG}")
con = sqlite3.connect(CATALOG)
con.row_factory = sqlite3.Row
rows = [dict(r) for r in con.execute(
    "SELECT * FROM tools WHERE noise=0 ORDER BY score DESC")]
index = [{"name": r["name"], "full_name": r["full_name"], "stars": r["stars"],
          "category": r["category"], "language": r["language"],
          "desc": (r["description"] or "")[:180], "url": r["url"],
          "install_method": r["install_method"], "install_spec": r["install_spec"],
          "kind": r.get("kind", "tool"),
          "archived": r["archived"], "pushed_at": r["pushed_at"]}
         for r in rows if r["stars"] >= a.min_stars]
json.dump(index, open(os.path.join(HERE, "tools_index.json"), "w"),
          ensure_ascii=False, indent=0)
print(f"[+] tools_index.json: {len(index)} 个工具 (★>={a.min_stars})")

if os.path.exists(VULNDB):
    shutil.copy(VULNDB, os.path.join(HERE, "vulndb.sqlite"))
    print(f"[+] vulndb.sqlite: {os.path.getsize(VULNDB)//1024//1024} MB")
else:
    print("! 还没有 vulndb.sqlite")

if a.rebuild:
    p = subprocess.run(["docker", "build", "-t", a.tag, HERE], cwd=HERE)
    print("构建完成" if p.returncode == 0 else "! 构建失败")
