#!/bin/bash
# 双击这个文件就能打开 SecForge 图形界面
cd "$(dirname "$0")/.." || exit 1
echo "正在启动 SecForge 图形界面 ..."
exec .venv/bin/python ui/app.py
