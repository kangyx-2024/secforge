#!/bin/bash
# SecForge.app 的启动器 —— 由 Finder 双击触发, 不显示终端窗口
# 1) 已经在跑就直接开浏览器  2) 没跑就后台拉起来再开

# Finder 启动的进程 PATH 很精简, docker/curl/hermes 都可能找不到 —— 先补齐
export PATH="/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:$HOME/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"

# 工具箱根目录：环境变量 SECFORGE_ROOT → ~/.secforge_root 文件 → ~/secforge
APP_DIR="${SECFORGE_ROOT:-}"
if [ -z "$APP_DIR" ] && [ -f "$HOME/.secforge_root" ]; then
  APP_DIR="$(cat "$HOME/.secforge_root")"
fi
[ -z "$APP_DIR" ] && APP_DIR="$HOME/secforge"
PORT=8787
LOG=/tmp/secforge_ui.log

# 端口活着? 直接打开
if curl -s -m 2 -o /dev/null "http://127.0.0.1:$PORT/"; then
  open "http://127.0.0.1:$PORT"
  exit 0
fi

cd "$APP_DIR" || exit 1

# 确保容器也在跑(图形界面要能跑工具)
if ! docker ps --filter name=^secforge$ -q | grep -q .; then
  docker start secforge >/dev/null 2>&1 || \
    docker run -d --name secforge --hostname secforge \
      --cap-add NET_ADMIN --cap-add NET_RAW \
      -v secforge_work:/work -v secforge_loot:/loot \
      secforge/kali:standard >/dev/null 2>&1
fi

# 后台起服务, 完全脱离 App 进程, 这样 App 可以立刻退出不占 Dock
nohup "$APP_DIR/.venv/bin/python" "$APP_DIR/ui/app.py" --no-browser >>"$LOG" 2>&1 &
disown

# 等服务起来(最多 20 秒)再开浏览器
for i in $(seq 1 40); do
  if curl -s -m 1 -o /dev/null "http://127.0.0.1:$PORT/"; then
    open "http://127.0.0.1:$PORT"
    exit 0
  fi
  sleep 0.5
done

osascript -e 'display alert "SecForge 启动失败" message "服务没起来，看日志 /tmp/secforge_ui.log" as critical'
exit 1
