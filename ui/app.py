#!/usr/bin/env python3
# ⚠️ 使用声明：仅供合法的网络安全工作 —— 你自己的资产，或你持有书面授权的目标。
#    严禁用于任何未授权的系统。相关行为由《刑法》第 285 / 286 条规制。详见 USAGE-POLICY.md
"""SecForge GUI —— 本机图形界面 (标准库 HTTP 服务 + 单页前端)

启动: .venv/bin/python ui/app.py        → http://127.0.0.1:8787
逻辑直接复用 mcp/server.py, 所以界面和 AI 走的是同一套工具库/漏洞库/容器。

接口:
  GET  /api/overview                      总览
  GET  /api/tools?q=&cat=&kind=&...       工具库检索
  GET  /api/categories                    分类统计
  GET  /api/vulns?q=&kev=1&...            漏洞库检索
  GET  /api/vuln?id=CVE-...               CVE 详情
  GET  /api/win?build=14393               Windows 版本 -> 漏洞+补丁
  POST /api/run                           SSE 流式跑工具 + 自动关联漏洞
  GET  /api/jobs  /api/job_output?id=     后台任务
  GET  /api/image_status                  镜像/容器
  POST /api/container {action}            起停容器
  POST /api/install {name}                装工具库里没装的工具
"""
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))

# Finder/App 双击启动时 PATH 是精简的(没有 /opt/homebrew/bin、~/.local/bin),
# 而本服务要调 docker(Homebrew) 和 hermes(~/.local/bin) —— 先把 PATH 补齐,
# 这样下面所有 subprocess 调用(docker exec / hermes -z)才能找到。
os.environ["PATH"] = os.pathsep.join([
    "/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
    os.path.expanduser("~/.local/bin"), "/usr/bin", "/bin", "/usr/sbin", "/sbin",
    os.environ.get("PATH", ""),
])

# 复用 MCP 服务器里的全部逻辑
import importlib.util
_spec = importlib.util.spec_from_file_location("secforge_srv", os.path.join(ROOT, "mcp", "server.py"))
srv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(srv)

PORT = int(os.environ.get("SECFORGE_PORT", "8787"))


def rows(cur, limit=None):
    out = [dict(r) for r in cur]
    return out[:limit] if limit else out


# ---------------------------------------------------------------- API
def api_overview():
    d = {"container": srv.container_up()}
    c = srv.catalog_conn()
    if c:
        d["tools_raw"] = c.execute("SELECT COUNT(*) FROM tools").fetchone()[0]
        d["tools"] = c.execute("SELECT COUNT(*) FROM tools WHERE noise=0 AND kind='tool'").fetchone()[0]
        d["refs"] = c.execute("SELECT COUNT(*) FROM tools WHERE noise=0 AND kind='reference'").fetchone()[0]
    v = srv.vulndb_conn()
    if v:
        q = v.execute
        d["cves"] = q("SELECT COUNT(*) FROM cve").fetchone()[0]
        d["kev"] = q("SELECT COUNT(*) FROM cve WHERE kev=1").fetchone()[0]
        d["poc"] = q("SELECT COUNT(*) FROM cve WHERE poc=1").fetchone()[0]
        d["critical"] = q("SELECT COUNT(*) FROM cve WHERE cvss>=9").fetchone()[0]
        d["with_cvss"] = q("SELECT COUNT(*) FROM cve WHERE cvss IS NOT NULL").fetchone()[0]
    img = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}|{{.Size}}"],
                         capture_output=True, text=True).stdout
    d["image"] = next((l.replace("|", "  ") for l in img.splitlines() if "secforge" in l), "无")
    ps = subprocess.run(["docker", "ps", "-a", "--filter", "name=^secforge$",
                         "--format", "{{.Status}}"], capture_output=True, text=True).stdout.strip()
    d["container_status"] = ps or "未创建"
    d["pentagi"] = len(subprocess.run(["docker", "ps", "--filter", "name=pentagi", "-q"],
                                      capture_output=True, text=True).stdout.strip()) > 0
    lu = os.path.join(ROOT, "vulndb", "last_update.json")
    if os.path.exists(lu):
        try:
            d["last_update"] = json.load(open(lu))
        except Exception:
            pass
    return d


def api_tools(p):
    c = srv.catalog_conn()
    if not c:
        return {"rows": [], "total": 0}
    w, a = [], []
    if p.get("q"):
        w.append("(name LIKE ? OR description LIKE ? OR topics LIKE ? OR full_name LIKE ?)")
        a += [f"%{p['q']}%"] * 4
    if p.get("cat"):
        w.append("category = ?"); a.append(p["cat"])
    kd = p.get("kind", "tool")
    if kd:
        w.append("kind = ?"); a.append(kd)
    if not p.get("noise"):
        w.append("noise = 0")
    if p.get("method"):
        w.append("install_method = ?"); a.append(p["method"])
    if p.get("min_stars"):
        w.append("stars >= ?"); a.append(int(p["min_stars"]))
    where = (" WHERE " + " AND ".join(w)) if w else ""
    total = c.execute(f"SELECT COUNT(*) FROM tools{where}", a).fetchone()[0]
    order = {"score": "score DESC", "stars": "stars DESC", "pushed": "pushed_at DESC"}.get(p.get("sort", "score"), "score DESC")
    cur = c.execute(f"""SELECT name,full_name,stars,category,language,install_method,install_spec,
                        description,url,pushed_at,archived,kind FROM tools{where}
                        ORDER BY {order} LIMIT ?""", a + [int(p.get("limit", 60))])
    return {"rows": rows(cur), "total": total}


def api_vulns(p):
    v = srv.vulndb_conn()
    if not v:
        return {"rows": [], "total": 0}
    w, a = [], []
    if p.get("q"):
        w.append("(title LIKE ? OR description LIKE ? OR affected LIKE ? OR poc_refs LIKE ? OR cve_id LIKE ?)")
        a += [f"%{p['q']}%"] * 5
    if p.get("product"):
        w.append("cve_id IN (SELECT cve_id FROM affected WHERE product LIKE ?)"); a.append(f"%{p['product']}%")
    if p.get("impact"):
        w.append("impact LIKE ?"); a.append(f"%{p['impact']}%")
    if p.get("sev"):
        w.append("severity = ?"); a.append(p["sev"])
    if p.get("min_cvss"):
        w.append("cvss >= ?"); a.append(float(p["min_cvss"]))
    if p.get("year"):
        w.append("published LIKE ?"); a.append(f"{p['year']}%")
    if p.get("kev"):
        w.append("kev = 1")
    if p.get("poc"):
        w.append("poc = 1")
    where = (" WHERE " + " AND ".join(w)) if w else ""
    total = v.execute(f"SELECT COUNT(*) FROM cve{where}", a).fetchone()[0]
    cur = v.execute(f"""SELECT cve_id,title,severity,cvss,impact,kev,kev_ransomware,poc,
                        affected,kbs,published,poc_refs,sources FROM cve{where}
                        ORDER BY kev DESC, poc DESC, COALESCE(cvss,0) DESC LIMIT ?""",
                    a + [int(p.get("limit", 50))])
    return {"rows": rows(cur), "total": total}


def api_vuln(p):
    v = srv.vulndb_conn()
    r = v.execute("SELECT * FROM cve WHERE cve_id=?", ((p.get("id") or "").upper(),)).fetchone()
    if not r:
        return {"error": "未找到"}
    d = dict(r)
    d["products"] = rows(v.execute("SELECT DISTINCT product, cpe, kb FROM affected WHERE cve_id=? "
                                   "ORDER BY product LIMIT 200", (d["cve_id"],)))
    return d


def api_win(p):
    v = srv.vulndb_conn()
    build = (p.get("build") or "").strip()
    ver = (p.get("version") or "").strip()
    if build:
        import re
        build = re.sub(r"^10\.0\.", "", build)
    # 版本表三列: 显示名 / 内部版本号 / 产品匹配串。匹配串必须是 affected.product 的真子串。
    rows_v = list(v.execute("SELECT label, build, COALESCE(match, label) FROM win_versions"))
    match = ""
    if ver:
        for L, B, M in rows_v:
            if ver.lower() == L.lower():
                match, ver, build = M, L, (build or B or "")
                break
    if not match and build:
        for L, B, M in rows_v:
            if B == build:
                match, ver = M, L
                break
    if not match:
        if not ver:
            return {"error": "请输入版本或内部版本号"}
        match = ver
    w, a = ["cve_id IN (SELECT cve_id FROM affected WHERE product LIKE ?)"], [f"%{match}%"]
    cur = v.execute(f"""SELECT cve_id,title,severity,cvss,impact,kev,poc,affected,kbs,published
                        FROM cve WHERE {' OR '.join(w)}
                        ORDER BY COALESCE(cvss,0) DESC LIMIT 4000""", a)
    all_rows = sorted(rows(cur), key=lambda r: (-(r["kev"] or 0), -(r["poc"] or 0), -(r["cvss"] or 0)))
    crit = [r for r in all_rows if r["kev"] or (r["cvss"] or 0) >= 8 or r["severity"] == "Critical"]
    import re
    kbs = []
    for r in all_rows:
        for kb in re.findall(r"KB\d+", r["kbs"] or ""):
            if kb not in kbs:
                kbs.append(kb)
    return {"version": ver, "build": build, "total": len(all_rows),
            "critical": crit[:60], "recent": all_rows[:40], "kbs": kbs}


def api_run_stream(p):
    """SSE: 跑工具, 边跑边推输出, 最后推漏洞关联"""
    tool = p.get("tool", "nmap")
    args = p.get("args", "")
    target = p.get("target", "")
    g = srv.guard(target) if target else ""
    if g:
        yield f"data: {json.dumps({'type':'error','text':g}, ensure_ascii=False)}\n\n"
        return
    if not args and target:
        args = {"nmap": f"-sV -T4 -Pn {target}", "nuclei": f"-u {target} -severity low,medium,high,critical",
                "whatweb": f"-a 3 {target}", "nikto": f"-h {target}",
                "httpx": f"-u {target} -title -tech-detect -status-code",
                "ffuf": f"-u {target}/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403",
                "gobuster": f"dir -u {target} -w /usr/share/wordlists/dirb/common.txt -q",
                "nmap-full": f"-sV -sC -T4 -Pn {target}"}.get(tool, target)
    real_tool = "nmap" if tool == "nmap-full" else tool
    cmd = f"{real_tool} {args}"
    yield f"data: {json.dumps({'type':'cmd','text':'$ ' + cmd}, ensure_ascii=False)}\n\n"
    if not srv.container_up():
        yield f"data: {json.dumps({'type':'error','text':'容器没跑, 先在设置里启动'}, ensure_ascii=False)}\n\n"
        return
    buf = []
    p2 = subprocess.Popen(["docker", "exec", srv.CONTAINER, "bash", "-lc", f"{cmd} 2>&1"],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    try:
        for line in p2.stdout:
            buf.append(line)
            yield f"data: {json.dumps({'type':'out','text':line.rstrip()}, ensure_ascii=False)}\n\n"
    except GeneratorExit:
        p2.kill()
        return
    p2.wait()
    text = "".join(buf)
    yield f"data: {json.dumps({'type':'done','code':p2.returncode}, ensure_ascii=False)}\n\n"
    try:
        block = srv._vuln_auto_block(text, limit=15)
    except Exception as e:
        block = f"[关联失败 {e}]"
    if block:
        yield f"data: {json.dumps({'type':'vuln','text':block}, ensure_ascii=False)}\n\n"
    # 存一份
    try:
        srv.dex(f"mkdir -p /loot/runs && cat > /loot/runs/ui_{tool}_{int(time.time())}.log <<'XEOF'\n{text[:200000]}\nXEOF", 60)
    except Exception:
        pass


def api_jobs():
    out = srv.dex("ls -1 /loot/jobs/*.log 2>/dev/null | head -40", 30)
    files = [f.strip() for f in out.splitlines() if f.strip().endswith(".log")]
    res = []
    for f in files:
        jid = os.path.basename(f)[:-4]
        alive = srv.dex(f"kill -0 $(cat /loot/jobs/{jid}.pid) 2>/dev/null && echo RUN || echo DONE", 20).strip()
        size = srv.dex(f"wc -l < {f} 2>/dev/null", 20).strip()
        res.append({"jid": jid, "state": "运行中" if "RUN" in alive else "已结束", "lines": size})
    return {"rows": res}


def api_job_output(p):
    jid = p.get("id", "")
    return {"text": srv.dex(f"tail -n 200 /loot/jobs/{jid}.log 2>/dev/null", 30)}


def api_install(p):
    return {"text": srv.sec_install_tool(p.get("name", ""))}


# ---------------------------------------------------------------- AI 对话
# 直接调用本机的 hermes 真身(带全部工具 + SecForge MCP + 记忆 + 技能):
#   hermes -z "<消息>"                非交互, 只输出最终答复
#   hermes -z ... --resume <session>  续接上一次会话(上下文连续)
_CHAT_LOCK = threading.Lock()
_CHAT_PROC = {"p": None}
_SESS_RE = re.compile(r"\d{8}_\d{6}_[0-9a-f]+")


def _find_bin(name, extra=()):
    """Finder 双击启动的进程 PATH 很精简(~/.local/bin, /opt/homebrew/bin 都不在里面),
    所以这里显式找一遍, 不能只靠 PATH。"""
    for c in list(extra) + [shutil.which(name),
                            os.path.expanduser(f"~/.local/bin/{name}"),
                            f"/opt/homebrew/bin/{name}",
                            f"/usr/local/bin/{name}",
                            f"/usr/bin/{name}"]:
        if c and os.path.exists(c):
            return c
    return name


HERMES = _find_bin("hermes")


def newest_session_id():
    """列表里最新一条会话的 ID (用于首次对话后抓到它, 后续 --resume 续接)"""
    try:
        out = subprocess.run([HERMES, "sessions", "list"], capture_output=True,
                             text=True, timeout=60).stdout
    except Exception:
        return None
    for line in out.splitlines():
        if "─" in line or line.lower().startswith("title"):
            continue
        m = _SESS_RE.search(line)
        if m:
            return m.group(0)
    return None


def api_chat_stream(p):
    """SSE: 把消息发给 hermes 真身, 流式把答复推回来"""
    msg = (p.get("message") or "").strip()
    sid = (p.get("session") or "").strip()
    yolo = p.get("yolo") in ("1", "true", "True", True)
    if not msg:
        yield f"data: {json.dumps({'type':'error','text':'说点什么'}, ensure_ascii=False)}\n\n"
        return
    if not _CHAT_LOCK.acquire(blocking=False):
        yield f"data: {json.dumps({'type':'error','text':'上一条还在跑, 等它结束或点停止'}, ensure_ascii=False)}\n\n"
        return
    try:
        before = newest_session_id() if not sid else sid
        cmd = [HERMES]
        if yolo:
            cmd.append("--yolo")
        cmd += ["-z", msg]
        if sid:
            cmd += ["--resume", sid]
        yield f"data: {json.dumps({'type':'start','session':sid or '', 'cmd':' '.join(cmd[:3])+' …'}, ensure_ascii=False)}\n\n"
        t0 = time.time()
        proc = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        _CHAT_PROC["p"] = proc
        buf = []
        last = 0
        try:
            for line in proc.stdout:
                buf.append(line)
                if time.time() - last > 0.4:      # 攒一下再推, 别把 SSE 打爆
                    chunk = "".join(buf)
                    buf = []
                    last = time.time()
                    yield f"data: {json.dumps({'type':'out','text':chunk}, ensure_ascii=False)}\n\n"
        except GeneratorExit:
            proc.kill()
            _CHAT_PROC["p"] = None
            return
        proc.wait(timeout=30)
        if buf:
            yield f"data: {json.dumps({'type':'out','text':''.join(buf)}, ensure_ascii=False)}\n\n"
        # 抓本次会话 ID: 没指定过就取最新的
        nsid = sid
        if not nsid:
            after = newest_session_id()
            nsid = after if after and after != before else ""
        yield f"data: {json.dumps({'type':'done','code':proc.returncode,'session':nsid,'seconds':round(time.time()-t0,1)}, ensure_ascii=False)}\n\n"
    except Exception as e:
        yield f"data: {json.dumps({'type':'error','text':f'调用失败: {e}'}, ensure_ascii=False)}\n\n"
    finally:
        _CHAT_PROC["p"] = None
        _CHAT_LOCK.release()


def stop_chat():
    p = _CHAT_PROC.get("p")
    if p and p.poll() is None:
        p.kill()
        return "已停止"
    # 也可能是 DeepSeek 那个大脑在跑
    try:
        _DS.stop()
        return "已通知 DeepSeek 停下（跑到当前工具结束就停）"
    except Exception:
        return "没有在跑的任务"


# ---------------------------------------------------------------- 第二个大脑: DeepSeek 直连
# 不经过 Hermes —— 同一个工具箱(同一批 sec_* 函数 + 同一个容器), 两个大脑可以同时用。
import importlib.util as _ilu
import queue as _queue

_ds_spec = _ilu.spec_from_file_location("dsagent", os.path.join(HERE, "deepseek_agent.py"))
dsmod = _ilu.module_from_spec(_ds_spec)
_ds_spec.loader.exec_module(dsmod)
_DS = dsmod.DeepSeekAgent()
_DS_LOCK = threading.Lock()


def api_ds_stream(p):
    """SSE: 直连 DeepSeek, 自己跑工具循环(把每次工具调用也推给界面看)"""
    msg = (p.get("message") or "").strip()
    if p.get("reset") in ("1", "true", "True", True):
        _DS.reset()
        if not msg:
            yield f"data: {json.dumps({'type': 'start', 'brain': 'deepseek', 'model': _DS.model, 'reset': True}, ensure_ascii=False)}\n\n"
            yield f"data: {json.dumps({'type': 'done', 'code': 0, 'seconds': 0, 'brain': 'deepseek'}, ensure_ascii=False)}\n\n"
            return
    if not msg:
        yield f"data: {json.dumps({'type': 'error', 'text': '说点什么'}, ensure_ascii=False)}\n\n"
        return
    if not _DS_LOCK.acquire(blocking=False):
        yield f"data: {json.dumps({'type': 'error', 'text': 'DeepSeek 上一条还在跑'}, ensure_ascii=False)}\n\n"
        return
    try:
        yield f"data: {json.dumps({'type': 'start', 'brain': 'deepseek', 'model': _DS.model, 'tools': len(dsmod.TOOL_SCHEMAS)}, ensure_ascii=False)}\n\n"
        t0 = time.time()
        q = _queue.Queue()

        def ev(kind, text):
            q.put((kind, text))

        def work():
            try:
                ans = _DS.run(msg, ev)
                q.put(("__done__", ans))
            except Exception as e:
                q.put(("__err__", f"{type(e).__name__}: {e}"))

        threading.Thread(target=work, daemon=True).start()
        while True:
            kind, text = q.get()
            if kind == "__done__":
                yield f"data: {json.dumps({'type': 'out', 'text': text}, ensure_ascii=False)}\n\n"
                yield f"data: {json.dumps({'type': 'done', 'code': 0, 'seconds': round(time.time()-t0, 1), 'brain': 'deepseek'}, ensure_ascii=False)}\n\n"
                break
            if kind == "__err__":
                yield f"data: {json.dumps({'type': 'error', 'text': text}, ensure_ascii=False)}\n\n"
                yield f"data: {json.dumps({'type': 'done', 'code': 1, 'seconds': round(time.time()-t0, 1), 'brain': 'deepseek'}, ensure_ascii=False)}\n\n"
                break
            yield f"data: {json.dumps({'type': kind, 'text': text}, ensure_ascii=False)}\n\n"
    finally:
        _DS_LOCK.release()


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200, ctype="application/json; charset=utf-8"):
        b = obj if isinstance(obj, bytes) else json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        u = urlparse(self.path)
        p = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            if u.path in ("/", "/index.html"):
                return self._send(open(os.path.join(HERE, "index.html"), "rb").read(),
                                  ctype="text/html; charset=utf-8")
            if u.path == "/api/overview":
                return self._send(api_overview())
            if u.path == "/api/tools":
                return self._send(api_tools(p))
            if u.path == "/api/categories":
                c = srv.catalog_conn()
                return self._send(rows(c.execute(
                    "SELECT category, COUNT(*) n FROM tools WHERE noise=0 AND kind='tool' "
                    "GROUP BY category ORDER BY n DESC")))
            if u.path == "/api/vulns":
                return self._send(api_vulns(p))
            if u.path == "/api/vuln":
                return self._send(api_vuln(p))
            if u.path == "/api/win":
                return self._send(api_win(p))
            if u.path == "/api/jobs":
                return self._send(api_jobs())
            if u.path == "/api/job_output":
                return self._send(api_job_output(p))
            if u.path == "/api/image_status":
                return self._send({"text": srv.sec_image_status()})
            if u.path == "/api/buildlog":
                try:
                    out = subprocess.run(["tail", "-n", "60", "/tmp/secforge_build.log"],
                                         capture_output=True, text=True).stdout
                except Exception as e:
                    out = str(e)
                return self._send({"text": out or "还没有构建日志"})
            if u.path == "/api/ds":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                for chunk in api_ds_stream(p):
                    try:
                        self.wfile.write(chunk.encode())
                        self.wfile.flush()
                    except BrokenPipeError:
                        return
                return
            if u.path == "/api/chat":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                for chunk in api_chat_stream(p):
                    try:
                        self.wfile.write(chunk.encode())
                        self.wfile.flush()
                    except BrokenPipeError:
                        return
                return
            if u.path == "/api/run":
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                for chunk in api_run_stream(p):
                    self.wfile.write(chunk.encode())
                    self.wfile.flush()
                return
            self._send({"error": "not found"}, 404)
        except BrokenPipeError:
            pass
        except Exception as e:
            try:
                self._send({"error": str(e)}, 500)
            except Exception:
                pass

    def do_POST(self):
        u = urlparse(self.path)
        n = int(self.headers.get("Content-Length") or 0)
        try:
            p = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            p = {}
        if u.path == "/api/container":
            act = p.get("action")
            if act == "start":
                r = srv.sec_start_container()
            else:
                subprocess.run(["docker", "stop", srv.CONTAINER], capture_output=True)
                r = "已停止"
            return self._send({"text": r})
        if u.path == "/api/install":
            return self._send(api_install(p))
        if u.path == "/api/chat_stop":
            return self._send({"text": stop_chat()})
        if u.path == "/api/build":
            prof = p.get("profile", "standard")
            cats = p.get("categories", "")
            cmd = [sys.executable, os.path.join(ROOT, "image", "build_image.py"),
                   "--profile", prof, "--no-run"]
            if cats:
                cmd += ["--categories", cats]
            log = open("/tmp/secforge_build.log", "a")
            subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True, cwd=os.path.join(ROOT, "image"))
            return self._send({"text": f"已后台开始构建 {prof}，日志 /tmp/secforge_build.log（20-40 分钟）"})
        if u.path == "/api/job_start":
            return self._send({"text": srv.sec_job_start(p.get("name", "job"),
                                                         p.get("command", "true"),
                                                         p.get("target", ""))})
        self._send({"error": "not found"}, 404)


def main():
    s = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    url = f"http://127.0.0.1:{PORT}"
    print(f"SecForge GUI → {url}")
    print("Ctrl+C 退出")
    if "--no-browser" not in sys.argv:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        s.serve_forever()
    except KeyboardInterrupt:
        print("\n再见~")


if __name__ == "__main__":
    main()
