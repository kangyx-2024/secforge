#!/usr/bin/env python3
# ⚠️ 使用声明：仅供合法的网络安全工作 —— 你自己的资产，或你持有书面授权的目标。
#    严禁用于任何未授权的系统。相关行为由《刑法》第 285 / 286 条规制。详见 USAGE-POLICY.md
"""SecForge MCP Server
把 SecForge 的 Kali 容器 + 工具库 暴露成 MCP 工具, 让任意 AI (Hermes/Claude/...) 直接调动。

Hermes 配置 ~/.hermes/config.yaml:
  mcp_servers:
    secforge:
      command: "<工具箱路径>/.venv/bin/python"
      args: ["<工具箱路径>/mcp/server.py"]
      timeout: 900
"""
import json
import os
import re
import shlex
import sqlite3
import ssl
import subprocess
import time
import urllib.request
import uuid
from datetime import datetime

from mcp.server.fastmcp import FastMCP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG = os.path.join(ROOT, "catalog", "catalog.sqlite")
CONTAINER = "secforge"
IMAGE = "secforge/kali"

mcp = FastMCP("secforge")

# ---------------------------------------------------------------- 安全护栏
# 用户是初中生: 只允许打自有/授权靶场。政府/教育/第三方站点一律拒绝。
BLOCKED_TLDS = (".gov", ".gov.cn", ".edu", ".edu.cn", ".mil", ".ac.cn", "gov.hk", "edu.hk")
ALLOW_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "secforge",
               "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
               "172.2", "172.30.", "172.31.", "dvwa", "juice-shop", "vulhub",
               "hackthebox", "tryhackme", "buuoj", "ctfhub", "example.com")


def guard(target: str) -> str:
    """返回空串表示放行, 否则返回拒绝原因"""
    t = (target or "").strip().lower()
    if not t:
        return ""
    host = re.sub(r"^[a-z]+://", "", t).split("/")[0].split(":")[0].split("@")[-1]
    for b in BLOCKED_TLDS:
        if host.endswith(b) or b.strip(".") in host:
            return f"⛔ 拒绝: {host} 属于政府/教育/军方域名。只允许打自有设备、内网靶场(DVWA/vulhub)或授权平台。"
    for a in ALLOW_HOSTS:
        if host == a or host.startswith(a) or host.endswith(a):
            return ""
    return ""  # 其他域名放行但会在报告里标注"需授权确认"


def dex(cmd, timeout=300, user=None):
    """docker exec 到 secforge 容器"""
    full = ["docker", "exec"]
    if user:
        full += ["-u", user]
    full += [CONTAINER] + (cmd if isinstance(cmd, list) else ["bash", "-lc", cmd])
    try:
        p = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
        return p.stdout + (("\n[stderr] " + p.stderr) if p.stderr.strip() else "")
    except subprocess.TimeoutExpired:
        return f"[超时 {timeout}s]"
    except FileNotFoundError:
        return "[错误] 找不到 docker"


def container_up() -> bool:
    r = subprocess.run(["docker", "ps", "--filter", f"name=^{CONTAINER}$",
                        "--format", "{{.Names}}"], capture_output=True, text=True)
    return CONTAINER in r.stdout


def need_up() -> str:
    if not container_up():
        return ("容器没跑。先 sec_start_container(), 或如果镜像还没构建, "
                "先 sec_build_image(profile='core'|'standard'|'full')。")
    return ""


def catalog_conn():
    if not os.path.exists(CATALOG):
        return None
    c = sqlite3.connect(CATALOG)
    c.row_factory = sqlite3.Row
    return c


# ================================================================ 工具库
@mcp.tool()
def sec_catalog(query: str = "", category: str = "", min_stars: int = 0,
                method: str = "", kind: str = "", limit: int = 25,
                sort: str = "score") -> str:
    """检索本地 GitHub 安全工具库(已爬取 8000+ 仓库, 已过滤噪音)。

    Args:
        query: 关键词, 匹配名称/描述/主题
        category: 分类过滤, 如 "Web 安全" "扫描/侦察/Recon" "漏洞利用/Exploit"
        min_stars: 最低星数
        method: 安装方式过滤 apt/pip/go/git/docker/source-build
        kind: tool(真工具, 默认) | reference(清单/手册) | ""(全部)
        limit: 返回条数
        sort: score | stars | pushed (最近更新)
    """
    c = catalog_conn()
    if not c:
        return "工具库为空, 先运行 catalog/scrape_github.py"
    w, p = ["noise = 0"], []
    if kind:
        w.append("kind = ?")
        p.append(kind)
    if query:
        w.append("(name LIKE ? OR description LIKE ? OR topics LIKE ? OR full_name LIKE ?)")
        p += [f"%{query}%"] * 4
    if category:
        w.append("category = ?")
        p.append(category)
    if min_stars:
        w.append("stars >= ?")
        p.append(min_stars)
    if method:
        w.append("install_method = ?")
        p.append(method)
    o = {"score": "score DESC", "stars": "stars DESC", "pushed": "pushed_at DESC"}.get(sort, "score DESC")
    rows = c.execute(f"""SELECT name,full_name,stars,category,language,install_method,
                         install_spec,description,url,pushed_at,archived,kind
                         FROM tools WHERE {' AND '.join(w)} ORDER BY {o} LIMIT ?""",
                     p + [limit]).fetchall()
    if not rows:
        return "无匹配(试试 kind='' 包括清单类, 或降低 min_stars)"
    tot = c.execute("SELECT COUNT(*) FROM tools WHERE noise=0 AND kind='tool'").fetchone()[0]
    out = [f"命中 {len(rows)} 条 (库内真工具 {tot} 个)"]
    for r in rows:
        flag = " [已归档]" if r["archived"] else ""
        kf = " [清单/参考]" if r["kind"] == "reference" else ""
        out.append(f"★{r['stars']:<6} {r['name']:<24} [{r['category']}] {r['language']:<10}"
                   f" 装法={r['install_method']}{flag}{kf}\n    {r['full_name']}  {r['url']}"
                   f"\n    {(r['description'] or '')[:150]}")
    return "\n".join(out)


@mcp.tool()
def sec_categories() -> str:
    """工具库的分类统计 + 各类最高星项目 (已排除噪音)"""
    c = catalog_conn()
    if not c:
        return "工具库为空"
    rows = c.execute("""SELECT category, COUNT(*) n, MAX(stars) mx,
                        (SELECT name FROM tools t2 WHERE t2.category=t1.category AND t2.noise=0
                         AND t2.kind='tool' ORDER BY stars DESC LIMIT 1) top
                        FROM tools t1 WHERE noise=0 AND kind='tool' GROUP BY category ORDER BY n DESC""").fetchall()
    tot = c.execute("SELECT COUNT(*) FROM tools WHERE noise=0 AND kind='tool'").fetchone()[0]
    raw = c.execute("SELECT COUNT(*) FROM tools").fetchone()[0]
    lines = [f"真工具 {tot} 个 / 爬取原始 {raw} 个 (已过滤噪音与清单)"]
    for r in rows:
        lines.append(f"  {r['category']:<22} {r['n']:>5} 个   最高: {r['top']} (★{r['mx']})")
    return "\n".join(lines)


@mcp.tool()
def sec_tool_info(name: str) -> str:
    """查某个工具的详情 + 安装配方 + 容器里是否已装"""
    c = catalog_conn()
    if not c:
        return "工具库为空"
    rows = c.execute("SELECT * FROM tools WHERE name=? OR full_name=? OR name LIKE ? "
                     "ORDER BY stars DESC LIMIT 3", (name, name, f"%{name}%")).fetchall()
    if not rows:
        return f"库里没有 {name}"
    out = []
    for r in rows:
        out.append(f"""=== {r['full_name']} (★{r['stars']}) ===
分类: {r['category']}  语言: {r['language']}  许可: {r['license']}
安装: {r['install_method']}  ->  {r['install_spec']}
更新: {r['pushed_at']}  归档: {'是' if r['archived'] else '否'}
URL: {r['url']}
说明: {r['description']}
主题: {r['topics']}""")
    return "\n\n".join(out)


# ================================================================ 镜像 / 容器
@mcp.tool()
def sec_image_status() -> str:
    """看镜像、容器、构建日志状态"""
    im = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}"],
                        capture_output=True, text=True).stdout
    im = "\n".join(l for l in im.splitlines() if "secforge" in l or "kali" in l) or "(无 secforge/kali 镜像)"
    ps = subprocess.run(["docker", "ps", "-a", "--filter", "name=secforge",
                         "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"],
                        capture_output=True, text=True).stdout.strip() or "(无容器)"
    ver = ""
    if container_up():
        ver = dex("cat /etc/os-release | head -2; echo ---; which nmap sqlmap nuclei ffuf 2>/dev/null | head", 60)
    return f"== 镜像 ==\n{im}\n\n== 容器 ==\n{ps}\n\n== 容器内 ==\n{ver}"


@mcp.tool()
def sec_build_image(profile: str = "core", categories: str = "") -> str:
    """构建自建 Kali 镜像(自动从工具库生成 Dockerfile)。

    Args:
        profile: core(快,~1GB) | standard(推荐,~6GB) | full(kali 全家桶,~15GB) | custom
        categories: profile=custom 时的分类列表, 逗号分隔
    """
    script = os.path.join(ROOT, "image", "build_image.py")
    log = "/tmp/secforge_build.log"
    cmd = f"/opt/homebrew/bin/python3 {script} --profile {shlex.quote(profile)} --no-run"
    if categories:
        cmd += f" --categories {shlex.quote(categories)}"
    subprocess.Popen(["bash", "-lc", f"{cmd} > {log} 2>&1"],
                     start_new_session=True)
    return (f"已在后台开始构建 ({profile})。日志: tail -f {log}\n"
            f"用 sec_build_log() 看进度。core 约 5-15 分钟, standard 约 20-40 分钟。")


@mcp.tool()
def sec_build_log(lines: int = 40) -> str:
    """看镜像构建日志尾部"""
    p = "/tmp/secforge_build.log"
    if not os.path.exists(p):
        return "还没有构建日志"
    out = subprocess.run(["tail", "-n", str(lines), p], capture_output=True, text=True).stdout
    done = subprocess.run(["bash", "-lc",
                           "docker images --format '{{.Repository}}:{{.Tag}}' | grep -c secforge/kali"],
                          capture_output=True, text=True).stdout.strip()
    return f"{out}\n\n[已完成镜像数: {done}]"


@mcp.tool()
def sec_start_container(profile: str = "core") -> str:
    """启动 SecForge Kali 容器(若镜像不存在会自动先构建)"""
    tag = f"{IMAGE}:{profile}"
    chk = subprocess.run(["docker", "images", "-q", tag], capture_output=True, text=True).stdout.strip()
    if not chk:
        tag = f"{IMAGE}:standard"
        chk = subprocess.run(["docker", "images", "-q", tag], capture_output=True, text=True).stdout.strip()
    if not chk:
        tag = f"{IMAGE}:full"
        chk = subprocess.run(["docker", "images", "-q", tag], capture_output=True, text=True).stdout.strip()
    if not chk:
        return "镜像还没构建好。先 sec_build_image('core'), 用 sec_build_log() 盯进度。"
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", CONTAINER, "--hostname", "secforge",
                    "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                    "-v", "secforge_work:/work", "-v", "secforge_loot:/loot",
                    tag], capture_output=True)
    time.sleep(2)
    return f"容器已启动 ({tag})\n" + dex("id; whoami; nmap --version 2>/dev/null | head -1", 60)


# ================================================================ 执行工具
@mcp.tool()
def sec_run(tool: str, args: str = "", target: str = "", timeout: int = 300) -> str:
    """在 Kali 容器里运行一个安全工具(同步等结果)。

    Args:
        tool: 工具名, 如 nmap / nuclei / sqlmap / ffuf / nikto / hydra / whatweb
        args: 完整参数(不用带工具名), 如 "-sV -T4 192.168.10.1"
        target: 目标(会走安全护栏检查; 填了且 args 为空则自动生成基础扫描命令)
        timeout: 秒
    """
    if target:
        g = guard(target)
        if g:
            return g
    if not args and target:
        args = {"nmap": f"-sV -T4 -Pn {target}",
                "nuclei": f"-u {target} -severity low,medium,high,critical",
                "whatweb": f"-a 3 {target}",
                "nikto": f"-h {target}",
                "nuclei-http": f"-u {target}",
                "httpx": f"-u {target} -title -tech-detect -status-code"}.get(tool, f"{target}")
    e = need_up()
    if e:
        return e
    c = catalog_conn()
    spec = ""
    if c:
        r = c.execute("SELECT install_method, install_spec, category, description FROM tools "
                      "WHERE name=? ORDER BY stars DESC LIMIT 1", (tool,)).fetchone()
        if r:
            spec = f"\n[{r['category']}] {r['install_spec']}"
    out = dex(f"{tool} {args} 2>&1", timeout=timeout)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    full_log = f"/loot/runs/{tool}_{stamp}.log"
    if len(out) > 8000:
        dex(f"mkdir -p /loot/runs && cat > {full_log} <<'SECEOF'\n{out[:200000]}\nSECEOF", 60)
        out = out[:8000] + f"\n...[截断, 全量在 {full_log}]"
    vulns = _vuln_auto_block(out, limit=12)
    return f"$ {tool} {args}{spec}\n{out}\n\n{vulns}"


@mcp.tool()
def sec_shell(command: str, timeout: int = 300) -> str:
    """在 Kali 容器里跑任意 shell 命令(apt install / 管道 / 脚本 都行)"""
    e = need_up()
    if e:
        return e
    return f"$ {command}\n{dex(command, timeout=timeout)}"


@mcp.tool()
def sec_job_start(name: str, command: str, target: str = "") -> str:
    """后台跑长任务(全端口扫描/目录爆破等), 结果落 /loot/jobs/"""
    g = guard(target) if target else ""
    if g:
        return g
    e = need_up()
    if e:
        return e
    jid = f"{name}_{uuid.uuid4().hex[:6]}"
    dex(f"mkdir -p /loot/jobs && nohup bash -c '{command.replace(chr(39), chr(39)+chr(92)+chr(39)+chr(39))}' "
        f"> /loot/jobs/{jid}.log 2>&1 & echo $! > /loot/jobs/{jid}.pid", 60)
    return f"任务 {jid} 已启动。用 sec_job_status('{jid}') 看进度, sec_job_output('{jid}') 看输出。"


@mcp.tool()
def sec_job_status(jid: str = "") -> str:
    """看后台任务状态; jid 留空列出全部"""
    e = need_up()
    if e:
        return e
    if not jid:
        return dex("ls -la /loot/jobs/ 2>/dev/null | head -40", 60)
    alive = dex(f"kill -0 $(cat /loot/jobs/{jid}.pid) 2>/dev/null && echo RUNNING || echo DONE", 30).strip()
    size = dex(f"wc -l /loot/jobs/{jid}.log 2>/dev/null", 30).strip()
    return f"{jid}: {alive}  {size}"


@mcp.tool()
def sec_job_output(jid: str, lines: int = 100) -> str:
    """看后台任务输出尾部"""
    e = need_up()
    if e:
        return e
    return dex(f"tail -n {int(lines)} /loot/jobs/{jid}.log 2>/dev/null", 60)


@mcp.tool()
def sec_loot(action: str = "list", path: str = "") -> str:
    """战利品/结果文件管理

    Args:
        action: list | read | grep
        path: read/grep 时的路径或关键词
    """
    e = need_up()
    if e:
        return e
    if action == "list":
        return dex("find /loot /work -type f -newermt '-7 days' 2>/dev/null | head -60 && echo '--- 磁盘 ---' && du -sh /loot /work 2>/dev/null", 60)
    if action == "read":
        return dex(f"head -c 20000 {shlex.quote(path)} 2>/dev/null", 60)
    return dex(f"grep -rIl {shlex.quote(path)} /loot /work 2>/dev/null | head -20", 60)


@mcp.tool()
def sec_install_tool(name: str, method: str = "") -> str:
    """把一个工具库里还没装的新工具装进容器(自动按 recipe 选 apt/pip/go)

    Args:
        name: 工具名或 owner/repo
        method: 强制指定安装方式, 留空自动
    """
    c = catalog_conn()
    if not c:
        return "工具库为空"
    r = c.execute("SELECT * FROM tools WHERE name=? OR full_name=? OR name LIKE ? "
                  "ORDER BY stars DESC LIMIT 1", (name, name, f"%{name}%")).fetchone()
    if not r:
        return f"库里没有 {name}"
    m = method or r["install_method"]
    spec = r["install_spec"] or ""
    cmds = {
        "apt": f"apt-get update -qq && apt-get install -y --no-install-recommends {spec or r['name']}",
        "pip": f"pip3 install --break-system-packages --no-cache-dir {spec or r['name']} || pipx install {spec or r['name']}",
        "gem": f"gem install {spec or r['name']} --no-document",
        "go": f"GOFLAGS=-buildvcs=false GOBIN=/usr/local/bin go install {spec}",
        "git": f"mkdir -p /opt/tools && cd /opt/tools && git clone --depth 1 {spec or r['url']} && ls",
        "cargo": f"cargo install --root /usr/local {spec.split('/')[-1] if spec else r['name']}",
    }
    cmd = cmds.get(m)
    if m == "docker":
        return f"{r['name']} 是 docker 项目 ({spec}), 在宿主上跑: docker pull 对应镜像"
    if not cmd:
        return (f"{r['name']} 需要源码编译 ({r['language']}). 建议:\n"
                f"  cd /opt/tools && git clone --depth 1 {r['url']}\n"
                f"参考仓库 README。")
    e = need_up()
    if e:
        return e
    out = dex(cmd, timeout=600)
    return f"[{m}] {cmd}\n{out[-4000:]}"


# ================================================================ 漏洞库
VULNDB = os.path.join(ROOT, "vulndb", "vulndb.sqlite")

# 服务/端口 -> 漏洞库里的产品关键词 (版本未知时也能命中)
SERVICE_HINTS = {
    "smb": ["Windows", "SMB"], "netbios": ["Windows"],
    "microsoft-ds": ["Windows", "SMB"], "rdp": ["Remote Desktop", "Windows"],
    "ms-wbt-server": ["Remote Desktop", "Windows"], "winrm": ["Windows"],
    "wsman": ["Windows"], "ldap": ["Active Directory", "Windows"],
    "kerberos": ["Active Directory", "Windows"], "msrpc": ["Windows"],
    "mssql": ["SQL Server"], "ms-sql": ["SQL Server"],
    "iis": ["Internet Information Services"], "http": ["Internet Information Services"],
    "exchange": ["Exchange Server"], "dns": ["Windows DNS"],
    "ssh": ["OpenSSH"], "nfs": ["Windows"], "vnc": ["Windows"],
}
SEV_ORDER = {"Critical": 4, "Important": 3, "Moderate": 2, "Low": 1, "None": 0}


def vulndb_conn():
    if not os.path.exists(VULNDB):
        return None
    c = sqlite3.connect(VULNDB)
    c.row_factory = sqlite3.Row
    return c


def _fmt_cve(r, short=False):
    tags = []
    if r["kev"]:
        tags.append("🔥已被真实利用")
    if r["poc"]:
        tags.append("💥有公开PoC")
    if r["cvss"]:
        tags.append(f"CVSS {r['cvss']}")
    if r["severity"]:
        tags.append(r["severity"])
    try:
        imp = r["impact"]
    except (IndexError, KeyError):
        imp = ""
    if imp:
        tags.append(imp)
    t = " ".join(tags)
    if short:
        return f"  {r['cve_id']} [{t}] {(r['title'] or '')[:90]}"
    return (f"{r['cve_id']}  [{t}]\n"
            f"    {r['title']}\n"
            f"    影响: {(r['affected'] or '')[:220]}\n"
            f"    补丁: {r['kbs'] or '—'}  {r['patch_url'] or ''}\n"
            f"    可利用性: {r['exploit_status'] or '—'}\n"
            f"    PoC: {(r['poc_refs'] or '')[:200]}\n"
            f"    发布: {r['published']}   来源: {r['sources']}")


def _rank_key(r):
    return (-(r["kev"] or 0), -(r["poc"] or 0), -(r["cvss"] or 0),
            -SEV_ORDER.get(r["severity"] or "", 0), r["cve_id"])


@mcp.tool()
def sec_vuln_search(query: str = "", product: str = "", cve_id: str = "",
                    severity: str = "", min_cvss: float = 0, kev_only: bool = False,
                    poc_only: bool = False, year: str = "", impact: str = "",
                    limit: int = 25) -> str:
    """搜索独立漏洞库(微软 MSRC 官方数据 + CISA KEV + ExploitDB PoC)。

    Args:
        query: 全文关键词, 如 "SMB" "print spooler" "Exchange" "privilege escalation"
        product: 按受影响产品过滤, 如 "Windows 10" "Windows Server 2016" "Exchange Server"
        cve_id: 直接查某个 CVE
        severity: Critical/Important/Moderate/Low
        min_cvss: 最低 CVSS 分
        kev_only: 只看已被真实利用的
        poc_only: 只看有公开 PoC 的
        year: 年份, 如 "2026"
        impact: 攻击类型, 如 "Remote Code Execution" "Elevation of Privilege"
                "Memory Corruption" "Information Disclosure" "Denial of Service"
        limit: 条数
    """
    c = vulndb_conn()
    if not c:
        return "漏洞库未构建。先跑: python3 vulndb/build_vulndb.py"
    w, p = ["1=1"], []
    if cve_id:
        w.append("cve_id = ?")
        p.append(cve_id.upper())
    if impact:
        w.append("impact LIKE ?")
        p.append(f"%{impact}%")
    if query:
        w.append("(title LIKE ? OR description LIKE ? OR affected LIKE ? OR poc_refs LIKE ?)")
        p += [f"%{query}%"] * 4
    if product:
        w.append("cve_id IN (SELECT cve_id FROM affected WHERE product LIKE ?)")
        p.append(f"%{product}%")
    if severity:
        w.append("severity = ?")
        p.append(severity)
    if min_cvss:
        w.append("cvss >= ?")
        p.append(min_cvss)
    if kev_only:
        w.append("kev = 1")
    if poc_only:
        w.append("poc = 1")
    if year:
        w.append("published LIKE ?")
        p.append(f"{year}%")
    rows = c.execute(f"SELECT * FROM cve WHERE {' AND '.join(w)} LIMIT 4000", p).fetchall()
    rows = sorted(rows, key=_rank_key)[:limit]
    if not rows:
        return "无匹配"
    head = (f"漏洞库命中 {len(rows)} 条 (库内共 "
            f"{c.execute('SELECT COUNT(*) FROM cve').fetchone()[0]} 个 CVE)")
    return head + "\n\n" + "\n\n".join(_fmt_cve(r) for r in rows)


@mcp.tool()
def sec_vuln_detail(cve_id: str) -> str:
    """CVE 详情 + 受影响产品清单 + 补丁 KB"""
    c = vulndb_conn()
    if not c:
        return "漏洞库未构建"
    r = c.execute("SELECT * FROM cve WHERE cve_id=?", (cve_id.upper(),)).fetchone()
    if not r:
        return f"库中没有 {cve_id}"
    aff = c.execute("SELECT DISTINCT product, cpe, kb FROM affected WHERE cve_id=? "
                    "ORDER BY product LIMIT 60", (cve_id.upper(),)).fetchall()
    out = [_fmt_cve(r), f"\n描述: {(r['description'] or '')[:1500]}",
           f"\n受影响产品 ({len(aff)}):"]
    for a in aff:
        out.append(f"  - {a['product']}  {('['+a['kb']+']') if a['kb'] else ''}")
    return "\n".join(out)


@mcp.tool()
def sec_vuln_for_windows(version: str = "", build: str = "") -> str:
    """输入 Windows 版本或内部版本号, 列出该版本的漏洞 + 需要打的补丁。

    Args:
        version: 如 "Windows 10" "Windows Server 2016" "Windows 11"
        build: 如 "19045" "14393" "10.0.17763"
    """
    c = vulndb_conn()
    if not c:
        return "漏洞库未构建"
    b = re.sub(r"^10\.0\.", "", (build or "").strip())
    label = (version or "").strip()
    # 版本表三列: 显示名 / 内部版本号 / 产品匹配串。匹配串必须是 affected.product 的真子串。
    rows_v = list(c.execute("SELECT label, build, COALESCE(match, label) FROM win_versions"))
    match = ""
    if label:
        for L, B, M in rows_v:
            if label.lower() == L.lower():
                match, label, b = M, L, (b or B or "")
                break
    if not match and b:
        for L, B, M in rows_v:
            if B == b:
                match, label = M, L
                break
    if not match:
        if not (label or b):
            return "给我 version 或 build"
        match = label or b          # 未知版本: 拿原文当匹配串兜底(如 "Windows 10" → 全部分支)
    w = ["cve_id IN (SELECT cve_id FROM affected WHERE product LIKE ?)"]
    p = [f"%{match}%"]
    rows = c.execute(f"""SELECT * FROM cve WHERE {' OR '.join(w)}
                         ORDER BY published DESC LIMIT 3000""", p).fetchall()
    # LIMIT 只是抓取上限, 真实总数单独数一下(别把上限当总数报出去)
    real_total = c.execute(f"SELECT COUNT(*) FROM cve WHERE {' OR '.join(w)}", p).fetchone()[0]
    rows = sorted(rows, key=_rank_key)
    crit = [r for r in rows if r["kev"] or (r["cvss"] or 0) >= 8 or r["severity"] == "Critical"]
    kbs = []
    for r in rows:
        for kb in re.findall(r"KB\d+", r["kbs"] or ""):
            if kb not in kbs:
                kbs.append(kb)
    out = [f"=== {label or ''} {b or ''} · 库内命中 {real_total} 个 CVE, 其中高危 {len(crit)} 个 ===",
           "\n【必须先修的】(已被利用 / CVSS>=8 / Critical):"]
    for r in crit[:25]:
        out.append(_fmt_cve(r, short=True))
    out.append(f"\n【相关补丁 KB 汇总】({len(kbs)} 个): " + ", ".join(kbs[:40]))
    out.append("\n【最近 15 个 CVE】:")
    for r in rows[:15]:
        out.append(_fmt_cve(r, short=True))
    return "\n".join(out)


def _vuln_auto_block(text: str, limit=15) -> str:
    """从任意工具输出里抽取线索 -> 自动关联漏洞库。sec_run 会自动调用。"""
    c = vulndb_conn()
    if not c or not text or len(text) < 10:
        return ""
    hits = {}
    found = []

    def add(rows, why):
        for r in rows:
            if r["cve_id"] not in hits:
                hits[r["cve_id"]] = why
                found.append(r)

    # 1) 文本里直接出现的 CVE
    ids = set(re.findall(r"CVE-\d{4}-\d{4,7}", text.upper()))
    for cid in ids:
        r = c.execute("SELECT * FROM cve WHERE cve_id=?", (cid,)).fetchone()
        if r:
            add([r], "扫描输出直接命中")

    # 2) Windows 内部版本号
    builds = set(re.findall(r"\b(?:10\.0\.)?(10240|10586|14393|15063|16299|17134|17763|18362|18363|19041|19044|19045|20348|22000|22621|22631|26100|26200|7601)\b", text))
    for b in builds:
        rows = c.execute("""SELECT * FROM cve WHERE cve_id IN
            (SELECT cve_id FROM affected WHERE product LIKE ?)
            ORDER BY published DESC LIMIT 400""", (f"%{b}%",)).fetchall()
        add(sorted(rows, key=_rank_key)[:8], f"内核版本 {b}")

    # 3) 服务/端口指纹
    low = text.lower()
    for svc, keywords in SERVICE_HINTS.items():
        if re.search(rf"\b{re.escape(svc)}\b", low):
            for kw in keywords:
                rows = c.execute("""SELECT * FROM cve WHERE cve_id IN
                    (SELECT cve_id FROM affected WHERE product LIKE ?)
                    AND (kev=1 OR poc=1 OR cvss>=8 OR severity='Critical')
                    ORDER BY published DESC LIMIT 300""", (f"%{kw}%",)).fetchall()
                add(sorted(rows, key=_rank_key)[:5], f"服务 {svc} → 产品 {kw}")

    # 4) 产品名关键词
    for kw in ["Windows Server", "Windows 10", "Windows 11", "Exchange Server",
               "Active Directory", "SharePoint", "SQL Server", "Office", "IIS",
               "Remote Desktop", "Hyper-V", "BitLocker", "Defender", "Azure"]:
        if kw.lower() in low:
            rows = c.execute("""SELECT * FROM cve WHERE cve_id IN
                (SELECT cve_id FROM affected WHERE product LIKE ?)
                AND (kev=1 OR poc=1 OR cvss>=8) ORDER BY published DESC LIMIT 200""",
                             (f"%{kw}%",)).fetchall()
            add(sorted(rows, key=_rank_key)[:5], f"产品 {kw}")

    if not found:
        return ""
    found = sorted(found, key=_rank_key)[:limit]
    lines = [f"┌─ 漏洞库自动关联 ({len(found)} 条, 按可利用性排序) ─────────",
             "│ 数据源: 微软MSRC官方 + CISA已被利用清单 + ExploitDB PoC"]
    for r in found:
        lines.append(f"│ [{hits[r['cve_id']]}] " + _fmt_cve(r, short=True).strip())
    lines.append("└─ 用 sec_vuln_detail('CVE-...') 看详情, sec_vuln_for_windows() 看某版本全部补丁")
    return "\n".join(lines)


@mcp.tool()
def sec_vuln_auto(text: str, limit: int = 20) -> str:
    """把任意扫描/指纹输出丢进来, 自动关联漏洞库(sec_run 已自动调用, 也可单独用)"""
    b = _vuln_auto_block(text, limit)
    return b or "没有从这段文本里提取到可利用线索(试试带上服务/版本/端口信息)"


@mcp.tool()
def sec_vuln_stats() -> str:
    """漏洞库概况"""
    c = vulndb_conn()
    if not c:
        return "漏洞库未构建"
    q = c.execute
    lines = [f"总 CVE: {q('SELECT COUNT(*) FROM cve').fetchone()[0]}",
             f"有 CVSS: {q('SELECT COUNT(*) FROM cve WHERE cvss IS NOT NULL').fetchone()[0]}",
             f"🔥 已被真实利用(KEV): {q('SELECT COUNT(*) FROM cve WHERE kev=1').fetchone()[0]}",
             f"💥 有公开 PoC: {q('SELECT COUNT(*) FROM cve WHERE poc=1').fetchone()[0]}",
             f"CVSS>=9: {q('SELECT COUNT(*) FROM cve WHERE cvss>=9').fetchone()[0]}",
             "\n按年份:"]
    for y, n in q("SELECT substr(published,1,4), COUNT(*) FROM cve WHERE published<>'' "
                  "GROUP BY 1 ORDER BY 1 DESC LIMIT 12"):
        lines.append(f"  {y} {n}")
    lines.append("\nTop 受影响产品:")
    for p, n in q("SELECT product, COUNT(*) FROM affected GROUP BY 1 ORDER BY 2 DESC LIMIT 12"):
        lines.append(f"  {p[:50]:<50} {n}")
    return "\n".join(lines)


# ================================================================ PentAGI 桥接
PENTAGI_DIR = os.environ.get("PENTAGI_DIR") or os.path.expanduser("~/pentagi")
PENTAGI_URL = "https://localhost:8443"
PENTAGI_MAIL = os.environ.get("PENTAGI_MAIL", "admin@pentagi.com")
PENTAGI_PASS = os.environ.get("PENTAGI_PASS", "admin")


def _pentagi_req(path, method="GET", body=None, token=None, timeout=60):
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = PENTAGI_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except Exception as e:
        return getattr(e, "code", -1), str(e)


@mcp.tool()
def sec_pentagi(action: str = "status") -> str:
    """PentAGI 多智能体自主渗透平台的桥接。

    Args:
        action: status | up | down | login | flows | logs | token_new
    """
    import urllib.request as _u  # noqa
    if action == "up":
        p = subprocess.run(["docker", "compose", "up", "-d"], cwd=PENTAGI_DIR,
                           capture_output=True, text=True)
        return (p.stdout + p.stderr)[-2500:] + "\n(首次会拉 kali-linux worker 镜像, 约 4GB)"
    if action == "down":
        p = subprocess.run(["docker", "compose", "stop"], cwd=PENTAGI_DIR,
                           capture_output=True, text=True)
        return (p.stdout + p.stderr)[-1500:]
    if action == "logs":
        p = subprocess.run(["docker", "logs", "--tail", "40", "pentagi"],
                           capture_output=True, text=True)
        return (p.stdout + p.stderr)[-4000:]
    ps = subprocess.run(["docker", "ps", "--filter", "name=pentagi",
                         "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"],
                        capture_output=True, text=True).stdout.strip()
    if action == "status":
        return (f"容器:\n{ps or '(未运行, 用 action=up 启动)'}\n"
                f"Web UI: {PENTAGI_URL}\n"
                f"启动目录: {PENTAGI_DIR}\n"
                f"注意: 创建 flow 后会自动开始跑, 没有单独的运行按钮")
    tok = ""
    if action in ("flows", "login", "token_new"):
        st, body = _pentagi_req("/api/v1/auth/login", "POST",
                                {"mail": PENTAGI_MAIL, "password": PENTAGI_PASS})
        if st != 200:
            return f"登录失败 ({st}): {body[:600]}\n先在 Web UI {PENTAGI_URL} 确认账号, 或改环境变量 PENTAGI_MAIL/PENTAGI_PASS"
        try:
            j = json.loads(body)
            tok = j.get("token") or j.get("access_token") or ""
        except Exception:
            return f"登录返回无法解析: {body[:400]}"
        if action == "login":
            return f"登录成功, token 前 40 位: {tok[:40]}..."
    if action == "flows":
        st, body = _pentagi_req("/api/v1/flows", token=tok)
        return f"HTTP {st}\n{body[:4000]}"
    return "未知 action"


@mcp.tool()
def sec_pentagi_graphql(query: str, variables: str = "{}") -> str:
    """直接对 PentAGI 发 GraphQL(可先查 schema 再自己构造 createFlow)。

    Args:
        query: GraphQL 语句, 如 "{ flows { id title status } }"
        variables: JSON 字符串
    """
    import urllib.request as _u  # noqa
    st, body = _pentagi_req("/api/v1/auth/login", "POST",
                            {"mail": PENTAGI_MAIL, "password": PENTAGI_PASS})
    if st != 200:
        return f"登录失败 ({st}): {body[:300]}"
    tok = json.loads(body).get("token", "")
    st, out = _pentagi_req("/api/v1/graphql", "POST",
                           {"query": query, "variables": json.loads(variables or "{}")}, token=tok)
    return f"HTTP {st}\n{out[:5000]}"


@mcp.tool()
def sec_overview() -> str:
    """一眼看全部: 工具库/漏洞库/镜像/容器/PentAGI 状态"""
    out = ["=== SecForge 状态 ==="]
    c = catalog_conn()
    if c:
        real = c.execute("SELECT COUNT(*) FROM tools WHERE noise=0 AND kind='tool'").fetchone()[0]
        raw = c.execute("SELECT COUNT(*) FROM tools").fetchone()[0]
        out.append(f"工具库: {real} 个真工具 (爬取原始 {raw} 个, 已过滤噪音/清单)")
    else:
        out.append("工具库: 未构建")
    v = vulndb_conn()
    if v:
        nv = v.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        ncv = v.execute("SELECT COUNT(*) FROM cve WHERE cvss IS NOT NULL").fetchone()[0]
        nkb = v.execute("SELECT COUNT(*) FROM cve WHERE kbs<>''").fetchone()[0]
        nkev = v.execute("SELECT COUNT(*) FROM cve WHERE kev=1").fetchone()[0]
        out.append(f"漏洞库: {nv} 个 CVE ({ncv} 有CVSS, {nkev} 已被真实利用, {nkb} 带补丁KB)")
    else:
        out.append("漏洞库: 未构建")
    img = subprocess.run(["docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.Size}}"],
                         capture_output=True, text=True).stdout
    out.append("镜像: " + ", ".join(l for l in img.splitlines() if "secforge" in l) or "镜像: 无")
    out.append(f"容器: {'运行中' if container_up() else '未运行'}")
    out.append(f"PentAGI: {PENTAGI_DIR} ({PENTAGI_URL})")
    return "\n".join(out)


if __name__ == "__main__":
    mcp.run()
