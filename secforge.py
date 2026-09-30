#!/usr/bin/env python3
"""SecForge CLI —— 不开 AI 也能用的一体化入口
    secforge build [core|standard|full]      构建 Kali 镜像
    secforge up / down / sh                  起停容器 / 进 shell
    secforge tools <关键词>                   搜工具库
    secforge vuln <关键词>                    搜漏洞库
    secforge win <build>                      Windows 版本漏洞+补丁
    secforge scan <目标>                      一键 nmap+nuclei 并自动关联 CVE
    secforge mcp                             打印 MCP 配置片段
"""
import os
import re
import sqlite3
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
PY = os.path.join(ROOT, ".venv", "bin", "python")
CAT = os.path.join(ROOT, "catalog", "catalog.sqlite")
VDB = os.path.join(ROOT, "vulndb", "vulndb.sqlite")
CONTAINER = "secforge"


def dex(cmd, timeout=600):
    p = subprocess.run(["docker", "exec", CONTAINER, "bash", "-lc", cmd],
                       capture_output=True, text=True, timeout=timeout)
    return p.stdout + p.stderr


def catalog(args, limit=20):
    if not os.path.exists(CAT):
        return print("工具库为空: 先跑 catalog/scrape_github.py")
    c = sqlite3.connect(CAT)
    kw = " ".join(args)
    rows = c.execute("""SELECT name,stars,category,install_method,description,url
                        FROM tools WHERE name LIKE ? OR description LIKE ? OR topics LIKE ?
                        ORDER BY score DESC LIMIT ?""",
                     (f"%{kw}%",) * 2 + (f"%{kw}%", limit)).fetchall()
    for r in rows:
        print(f"★{r[1]:<6} {r[0]:<24} [{r[2]}] {r[3]}\n    {(r[4] or '')[:110]}\n    {r[5]}")
    print(f"\n{len(rows)} 条")


def vuln(args, limit=15):
    if not os.path.exists(VDB):
        return print("漏洞库为空: 先跑 vulndb/build_vulndb.py")
    c = sqlite3.connect(VDB)
    c.row_factory = sqlite3.Row
    kw = " ".join(args)
    rows = c.execute("""SELECT * FROM cve WHERE title LIKE ? OR description LIKE ?
                        OR affected LIKE ? LIMIT 3000""", (f"%{kw}%",) * 3).fetchall()
    rows = sorted(rows, key=lambda r: (-(r["kev"] or 0), -(r["poc"] or 0), -(r["cvss"] or 0)))[:limit]
    for r in rows:
        t = " ".join(x for x in [
            "🔥已被利用" if r["kev"] else "", "💥PoC" if r["poc"] else "",
            f"CVSS {r['cvss']}" if r["cvss"] else "", r["severity"] or ""] if x)
        print(f"{r['cve_id']} [{t}]\n    {(r['title'] or '')[:100]}\n"
              f"    影响: {(r['affected'] or '')[:130]}\n    补丁: {r['kbs'] or '—'}")
    print(f"\n{len(rows)} 条")


def win(args):
    b = re.sub(r"^10\.0\.", "", args[0]) if args else ""
    c = sqlite3.connect(VDB)
    c.row_factory = sqlite3.Row
    rows = c.execute("""SELECT * FROM cve WHERE cve_id IN
        (SELECT cve_id FROM affected WHERE product LIKE ?)
        ORDER BY published DESC LIMIT 2000""", (f"%{b}%",)).fetchall()
    crit = sorted([r for r in rows if r["kev"] or (r["cvss"] or 0) >= 8 or r["severity"] == "Critical"],
                  key=lambda r: (-(r["kev"] or 0), -(r["cvss"] or 0)))
    print(f"=== build {b}: 命中 {len(rows)} 个 CVE, 高危 {len(crit)} 个 ===")
    for r in crit[:30]:
        print(f"  {r['cve_id']} [{'🔥' if r['kev'] else ''}{'💥' if r['poc'] else ''} CVSS {r['cvss']}] "
              f"{(r['title'] or '')[:80]}  {r['kbs'] or ''}")


def scan(target):
    print(">>> nmap 服务识别 ...")
    out1 = dex(f"nmap -sV -T4 -Pn --top-ports 1000 {target} 2>&1", 900)
    print(out1[-6000:])
    print("\n>>> nuclei 漏洞扫描 ...")
    out2 = dex(f"nuclei -u {target} -severity low,medium,high,critical -silent 2>&1 | head -200", 1800)
    print(out2[-4000:])
    sys.path.insert(0, os.path.join(ROOT, "mcp"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("srv", os.path.join(ROOT, "mcp", "server.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    print("\n" + (m._vuln_auto_block(out1 + out2, 20) or "无自动关联结果"))


def mcp_conf():
    print(f"""把下面加进 ~/.hermes/config.yaml:
mcp_servers:
  secforge:
    command: "{PY}"
    args: ["{os.path.join(ROOT, 'mcp', 'server.py')}"]
    timeout: 900""")


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__)
    elif a[0] == "build":
        os.execv("/opt/homebrew/bin/python3",
                 ["python3", os.path.join(ROOT, "image", "build_image.py"),
                  "--profile", a[1] if len(a) > 1 else "standard"])
    elif a[0] == "up":
        subprocess.run(["docker", "start", CONTAINER])
    elif a[0] == "down":
        subprocess.run(["docker", "stop", CONTAINER])
    elif a[0] == "sh":
        os.system(f"docker exec -it {CONTAINER} bash")
    elif a[0] == "tools":
        catalog(a[1:])
    elif a[0] == "vuln":
        vuln(a[1:])
    elif a[0] == "win":
        win(a[1:])
    elif a[0] == "scan":
        scan(a[1])
    elif a[0] == "mcp":
        mcp_conf()
    else:
        print(__doc__)
