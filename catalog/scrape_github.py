#!/usr/bin/env python3
"""SecForge - GitHub 安全工具爬虫

爬取 GitHub 上所有扫描/攻击/防御/漏洞类工具, 分类归档到 SQLite。
认证走 gh CLI (已登录), 5000 req/h; search 接口 30 req/min -> 自动限速。
用法: python3 scrape_github.py [--pages 2] [--min-stars 30]
"""
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "catalog.sqlite")
RAW = os.path.join(HERE, "raw_repos.json")

# ---------------------------------------------------------------- 抓取源
# 1) topic 维度: 覆盖扫描/攻击/防御/漏洞/取证/逆向/情报
TOPICS = [
    "penetration-testing", "pentest", "security-tools", "hacking", "hacking-tool",
    "vulnerability-scanner", "vulnerability-detection", "exploit", "exploitation",
    "red-team", "blueteam", "blue-team", "purple-team", "offensive-security",
    "network-security", "web-security", "application-security", "cloud-security",
    "container-security", "supply-chain-security", "devsecops",
    "password-cracking", "brute-force", "wifi-hacking", "wireless-security",
    "osint", "reconnaissance", "subdomain-enumeration", "port-scanner",
    "fuzzing", "fuzzer", "malware-analysis", "reverse-engineering",
    "digital-forensics", "incident-response", "threat-hunting",
    "threat-intelligence", "siem", "ids", "ips", "honeypot", "c2",
    "post-exploitation", "privilege-escalation", "ctf-tools", "bugbounty",
    "sql-injection", "xss", "rce", "payload", "shellcode", "antivirus",
    "infosec", "cybersecurity", "kali-linux", "linux-hardening", "firewall",
    "vulnerability-management", "easm", "attack-surface", "api-security",
    "mobile-security", "android-security", "iot-security", "hardware-hacking",
    "social-engineering", "phishing", "log-analysis", "packet-capture",
    "network-analysis", "proxy", "scanner", "enumeration", "audit",
    "security-audit", "compliance", "honeypots", "antiforensics",
]

# 2) 关键字搜索维度: 兜底, 抓 topic 没覆盖到的
QUERIES = [
    "vulnerability scanner in:name,description,readme stars:>200",
    "penetration testing framework in:name,description,readme stars:>300",
    "exploitation framework in:name,description stars:>200",
    "subdomain enumeration in:name,description stars:>100",
    "web fuzzer in:name,description stars:>200",
    "IDS intrusion detection in:name,description stars:>300",
    "SIEM security information event management in:name,description stars:>200",
    "malware analysis in:name,description stars:>200",
    "reverse engineering tool in:name,description stars:>300",
    "forensics tool in:name,description stars:>200",
    "OSINT framework in:name,description stars:>200",
    "C2 framework in:name,description stars:>200",
    "privilege escalation in:name,description stars:>100",
    "password cracker in:name,description stars:>200",
    "wifi attack tool in:name,description stars:>100",
    "payload generator in:name,description stars:>100",
    "security scanner in:name,description stars:>500",
    "vulnerability management in:name,description stars:>200",
    "attack surface management in:name,description stars:>100",
    "threat detection in:name,description stars:>200",
]

# ---------------------------------------------------------------- 分类规则
# 顺序敏感: 先匹配的先赢
CATEGORY_RULES = [
    ("漏洞利用/Exploit", ["exploit", "exploitation", "metasploit", "rce", "0day", "poc-", "payload", "shellcode", "c2", "command-and-control", "post-exploitation", "privilege-escalation", "privesc", "lateral-movement", "implant", "rat-"]),
    ("无线/Wireless", ["wifi", "wireless", "wpa", "wep", "bluetooth", "sdr", "rfid", "nfc", "802.11", "deauth", "aircrack"]),
    ("Web 安全", ["web-security", "sql-injection", "sqli", "xss", "csrf", "ssrf", "web-shell", "waf", "web-app", "api-security", "rest-api-security", "jwt", "directory-brute", "fuzzing", "fuzzer", "burp", "web-scanner"]),
    ("扫描/侦察/Recon", ["scanner", "scanning", "recon", "reconnaissance", "enumeration", "subdomain", "port-scan", "nmap", "asset-discovery", "attack-surface", "easm", "fingerprint", "crawler", "osint", "shodan", "google-dork", "social-engineering", "phishing", "information-gathering", "footprinting"]),
    ("密码/认证", ["password", "hashcat", "john-the-ripper", "brute-force", "credential", "kerberos", "kerberoast", "cracking", "wordlist", "auth-bypass"]),
    ("漏洞库/管理", ["vulnerability-management", "vulnerability-detection", "cve", "nvd", "vulnerability-scanner", "sca", "sbom", "dependency-check", "patch-management", "cve-database", "advisory", "bug-bounty-tool"]),
    ("防御/蓝队/检测", ["blue-team", "blueteam", "defense", "detection", "ids", "ips", "edr", "hids", "nids", "yara", "sigma", "siem", "soc-", "threat-hunting", "threat-detection", "hardening", "firewall", "honeypot", "antivirus", "malware-detection", "log-analysis", "monitoring", "audit", "compliance", "benchmark", "cis-", "ration", "purple-team", "deception"]),
    ("威胁情报/OSINT", ["threat-intelligence", "threat-intel", "ioc", "osint", "cti", "attack-surface", "dark-web", "leak", "intelligence", "mitre", "attck", "hunting"]),
    ("取证/应急响应", ["forensics", "forensic", "incident-response", "dfir", "memory-dump", "volatility", "disk-image", "evidence", "artifact", "timeline", "acquisition", "triage"]),
    ("逆向/恶意代码分析", ["reverse-engineering", "reversing", "disassembler", "decompiler", "ghidra", "ida", "radare", "binary-analysis", "malware", "disassembly", "debugger", "emulation", "unpacker", "firmware", "android-security", "mobile-security", "ios-security", "apk"]),
    ("云/容器/供应链", ["cloud-security", "aws", "azure", "gcp", "kubernetes", "k8s", "docker-security", "container-security", "iac", "terraform", "supply-chain", "devsecops", "cicd-security", "sast", "dast", "secrets-detection", "serverless"]),
    ("网络/流量分析", ["network-security", "packet-capture", "pcap", "sniffer", "proxy", "mitm", "network-analysis", "traffic-analysis", "tunnel", "vpn", "dns-security", "ssl", "tls", "netflow", "router", "switch-"]),
    ("硬件/物联网", ["hardware-hacking", "iot", "embedded", "firmware", "uart", "jtag", "swd", "logic-analyzer", "badusb", "rf"]),
    ("CTF/靶场/学习", ["ctf", "capture-the-flag", "vulnerable", "dvwa", "juice-shop", "lab", "practice", "cheatsheet", "awesome-list", "awesome-", "roadmap", "learning", "writeup", "payloadsallthethings", "training", "hackthebox"]),
]

INSTALL_OVERRIDES = {
    "nmap": ("apt", "nmap"),
    "sqlmap": ("apt", "sqlmap"),
    "metasploit": ("apt", "metasploit-framework"),
    "burp": ("manual", "Burp Suite (GUI/JAR)"),
    "nuclei": ("go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "subfinder": ("go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx": ("go", "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "naabu": ("go", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    "katana": ("go", "github.com/projectdiscovery/katana/cmd/katana@latest"),
    "ffuf": ("go", "github.com/ffuf/ffuf/v2@latest"),
    "gobuster": ("go", "github.com/OJ/gobuster/v3@latest"),
    "amass": ("go", "github.com/owasp-amass/amass/v4/...@master"),
    "feroxbuster": ("apt", "feroxbuster"),
    "hydra": ("apt", "hydra"),
    "hashcat": ("apt", "hashcat"),
    "john": ("apt", "john"),
    "aircrack-ng": ("apt", "aircrack-ng"),
    "wireshark": ("apt", "tshark"),
    "responder": ("git", "https://github.com/lgandx/Responder"),
    "impacket": ("pip", "impacket"),
    "bloodhound": ("apt", "bloodhound"),
    "sliver": ("go", "github.com/BishopFox/sliver/client@latest"),
    "chisel": ("go", "github.com/jpillora/chisel@latest"),
    "linpeas": ("git", "https://github.com/peass-ng/PEASS-ng"),
    "winpeas": ("git", "https://github.com/peass-ng/PEASS-ng"),
    "prowler": ("pip", "prowler"),
    "trivy": ("apt", "trivy"),
    "grype": ("curl-release", "anchore/grype"),
    "semgrep": ("pip", "semgrep"),
    "openvas": ("apt", "gvm"),
    "wpscan": ("gem", "wpscan"),
    "zaproxy": ("apt", "zaproxy"),
    "volatility": ("pip", "volatility3"),
    "yara": ("apt", "yara"),
    "ghidra": ("apt", "ghidra"),
    "radare2": ("apt", "radare2"),
    "binwalk": ("apt", "binwalk"),
    "mitmproxy": ("pip", "mitmproxy"),
    "bettercap": ("go", "github.com/bettercap/bettercap@latest"),
    "theharvester": ("apt", "theharvester"),
    "recon-ng": ("apt", "recon-ng"),
    "spiderfoot": ("pip", "spiderfoot"),
    "sherlock": ("pip", "sherlock-project"),
    "exploitdb": ("apt", "exploitdb"),
    "searchsploit": ("apt", "exploitdb"),
    "amass-cli": ("apt", "amass"),
    "kube-hunter": ("pip", "kube-hunter"),
    "kubescape": ("curl-release", "kubescape/kubescape"),
    "checkov": ("pip", "checkov"),
    "tfsec": ("curl-release", "aquasecurity/tfsec"),
    "zeek": ("apt", "zeek"),
    "suricata": ("apt", "suricata"),
    "snort": ("apt", "snort"),
    "osquery": ("apt", "osquery"),
    "atomic-red-team": ("git", "https://github.com/redcanaryco/atomic-red-team"),
    "caldera": ("git", "https://github.com/mitre/caldera"),
    "empire": ("git", "https://github.com/BC-SECURITY/Empire"),
    "havoc": ("git", "https://github.com/HavocFramework/Havoc"),
    "mythic": ("git", "https://github.com/its-a-feature/Mythic"),
}


def sh(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"


def gh_api(path, retries=4):
    """调用 GitHub API, 处理限速"""
    for i in range(retries):
        rc, out, err = sh(["gh", "api", path], timeout=90)
        if rc == 0:
            try:
                return json.loads(out)
            except json.JSONDecodeError:
                return None
        if "rate limit" in (err + out).lower() or "403" in err or "abuse" in err.lower():
            wait = 20 * (i + 1)
            print(f"    限速, 等 {wait}s ...", flush=True)
            time.sleep(wait)
            continue
        print(f"    ! api 错误: {err.strip()[:200]}", flush=True)
        time.sleep(3)
    return None


def norm_repo(r, source):
    if not r or r.get("archived"):
        pass  # 归档的也留, 标记一下
    return {
        "full_name": r.get("full_name"),
        "name": r.get("name"),
        "owner": (r.get("owner") or {}).get("login"),
        "stars": r.get("stargazers_count") or 0,
        "forks": r.get("forks_count") or 0,
        "description": (r.get("description") or "")[:600],
        "language": r.get("language") or "",
        "topics": ",".join(r.get("topics") or []),
        "license": ((r.get("license") or {}).get("spdx_id") or ""),
        "url": r.get("html_url"),
        "homepage": r.get("homepage") or "",
        "created_at": (r.get("created_at") or "")[:10],
        "pushed_at": (r.get("pushed_at") or "")[:10],
        "archived": 1 if r.get("archived") else 0,
        "is_fork": 1 if r.get("fork") else 0,
        "open_issues": r.get("open_issues_count") or 0,
        "source": source,
    }


def classify(repo):
    blob = " ".join([
        repo["name"] or "", repo["description"] or "",
        repo["topics"] or "", (repo["full_name"] or "").split("/")[0],
    ]).lower()
    for cat, kws in CATEGORY_RULES:
        for k in kws:
            if k in blob:
                return cat
    return "其他/未分类"


def install_hint(repo):
    """推断安装方式: (method, spec)"""
    name = (repo["name"] or "").lower()
    full = (repo["full_name"] or "").lower()
    for key, val in INSTALL_OVERRIDES.items():
        if key == name or key in full:
            return val
    lang = (repo["language"] or "").lower()
    blob = ((repo["description"] or "") + repo["topics"]).lower()
    if lang == "go":
        return ("go", repo["full_name"])
    if lang == "python":
        return ("pip", repo["full_name"])
    if lang == "rust":
        return ("cargo", repo["full_name"])
    if lang == "ruby":
        return ("gem", repo["full_name"])
    if lang in ("shell", "dockerfile"):
        return ("git", repo["url"])
    if "docker" in blob or "dockerfile" in blob:
        return ("docker", repo["full_name"])
    if lang in ("c", "c++", "c#", "java", "javascript", "typescript", "php", "perl"):
        return ("source-build", repo["url"])
    if lang == "html" or lang == "markdown":
        return ("reference", repo["url"])
    return ("unknown", repo["url"])


def main():
    pages = 2
    min_stars = 30
    if "--pages" in sys.argv:
        pages = int(sys.argv[sys.argv.index("--pages") + 1])
    if "--min-stars" in sys.argv:
        min_stars = int(sys.argv[sys.argv.index("--min-stars") + 1])

    seen = {}
    if os.path.exists(RAW):
        try:
            seen = {r["full_name"]: r for r in json.load(open(RAW))}
            print(f"续跑: 已有 {len(seen)} 个仓库")
        except Exception:
            seen = {}

    # ---- topic 抓取
    for i, t in enumerate(TOPICS, 1):
        for p in range(1, pages + 1):
            q = urllib.parse.quote(f"topic:{t} stars:>={min_stars}")
            data = gh_api(f"search/repositories?q={q}&sort=stars&order=desc&per_page=100&page={p}")
            items = (data or {}).get("items") or []
            for r in items:
                nr = norm_repo(r, f"topic:{t}")
                if nr["full_name"] and not nr["is_fork"]:
                    seen[nr["full_name"]] = nr
            print(f"[{i}/{len(TOPICS)}] topic:{t} p{p} -> +{len(items)} (总 {len(seen)})", flush=True)
            if len(items) < 100:
                break
            time.sleep(2.2)
        json.dump(list(seen.values()), open(RAW, "w"), ensure_ascii=False)

    # ---- 关键字抓取
    for i, q0 in enumerate(QUERIES, 1):
        q = urllib.parse.quote(q0)
        data = gh_api(f"search/repositories?q={q}&sort=stars&order=desc&per_page=100&page=1")
        items = (data or {}).get("items") or []
        for r in items:
            nr = norm_repo(r, f"query:{q0.split()[0]}")
            if nr["full_name"] and not nr["is_fork"]:
                seen[nr["full_name"]] = nr
        print(f"[kw {i}/{len(QUERIES)}] {q0[:40]} -> +{len(items)} (总 {len(seen)})", flush=True)
        time.sleep(2.2)

    repos = list(seen.values())

    # ---- 入库
    con = sqlite3.connect(DB)
    c = con.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS tools(
        full_name TEXT PRIMARY KEY, name TEXT, owner TEXT, stars INTEGER, forks INTEGER,
        description TEXT, language TEXT, topics TEXT, license TEXT, url TEXT, homepage TEXT,
        created_at TEXT, pushed_at TEXT, archived INTEGER, open_issues INTEGER,
        source TEXT, category TEXT, install_method TEXT, install_spec TEXT, score REAL)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_cat ON tools(category)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_stars ON tools(stars)")

    for r in repos:
        cat = classify(r)
        meth, spec = install_hint(r)
        # 打分: 星级对数 + 活跃度
        import math
        score = math.log10(r["stars"] + 10) * 10
        if r["pushed_at"] and r["pushed_at"] >= "2024-01-01":
            score += 5
        if r["archived"]:
            score -= 12
        if r["description"]:
            score += 2
        c.execute("""INSERT OR REPLACE INTO tools VALUES
            (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (r["full_name"], r["name"], r["owner"], r["stars"], r["forks"],
                   r["description"], r["language"], r["topics"], r["license"], r["url"],
                   r["homepage"], r["created_at"], r["pushed_at"], r["archived"],
                   r["open_issues"], r["source"], cat, meth, spec, round(score, 2)))
    con.commit()

    print("\n" + "=" * 60)
    print(f"总数: {len(repos)}")
    for row in c.execute("SELECT category, COUNT(*), MAX(stars) FROM tools GROUP BY category ORDER BY COUNT(*) DESC"):
        print(f"  {row[0]:<22} {row[1]:>5}  (最高★{row[2]})")
    print("\n安装方式分布:")
    for row in c.execute("SELECT install_method, COUNT(*) FROM tools GROUP BY install_method ORDER BY COUNT(*) DESC"):
        print(f"  {row[0]:<16} {row[1]:>5}")
    con.close()
    print(f"\n→ {DB}")


if __name__ == "__main__":
    main()
