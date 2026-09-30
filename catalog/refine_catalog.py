#!/usr/bin/env python3
"""SecForge 目录精炼器 —— 把爬来的原始仓库过滤成真正的安全工具库。

问题: topic/keyword 搜索会带进大量噪音 (awesome-python / v2rayN / public-apis /
one-api / books ...), 它们只是描述里恰好出现了 hacking/proxy/awesome 就混进来了。

做三件事:
  1. noise 标记: 必须命中「安全术语」或「安全 topic」, 否则标 noise=1 (默认不出现在检索里)
  2. kind 分类:  tool(真工具) / reference(awesome-list、手册、路线图) / data / unknown
  3. category 重算: 更严格的规则 + noise 不打分

用法: python3 refine_catalog.py [--drop-noise]
"""
import argparse
import re
import sqlite3

HERE_DB = "catalog.sqlite"

# ① GitHub 上明确属于安全领域的 topic (爬取时按这些 topic 来的, 命中即认为安全)
SEC_TOPICS = {
    "penetration-testing", "pentest", "security-tools", "hacking", "hacking-tool",
    "vulnerability-scanner", "vulnerability-detection", "exploit", "exploitation",
    "red-team", "blueteam", "blue-team", "purple-team", "offensive-security",
    "network-security", "web-security", "application-security", "cloud-security",
    "container-security", "supply-chain-security", "devsecops", "password-cracking",
    "brute-force", "wifi-hacking", "wireless-security", "osint", "reconnaissance",
    "subdomain-enumeration", "port-scanner", "fuzzing", "fuzzer", "malware-analysis",
    "reverse-engineering", "digital-forensics", "incident-response", "threat-hunting",
    "threat-intelligence", "siem", "ids", "ips", "honeypot", "c2",
    "post-exploitation", "privilege-escalation", "ctf-tools", "bugbounty",
    "sql-injection", "xss", "rce", "payload", "shellcode", "antivirus",
    "infosec", "cybersecurity", "kali-linux", "linux-hardening", "firewall",
    "vulnerability-management", "easm", "attack-surface", "api-security",
    "mobile-security", "android-security", "iot-security", "hardware-hacking",
    "social-engineering", "phishing", "log-analysis", "packet-capture",
    "network-analysis", "enumeration", "security-audit", "antiforensics",
    "honeypots", "penetration-testing-tools", "redteaming", "cyber-security",
    "security-scanner", "web-security-scanner", "exploit-development",
    "penetration-test", "security-testing", "ethical-hacking", "web-app-security",
    "network-scanner", "security-awareness", "zero-day", "cve", "nvd",
    "threat-modeling", "attack-surface-management", "offensive",
}

# ② 强安全术语 (出现在名字/描述里才认) —— 故意收得很严, 防止 "proxy" "scan" 这种泛词
SEC_TERMS = [
    "pentest", "penetration test", "penetration-test", "hacking tool", "hack tool",
    "exploit", "exploitation", "vulnerability", "vuln ", "cve-", "zero-day", "0day",
    "malware", "ransomware", "rootkit", "backdoor", "webshell", "web shell",
    "keylogger", "credential dump", "lsass", "mimikatz", "kerberoast",
    "reverse engineer", "reversing", "disassembl", "decompil", "ghidra", "radare",
    "forensic", "dfir", "incident response", "memory dump", "volatility",
    "threat intel", "threat hunt", "mitre att", "ioc ", "indicators of compromise",
    "siem", "ids/ips", "intrusion detection", "intrusion prevention", "edr", "xdr",
    "honeypot", "yara", "sigma rule", "detection rule", "log analysis",
    "osint", "reconnaissance", "recon-", "subdomain", "attack surface", "asset discovery",
    "network scanner", "port scanner", "port scan", "service fingerprint",
    "sql injection", "sqli", "xss", "csrf", "ssrf", "xxe", "rce ", "lfi", "rfi",
    "web shell", "waf", "brute force", "bruteforce", "password crack", "hash crack",
    "hashcat", "john the ripper", "hydra", "wordlist", "credential stuffing",
    "metasploit", "exploitdb", "searchsploit", "poc-", "proof of concept",
    "c2 framework", "command and control", "post-exploitation", "privilege escalation",
    "privesc", "lateral movement", "pivoting", "payload", "shellcode", "implant",
    "red team", "blue team", "purple team", "adversary", "attack simulation",
    "penetration", "bug bounty", "vulnerability management", "vulnerability scan",
    "security scanner", "security scan", "security audit", "security testing",
    "security tool", "security toolkit", "offensive security", "defensive security",
    "cyber security", "cybersecurity", "infosec", "information security",
    "sast", "dast", "sbom", "software composition analysis", "secret scanning",
    "secrets detection", "container security", "kubernetes security", "k8s security",
    "cloud security", "iac scan", "misconfiguration", "compliance scan",
    "hardening", "cis benchmark", "attack surface management", "threat model",
    "phishing", "social engineering", "wireless attack", "wifi hacking", "wpa",
    "deauth", "aircrack", "packet capture", "pcap", "sniffer", "mitm", "man in the middle",
    "fuzzing", "fuzzer", "afl-", "oss-fuzz", "ctf", "capture the flag", "pwntools",
    "shellcode", "binary exploitation", "heap exploitation", "kernel exploit",
    "hardware hacking", "badusb", "firmware analysis", "iot security", "rfid",
    "bluetooth attack", "sdr", "jtag", "uart", "ble ", "log4shell",
    "owasp", "nuclei", "sqlmap", "burp suite", "nikto", "openvas", "nessos",
    "nessus", "acunetix", "zap proxy", "owasp zap", "gobuster", "ffuf", "dirb",
    "subfinder", "amass", "theharvester", "sherlock", "spiderfoot", "recon-ng",
    "bloodhound", "impacket", "evil-winrm", "responder", "crackmapexec",
    "linpeas", "winpeas", "peass", "chisel", "sliver", "cobalt strike", "havoc",
    "trivy", "grype", "syft", "checkov", "tfsec", "kube-bench", "kube-hunter",
    "semgrep", "bandit", "gitleaks", "trufflehog", "dependency-check",
    "volatility", "autopsy", "sleuthkit", "binwalk", "foremost", "freely available",
]

# ③ 明显不是安全工具的噪音 (命中且无强安全术语 -> noise)
NOISE_RE = re.compile(
    r"v2ray|shadowsocks|clash(?!.*security)|trojan-go|ssr-|sing-box|xray-core|"
    r"one-api|new-api|public-apis|free-for-dev|awesome-mac|awesome-python|"
    r"awesome-go|awesome-tuis|awesome-for-beginners|the-book-of-secret|"
    r"^books?$|programming-books|best-of-|interview|leetcode|algorithm|"
    r"data-science|machine-learning|deep-learning|llm-|chatgpt|stable-diffusion|"
    r"web-framework|ui-library|css-|vue-|react-|next\.js|node-best-practices|"
    r"headroom|agency-agents|worldmonitor|openworker|scientific-agent|"
    r"ai-website-cloner|static-analysis$|naughty-strings|game-|minecraft|"
    r"worldmonitor|deer-flow|gpt4free|swe-agent|dotenv|xonsh|netmaker|bytebase|"
    r"kubeshark|node-opcua|flipper-tesla|^certificates$|diagrams|freedev|"
    r"electron-|telegram-|wechat|微信|抖音|bilibili|proxy-pool|free-proxy",
    re.I)

REFERENCE_RE = re.compile(
    r"awesome|curated list|list of |collection of |cheat ?sheet|handbook|"
    r"roadmap|tutorial|guide|resources|books?$|papers|notes|wiki|"
    r"all-the-things|payloadsallthethings|reading-list|study|learning",
    re.I)

# ④ 名字里带这些词 = 铁定是安全项目, 不受噪音规则影响
CORE_SEC_NAME = re.compile(
    r"pentest|security|secur|hack|exploit|vuln|cyber|malware|forensic|recon|osint|"
    r"payload|shellcode|scanner|nuclei|sqlmap|nmap|xss|sqli|c2[-_]|backdoor|phish|"
    r"attack|defen[cs]e|threat|ids[-_]|siem|pcap|wir(e|eless)|wifi|passw|hashcrack|"
    r"reverse[-_]?(eng|shell)|pwn|ctf|red[-_]?team|blue[-_]?team|soc[-_]|edr|yara|"
    r"sigma|volatil|ghidra|radare|mimikatz|metasploit|impacket|burp|nikto|"
    r"bloodhound|linpeas|winpeas|gobuster|ffuf|subfinder|amass|trivy|grype|"
    r"nessus|openvas|acunetix|zap[-_]|wpscan|hydra|john[-_]|hashcat|aircrack|"
    r"bettercap|responder|chisel|sliver|empire|mythic|havoc|seclist|wordlist|"
    r"cybersecurity|infosec|bugbounty|bug[-_]bounty|adversary|maltego|shodan|"
    r"censys|deauth|wireless|netsec|sast|dast|sbom|checkov|tfsec|kubescape", re.I)

# ⑤ 描述里出现这些 = 安全领域
SEC_TERMS += [
    "security assessment", "penetration testing", "vulnerability assessment",
    "security research", "seclists", "wordlists", "security tester",
    "red teaming", "attack surface", "security engineer", "security operation",
    "cyber threat", "security posture", "security analyst",
]


def load(con):
    con.row_factory = sqlite3.Row
    return [dict(r) for r in con.execute("SELECT * FROM tools")]


def classify(r):
    """(is_sec, kind, noise)"""
    name = r["name"] or ""
    desc = r["description"] or ""
    topics = set(t.strip() for t in (r["topics"] or "").split(",") if t.strip())
    blob = f"{name} {desc} {' '.join(topics)}".lower()
    nlow = name.lower()

    sec_topic = bool(topics & SEC_TOPICS)
    sec_topic_n = len(topics & SEC_TOPICS)
    name_hit = any(t in nlow for t in SEC_TERMS)
    term_hits = {t for t in SEC_TERMS if t in blob}
    core_name = bool(CORE_SEC_NAME.search(name))

    # 判定: 名字含核心安全词 / 名字命中安全术语 / ≥2 个安全 topic / 描述命中 ≥2 个术语
    is_sec = core_name or name_hit or sec_topic_n >= 2 or len(term_hits) >= 2

    noise = 0
    if not is_sec:
        noise = 1
    elif NOISE_RE.search(name) and not core_name:
        noise = 1

    kind = "tool"
    if REFERENCE_RE.search(name + " " + desc[:120]) and \
            r["language"] in ("", "Markdown", "HTML", "TeX", "JavaScript", "TypeScript"):
        kind = "reference"
    if re.search(r"awesome|all-the-things|-list$|cheat ?sheet|^books?$", name, re.I):
        kind = "reference"
    if r["language"] in ("", "Markdown") and not core_name:
        kind = "reference" if kind == "tool" else kind
    return is_sec, kind, noise


CATS = [
    ("漏洞利用/Exploit", r"exploit|metasploit|rce\b|0day|zero-day|payload|shellcode|\bc2\b|command.and.control|post.exploit|privilege.escalat|privesc|lateral.movement|implant|rat\b|cobalt|sliver|havoc|mythic|empire|rootkit|backdoor|webshell"),
    ("无线/Wireless", r"\bwifi\b|wireless|\bwpa|deauth|aircrack|bluetooth|\bble\b|rfid|\bsdr\b|802\.11|zigbee|\brf\b"),
    ("Web 安全", r"web.security|sql.inject|sqli|\bxss\b|csrf|ssrf|xxe|waf\b|web.app|webapp|api.security|jwt|directory.brute|fuzz|burp|zap\b|nikto|http.smuggl|webshell|web.shell|dom.purif|browser.security|xss.payload"),
    ("扫描/侦察/Recon", r"scanner|scanning|reconnaiss|recon\b|enumerat|subdomain|port.scan|nmap|asset.discovery|attack.surface|\beasm\b|fingerprint|osint|shodan|dork|social.engineering|phishing|information.gathering|discovery|sherlock|amass|subfinder|nuclei|masscan|httpx|katana|theharvester|spiderfoot"),
    ("密码/认证", r"password|hashcat|john.the.ripper|brute.force|credential|kerberos|kerberoast|cracking|wordlist|hash.crack|auth.bypass|ntlm|mimikatz|evil-winrm|hydra"),
    ("漏洞库/管理", r"vulnerability.manage|vulnerability.detect|\bcve\b|\bnvd\b|vulnerability.scan|sbom|dependency.check|patch.manage|advisory|vulnerabilit"),
    ("防御/蓝队/检测", r"blue.team|blueteam|defen[cs]e|\bids\b|\bips\b|\bedr\b|\bxdr\b|\bxdr\b|yara|sigma|siem|\bsoc\b|threat.hunt|\bhids\b|\bnids\b|hardening|firewall|honeypot|antivirus|malware.detect|detection|monitoring|audit|compliance|benchmark|\bcis\b|purple.team|deception|\bdlp\b|adversary.emulat"),
    ("威胁情报/OSINT", r"threat.intel|\bioc\b|\bcti\b|osint|dark.web|leak|intelligence|mitre|att.ck|threat.hunt|indicators|maltego|shodan|censys"),
    ("取证/应急响应", r"forensic|incident.response|\bdfir\b|memory.dump|volatility|disk.image|evidence|artifact|timeline|acquisition|triage|autopsy|sleuthkit|binwalk|memoria"),
    ("逆向/恶意代码分析", r"reverse.engineer|reversing|disassembl|decompil|ghidra|\bida\b|radare|\brizin|binary.analysis|malware|firmware|unpacker|emulat|debugger|apk|android.security|mobile.security|ios.security|dynamic.analysis"),
    ("云/容器/供应链", r"cloud.security|\baws\b|azure|\bgcp\b|kubernetes|\bk8s\b|docker.security|container.security|\biac\b|terraform|supply.chain|devsecops|cicd.security|\bsast\b|\bdast\b|secrets.detect|serverless|trivy|grype|checkov|tfsec|kubescape|prowler|scout"),
    ("网络/流量分析", r"network.security|packet.capture|\bpcap\b|sniffer|\bmitm\b|network.analysis|traffic.analysis|tunnel|dns.security|\bssl\b|\btls\b|netflow|capture|zeek|suricata|snort|wireshark|tshark|nmap|arp|spoof"),
    ("硬件/物联网", r"hardware.hacking|\biot\b|embedded|firmware|uart|jtag|\bswd\b|logic.analyzer|badusb|rf\b|nfc|sdr|chip"),
    ("CTF/靶场/学习", r"\bctf\b|capture.the.flag|vulnerable.app|dvwa|juice.shop|\blab\b|practice|cheatsheet|roadmap|training|hackthebox|tryhackme|writeup|pwntools|pwn|binary.exploit|heap|kernel.exploit"),
]


def recat(r):
    blob = f"{r['name']} {r['description']} {r['topics']}".lower()
    hits = []
    for cat, pat in CATS:
        if re.search(pat, blob):
            hits.append(cat)
    if not hits:
        return "其他/未分类", 0
    return hits[0], len(hits)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--drop-noise", action="store_true", help="直接从库里删除噪音")
    a = ap.parse_args()

    con = sqlite3.connect(HERE_DB)
    rows = load(con)
    con.execute("ALTER TABLE tools ADD COLUMN kind TEXT DEFAULT 'tool'") if \
        "kind" not in [c[1] for c in con.execute("PRAGMA table_info(tools)")] else None
    con.execute("ALTER TABLE tools ADD COLUMN noise INTEGER DEFAULT 0") if \
        "noise" not in [c[1] for c in con.execute("PRAGMA table_info(tools)")] else None

    n_noise = n_ref = 0
    for r in rows:
        _, kind, noise = classify(r)
        cat, nhit = recat(r)
        # 分数重算: 安全性/性质/活跃度
        score = r["score"] or 0
        if noise:
            score -= 60
        if kind == "reference":
            score -= 15
        if not r["archived"]:
            score += 3
        score += min(nhit, 3)
        if r["stars"] >= 5000:
            score += 3
        n_noise += noise
        n_ref += (kind == "reference")
        con.execute("UPDATE tools SET category=?, kind=?, noise=?, score=? WHERE full_name=?",
                    (cat, kind, noise, round(score, 2), r["full_name"]))
    if a.drop_noise:
        con.execute("DELETE FROM tools WHERE noise=1")
    con.commit()

    print(f"总数 {len(rows)}   噪音 {n_noise} ({(n_noise/max(len(rows),1))*100:.0f}%)   "
          f"参考清单 {n_ref}   真工具 {len(rows)-n_noise-n_ref}")
    print("\n=== 精炼后各分类 (只统计真工具, ★>=500) ===")
    q = """SELECT category, COUNT(*) n, MAX(stars) mx,
           (SELECT name FROM tools t2 WHERE t2.category=t1.category AND t2.noise=0
              AND t2.kind='tool' ORDER BY stars DESC LIMIT 1) top
           FROM tools t1 WHERE noise=0 AND kind='tool' AND stars>=500 GROUP BY category ORDER BY n DESC"""
    total = con.execute("SELECT COUNT(*) FROM tools WHERE noise=0 AND kind='tool'").fetchone()[0]
    print(f"(库内真工具共 {total})")
    for r in con.execute(q):
        print(f"  {r[0]:<22} {r[1]:>5}   最高: {r[2]} (★{r[3]})")
    print("\n=== 抽样检查 (各分类 ★ 最高的真工具) ===")
    for cat, in con.execute("SELECT DISTINCT category FROM tools WHERE noise=0 AND kind='tool' AND stars>=500"):
        tops = con.execute("SELECT name,stars FROM tools WHERE category=? AND noise=0 AND kind='tool' "
                           "ORDER BY stars DESC LIMIT 4", (cat,)).fetchall()
        print(f"  {cat}: " + ", ".join(f"{t[0]}(★{t[1]})" for t in tops))
    con.close()
