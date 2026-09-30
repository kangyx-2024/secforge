#!/usr/bin/env python3
"""SecForge - Kali 镜像自动生成器

读 catalog.sqlite -> 生成 Dockerfile -> 构建镜像 -> 起常驻容器。
用法:
  python3 build_image.py --profile standard   # 生成 + 构建 + 起容器
  python3 build_image.py --profile full       # kali 全家桶 (大, 10GB+)
  python3 build_image.py --profile custom --categories "扫描/侦察/Recon,Web 安全"
  python3 build_image.py --gen-only           # 只生成 Dockerfile 看一眼
"""
import argparse
import json
import os
import sqlite3
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(os.path.dirname(HERE), "catalog", "catalog.sqlite")
IMAGE = "secforge/kali"
CONTAINER = "secforge"

# Kali 官方元包 -> 我们分类的映射
KALI_META = {
    "扫描/侦察/Recon": ["kali-tools-information-gathering"],
    "漏洞库/管理": ["kali-tools-vulnerability"],
    "Web 安全": ["kali-tools-web", "kali-tools-database", "kali-tools-fuzzing"],
    "密码/认证": ["kali-tools-passwords"],
    "无线/Wireless": ["kali-tools-wireless", "kali-tools-802-11", "kali-tools-bluetooth", "kali-tools-rfid", "kali-tools-sdr"],
    "漏洞利用/Exploit": ["kali-tools-exploitation"],
    "防御/蓝队/检测": ["kali-tools-defensive"],
    "威胁情报/OSINT": ["kali-tools-osint"],
    "取证/应急响应": ["kali-tools-forensics"],
    "逆向/恶意代码分析": ["kali-tools-reverse-engineering"],
    "网络/流量分析": ["kali-tools-sniffing-spoofing", "kali-tools-voip"],
    "硬件/物联网": ["kali-tools-hardware"],
    "云/容器/供应链": [],  # kali 无元包, 走 pip/go
    "其他/未分类": [],
}

PROFILES = {
    # core: 秒级可用, 只装最核心 CLI
    "core": {
        "base": ["kali-linux-headless"],
        "metas": [],
        "extra_apt": ["nmap", "sqlmap", "nikto", "whatweb", "hydra", "john", "hashcat",
                      "gobuster", "dirb", "wpscan", "netcat-traditional", "dnsutils",
                      "curl", "wget", "git", "jq", "python3-pip", "golang-go", "tmux",
                      "net-tools", "iputils-ping", "traceroute", "masscan", "sslscan"],
        "go_tools": [],
        "pip_tools": [],
    },
    # standard: 日常渗透够用
    "standard": {
        "base": ["kali-linux-headless"],
        "metas": ["kali-tools-information-gathering", "kali-tools-vulnerability",
                  "kali-tools-web", "kali-tools-passwords", "kali-tools-exploitation",
                  "kali-tools-sniffing-spoofing", "kali-tools-post-exploitation",
                  "kali-tools-forensics", "kali-tools-reverse-engineering",
                  "kali-tools-reporting", "kali-tools-fuzzing"],
        "extra_apt": ["nmap", "masscan", "sqlmap", "nikto", "whatweb", "hydra", "john",
                      "hashcat", "wpscan", "gobuster", "ffuf", "feroxbuster", "amass",
                      "theharvester", "exploitdb", "netcat-traditional", "dnsutils",
                      "whois", "traceroute", "sslscan", "tcpdump", "tshark", "binwalk",
                      "yara", "radare2", "gdb", "tmux", "jq", "git", "curl", "wget",
                      "golang-go", "python3-pip", "python3-venv", "pipx", "unzip", "xz-utils",
                      # 编译期依赖 + 上次构建失败的 6 个工具 (Kali 源里都有打包版)
                      "libusb-1.0-0-dev", "libpcap-dev", "gcc", "make", "pkg-config",
                      "bettercap", "gitleaks", "trufflehog", "sliver", "wpscan", "ghidra",
                      "enum4linux", "smbclient", "crackmapexec", "responder", "mitmproxy",
                      "cmake"],  # mitmproxy 的 unicorn 依赖要 cmake 才能编译
        "go_tools": [],  # apt 里已有 ffuf/amass/feroxbuster/bettercap/gitleaks/trufflehog
        "pip_tools": ["impacket", "pwntools", "shodan", "dnspython", "requests"],
        # 注: mitmproxy 走 apt(kali 12.2.3), 不装 pip 版 —— pip 版依赖 unicorn 要编译
    },
    # full: kali 全家桶
    "full": {
        "base": ["kali-linux-headless"],
        "metas": ["kali-tools-everything"],
        "extra_apt": ["golang-go", "pipx", "jq", "git", "tmux", "python3-venv"],
        "go_tools": [],
        "pip_tools": ["impacket", "pwntools", "mitmproxy"],
    },
}

GO_TOOLS = {
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "tlsx": "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "interactsh": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "chisel": "github.com/jpillora/chisel@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "assetfinder": "github.com/tomnomnom/assetfinder@latest",
    "httprobe": "github.com/tomnomnom/httprobe@latest",
    "gospider": "github.com/jaeles-project/gospider@latest",
    # 注意: 这几个曾经用错模块路径导致构建时被 SKIP —— 现在全部改走 Kali apt / release 二进制:
    # bettercap(需 libusb-1.0-0-dev, @latest 解析到坏的 v2.24.1) / gitleaks(改名, 官方 apt 8.26)
    # trufflehog(@latest 撞 v3.0.0-rc3+incompatible) / sliver(client 带 replace) / wpscan(是 Ruby)
    # kubescape 不在 Kali 源, 用官方 install.sh 下 release 二进制 (见 Dockerfile 步骤 3b)
}

# 需要 git clone 后自行编译的 (go install 装不了)
GO_CLONE_ONLY = {
    "trufflehog": "https://github.com/trufflesecurity/trufflehog",
    "sliver": "https://github.com/BishopFox/sliver",
    "kubescape": "https://github.com/kubescape/kubescape",
}


def read_catalog():
    if not os.path.exists(CATALOG):
        print(f"! 还没 {CATALOG} (爬虫没跑完), 先生成不含工具索引的镜像")
        return []
    con = sqlite3.connect(CATALOG)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute(
        "SELECT * FROM tools ORDER BY score DESC")]
    con.close()
    return rows


def pick_tools_for_categories(rows, categories, per_cat=15):
    """从目录里挑每个分类 top N 的 pip/go 工具"""
    out = {"go": {}, "pip": {}, "git": {}, "docker": {}}
    for cat in categories:
        got = 0
        for r in rows:
            if r["category"] != cat or got >= per_cat:
                continue
            m, spec = r["install_method"], r["install_spec"] or ""
            if r["stars"] < 200 or r["archived"]:
                continue
            if m == "pip" and len(out["pip"]) < 25:
                out["pip"][r["name"].lower()] = spec
                got += 1
            elif m == "git" and len(out["git"]) < 25:
                out["git"][r["name"].lower()] = spec
                got += 1
            elif m == "docker" and len(out["docker"]) < 10:
                out["docker"][r["name"].lower()] = spec
                got += 1
    return out


def gen_dockerfile(profile, categories):
    rows = read_catalog()
    cfg = PROFILES[profile].copy()
    metas = list(cfg["metas"])
    extras = list(cfg["extra_apt"])

    if profile == "custom":
        for cat in categories:
            metas += KALI_META.get(cat, [])
        metas = sorted(set(m for m in metas if m))
        cfg["metas"] = metas
        cfg["go_tools"] = list(GO_TOOLS.values())
        cfg["pip_tools"] = ["impacket", "pwntools", "mitmproxy", "shodan", "dnspython", "checkov", "semgrep", "prowler", "kube-hunter", "volatility3", "spiderfoot"]
        extra_pick = pick_tools_for_categories(rows, categories)
        extras += list(extra_pick["pip"].values())[:0]
        cfg["pip_tools"] += [v for v in extra_pick["pip"].values() if v not in cfg["pip_tools"]]

    # 生成的工具索引 (容器内 /opt/secforge/tools.json), 供 AI 查询
    all_meta_pkgs = sorted(set(metas))
    apt_pkgs = all_meta_pkgs + sorted(set(extras))
    go_pkgs = cfg["go_tools"] or list(GO_TOOLS.values())
    pip_pkgs = cfg["pip_tools"]

    # 目录里全部工具的元信息打包进镜像 (AI 可离线检索)
    index = [{
        "name": r["name"], "full_name": r["full_name"], "stars": r["stars"],
        "category": r["category"], "language": r["language"],
        "desc": (r["description"] or "")[:180], "url": r["url"],
        "install_method": r["install_method"], "install_spec": r["install_spec"],
        "archived": r["archived"], "pushed_at": r["pushed_at"],
    } for r in rows if r["stars"] >= 100]

    os.makedirs(HERE, exist_ok=True)
    json.dump(index, open(os.path.join(HERE, "tools_index.json"), "w"),
              ensure_ascii=False, indent=0)

    import shlex
    vuln_src = os.path.join(os.path.dirname(HERE), "vulndb", "vulndb.sqlite")
    vuln_copy = ""
    if os.path.exists(vuln_src):
        import shutil
        shutil.copy(vuln_src, os.path.join(HERE, "vulndb.sqlite"))
        vuln_copy = "COPY vulndb.sqlite /opt/secforge/vulndb.sqlite\n"
        print(f"[+] 漏洞库已打入镜像 ({os.path.getsize(vuln_src)//1024//1024} MB)")
    apt_list = " ".join(shlex.quote(p) for p in apt_pkgs)
    go_list = " ".join(shlex.quote(v) for v in go_pkgs)
    pipx_list = " ".join(shlex.quote(p) for p in pip_pkgs)
    pip_mod_list = " ".join(shlex.quote(p) for p in pip_pkgs)

    go_run = (f'for spec in {go_list}; do echo "=== $spec"; '
              f'GOBIN=/usr/local/bin GOFLAGS=-buildvcs=false go install "$spec" '
              f'|| echo "!! SKIP $spec"; done; go clean -cache -modcache 2>/dev/null || true'
              ) if go_pkgs else 'echo "skip go tools"'
    pipx_run = (f'for p in {pipx_list}; do pipx install --quiet "$p" || '
                f'pipx install --quiet --pip-args=--no-deps "$p" || echo "!! SKIP $p"; done; '
                f'pipx ensurepath || true') if pip_pkgs else 'echo "skip pipx tools"'
    pip_run = (f'pip3 install --no-cache-dir --break-system-packages {pip_mod_list} '
               f'|| echo "!! 部分 python 包失败(不影响主体)"') if pip_mod_list else 'echo "skip pip modules"'

    df = f"""# ── SecForge Kali · 自动生成, 勿手改 ──
# profile={profile} categories={','.join(categories) or 'all'} tools={len(index)}
FROM kalilinux/kali-rolling:latest
LABEL org.secforge.profile="{profile}"

ENV DEBIAN_FRONTEND=noninteractive \\
    LANG=C.UTF-8 \\
    GOPATH=/root/go \\
    GOBIN=/root/go/bin \\
    PATH=/root/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \\
    PIP_BREAK_SYSTEM_PACKAGES=1 \\
    GOPROXY=https://goproxy.cn,direct \\
    GOSUMDB=off \\
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \\
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn

# 0+1) 源(HTTP, 自动切换) + ca-certificates + Kali 元包/工具安装
# 注: kali 基础镜像没有 ca-certificates, 直接用 https 源会 certificate verify failed,
#     所以先用 http 源(apt 有 GPG 签名校验, 安全), 装完 CA 再用 https
RUN rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources || true; \
    for M in http://mirrors.tuna.tsinghua.edu.cn/kali http://mirrors.ustc.edu.cn/kali http://mirrors.aliyun.com/kali http://ftp.riken.jp/Linux/kali http://kali.download/kali; do \
      echo "deb $M kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list; \
      if apt-get update >/dev/null 2>&1 && apt-get -s install -y nmap >/dev/null 2>&1; then echo "MIRROR_OK=$M"; break; fi; \
      echo "!! mirror $M 不可用, 换下一个"; sleep 3; done; \
    apt-get install -y --no-install-recommends ca-certificates openssl || true; \
    update-ca-certificates || true; \
    (apt-get install -y --no-install-recommends {apt_list} \
     || (for p in {apt_list}; do echo "=== retry $p"; apt-get install -y --no-install-recommends $p || echo "!! SKIP $p"; done)) ; \
    apt-get -y --fix-broken install || true; apt-get clean; rm -rf /var/lib/apt/lists/*; \
    echo "=== 自检 ==="; for b in nmap sqlmap hydra nikto masscan; do command -v $b || echo "缺 $b"; done; \
    python3 -c "import urllib.request as u; u.urlopen('https://goproxy.cn',timeout=10); print('HTTPS_OK')" || echo "HTTPS_FAIL(Go/pip 走 https 会受影响)"

# 2) Go 工具 (projectdiscovery 全家桶等, 走 goproxy.cn)
RUN {go_run}

# 2b) kubescape 不在 Kali 源里, 拉官方 release 二进制 (arm64)
# 坑: 用宽松正则会把 downloader_xxx_linux_arm64.sbom.json 当成二进制下下来,
#     所以要先排除 sbom/json/sig/attest, 再校验是不是 ELF。
RUN U=$(curl -sL https://api.github.com/repos/kubescape/kubescape/releases/latest \
          | jq -r '[.assets[]|select(.name|test("linux";"i"))|select(.name|test("arm64|aarch64";"i"))|select(.name|test("sbom|json|sha256|sig|attest|source|spdx";"i")|not)|.browser_download_url][0]//empty'); \
    echo "kubescape asset = $U"; \
    if [ -n "$U" ]; then curl -sL "$U" -o /tmp/ks; \
      if head -c 4 /tmp/ks | grep -q ELF; then chmod +x /tmp/ks && mv /tmp/ks /usr/local/bin/kubescape; \
      else mkdir -p /tmp/ksx && tar xzf /tmp/ks -C /tmp/ksx 2>/dev/null && \
           find /tmp/ksx -type f -size +1M -exec sh -c 'head -c4 "$1"|grep -q ELF && cp "$1" /usr/local/bin/kubescape' _ {{}} \\; ; fi; \
    fi; \
    chmod +x /usr/local/bin/kubescape 2>/dev/null; \
    /usr/local/bin/kubescape version 2>/dev/null | head -2 || echo "!! kubescape 跳过(不影响其他工具)"

# 3) Python 工具 (pipx 隔离 + 系统 pip 模块)
RUN {pipx_run}
RUN {pip_run}

# 4) 工具索引 (AI 可离线检索全部 GitHub 工具)
COPY tools_index.json /opt/secforge/tools_index.json
COPY sec /usr/local/bin/sec
{vuln_copy}RUN chmod +x /usr/local/bin/sec

# 5) 工作区
RUN mkdir -p /work /loot /root/.config
WORKDIR /work
VOLUME ["/work", "/loot"]
CMD ["sleep", "infinity"]
"""
    path = os.path.join(HERE, "Dockerfile")
    open(path, "w").write(df)
    print(f"[+] Dockerfile -> {path}  ({len(apt_pkgs)} apt 包, ~{len(go_pkgs)} go 工具, {len(pip_pkgs)} pip)")
    return path, index


SEC_HELPER = r"""#!/bin/bash
# SecForge 容器内工具速查 (AI / 人 都用这个)
IDX=/opt/secforge/tools_index.json
case "$1" in
  list)     jq -r '.[] | select(.category=="'"${2:-}"'") | "\(.name)\t\(.stars)\t\(.install_method)"' $IDX 2>/dev/null | head -60 ;;
  search)   jq -r --arg q "$2" '.[] | select((.name+" "+(.desc//"")) | test($q;"i")) | "\(.name)\t\(.stars)\t\(.desc[:70])"' $IDX | head -40 ;;
  cats)     jq -r '.[].category' $IDX | sort | uniq -c | sort -rn ;;
  info)     jq -r --arg n "$2" '.[] | select(.name==$n)' $IDX ;;
  which)    command -v "$2" ;;
  *) echo "sec {list <分类>|search <关键词>|cats|info <工具>|which <工具>}" ;;
esac
"""


def build(profile, categories, tag=None):
    tag = tag or f"{IMAGE}:{profile}"
    open(os.path.join(HERE, "sec"), "w").write(SEC_HELPER)
    os.chmod(os.path.join(HERE, "sec"), 0o755)

    print(f"[*] 构建 {tag} (这一步可能几十分钟, 取决于 profile) ...")
    p = subprocess.run(
        ["docker", "build", "-t", tag, "--platform", "linux/arm64", HERE],
        text=True)
    if p.returncode != 0:
        print("! 构建失败")
        return False
    print(f"[+] 镜像完成: {tag}")
    return True


def run_container(tag=None, profile="standard"):
    tag = tag or f"{IMAGE}:{profile}"
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", CONTAINER,
                    "--hostname", "secforge",
                    "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
                    "-v", "secforge_work:/work", "-v", "secforge_loot:/loot",
                    tag], check=False)
    r = subprocess.run(["docker", "ps", "--filter", f"name={CONTAINER}",
                        "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}"],
                       capture_output=True, text=True)
    print(r.stdout.strip() or "! 容器未启动")
    return r.stdout.strip()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="standard", choices=list(PROFILES) + ["custom"])
    ap.add_argument("--categories", default="", help="custom 时指定, 逗号分隔")
    ap.add_argument("--gen-only", action="store_true")
    ap.add_argument("--no-run", action="store_true")
    a = ap.parse_args()
    cats = [c.strip() for c in a.categories.split(",") if c.strip()]
    gen_dockerfile(a.profile, cats)
    if not a.gen_only:
        if build(a.profile, cats) and not a.no_run:
            run_container(profile=a.profile)
