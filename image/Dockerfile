# ── SecForge Kali · 自动生成, 勿手改 ──
# profile=standard categories=all tools=6321
FROM kalilinux/kali-rolling:latest
LABEL org.secforge.profile="standard"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    GOPATH=/root/go \
    GOBIN=/root/go/bin \
    PATH=/root/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    GOPROXY=https://goproxy.cn,direct \
    GOSUMDB=off \
    PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
    PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn

# 0+1) 源(HTTP, 自动切换) + ca-certificates + Kali 元包/工具安装
# 注: kali 基础镜像没有 ca-certificates, 直接用 https 源会 certificate verify failed,
#     所以先用 http 源(apt 有 GPG 签名校验, 安全), 装完 CA 再用 https
RUN rm -f /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources || true;     for M in http://mirrors.tuna.tsinghua.edu.cn/kali http://mirrors.ustc.edu.cn/kali http://mirrors.aliyun.com/kali http://ftp.riken.jp/Linux/kali http://kali.download/kali; do       echo "deb $M kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list;       if apt-get update >/dev/null 2>&1 && apt-get -s install -y nmap >/dev/null 2>&1; then echo "MIRROR_OK=$M"; break; fi;       echo "!! mirror $M 不可用, 换下一个"; sleep 3; done;     apt-get install -y --no-install-recommends ca-certificates openssl || true;     update-ca-certificates || true;     (apt-get install -y --no-install-recommends kali-tools-exploitation kali-tools-forensics kali-tools-fuzzing kali-tools-information-gathering kali-tools-passwords kali-tools-post-exploitation kali-tools-reporting kali-tools-reverse-engineering kali-tools-sniffing-spoofing kali-tools-vulnerability kali-tools-web amass bettercap binwalk cmake crackmapexec curl dnsutils enum4linux exploitdb feroxbuster ffuf gcc gdb ghidra git gitleaks gobuster golang-go hashcat hydra john jq libpcap-dev libusb-1.0-0-dev make masscan mitmproxy netcat-traditional nikto nmap pipx pkg-config python3-pip python3-venv radare2 responder sliver smbclient sqlmap sslscan tcpdump theharvester tmux traceroute trufflehog tshark unzip wget whatweb whois wpscan xz-utils yara      || (for p in kali-tools-exploitation kali-tools-forensics kali-tools-fuzzing kali-tools-information-gathering kali-tools-passwords kali-tools-post-exploitation kali-tools-reporting kali-tools-reverse-engineering kali-tools-sniffing-spoofing kali-tools-vulnerability kali-tools-web amass bettercap binwalk cmake crackmapexec curl dnsutils enum4linux exploitdb feroxbuster ffuf gcc gdb ghidra git gitleaks gobuster golang-go hashcat hydra john jq libpcap-dev libusb-1.0-0-dev make masscan mitmproxy netcat-traditional nikto nmap pipx pkg-config python3-pip python3-venv radare2 responder sliver smbclient sqlmap sslscan tcpdump theharvester tmux traceroute trufflehog tshark unzip wget whatweb whois wpscan xz-utils yara; do echo "=== retry $p"; apt-get install -y --no-install-recommends $p || echo "!! SKIP $p"; done)) ;     apt-get -y --fix-broken install || true; apt-get clean; rm -rf /var/lib/apt/lists/*;     echo "=== 自检 ==="; for b in nmap sqlmap hydra nikto masscan; do command -v $b || echo "缺 $b"; done;     python3 -c "import urllib.request as u; u.urlopen('https://goproxy.cn',timeout=10); print('HTTPS_OK')" || echo "HTTPS_FAIL(Go/pip 走 https 会受影响)"

# 2) Go 工具 (projectdiscovery 全家桶等, 走 goproxy.cn)
RUN for spec in github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest github.com/projectdiscovery/httpx/cmd/httpx@latest github.com/projectdiscovery/naabu/v2/cmd/naabu@latest github.com/projectdiscovery/katana/cmd/katana@latest github.com/projectdiscovery/dnsx/cmd/dnsx@latest github.com/projectdiscovery/tlsx/cmd/tlsx@latest github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest github.com/jpillora/chisel@latest github.com/lc/gau/v2/cmd/gau@latest github.com/tomnomnom/waybackurls@latest github.com/tomnomnom/assetfinder@latest github.com/tomnomnom/httprobe@latest github.com/jaeles-project/gospider@latest; do echo "=== $spec"; GOBIN=/usr/local/bin GOFLAGS=-buildvcs=false go install "$spec" || echo "!! SKIP $spec"; done; go clean -cache -modcache 2>/dev/null || true

# 2b) kubescape 不在 Kali 源里, 拉官方 release 二进制 (arm64)
# 坑: 用宽松正则会把 downloader_xxx_linux_arm64.sbom.json 当成二进制下下来,
#     所以要先排除 sbom/json/sig/attest, 再校验是不是 ELF。
RUN U=$(curl -sL https://api.github.com/repos/kubescape/kubescape/releases/latest           | jq -r '[.assets[]|select(.name|test("linux";"i"))|select(.name|test("arm64|aarch64";"i"))|select(.name|test("sbom|json|sha256|sig|attest|source|spdx";"i")|not)|.browser_download_url][0]//empty');     echo "kubescape asset = $U";     if [ -n "$U" ]; then curl -sL "$U" -o /tmp/ks;       if head -c 4 /tmp/ks | grep -q ELF; then chmod +x /tmp/ks && mv /tmp/ks /usr/local/bin/kubescape;       else mkdir -p /tmp/ksx && tar xzf /tmp/ks -C /tmp/ksx 2>/dev/null &&            find /tmp/ksx -type f -size +1M -exec sh -c 'head -c4 "$1"|grep -q ELF && cp "$1" /usr/local/bin/kubescape' _ {} \; ; fi;     fi;     chmod +x /usr/local/bin/kubescape 2>/dev/null;     /usr/local/bin/kubescape version 2>/dev/null | head -2 || echo "!! kubescape 跳过(不影响其他工具)"

# 3) Python 工具 (pipx 隔离 + 系统 pip 模块)
RUN for p in impacket pwntools shodan dnspython requests; do pipx install --quiet "$p" || pipx install --quiet --pip-args=--no-deps "$p" || echo "!! SKIP $p"; done; pipx ensurepath || true
RUN pip3 install --no-cache-dir --break-system-packages impacket pwntools shodan dnspython requests || echo "!! 部分 python 包失败(不影响主体)"

# 4) 工具索引 (AI 可离线检索全部 GitHub 工具)
COPY tools_index.json /opt/secforge/tools_index.json
COPY sec /usr/local/bin/sec
COPY vulndb.sqlite /opt/secforge/vulndb.sqlite
RUN chmod +x /usr/local/bin/sec

# 5) 工作区
RUN mkdir -p /work /loot /root/.config
WORKDIR /work
VOLUME ["/work", "/loot"]
CMD ["sleep", "infinity"]
