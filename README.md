<div align="center">

# SecForge

**工具箱里的安全全家桶 —— 5000+ 工具索引 · 59000+ 漏洞库 · AI 编排 · 自建 Kali 镜像 · 原生 macOS 界面**

把扫描 / 攻击 / 防御 / 漏洞研究要用的东西塞进一个盒子，
让 AI 帮你调用它们，界面是一个真正的原生 App（不是浏览器套壳）。

[![License](https://img.shields.io/badge/license-MIT-4e9a63)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-d97a2b)](#-快速开始)
[![Python](https://img.shields.io/badge/python-3.11%2B-4e9a63)](#-快速开始)
[![MCP](https://img.shields.io/badge/MCP-22%20tools-d97a2b)](#-接进-ai-自带-key)
[![Authorized use only](https://img.shields.io/badge/use-authorized%20targets%20only-c0392b)](USAGE-POLICY.md)

<sub>English TL;DR — SecForge is a self-hosted security toolkit: it indexes 5,000+ GitHub
security tools, ships a 59,000-CVE local database (MSRC + CISA KEV + ExploitDB + NVD),
builds its own Kali Docker image, exposes 22 MCP tools to any AI agent, and drives
everything from a **native macOS app (Swift/SwiftUI — no Electron, no browser)**.
Bring your own LLM API key. Authorized targets only.</sub>

</div>

---

## ⚠️ 使用声明 —— 请先读这一段

> **本项目仅用于合法的网络安全工作。禁止用于任何未授权的攻击行为。**

**只有两种情况你可以用：**

| | 说明 |
|---|---|
| ✅ **你自己的资产** | 你自己的电脑 / 服务器 / 路由器 / 家里的局域网 / 自己搭的靶场（DVWA、Juice Shop、vulhub、Metasploitable） |
| ✅ **你持有书面授权的目标** | 签了授权书 / SOW 的渗透测试项目；目标在公开范围（Scope）内的漏洞赏金项目（HackerOne、Bugcrowd、补天、漏洞盒子、CNVD） |

**以下行为一律禁止**（在中国大陆由《刑法》第 285 条、第 286 条、《网络安全法》第 27 条规制）：

- ❌ 未经授权扫描、探测、入侵任何他人的网站、服务器、设备、个人电脑、手机
- ❌ 利用漏洞获取数据、提权、留后门、植入木马 / 勒索软件
- ❌ 窃取他人账号、密码、隐私数据、商业数据
- ❌ 对政府、教育、医疗、金融、能源等**关键信息基础设施**做任何探测或攻击
- ❌ 把本工具或其产出用于人身攻击、骚扰、敲诈、炫耀
- ❌ 把本工具包装成攻击服务对外提供

**后果是刑事责任（可判有期徒刑）、民事赔偿、留案底、监护人连带赔偿 —— 不是「被批评一顿」。**

本项目已把护栏写进代码（见下方「合法使用」一节）：政府、教育、军方域名会被
**直接拒绝**，换任何 AI 大脑都绕不过去。但护栏只是最低限度的保护，
**真正的边界在你自己的判断里**。

📄 完整条款：[USAGE-POLICY.md](USAGE-POLICY.md)

---

## 它解决什么问题

想认真学安全，你得先干这些事：装 Kali（或者 40 个工具各自装）、到处找工具、
翻十几个网站查漏洞、还得记住一堆参数。真开始干活了又是一堆手工步骤。

SecForge 把这些压成三层：

```
①  工具库    爬 GitHub 78 个安全 topic + 20 组关键词搜索 → 过滤噪音 → 本地 SQLite 索引
②  漏洞库    微软 MSRC + CISA KEV + ExploitDB + NVD 年度 feed → 统一到一张表
③  执行层    自建 Kali 镜像（Dockerfile 由工具库自动生成）+ AI 编排 + 原生界面
```

**核心是第 ③ 层**：你对着界面说「扫一下 192.168.10.1，把开放的服务和已知漏洞对应起来」，
AI 自己决定调哪个工具、传什么参数、拿结果去查漏洞库、最后给你结论。你不用记参数。

---

## 实测数据（不是估算，是库里真实的）

| | 数量 | 说明 |
|---|---|---|
| GitHub 安全工具 | **5,266** | 从 8,446 个仓库里过滤掉噪音/清单，15 个分类 |
| 参考清单 | 710 | awesome-list / cheat-sheet 类，单独归类 |
| CVE 漏洞库 | **59,876** | 其中 56,967 条有 CVSS 评分 |
| 已被真实利用（CISA KEV） | **1,729** | 标记 🔥，优先看这些 |
| 有公开 PoC | **25,086** | 标记 💥，附 ExploitDB 编号 |
| 带补丁号（KB） | **9,070** | 直接告诉你打哪个补丁 |
| 受影响产品条目 | 253,921 | 按产品反查漏洞用 |
| Windows 版本覆盖 | 27 个 | Win11 各代 / Win10 全分支 / Server / 8.1 / 7 SP1 |
| Kali 镜像 | 2,091 个包 | 21.3GB，含 Metasploit 2604 个载荷 |
| MCP 工具 | 22 个 | 任何支持 MCP 的 AI 都能直接用 |
| 原生 App | 1.2MB | Mach-O arm64 真二进制 |

**Windows 版本能查到什么**（真实输出）：

```
Windows 7 SP1        → 2,078 个 CVE，头一个是 CVE-2019-0708 BlueKeep (CVSS 9.8)
Windows 8.1          → 2,360 个 CVE，含 CVE-2017-0143 永恒之蓝
Windows Server 2019  → 5,775 个 CVE，头一个是 CVE-2020-1472 Zerologon (CVSS 10.0)
Windows 10 22H2      → 3,072 个 CVE，706 个补丁 KB 号
Windows 11 24H2      → 2,412 个 CVE
```

---

## 界面

两个前端，都真实可用：

| | 位置 | 说明 |
|---|---|---|
| **原生版** | `/Applications/SecForge.app` | Swift + SwiftUI 写的真 macOS 程序。**没有 HTML、没有浏览器、没有 Python 后端**：SQLite 由 Swift 直接读，docker 直接调。1.2MB |
| 网页版 | `ui/启动SecForge.command` | Python 标准库 HTTP 服务 + 单页 HTML，方便改 |

原生版页签：**总览 / 工具库 / 漏洞库 / Windows 漏洞 / 扫描 / 问 AI（双大脑） / 容器与镜像**。
深色 + 军绿 + 战术橙，全原生控件，跟随系统深浅色。

构建原生版：

```bash
cd native && ./build.sh      # 编译 + 打包 + ad-hoc 签名 → /Applications/SecForge.app
file /Applications/SecForge.app/Contents/MacOS/SecForge
# → Mach-O 64-bit executable arm64        （不是 shell script，不是网页壳）
```

> 启动用 `open /Applications/SecForge.app`。
> `open -a /Applications/SecForge.app` 是不行的 —— `-a` 后面要跟 App **名字**不是路径。

---

## 接进 AI（自带 key）

**本仓库不带任何模型密钥，也不会代替你调用任何模型 —— AI 部分你自己部署、自己配 key。**
不配也能用，只是「问 AI」页签的 DeepSeek 大脑不可用，其余全部功能（工具库、漏洞库、
扫描、关联分析）都正常。

```bash
cp .env.example .env
# 打开 .env 填上你自己的 key（申请：https://platform.deepseek.com/api_keys）
DEEPSEEK_API_KEY=sk-你的key
```

`ui/deepseek_agent.py` 里写的是 DeepSeek 的 OpenAI 兼容接口。换别家（本地
Ollama / vLLM、通义、Moonshot、OpenAI 官方……）只改文件顶部两个常量即可。

**双大脑设计 —— 同一批工具，两个控制器：**

| 大脑 | 怎么跑 | 权限 | 特点 |
|---|---|---|---|
| **DeepSeek 直连** | 直接调 API，自己跑工具循环 | 只能动容器 | 快；每次工具调用都显示给你看；不需要装别的 |
| **Hermes 真身**（可选） | 调本机 [Hermes Agent](https://hermes-agent.nousresearch.com/docs) | 全权限 | 有跨会话记忆和技能库；危险命令会弹审批 |

两个大脑共用**同一个 Kali 容器、同一份漏洞库、同一批工具**，所以可以同时开着轮流使唤。
工具 schema 是从函数签名和 docstring 自动生成的 —— 加新工具不用改大脑那边的代码。

**任何 MCP 客户端都能接**（Claude Desktop / Cursor / 自己的 agent）：

```bash
hermes config set mcp_servers.secforge.command /path/to/secforge/.venv/bin/python
hermes config set mcp_servers.secforge.args '["/path/to/secforge/mcp/server.py"]'
```

---

## ☠️ 合法使用

> **这个工具只允许用于你自己拥有的设备、你自己搭的靶场、或者你拿到书面授权的目标。**
> 完整条款见 [USAGE-POLICY.md](USAGE-POLICY.md)。

这不是免责声明里凑字数的一句 —— 它**写在代码里**：

```python
# mcp/server.py
BLOCKED_TLDS = (".gov", ".gov.cn", ".edu", ".edu.cn", ".mil", ".ac.cn", ...)

def guard(target):
    """返回空串表示放行, 否则返回拒绝原因"""
```

政府、教育、军方域名会被直接拒绝，**换哪个 AI 大脑都绕不过去**（护栏长在工具上，不在大脑上）。
腾讯等厂商的客户端反外挂条款、以及《刑法》第 285/286 条，都不是「我就试试」级别的后果。

**建议的练习靶场**（全部合法）：

| 靶场 | 怎么起 |
|---|---|
| OWASP Juice Shop | `docker run -d -p 3000:3000 bkimminich/juice-shop` |
| DVWA | `docker run -d -p 8080:80 vulnerables/web-dvwa` |
| vulhub | [vulhub.org](https://vulhub.org) —— 一堆现成漏洞环境 |
| Metasploitable / HackTheBox / TryHackMe | 专门的「生来被打」的靶机 |

---

## 快速开始

**需要**：macOS（或 Linux）、Docker、Python 3.11+、约 30GB 磁盘。
Windows 用户请用 WSL2。

```bash
git clone https://github.com/kangyx-2024/secforge.git
cd secforge
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env        # 可选：填 AI key
```

**第一步：拿数据**（仓库里不含数据库，127MB 超过 GitHub 单文件上限）

```bash
scripts/fetch_data.sh       # 优先从 Release 下载现成的库；没有就自己构建
```

自己构建（需要 `gh` CLI 已登录，因为 GitHub 搜索 API 有速率限制）：

```bash
# 工具库：爬 GitHub → 过滤噪音（约 30-60 分钟）
.venv/bin/python catalog/scrape_github.py --pages 2 --min-stars 30
.venv/bin/python catalog/refine_catalog.py

# 漏洞库：MSRC + KEV + ExploitDB（约 1-2 小时）
.venv/bin/python vulndb/build_vulndb.py --from 2016-Jan

# 补 CVSS 评分（下 NVD 年度 feed，约 20 分钟）
.venv/bin/python vulndb/fill_cvss_nvd.py
```

**第二步：建 Kali 镜像**（Dockerfile 由工具库自动生成，约 20-40 分钟）

```bash
.venv/bin/python image/build_image.py          # → secforge/kali:standard（21.3GB / 2091 包）
docker run -d --name secforge --cap-add NET_ADMIN --cap-add NET_RAW \
  -v secforge_work:/work -v secforge_loot:/loot secforge/kali:standard
```

> 镜像是**你自己在本机从上游软件源构建**的。本仓库只提供 Dockerfile 生成器，
> 不打包、不再分发任何第三方二进制 —— 各工具仍受其原始许可证约束。

**第三步：开界面**

```bash
cd native && ./build.sh          # 原生 App（推荐）
# 或
ui/启动SecForge.command          # 网页版
```

**第四步（可选）：每天自动更新漏洞库**

```bash
.venv/bin/python vulndb/update_daily.py      # 增量拉 NVD modified feed + KEV + 当月 MSRC
# 加进 crontab 就是每天自动更新，实测一次能补 8000+ 条
```

---

## 架构

```
secforge/
├── catalog/        GitHub 爬虫 + 目录精炼          → catalog.sqlite（工具库）
├── vulndb/         MSRC + KEV + ExploitDB + NVD    → vulndb.sqlite（漏洞库）
│   ├── build_vulndb.py       全量构建
│   ├── fill_cvss_nvd.py      补 CVSS / severity / CWE
│   └── update_daily.py       每日增量
├── image/          Dockerfile 生成器 + 镜像构建     → secforge/kali:standard
├── mcp/            MCP 服务器（22 个工具，stdio）   → 给任何 AI 用
├── ui/             网页版界面 + DeepSeek 直连大脑
├── native/         原生 macOS App（Swift + SwiftUI）
└── secforge.py     命令行入口
```

**关键设计**：AI 大脑不直接碰工具，中间隔一层 MCP/函数调用。所以
（a）换大脑不用改工具，（b）护栏写在工具里，换大脑绕不过去。

---

## 常见问题

**Q：为什么不直接把数据库放进仓库？**
A：`vulndb.sqlite` 127MB，GitHub 单文件硬上限 100MB。用 `scripts/fetch_data.sh` 下载
Release 附件，或者按上面自己构建。

**Q：能不能不装 AI 只用工具库和漏洞库？**
A：可以。工具库、漏洞库、Windows 版本查询、扫描执行都不依赖 AI。

**Q：支持 Windows / Linux 吗？**
A：扫描和漏洞库是跨平台的（Python）；原生 App 目前是 macOS。
Linux 用网页版界面，Windows 用 WSL2。

**Q：为什么只支持 DeepSeek？**
A：不限。`ui/deepseek_agent.py` 用的是 OpenAI 兼容格式，改成你本地 Ollama 或者
任何 OpenAI 兼容服务只改两个常量。默认给 DeepSeek 是因为它便宜、函数调用稳定。

**Q：跟 PentAGI / Nuclei / 其他 AI 渗透工具什么关系？**
A：互补。SecForge 的定位是**本地索引 + 编排层**：它不重写任何扫描器，而是把已有的
几千个工具和 6 万条漏洞整理成 AI 能用的形式。你也可以只把它的 MCP 服务器接到
你自己的 agent 上。

---

## 数据来源与致谢

- **工具索引**：GitHub Search API（78 个安全 topic + 20 组关键词）
- **漏洞数据**：Microsoft MSRC CVRF、CISA KEV、ExploitDB、NIST NVD
- **所有实际工具**：归各自上游项目所有（nmap / Metasploit / nuclei / sqlmap / hydra / ...）

SecForge 只做编排，不重造轮子。

---

## License

MIT —— 见 [LICENSE](LICENSE)。
使用前请读 [USAGE-POLICY.md](USAGE-POLICY.md)（可接受使用政策）。
**本软件仅限用于合法的网络安全工作：你自己的资产，或你持有书面授权的目标。**

<div align="center"><sub>Built for learning. Use only on systems you are authorized to test.</sub></div>
