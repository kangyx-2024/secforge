import Foundation

struct ChatLine: Identifiable {
    let id = UUID()
    var role: String          // you / ai / tool / result / err
    var text: String
}

/// 两个大脑：Hermes 真身（走 hermes -z）和 DeepSeek 直连（自己跑工具循环）。
/// 共用同一份 SQLite 和同一个容器 —— 换了大脑，工具还是那批工具，护栏也还是那套护栏。
final class ChatEngine: ObservableObject {
    @Published var lines: [ChatLine] = []
    @Published var busy = false
    @Published var status = "新对话"
    @Published var brain = "hermes"

    private var hermesSession = ""
    private var dsHistory: [[String: Any]] = []
    private var stopFlag = false

    func newChat() {
        lines = []
        hermesSession = ""
        dsHistory = []
        status = "新对话"
    }

    func stop() {
        stopFlag = true
        status = "已请求停止"
    }

    func send(_ raw: String, db: SQLiteDB?) {
        let msg = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !msg.isEmpty, !busy else { return }
        stopFlag = false
        lines.append(ChatLine(role: "you", text: msg))
        busy = true
        status = brain == "ds" ? "DeepSeek 思考中…" : "Hermes 思考中…"
        if brain == "ds" { askDeepSeek(msg, db: db) } else { askHermes(msg) }
    }

    // ------------------------------------------------------------ Hermes 真身
    private func askHermes(_ msg: String) {
        DispatchQueue.global().async {
            guard let hb = whichBin("hermes") else {
                DispatchQueue.main.async {
                    self.lines.append(ChatLine(role: "err", text: "找不到 hermes 命令"))
                    self.busy = false
                }
                return
            }
            var args = ["-z", msg]
            if !self.hermesSession.isEmpty { args += ["--resume", self.hermesSession] }
            let t0 = Date()
            let out = Shell.run(hb, args, timeout: 900)
            let sid = self.newestSession(hb)
            DispatchQueue.main.async {
                let txt = out.trimmingCharacters(in: .whitespacesAndNewlines)
                self.lines.append(ChatLine(role: "ai", text: txt.isEmpty ? "(没有输出)" : txt))
                if !sid.isEmpty { self.hermesSession = sid }
                self.busy = false
                self.status = "Hermes · 用时 \(String(format: "%.1f", Date().timeIntervalSince(t0)))s"
            }
        }
    }

    private func newestSession(_ hb: String) -> String {
        let out = Shell.run(hb, ["sessions", "list"], timeout: 60)
        var best = ""
        var rest = Substring(out)
        while let r = rest.range(of: "[0-9]{8}_[0-9]{6}_[0-9a-f]+", options: .regularExpression) {
            let s = String(rest[r])
            if s > best { best = s }
            rest = rest[r.upperBound...]
        }
        return best
    }

    // ------------------------------------------------------------ DeepSeek 直连
    private func dsKey() -> String {
        for p in [SF_ROOT + "/.env", NSHomeDirectory() + "/.hermes/.env"] {
            guard let txt = try? String(contentsOfFile: p, encoding: .utf8) else { continue }
            for line in txt.split(separator: "\n") {
                let s = line.trimmingCharacters(in: .whitespaces)
                if s.hasPrefix("DEEPSEEK_API_KEY=") {
                    return s.replacingOccurrences(of: "DEEPSEEK_API_KEY=", with: "")
                        .trimmingCharacters(in: CharacterSet(charactersIn: "\"' "))
                }
            }
        }
        return ProcessInfo.processInfo.environment["DEEPSEEK_API_KEY"] ?? ""
    }

    private func askDeepSeek(_ msg: String, db: SQLiteDB?) {
        dsHistory.append(["role": "user", "content": msg])
        dsStep(db: db, round: 0)
    }

    private func dsStep(db: SQLiteDB?, round: Int) {
        if stopFlag {
            DispatchQueue.main.async { self.busy = false; self.status = "已停止" }
            return
        }
        if round >= 12 {
            DispatchQueue.main.async {
                self.lines.append(ChatLine(role: "err", text: "工具调用轮数过多，停了"))
                self.busy = false
            }
            return
        }
        let key = dsKey()
        guard !key.isEmpty else {
            DispatchQueue.main.async {
                self.lines.append(ChatLine(role: "err", text: "没找到 DEEPSEEK_API_KEY"))
                self.busy = false
            }
            return
        }
        var msgs: [[String: Any]] = [["role": "system", "content": Self.systemPrompt]]
        msgs += dsHistory.suffix(40)
        let body: [String: Any] = ["model": "deepseek-chat", "messages": msgs,
                                   "tools": Self.toolDefs, "temperature": 0.3, "max_tokens": 3000]
        var req = URLRequest(url: URL(string: "https://api.deepseek.com/v1/chat/completions")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(key)", forHTTPHeaderField: "Authorization")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        req.timeoutInterval = 180

        URLSession.shared.dataTask(with: req) { data, _, err in
            if let err {
                DispatchQueue.main.async {
                    self.lines.append(ChatLine(role: "err", text: "DeepSeek 连接失败: \(err.localizedDescription)"))
                    self.busy = false
                }
                return
            }
            guard let data,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let choices = obj["choices"] as? [[String: Any]],
                  let m = choices.first?["message"] as? [String: Any] else {
                let s = data.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                DispatchQueue.main.async {
                    self.lines.append(ChatLine(role: "err", text: "返回异常: \(s.prefix(300))"))
                    self.busy = false
                }
                return
            }
            if let calls = m["tool_calls"] as? [[String: Any]], !calls.isEmpty {
                var asst: [String: Any] = ["role": "assistant", "content": m["content"] as? String ?? ""]
                asst["tool_calls"] = calls
                self.dsHistory.append(asst)
                for c in calls {
                    let fn = c["function"] as? [String: Any] ?? [:]
                    let name = fn["name"] as? String ?? ""
                    let rawArgs = fn["arguments"] as? String ?? "{}"
                    let args = (try? JSONSerialization.jsonObject(with: rawArgs.data(using: .utf8) ?? Data())) as? [String: Any] ?? [:]
                    let pretty = (try? JSONSerialization.data(withJSONObject: args, options: [.sortedKeys])).flatMap { String(data: $0, encoding: .utf8) } ?? rawArgs
                    DispatchQueue.main.async {
                        self.lines.append(ChatLine(role: "tool", text: "→ \(name)(\(pretty))"))
                        self.status = "DeepSeek 正在调 \(name)…"
                    }
                    let result = Self.execTool(name, args, db: db)
                    DispatchQueue.main.async {
                        self.lines.append(ChatLine(role: "result", text: String(result.prefix(1800))))
                    }
                    self.dsHistory.append(["role": "tool", "tool_call_id": c["id"] as? String ?? "",
                                           "content": String(result.prefix(20000))])
                }
                self.dsStep(db: db, round: round + 1)
                return
            }
            let answer = m["content"] as? String ?? ""
            DispatchQueue.main.async {
                self.lines.append(ChatLine(role: "ai", text: answer))
                self.busy = false
                self.status = "DeepSeek 直连 · 第 \(round + 1) 轮"
            }
            self.dsHistory.append(["role": "assistant", "content": answer])
        }.resume()
    }

    // ------------------------------------------------------------ 工具定义（给 DeepSeek 看）
    static let toolDefs: [[String: Any]] = [
        ChatEngine.fn("sec_overview", "看工具箱总体状态：工具库数量、漏洞库数量、镜像、容器、PentAGI。", [:]),
        ChatEngine.fn("sec_catalog", "检索本地 GitHub 安全工具库（5000+ 真工具）。", [
            "query": ["type": "string", "description": "关键词，如 scanner / nuclei / ad"],
            "category": ["type": "string", "description": "分类，如 web / network / password"],
            "limit": ["type": "integer", "description": "返回条数，默认 10"]]),
        ChatEngine.fn("sec_vuln_search", "搜索本地漏洞库（59876 条 CVE，含微软 MSRC / CISA KEV / ExploitDB）。", [
            "query": ["type": "string", "description": "关键词，如 SMB / RDP / SQL Server"],
            "kev_only": ["type": "boolean", "description": "只看已被真实利用的"],
            "poc_only": ["type": "boolean", "description": "只看有公开 PoC 的"],
            "min_cvss": ["type": "number", "description": "最低 CVSS 分"],
            "limit": ["type": "integer", "description": "返回条数，默认 8"]]),
        ChatEngine.fn("sec_vuln_detail", "查某个 CVE 的详情 + 受影响产品 + 补丁 KB。", [
            "cve_id": ["type": "string", "description": "如 CVE-2020-0796"]]),
        ChatEngine.fn("sec_vuln_for_windows", "查某个 Windows 版本的漏洞和要打的补丁。version 填显示名（如 \"Windows 10 22H2\"、\"Windows 11 24H2\"、\"Windows Server 2019\"、\"Windows 7 SP1\"），build 填内部版本号（如 19045）。给一个就行。", [
            "version": ["type": "string", "description": "版本名，如 Windows 10 22H2"],
            "build": ["type": "string", "description": "内部版本号，如 19045"]]),
        ChatEngine.fn("sec_run", "在隔离的 Kali 容器里跑一个安全工具，返回输出。", [
            "tool": ["type": "string", "description": "nmap / nuclei / nikto / whatweb / httpx / ffuf / gobuster / sqlmap"],
            "args": ["type": "string", "description": "传给工具的完整参数，如 -sV -T4 -Pn 192.168.10.1"]]),
        ChatEngine.fn("sec_shell", "在容器里跑任意 shell 命令（查文件、装工具、看进程）。", [
            "cmd": ["type": "string", "description": "shell 命令"]]),
    ]

    private static func fn(_ name: String, _ desc: String, _ props: [String: Any]) -> [String: Any] {
        var required: [String] = []
        if name == "sec_vuln_detail" { required = ["cve_id"] }
        if name == "sec_run" { required = ["tool", "args"] }
        if name == "sec_shell" { required = ["cmd"] }
        return ["type": "function", "function": [
            "name": name, "description": desc,
            "parameters": ["type": "object", "properties": props, "required": required]]]
    }

    // ------------------------------------------------------------ 工具执行（原生实现，不经过任何网页服务）
    static func execTool(_ name: String, _ a: [String: Any], db: SQLiteDB?) -> String {
        let cat = SQLiteDB(CATALOG_DB)
        switch name {
        case "sec_overview":
            var out = "=== SecForge 状态 ===\n"
            if cat.ok {
                out += "工具库: \(cat.n("SELECT COUNT(*) AS n FROM tools WHERE noise=0 AND kind='tool'")) 个真工具\n"
            }
            if let db, db.ok {
                out += "漏洞库: \(db.n("SELECT COUNT(*) AS n FROM cve")) 个 CVE"
                out += " (\(db.n("SELECT COUNT(*) AS n FROM cve WHERE kev=1")) 已被真实利用, "
                out += "\(db.n("SELECT COUNT(*) AS n FROM cve WHERE kbs IS NOT NULL AND kbs != ''")) 带补丁KB)\n"
            }
            out += "容器: " + Shell.run("docker", ["ps", "-a", "--filter", "name=^\(CONTAINER)$", "--format", "{{.Status}}"], timeout: 30).trimmingCharacters(in: .whitespacesAndNewlines)
            return out

        case "sec_catalog":
            guard cat.ok else { return "工具库打不开" }
            var w = ["noise = 0"]; var binds: [Any] = []
            if let q = a["query"] as? String, !q.isEmpty {
                w.append("(name LIKE ? OR description LIKE ? OR topics LIKE ?)")
                binds += ["%\(q)%", "%\(q)%", "%\(q)%"]
            }
            if let c = a["category"] as? String, !c.isEmpty { w.append("category = ?"); binds.append(c) }
            let lim = (a["limit"] as? Int) ?? (a["limit"] as? Double).map(Int.init) ?? 10
            let rows = cat.q("SELECT name,stars,category,language,description,url,install_method FROM tools WHERE \(w.joined(separator: " AND ")) ORDER BY score DESC LIMIT \(max(1, min(lim, 40)))", binds)
            if rows.isEmpty { return "没有匹配的工具" }
            return rows.map { "\($0.str("name"))  ⭐\($0.int("stars"))  [\($0.str("category"))/\($0.str("language"))]\n   \($0.str("description").prefix(160))\n   \($0.str("url"))\n   安装: \($0.str("install_method"))" }.joined(separator: "\n")

        case "sec_vuln_search":
            guard let db, db.ok else { return "漏洞库打不开" }
            var w: [String] = []; var binds: [Any] = []
            if let q = a["query"] as? String, !q.isEmpty {
                w.append("(title LIKE ? OR description LIKE ? OR affected LIKE ? OR cve_id LIKE ?)")
                binds += ["%\(q)%", "%\(q)%", "%\(q)%", "%\(q)%"]
            }
            if (a["kev_only"] as? Bool) == true { w.append("kev = 1") }
            if (a["poc_only"] as? Bool) == true { w.append("poc = 1") }
            if let m = a["min_cvss"] as? Double, m > 0 { w.append("cvss >= ?"); binds.append(m) }
            let lim = (a["limit"] as? Int) ?? (a["limit"] as? Double).map(Int.init) ?? 8
            let where_ = w.isEmpty ? "" : " WHERE " + w.joined(separator: " AND ")
            let rows = db.q("SELECT cve_id,title,cvss,severity,kev,poc,kbs,affected,poc_refs FROM cve\(where_) ORDER BY kev DESC, poc DESC, COALESCE(cvss,0) DESC LIMIT \(max(1, min(lim, 40)))", binds)
            if rows.isEmpty { return "没命中" }
            return "命中 \(db.n("SELECT COUNT(*) AS n FROM cve\(where_)", binds)) 条（共 \(db.n("SELECT COUNT(*) AS n FROM cve")) 个 CVE）\n\n" + rows.map { r in
                var t = ""
                if r.int("kev") == 1 { t += "🔥已被真实利用 " }
                if r.int("poc") == 1 { t += "💥有PoC " }
                var s = "\(r.str("cve_id"))  [\(t)CVSS \(String(format: "%.1f", r.dbl("cvss"))) \(r.str("severity"))]\n   \(r.str("title"))\n   影响: \(r.str("affected").prefix(120))"
                let kb = r.str("kbs"); if !kb.isEmpty { s += "\n   补丁: \(kb)" }
                let pr = r.str("poc_refs"); if !pr.isEmpty { s += "\n   PoC: \(pr.prefix(160))" }
                return s
            }.joined(separator: "\n\n")

        case "sec_vuln_detail":
            guard let db, db.ok else { return "漏洞库打不开" }
            let id = ((a["cve_id"] as? String) ?? "").uppercased()
            let rows = db.q("SELECT * FROM cve WHERE cve_id=?", [id])
            guard let r = rows.first else { return "没找到 \(id)" }
            var s = "\(r.str("cve_id"))  \(r.str("title"))\nCVSS: \(String(format: "%.1f", r.dbl("cvss"))) \(r.str("severity"))\n"
            if r.int("kev") == 1 { s += "🔥 已被真实利用（CISA KEV）\n" }
            if r.int("poc") == 1 { s += "💥 有公开 PoC\n" }
            if !r.str("kbs").isEmpty { s += "补丁: \(r.str("kbs"))\n" }
            if !r.str("cwe").isEmpty { s += "CWE: \(r.str("cwe"))\n" }
            s += "发布: \(r.str("published"))\n\n简介: \(r.str("description").prefix(700))\n"
            let prods = db.q("SELECT DISTINCT product, kb FROM affected WHERE cve_id=? LIMIT 30", [id])
            if !prods.isEmpty {
                s += "\n受影响产品:\n" + prods.map { "  - \($0.str("product"))\($0.str("kb").isEmpty ? "" : "  [\($0.str("kb"))]")" }.joined(separator: "\n")
            }
            return s

        case "sec_vuln_for_windows":
            guard let db, db.ok else { return "漏洞库打不开" }
            let b = (a["build"] as? String ?? "").replacingOccurrences(of: "10.0.", with: "")
            let want = (a["version"] as? String ?? "").trimmingCharacters(in: .whitespaces)
            guard !b.isEmpty || !want.isEmpty else { return "要给 version 或 build，比如 version=\"Windows 10 22H2\" 或 build=\"19045\"" }
            // 三列表：显示名 / 内部版本号 / 产品匹配串 —— 匹配串才是拿去 LIKE 的真子串
            let vers = db.q("SELECT label, build, COALESCE(match,label) AS m FROM win_versions")
            var label = "", match = ""
            if !want.isEmpty {
                for r in vers where want.lowercased() == r.str("label").lowercased() {
                    label = r.str("label"); match = r.str("m"); break
                }
            }
            if match.isEmpty && !b.isEmpty {
                for r in vers where r.str("build") == b {
                    label = r.str("label"); match = r.str("m"); break
                }
            }
            if match.isEmpty { match = want.isEmpty ? b : want; label = match }   // 兜底：原文当匹配串
            let q = "SELECT cve_id,title,cvss,severity,kev,poc,kbs FROM cve WHERE cve_id IN (SELECT cve_id FROM affected WHERE product LIKE ?)"
            let rows = db.q(q + " ORDER BY kev DESC, poc DESC, COALESCE(cvss,0) DESC LIMIT 60", ["%\(match)%"])
            let total = db.n("SELECT COUNT(*) AS n FROM cve WHERE cve_id IN (SELECT cve_id FROM affected WHERE product LIKE ?)", ["%\(match)%"])
            var s = "\(label)：库内共 \(total) 个相关 CVE\n\n最该先修的:\n"
            s += rows.prefix(25).map { "  \($0.str("cve_id"))  CVSS \(String(format: "%.1f", $0.dbl("cvss")))\($0.int("kev") == 1 ? " 🔥" : "")\($0.int("poc") == 1 ? " 💥" : "")  \($0.str("title").prefix(90))\($0.str("kbs").isEmpty ? "" : "\n      补丁 \($0.str("kbs"))")" }.joined(separator: "\n")
            return s

        case "sec_run":
            let tool = a["tool"] as? String ?? "nmap"
            let args = a["args"] as? String ?? ""
            let target = args.split(separator: " ").last.map(String.init) ?? ""
            let g = Guard.check(target)
            if !g.isEmpty { return g }
            guard let docker = whichBin("docker") else { return "找不到 docker" }
            return Shell.run(docker, ["exec", CONTAINER, "bash", "-lc", "\(tool) \(args) 2>&1"], timeout: 300)

        case "sec_shell":
            let cmd = a["cmd"] as? String ?? ""
            guard !cmd.isEmpty else { return "命令为空" }
            guard let docker = whichBin("docker") else { return "找不到 docker" }
            return Shell.run(docker, ["exec", CONTAINER, "bash", "-lc", cmd], timeout: 300)

        default:
            return "没有这个工具: \(name)"
        }
    }

    static let systemPrompt = """
    你是 SecForge 工具箱的 AI 操作员（运行在用户 Mac 上的原生 App 里）。
    你有工具可以：查本地 GitHub 安全工具库、查本地漏洞库(59876 条 CVE，含 MSRC/KEV/ExploitDB)、
    在隔离的 Kali 容器里跑安全工具。

    规矩：
    1. 用中文，简洁直接。
    2. 要干活就真调工具，别只描述。拿到结果再下结论。
    3. 只报告工具真实返回的内容，不许编造 CVE 号或补丁号。
    4. 目标只允许自有设备、内网靶场、授权平台。政府/教育/军方域名会被工具层直接拒绝，
       遇到拒绝就如实说明，不要绕。
    5. 做完给结论：发现了什么、下一步建议什么。
    """
}
