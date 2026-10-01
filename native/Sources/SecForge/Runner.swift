import Foundation

/// 跑工具 + 边跑边出结果 + 自动关联漏洞库（对应原来网页版的 /api/run）
final class Runner: ObservableObject {
    @Published var lines: [String] = []
    @Published var running = false
    @Published var vulnBlock = ""
    @Published var lastCmd = ""

    /// 下拉框里实际能选的工具（启动时探测容器后过滤，不再靠“我记得装过”）
    @Published var availableTools: [String] = Runner.tools
    /// 容器里没有、被隐藏掉的
    @Published var missingTools: [String] = []
    /// 探测结果说明，显示在界面上
    @Published var checkNote = "还没检查"

    private var proc: Process?
    private let lock = NSLock()

    /// 菜单（想提供的工具）。实际能不能用由 checkAvailable() 探测。
    static let tools = ["nmap", "nmap-full", "nuclei", "whatweb", "nikto", "httpx",
                        "ffuf", "gobuster", "sqlmap", "wpscan", "dirsearch", "masscan"]

    /// 伪工具名 → 真正要去容器里找的可执行文件名
    static func probeName(_ t: String) -> String { t == "nmap-full" ? "nmap" : t }

    /// 去容器里逐个 `command -v`，把不存在的从下拉框里摘掉。
    /// 目的：工具列表跟着容器实际状态走，不会再出现“菜单上有、厨房没有”。
    func checkAvailable() {
        checkNote = "检查中…"
        let names = Array(Set(Runner.tools.map { Runner.probeName($0) })).sorted()
        let cmd = "for t in \(names.joined(separator: " ")); do "
                + "command -v \"$t\" >/dev/null 2>&1 || echo \"MISS:$t\"; done"
        DispatchQueue.global().async {
            let out = Shell.run("docker", ["exec", CONTAINER, "bash", "-lc", cmd], timeout: 90)
            let low = out.lowercased()
            // 容器没起来 / 找不到 docker —— 这时**不要**过滤，否则下拉框会空掉，
            // 空列表比“菜单多一道菜”更糟。
            let cantCheck = low.contains("not running") || low.contains("no such container")
                || low.contains("cannot connect") || out.hasPrefix("[找不到")
            var missing = Set<String>()
            for line in out.split(separator: "\n") {
                let s = line.trimmingCharacters(in: .whitespaces)
                if s.hasPrefix("MISS:") { missing.insert(String(s.dropFirst(5))) }
            }
            DispatchQueue.main.async {
                if cantCheck {
                    self.availableTools = Runner.tools
                    self.missingTools = []
                    self.checkNote = "没连上容器，列表未过滤（先在「容器与镜像」页启动）"
                    return
                }
                let avail = Runner.tools.filter { !missing.contains(Runner.probeName($0)) }
                if avail.isEmpty {          // 容器在但一个工具都没有？那八成镜像没建好
                    self.availableTools = Runner.tools
                    self.missingTools = []
                    self.checkNote = "容器里一个工具都没找到，可能镜像没构建好"
                    return
                }
                self.availableTools = avail
                self.missingTools = Runner.tools.filter { missing.contains(Runner.probeName($0)) }
                self.checkNote = self.missingTools.isEmpty
                    ? "\(avail.count) 个工具都在"
                    : "已隐藏容器里没有的 \(self.missingTools.count) 个：\(self.missingTools.joined(separator: "、"))"
            }
        }
    }

    static func defaultArgs(tool: String, target: String) -> String {
        switch tool {
        case "nmap", "nmap-full": return "-sV -T4 -Pn \(target)"
        case "nuclei":   return "-u \(target) -severity low,medium,high,critical"
        case "whatweb":  return "-a 3 \(target)"
        case "nikto":    return "-h \(target)"
        case "httpx":    return "-u \(target) -title -tech-detect -status-code"
        case "ffuf":     return "-u \(target)/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403"
        case "gobuster": return "dir -u \(target) -w /usr/share/wordlists/dirb/common.txt -q"
        case "sqlmap":   return "-u \(target) --batch --dbs"
        case "wpscan":   return "--url \(target) --no-update"
        case "dirsearch":return "-u \(target) -e php,html,js,json -t 20"
        case "masscan":  return "\(target) -p1-1000 --rate=1000"
        default:         return target
        }
    }

    func clear() {
        lines = []; vulnBlock = ""; lastCmd = ""
    }

    /// 返回空串表示放行；否则返回拒绝原因（和 Python 版同一套护栏）
    func start(tool: String, args: String, target: String) {
        guard !running else { return }
        if !target.isEmpty {
            let g = Guard.check(target)
            if !g.isEmpty {
                lines = ["$ ⛔ 拦下了", "", g, "", "允许的目标：自有设备 / 内网靶场（DVWA、vulhub、Juice Shop）/ 授权平台（HTB、THM、靶场）。"]
                return
            }
        }
        var a = args
        if a.isEmpty && !target.isEmpty { a = Runner.defaultArgs(tool: tool, target: target) }
        let realTool = (tool == "nmap-full") ? "nmap" : tool
        let cmd = a.isEmpty ? realTool : "\(realTool) \(a)"
        lastCmd = cmd
        lines = ["$ \(cmd)"]
        vulnBlock = ""
        running = true

        let p = Process()
        guard let docker = whichBin("docker") else {
            lines.append("[找不到 docker]"); running = false; return
        }
        p.executableURL = URL(fileURLWithPath: docker)
        p.arguments = ["exec", CONTAINER, "bash", "-lc", "\(cmd) 2>&1"]
        p.environment = appEnv()
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        var buf = ""
        pipe.fileHandleForReading.readabilityHandler = { fh in
            let d = fh.availableData
            if d.isEmpty { return }
            guard let s = String(data: d, encoding: .utf8) else { return }
            self.lock.lock(); buf += s; self.lock.unlock()
            let parts = s.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
            DispatchQueue.main.async { for x in parts where !x.isEmpty { self.lines.append(x) } }
        }
        p.terminationHandler = { [weak self] _ in
            guard let self else { return }
            pipe.fileHandleForReading.readabilityHandler = nil
            self.lock.lock(); let full = buf; self.lock.unlock()
            DispatchQueue.main.async {
                self.running = false
                self.vulnBlock = Runner.associateVulns(text: full, db: self.db)
                if !full.contains("output:") {
                    self.saveLoot(tool: tool, text: full)
                }
            }
        }
        self.proc = p
        do { try p.run() } catch {
            lines.append("[启动失败 \(error.localizedDescription)]"); running = false
        }
    }

    var db: SQLiteDB?   // 由 App 注入，用于漏洞关联

    func stop() {
        proc?.terminate()
        proc = nil
        running = false
    }

    private func saveLoot(tool: String, text: String) {
        let ts = Int(Date().timeIntervalSince1970)
        let name = "ui_\(tool)_\(ts).log"
        let tmp = NSTemporaryDirectory() + name
        try? text.write(toFile: tmp, atomically: true, encoding: .utf8)
        guard let docker = whichBin("docker") else { return }
        DispatchQueue.global().async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: docker)
            p.arguments = ["exec", CONTAINER, "bash", "-lc", "mkdir -p /loot/runs && cat > /loot/runs/\(name)"]
            p.environment = appEnv()
            let inp = Pipe(); p.standardInput = inp
            try? p.run()
            inp.fileHandleForWriting.write(text.data(using: .utf8) ?? Data())
            try? inp.fileHandleForWriting.close()
            p.waitUntilExit()
        }
    }

    // ---------------------------------------------------------------- 服务 -> 产品 映射
    private static let hints: [([String], [String])] = [
        (["microsoft-ds", "netbios", "smb"], ["SMB", "Windows"]),
        (["ms-wbt-server", "rdp", "3389"], ["Remote Desktop", "Windows"]),
        (["ms-sql", "mssql", "1433"], ["SQL Server"]),
        (["ldap", "kerberos"], ["Active Directory", "Windows"]),
        (["winrm", "wsman", "5985", "5986"], ["Windows"]),
        (["openssh", "ssh"], ["OpenSSH"]),
        (["vsftpd", "proftpd", "ftp"], ["vsftpd", "ProFTPD"]),
        (["mysql", "3306"], ["MySQL"]),
        (["vnc", "5900"], ["VNC"]),
        (["nginx"], ["nginx"]),
        (["apache", "httpd"], ["Apache"]),
        (["tomcat"], ["Tomcat"]),
        (["jboss"], ["JBoss"]),
        (["weblogic"], ["WebLogic"]),
        (["struts"], ["Struts"]),
        (["iis"], ["IIS"]),
    ]

    /// 从工具输出抽线索 -> 查本地漏洞库（优先已被真实利用 / 有 PoC 的）
    static func associateVulns(text: String, db: SQLiteDB?) -> String {
        guard let db, db.ok, text.count > 10 else { return "" }
        let low = text.lowercased()
        var products: [String] = []
        for (keys, prods) in hints where keys.contains(where: { low.contains($0) }) {
            for p in prods where !products.contains(p) { products.append(p) }
        }
        guard !products.isEmpty else { return "" }
        var out: [String] = ["【自动关联漏洞库】识别到线索: " + products.joined(separator: ", ")]
        var seen = Set<String>()
        for prod in products.prefix(4) {
            let rows = db.q("""
                SELECT cve_id,title,cvss,severity,kev,poc,kbs FROM cve
                WHERE (affected LIKE ? OR title LIKE ?) AND (kev=1 OR poc=1)
                ORDER BY kev DESC, poc DESC, COALESCE(cvss,0) DESC LIMIT 6
                """, ["%\(prod)%", "%\(prod)%"])
            for r in rows where seen.insert(r.str("cve_id")).inserted {
                var tag = ""
                if r.int("kev") == 1 { tag += "🔥已被真实利用 " }
                if r.int("poc") == 1 { tag += "💥有PoC " }
                let kb = r.str("kbs")
                var line = "  \(r.str("cve_id"))  [\(tag)CVSS \(String(format: "%.1f", r.dbl("cvss")))]  \(r.str("title"))"
                if !kb.isEmpty { line += "\n      补丁: \(kb)" }
                out.append(line)
            }
        }
        if out.count == 1 { out.append("  （本地库里没有匹配的高危条目）") }
        out.append("")
        out.append("提示: 上面是「优先级参考」，不是「你就一定能打进去」。要判断可利用性得看具体版本。")
        return out.joined(separator: "\n")
    }
}
