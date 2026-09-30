import Foundation
import SQLite3

// ---------------------------------------------------------------- 路径 / 常量
/// 工具箱根目录，优先级：环境变量 SECFORGE_ROOT → ~/secforge
func resolveRoot() -> String {
    if let e = ProcessInfo.processInfo.environment["SECFORGE_ROOT"], !e.isEmpty { return e }
    let home = NSHomeDirectory() + "/secforge"
    return home
}
let SF_ROOT = resolveRoot()
let CATALOG_DB = SF_ROOT + "/catalog/catalog.sqlite"
let VULNDB_DB = SF_ROOT + "/vulndb/vulndb.sqlite"
let CONTAINER = "secforge"

/// Finder 启动的 App 环境变量很精简 —— 手动补 PATH，否则找不到 docker/hermes
func appEnv() -> [String: String] {
    var e = ProcessInfo.processInfo.environment
    e["PATH"] = "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:\(NSHomeDirectory())/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    return e
}

func whichBin(_ name: String) -> String? {
    let cands = ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)",
                 "\(NSHomeDirectory())/.local/bin/\(name)", "/usr/bin/\(name)"]
    return cands.first { FileManager.default.isExecutableFile(atPath: $0) }
}

// ---------------------------------------------------------------- SQLite
typealias Row = [String: Any]

/// Windows 版本表的行：显示名 / 内部版本号 / 产品匹配串
/// 匹配串必须是 affected.product 里真实存在的子串（如 "Windows 10 Version 22H2"），
/// 不能用 "22H2" 这种短标签去猜，否则 Win10/Win11 会互相串台或干脆查不出东西。
struct WinVer: Identifiable, Hashable {
    var id: String { label }
    let label: String
    let build: String
    let match: String
}

extension Dictionary where Key == String, Value == Any {
    func str(_ k: String) -> String {
        if let s = self[k] as? String { return s }
        if let i = self[k] as? Int { return String(i) }
        if let d = self[k] as? Double { return String(d) }
        return ""
    }
    func int(_ k: String) -> Int {
        if let i = self[k] as? Int { return i }
        if let d = self[k] as? Double { return Int(d) }
        if let s = self[k] as? String { return Int(s) ?? 0 }
        return 0
    }
    func dbl(_ k: String) -> Double {
        if let d = self[k] as? Double { return d }
        if let i = self[k] as? Int { return Double(i) }
        if let s = self[k] as? String { return Double(s) ?? 0 }
        return 0
    }
    func has(_ k: String) -> Bool { (self[k] as? String)?.isEmpty == false || (self[k] as? Int) != nil }
}

final class SQLiteDB {
    private var h: OpaquePointer?
    init(_ path: String) {
        if sqlite3_open_v2(path, &h, SQLITE_OPEN_READONLY, nil) != SQLITE_OK {
            h = nil
        }
    }
    deinit { if h != nil { sqlite3_close(h) } }
    var ok: Bool { h != nil }
    private static let TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

    func q(_ sql: String, _ binds: [Any] = []) -> [Row] {
        guard let h else { return [] }
        var st: OpaquePointer?
        guard sqlite3_prepare_v2(h, sql, -1, &st, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(st) }
        for (i, b) in binds.enumerated() {
            let idx = Int32(i + 1)
            switch b {
            case let s as String: sqlite3_bind_text(st, idx, s, -1, SQLiteDB.TRANSIENT)
            case let n as Int:    sqlite3_bind_int64(st, idx, Int64(n))
            case let d as Double: sqlite3_bind_double(st, idx, d)
            default:              sqlite3_bind_null(st, idx)
            }
        }
        var out: [Row] = []
        while sqlite3_step(st) == SQLITE_ROW {
            var row: Row = [:]
            for c in 0..<sqlite3_column_count(st) {
                let name = String(cString: sqlite3_column_name(st, c))
                switch sqlite3_column_type(st, c) {
                case SQLITE_INTEGER: row[name] = Int(sqlite3_column_int64(st, c))
                case SQLITE_FLOAT:   row[name] = sqlite3_column_double(st, c)
                case SQLITE_NULL:    break
                default:
                    if let cs = sqlite3_column_text(st, c) { row[name] = String(cString: cs) }
                }
            }
            out.append(row)
        }
        return out
    }
    /// 取单个数字（SQL 里请写成 SELECT COUNT(*) AS n ...）
    func n(_ sql: String, _ binds: [Any] = []) -> Int { q(sql, binds).first?.int("n") ?? 0 }
}

// ---------------------------------------------------------------- 安全护栏（和 Python 那边同一套）
enum Guard {
    static let blocked = [".gov", ".gov.cn", ".edu", ".edu.cn", ".mil", ".ac.cn", "gov.hk", "edu.hk"]

    static func check(_ target: String) -> String {
        let t = target.trimmingCharacters(in: .whitespaces).lowercased()
        if t.isEmpty { return "" }
        var host = t
        if let r = host.range(of: "^[a-z]+://", options: .regularExpression) { host.removeSubrange(r) }
        host = host.split(separator: "/").first.map(String.init) ?? host
        host = host.split(separator: ":").first.map(String.init) ?? host
        if let last = host.split(separator: "@").last { host = String(last) }
        for b in blocked where host.hasSuffix(b) || host.contains(b.replacingOccurrences(of: ".", with: "")) {
            return "⛔ 拒绝: \(host) 属于政府/教育/军方域名。只允许打自有设备、内网靶场或授权平台。"
        }
        return ""
    }
}

// ---------------------------------------------------------------- 数据仓库
final class Store: ObservableObject {
    let catalog = SQLiteDB(CATALOG_DB)
    let vulndb = SQLiteDB(VULNDB_DB)

    // 总览
    @Published var toolsRaw = 0
    @Published var tools = 0
    @Published var refs = 0
    @Published var cves = 0
    @Published var kev = 0
    @Published var poc = 0
    @Published var critical = 0
    @Published var withCvss = 0
    @Published var imageSize = "—"
    @Published var containerStatus = "未创建"
    @Published var pentagiUp = false
    @Published var lastUpdate = "—"

    // 工具库
    @Published var toolRows: [Row] = []
    @Published var toolTotal = 0
    @Published var toolQuery = ""
    @Published var toolCat = ""
    @Published var toolKind = "tool"
    @Published var toolSort = "score"
    @Published var categories: [(String, Int)] = []

    // 漏洞库
    @Published var vulnRows: [Row] = []
    @Published var vulnTotal = 0
    @Published var vulnQuery = ""
    @Published var vulnKEV = false
    @Published var vulnPOC = false
    @Published var vulnMinCVSS = 0.0

    // Windows
    @Published var winVersions: [WinVer] = []
    @Published var winLabel = ""
    @Published var winResult: Row?
    @Published var winCrit: [Row] = []
    @Published var winKBs: [String] = []

    func refreshOverview() {
        if catalog.ok {
            toolsRaw = catalog.n("SELECT COUNT(*) AS n FROM tools")
            tools = catalog.n("SELECT COUNT(*) AS n FROM tools WHERE noise=0 AND kind='tool'")
            refs = catalog.n("SELECT COUNT(*) AS n FROM tools WHERE noise=0 AND kind='reference'")
            categories = catalog.q("SELECT category AS c, COUNT(*) AS n FROM tools WHERE noise=0 AND kind='tool' GROUP BY category ORDER BY n DESC")
                .map { ($0.str("c"), $0.int("n")) }
        }
        if vulndb.ok {
            cves = vulndb.n("SELECT COUNT(*) AS n FROM cve")
            kev = vulndb.n("SELECT COUNT(*) AS n FROM cve WHERE kev=1")
            poc = vulndb.n("SELECT COUNT(*) AS n FROM cve WHERE poc=1")
            critical = vulndb.n("SELECT COUNT(*) AS n FROM cve WHERE cvss>=9")
            withCvss = vulndb.n("SELECT COUNT(*) AS n FROM cve WHERE cvss IS NOT NULL")
            winVersions = vulndb.q("SELECT label, build, COALESCE(match, label) AS m FROM win_versions")
                .map { WinVer(label: $0.str("label"), build: $0.str("build"), match: $0.str("m")) }
        }
        let lu = SF_ROOT + "/vulndb/last_update.json"
        if let d = try? Data(contentsOf: URL(fileURLWithPath: lu)),
           let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] {
            lastUpdate = (o["time"] as? String) ?? (o["updated"] as? String) ?? "—"
        }
        DispatchQueue.global().async {
            let img = Shell.run("docker", ["images", "--format", "{{.Repository}}:{{.Tag}}|{{.Size}}"], timeout: 30)
            let line = img.split(separator: "\n").first { $0.contains("secforge") }.map(String.init) ?? "无"
            let ps = Shell.run("docker", ["ps", "-a", "--filter", "name=^\(CONTAINER)$", "--format", "{{.Status}}"], timeout: 30)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let pent = Shell.run("docker", ["ps", "--filter", "name=pentagi", "-q"], timeout: 30)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.main.async {
                self.imageSize = line.replacingOccurrences(of: "|", with: "  ")
                self.containerStatus = ps.isEmpty ? "未创建" : ps
                self.pentagiUp = !pent.isEmpty
            }
        }
    }

    func searchTools() {
        guard catalog.ok else { return }
        var w: [String] = [], a: [Any] = []
        if !toolQuery.isEmpty {
            w.append("(name LIKE ? OR description LIKE ? OR topics LIKE ? OR full_name LIKE ?)")
            let like = "%\(toolQuery)%"
            a += [like, like, like, like]
        }
        if !toolCat.isEmpty { w.append("category = ?"); a.append(toolCat) }
        if !toolKind.isEmpty { w.append("kind = ?"); a.append(toolKind) }
        w.append("noise = 0")
        let where_ = w.isEmpty ? "" : " WHERE " + w.joined(separator: " AND ")
        let order: String
        switch toolSort {
        case "stars": order = "stars DESC"
        case "pushed": order = "pushed_at DESC"
        default: order = "score DESC"
        }
        toolTotal = catalog.n("SELECT COUNT(*) AS n FROM tools\(where_)", a)
        toolRows = catalog.q("SELECT name,full_name,stars,category,language,install_method,install_spec,description,url,pushed_at,archived,kind FROM tools\(where_) ORDER BY \(order) LIMIT 200", a)
    }

    func searchVulns() {
        guard vulndb.ok else { return }
        var w: [String] = [], a: [Any] = []
        if !vulnQuery.isEmpty {
            w.append("(title LIKE ? OR description LIKE ? OR affected LIKE ? OR poc_refs LIKE ? OR cve_id LIKE ?)")
            let like = "%\(vulnQuery)%"
            a += [like, like, like, like, like]
        }
        if vulnKEV { w.append("kev = 1") }
        if vulnPOC { w.append("poc = 1") }
        if vulnMinCVSS > 0 { w.append("cvss >= ?"); a.append(vulnMinCVSS) }
        let where_ = w.isEmpty ? "" : " WHERE " + w.joined(separator: " AND ")
        vulnTotal = vulndb.n("SELECT COUNT(*) AS n FROM cve\(where_)", a)
        vulnRows = vulndb.q("SELECT cve_id,title,severity,cvss,impact,kev,kev_ransomware,poc,affected,kbs,published,poc_refs FROM cve\(where_) ORDER BY kev DESC, poc DESC, COALESCE(cvss,0) DESC LIMIT 200", a)
    }

    func lookupWindows(label: String) {
        guard vulndb.ok else { return }
        guard let v = winVersions.first(where: { $0.label == label }) else { return }
        let match = v.match.isEmpty ? v.label : v.match
        let all = vulndb.q("SELECT cve_id,title,severity,cvss,impact,kev,poc,affected,kbs,published FROM cve WHERE cve_id IN (SELECT cve_id FROM affected WHERE product LIKE ?) ORDER BY COALESCE(cvss,0) DESC LIMIT 4000", ["%\(match)%"])
        // 真实总条数（上面的 LIMIT 只是抓取上限，别拿它当总数报给用户）
        let trueTotal = vulndb.n("SELECT COUNT(*) AS n FROM cve WHERE cve_id IN (SELECT cve_id FROM affected WHERE product LIKE ?)", ["%\(match)%"])
        let sorted = all.sorted { l, r in
            if l.int("kev") != r.int("kev") { return l.int("kev") > r.int("kev") }
            if l.int("poc") != r.int("poc") { return l.int("poc") > r.int("poc") }
            return l.dbl("cvss") > r.dbl("cvss")
        }
        winResult = ["version": v.label, "build": v.build.isEmpty ? "—" : v.build, "match": match, "total": trueTotal]
        winCrit = Array(sorted.filter { $0.int("kev") == 1 || $0.dbl("cvss") >= 8 || $0.str("severity") == "Critical" }.prefix(60))
        var kbSeen = Set<String>()
        var kbs: [String] = []
        for r in sorted {
            let s = r.str("kbs")
            var rest = Substring(s)
            while let rng = rest.range(of: "KB[0-9]+", options: .regularExpression) {
                let kb = String(rest[rng])
                if kbSeen.insert(kb).inserted { kbs.append(kb) }
                rest = rest[rng.upperBound...]
            }
        }
        winKBs = kbs
    }
}

// ---------------------------------------------------------------- 起进程
enum Shell {
    @discardableResult
    static func run(_ launch: String, _ args: [String], timeout: Double = 120) -> String {
        let p = Process()
        if launch.contains("/") {
            p.executableURL = URL(fileURLWithPath: launch)
        } else if let b = whichBin(launch) {
            p.executableURL = URL(fileURLWithPath: b)
        } else {
            return "[找不到可执行文件 \(launch)]"
        }
        p.arguments = args
        p.environment = appEnv()
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        do { try p.run() } catch { return "[启动失败 \(error.localizedDescription)]" }
        let deadline = Date().addingTimeInterval(timeout)
        let sem = DispatchSemaphore(value: 0)
        var data = Data()
        DispatchQueue.global().async {
            data = pipe.fileHandleForReading.readDataToEndOfFile()
            sem.signal()
        }
        while sem.wait(timeout: .now() + 0.2) == .timedOut {
            if Date() > deadline { p.terminate(); return "[超时 \(Int(timeout))s]" }
        }
        return String(data: data, encoding: .utf8) ?? ""
    }
}
