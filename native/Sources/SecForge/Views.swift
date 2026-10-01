import SwiftUI

// ---------------------------------------------------------------- 配色：深色 + 军绿 + 战术橙
let C_BG     = Color(red: 0.055, green: 0.071, blue: 0.063)
let C_PANEL  = Color(red: 0.082, green: 0.102, blue: 0.090)
let C_LINE   = Color(red: 0.149, green: 0.188, blue: 0.165)
let C_GREEN  = Color(red: 0.306, green: 0.604, blue: 0.388)
let C_ORANGE = Color(red: 0.851, green: 0.478, blue: 0.169)
let C_TEXT   = Color(red: 0.847, green: 0.878, blue: 0.855)
let C_DIM    = Color(red: 0.541, green: 0.604, blue: 0.561)
let C_RED    = Color(red: 0.812, green: 0.325, blue: 0.310)

let MONO = Font.system(size: 12, design: .monospaced)

/// 维护者本机标记：仓库根目录存在 .owner 文件时，界面不再显示长篇使用声明。
/// 注意：只影响「声明显示」—— 护栏（Guard.check）对所有人生效，包括作者本机。
let IS_OWNER_BUILD = FileManager.default.fileExists(atPath: SF_ROOT + "/.owner")

// ---------------------------------------------------------------- 小零件
struct Card<Content: View>: View {
    let title: String?
    let content: Content
    init(_ title: String? = nil, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let title {
                Text(title).font(.system(size: 12, weight: .semibold)).foregroundColor(C_DIM)
            }
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(C_PANEL)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(C_LINE))
    }
}

struct Metric: View {
    let label: String
    let value: String
    let color: Color
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.system(size: 11)).foregroundColor(C_DIM)
            Text(value).font(.system(size: 23, weight: .semibold, design: .rounded)).foregroundColor(color)
        }
        .padding(13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(C_PANEL)
        .clipShape(RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(C_LINE))
    }
}

struct Tag: View {
    let text: String
    let color: Color
    var body: some View {
        Text(text)
            .font(.system(size: 10, weight: .semibold))
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(color.opacity(0.16))
            .foregroundColor(color)
            .clipShape(RoundedRectangle(cornerRadius: 4))
    }
}

func cvssColor(_ v: Double) -> Color {
    if v >= 9 { return C_RED }
    if v >= 7 { return C_ORANGE }
    if v > 0 { return C_GREEN }
    return C_DIM
}

// ---------------------------------------------------------------- 主框架
struct RootView: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var runner: Runner
    @EnvironmentObject var chat: ChatEngine
    @State private var page: String? = "总览"

    var body: some View {
        NavigationSplitView {
            List(selection: $page) {
                Section("工作台") {
                    Label("总览", systemImage: "square.grid.2x2").tag("总览")
                    Label("工具库", systemImage: "wrench.and.screwdriver").tag("工具库")
                    Label("漏洞库", systemImage: "shield").tag("漏洞库")
                    Label("Windows 漏洞", systemImage: "desktopcomputer").tag("win")
                }
                Section("执行") {
                    Label("扫描", systemImage: "dot.radiowaves.left.and.right").tag("扫描")
                    Label("问 AI · 双大脑", systemImage: "brain").tag("对话")
                }
                Section("系统") {
                    Label("容器与镜像", systemImage: "shippingbox").tag("系统")
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .background(C_PANEL)
            .navigationSplitViewColumnWidth(min: 210, ideal: 225, max: 260)
        } detail: {
            ZStack {
                C_BG.ignoresSafeArea()
                switch page ?? "总览" {
                case "工具库":  ToolsView()
                case "漏洞库":  VulnsView()
                case "win":     WindowsView()
                case "扫描":    ScanView()
                case "对话":    ChatView()
                case "系统":    SystemView()
                default:        OverviewView()
                }
            }
            .foregroundColor(C_TEXT)
        }
        .frame(minWidth: 1200, minHeight: 780)
        .task { store.refreshOverview(); store.searchTools(); store.searchVulns() }
    }
}

// ---------------------------------------------------------------- 总览
struct OverviewView: View {
    @EnvironmentObject var store: Store
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack(spacing: 10) {
                    Text("SecForge").font(.system(size: 26, weight: .bold, design: .rounded))
                    Text("原生 macOS 版").font(.system(size: 12)).foregroundColor(C_DIM)
                    Spacer()
                    Button("刷新") { store.refreshOverview() }
                }

                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 4), spacing: 10) {
                    Metric(label: "真工具（已过滤噪音）", value: "\(store.tools)", color: C_GREEN)
                    Metric(label: "CVE 漏洞库", value: "\(store.cves)", color: C_TEXT)
                    Metric(label: "已被真实利用（KEV）", value: "\(store.kev)", color: C_RED)
                    Metric(label: "有公开 PoC", value: "\(store.poc)", color: C_ORANGE)
                    Metric(label: "CVSS ≥ 9", value: "\(store.critical)", color: C_RED)
                    Metric(label: "有 CVSS 评分", value: "\(store.withCvss)", color: C_GREEN)
                    Metric(label: "参考清单", value: "\(store.refs)", color: C_DIM)
                    Metric(label: "爬取原始仓库", value: "\(store.toolsRaw)", color: C_DIM)
                }

                Card("运行环境") {
                    HStack(spacing: 26) {
                        VStack(alignment: .leading, spacing: 5) {
                            Text("Kali 容器").font(.system(size: 11)).foregroundColor(C_DIM)
                            HStack(spacing: 6) {
                                Circle().fill(store.containerStatus.contains("Up") ? C_GREEN : C_RED).frame(width: 8, height: 8)
                                Text(store.containerStatus).font(MONO)
                            }
                        }
                        VStack(alignment: .leading, spacing: 5) {
                            Text("镜像").font(.system(size: 11)).foregroundColor(C_DIM)
                            Text(store.imageSize).font(MONO)
                        }
                        VStack(alignment: .leading, spacing: 5) {
                            Text("PentAGI").font(.system(size: 11)).foregroundColor(C_DIM)
                            Text(store.pentagiUp ? "在跑 (https://localhost:8443)" : "没在跑").font(MONO)
                        }
                        VStack(alignment: .leading, spacing: 5) {
                            Text("漏洞库最后更新").font(.system(size: 11)).foregroundColor(C_DIM)
                            Text(store.lastUpdate).font(MONO)
                        }
                        Spacer()
                    }
                }

                Card("分类（工具库）") {
                    let cols = [GridItem(.adaptive(minimum: 150), spacing: 8)]
                    LazyVGrid(columns: cols, alignment: .leading, spacing: 8) {
                        ForEach(store.categories, id: \.0) { c in
                            HStack(spacing: 6) {
                                Text(c.0).font(.system(size: 12))
                                Text("\(c.1)").font(.system(size: 11)).foregroundColor(C_GREEN)
                                Spacer()
                            }
                            .padding(.horizontal, 9).padding(.vertical, 5)
                            .background(C_BG)
                            .clipShape(RoundedRectangle(cornerRadius: 7))
                            .overlay(RoundedRectangle(cornerRadius: 7).stroke(C_LINE))
                        }
                    }
                }

                if !IS_OWNER_BUILD {
                    Card("使用声明") {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("仅限合法用途：你自己的资产，或你持有书面授权的目标（渗透测试授权书 / 漏洞赏金 Scope）。")
                                .font(.system(size: 12.5)).foregroundColor(C_TEXT)
                            Text("禁止用于任何未授权的系统。政府、教育、军方域名会被直接拦下 —— 这条写死在代码里（sec_run / sec_job_start），换哪个 AI 大脑都绕不过去。\n完整条款：仓库里的 USAGE-POLICY.md")
                                .font(.system(size: 12.5)).foregroundColor(C_DIM)
                        }
                    }
                }
            }
            .padding(20)
        }
    }
}

// ---------------------------------------------------------------- 工具库
struct ToolsView: View {
    @EnvironmentObject var store: Store
    @State private var sel: Row?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                TextField("搜工具（名字 / 描述 / 标签）", text: $store.toolQuery)
                    .textFieldStyle(.roundedBorder).frame(width: 300)
                    .onSubmit { store.searchTools() }
                Picker("", selection: $store.toolCat) {
                    Text("全部分类").tag("")
                    ForEach(store.categories, id: \.0) { Text($0.0).tag($0.0) }
                }.frame(width: 170).onChange(of: store.toolCat) { _ in store.searchTools() }
                Picker("", selection: $store.toolSort) {
                    Text("相关度").tag("score"); Text("星标").tag("stars"); Text("最近更新").tag("pushed")
                }.frame(width: 120).onChange(of: store.toolSort) { _ in store.searchTools() }
                Picker("", selection: $store.toolKind) {
                    Text("工具").tag("tool"); Text("参考清单").tag("reference")
                }.frame(width: 120).onChange(of: store.toolKind) { _ in store.searchTools() }
                Button("搜索") { store.searchTools() }
                Spacer()
                Text("命中 \(store.toolTotal)").font(.system(size: 12)).foregroundColor(C_DIM)
            }

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 7) {
                    ForEach(Array(store.toolRows.enumerated()), id: \.offset) { _, r in
                        Card {
                            HStack(alignment: .top, spacing: 10) {
                                VStack(alignment: .leading, spacing: 4) {
                                    HStack(spacing: 7) {
                                        Text(r.str("name")).font(.system(size: 13.5, weight: .semibold)).foregroundColor(C_TEXT)
                                        Text("⭐\(r.int("stars"))").font(.system(size: 11)).foregroundColor(C_ORANGE)
                                        if !r.str("language").isEmpty { Tag(text: r.str("language"), color: C_GREEN) }
                                        if !r.str("category").isEmpty { Tag(text: r.str("category"), color: C_DIM) }
                                        if !r.str("install_method").isEmpty { Tag(text: r.str("install_method"), color: C_GREEN) }
                                        if r.int("archived") == 1 { Tag(text: "已归档", color: C_RED) }
                                    }
                                    Text(r.str("description")).font(.system(size: 12)).foregroundColor(C_DIM).lineLimit(2)
                                    Text(r.str("url")).font(MONO).foregroundColor(C_GREEN).textSelection(.enabled)
                                }
                                Spacer()
                            }
                        }
                    }
                }
                .padding(.bottom, 10)
            }
        }
        .padding(18)
    }
}

// ---------------------------------------------------------------- 漏洞库
struct VulnsView: View {
    @EnvironmentObject var store: Store
    @State private var minCVSS = 0.0

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                TextField("搜漏洞（CVE / 标题 / 产品 / PoC）", text: $store.vulnQuery)
                    .textFieldStyle(.roundedBorder).frame(width: 300)
                    .onSubmit { store.searchVulns() }
                Toggle("已被真实利用", isOn: $store.vulnKEV).onChange(of: store.vulnKEV) { _ in store.searchVulns() }
                Toggle("有 PoC", isOn: $store.vulnPOC).onChange(of: store.vulnPOC) { _ in store.searchVulns() }
                HStack(spacing: 6) {
                    Text("CVSS ≥").font(.system(size: 12)).foregroundColor(C_DIM)
                    Slider(value: $store.vulnMinCVSS, in: 0...10, step: 0.5)
                        .frame(width: 130)
                        .onChange(of: store.vulnMinCVSS) { _ in store.searchVulns() }
                    Text(String(format: "%.1f", store.vulnMinCVSS)).font(MONO).foregroundColor(C_ORANGE)
                }
                Button("搜索") { store.searchVulns() }
                Spacer()
                Text("命中 \(store.vulnTotal)").font(.system(size: 12)).foregroundColor(C_DIM)
            }

            ScrollView {
                LazyVStack(alignment: .leading, spacing: 7) {
                    ForEach(Array(store.vulnRows.enumerated()), id: \.offset) { _, r in
                        Card {
                            VStack(alignment: .leading, spacing: 5) {
                                HStack(spacing: 7) {
                                    Text(r.str("cve_id")).font(.system(size: 13, weight: .semibold, design: .monospaced)).foregroundColor(C_TEXT)
                                    Text(String(format: "%.1f", r.dbl("cvss"))).font(.system(size: 11, weight: .bold))
                                        .foregroundColor(cvssColor(r.dbl("cvss")))
                                    if r.int("kev") == 1 { Tag(text: "🔥 已被真实利用", color: C_RED) }
                                    if r.int("kev_ransomware") == 1 { Tag(text: "勒索软件在野", color: C_RED) }
                                    if r.int("poc") == 1 { Tag(text: "💥 有 PoC", color: C_ORANGE) }
                                    Text(r.str("published").prefix(10)).font(.system(size: 11)).foregroundColor(C_DIM)
                                }
                                Text(r.str("title")).font(.system(size: 12.5))
                                if !r.str("affected").isEmpty {
                                    Text("影响: \(r.str("affected"))").font(.system(size: 11.5)).foregroundColor(C_DIM).lineLimit(2)
                                }
                                if !r.str("kbs").isEmpty {
                                    Text("补丁: \(r.str("kbs"))").font(MONO).foregroundColor(C_GREEN).textSelection(.enabled)
                                }
                                if !r.str("poc_refs").isEmpty {
                                    Text("PoC: \(r.str("poc_refs"))").font(MONO).foregroundColor(C_ORANGE).lineLimit(2).textSelection(.enabled)
                                }
                            }
                        }
                    }
                }
                .padding(.bottom, 10)
            }
        }
        .padding(18)
    }
}

// ---------------------------------------------------------------- Windows 漏洞
struct WindowsView: View {
    @EnvironmentObject var store: Store
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Text("Windows 版本").font(.system(size: 13))
                Picker("", selection: $store.winLabel) {
                    Text("选一个版本").tag("")
                    ForEach(store.winVersions) { v in
                        Text(v.build.isEmpty ? v.label : "\(v.label)  (\(v.build))").tag(v.label)
                    }
                }.frame(width: 320).onChange(of: store.winLabel) { _ in store.lookupWindows(label: store.winLabel) }
                Button("查该版本漏洞") { store.lookupWindows(label: store.winLabel) }
                Spacer()
                if let r = store.winResult {
                    Text("\(r.str("version")) · 内部版本 \(r.str("build")) · 命中 \(r.int("total")) 个 CVE · 需要打 \(store.winKBs.count) 个补丁")
                        .font(.system(size: 12)).foregroundColor(C_DIM)
                }
            }
            if store.winLabel.isEmpty {
                Card {
                    Text("从下拉框选一个 Windows 版本（表里 27 个：Win 11 各代、Win 10 全部分支、Server 各代、8.1、7 SP1）。\n每个版本查的是库里的 MSRC 产品串，命中的是该版本自己的漏洞，不会跟别的版本串台。")
                        .font(.system(size: 12.5)).foregroundColor(C_DIM)
                }
            } else {
                HStack(alignment: .top, spacing: 12) {
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 7) {
                            Text("最该先修的（按 已被利用 → 有PoC → CVSS 排序）")
                                .font(.system(size: 12, weight: .semibold)).foregroundColor(C_DIM)
                            ForEach(Array(store.winCrit.enumerated()), id: \.offset) { _, r in
                                Card {
                                    HStack(spacing: 7) {
                                        Text(r.str("cve_id")).font(MONO).foregroundColor(C_TEXT)
                                        Text(String(format: "%.1f", r.dbl("cvss"))).font(.system(size: 11, weight: .bold))
                                            .foregroundColor(cvssColor(r.dbl("cvss")))
                                        if r.int("kev") == 1 { Tag(text: "🔥", color: C_RED) }
                                        if r.int("poc") == 1 { Tag(text: "💥PoC", color: C_ORANGE) }
                                    }
                                    Text(r.str("title")).font(.system(size: 12)).foregroundColor(C_TEXT).lineLimit(2)
                                    if !r.str("kbs").isEmpty {
                                        Text(r.str("kbs")).font(MONO).foregroundColor(C_GREEN).textSelection(.enabled)
                                    }
                                }
                            }
                        }
                    }
                    ScrollView {
                        Card("补丁清单（\(store.winKBs.count) 个）") {
                            Text(store.winKBs.joined(separator: "\n"))
                                .font(MONO).foregroundColor(C_GREEN).textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .frame(width: 260)
                }
            }
        }
        .padding(18)
    }
}

// ---------------------------------------------------------------- 扫描
struct ScanView: View {
    @EnvironmentObject var runner: Runner
    @State private var tool = "nmap"
    @State private var target = "127.0.0.1"
    @State private var args = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Card {
                VStack(alignment: .leading, spacing: 8) {
                    HStack(spacing: 10) {
                        Picker("工具", selection: $tool) {
                            ForEach(runner.availableTools, id: \.self) { Text($0).tag($0) }
                        }.frame(width: 180)
                        TextField("目标（IP / 域名，例如 192.168.10.1）", text: $target)
                            .textFieldStyle(.roundedBorder).frame(width: 300)
                        TextField("参数（留空用默认）", text: $args)
                            .textFieldStyle(.roundedBorder)
                        if runner.running {
                            Button("停止") { runner.stop() }.tint(C_RED)
                        } else {
                            Button("开始扫描") { runner.start(tool: tool, args: args, target: target) }
                                .tint(C_GREEN)
                        }
                        Button("清空") { runner.clear() }
                        Button("重新检查") { runner.checkAvailable() }
                            .help("重新去容器里确认哪些工具真实存在（装完新工具点一下就会出现在下拉框里）")
                    }
                    Text("ⓘ " + runner.checkNote)
                        .font(.system(size: 11.5)).foregroundColor(C_DIM)
                }
            }
            .onChange(of: runner.availableTools) { list in
                if !list.contains(tool), let first = list.first { tool = first }
            }

            Card("输出  \(runner.running ? "· 运行中…" : "")") {
                ScrollView {
                    VStack(alignment: .leading, spacing: 1) {
                        ForEach(Array(runner.lines.enumerated()), id: \.offset) { _, l in
                            Text(l).font(MONO)
                                .foregroundColor(l.hasPrefix("$") ? C_ORANGE : (l.hasPrefix("⛔") ? C_RED : C_TEXT))
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
                .frame(minHeight: 220, maxHeight: 340, alignment: .top)
                .textSelection(.enabled)
            }

            if !runner.vulnBlock.isEmpty {
                Card("自动关联漏洞库") {
                    Text(runner.vulnBlock).font(MONO).foregroundColor(C_GREEN)
                        .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                }
            }
            Spacer()
        }
        .padding(18)
    }
}

// ---------------------------------------------------------------- 对话
struct ChatView: View {
    @EnvironmentObject var chat: ChatEngine
    @EnvironmentObject var store: Store
    @State private var input = ""

    func send() {
        let t = input
        input = ""
        chat.send(t, db: store.vulndb)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Picker("大脑", selection: $chat.brain) {
                    Text("Hermes 真身（全权限：能改文件、上网、有记忆）").tag("hermes")
                    Text("DeepSeek 直连（只管工具箱，碰不到你的 Mac）").tag("ds")
                }.frame(width: 480)
                Text(chat.status).font(.system(size: 12)).foregroundColor(C_DIM)
                Spacer()
                if chat.busy { Button("停止") { chat.stop() }.tint(C_RED) }
                Button("新对话") { chat.newChat() }
            }

            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        if chat.lines.isEmpty {
                            Card {
                                Text("两个大脑共用同一个工具箱（同一个容器、同一份 59876 条漏洞库）。\nHermes 那个有全权限，危险命令会弹审批；DeepSeek 那个只能动容器，每步工具调用都会显示给你看。"
                                     + (IS_OWNER_BUILD ? "" : "\n\n⚠️ 仅限合法用途：你自己的资产，或你持有书面授权的目标。"))
                                    .font(.system(size: 12.5)).foregroundColor(C_DIM)
                            }
                        }
                        ForEach(chat.lines) { l in
                            lineView(l).id(l.id)
                        }
                    }
                    .padding(.bottom, 8)
                }
                .onChange(of: chat.lines.count) { _ in
                    if let last = chat.lines.last { withAnimation { proxy.scrollTo(last.id, anchor: .bottom) } }
                }
            }

            HStack(alignment: .bottom, spacing: 8) {
                TextEditor(text: $input)
                    .font(.system(size: 13))
                    .frame(height: 62)
                    .padding(6)
                    .background(C_PANEL)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay(RoundedRectangle(cornerRadius: 8).stroke(C_LINE))
                    .foregroundColor(C_TEXT)
                Button("发送") { send() }.tint(C_GREEN).disabled(chat.busy)
            }
        }
        .padding(18)
    }

    @ViewBuilder
    func lineView(_ l: ChatLine) -> some View {
        switch l.role {
        case "you":
            Text(l.text).font(.system(size: 13))
                .padding(9).frame(maxWidth: 620, alignment: .leading)
                .background(C_GREEN.opacity(0.18))
                .clipShape(RoundedRectangle(cornerRadius: 9))
                .frame(maxWidth: .infinity, alignment: .trailing)
        case "ai":
            Text(l.text).font(.system(size: 13))
                .padding(10).frame(maxWidth: .infinity, alignment: .leading)
                .background(C_PANEL).clipShape(RoundedRectangle(cornerRadius: 9))
                .overlay(RoundedRectangle(cornerRadius: 9).stroke(C_LINE))
                .textSelection(.enabled)
        case "tool":
            Text(l.text).font(MONO).foregroundColor(C_GREEN)
                .padding(6).frame(maxWidth: .infinity, alignment: .leading)
                .background(C_BG).clipShape(RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(C_LINE))
                .textSelection(.enabled)
        case "result":
            Text(l.text).font(.system(size: 11.5, design: .monospaced)).foregroundColor(C_DIM)
                .padding(7).frame(maxWidth: .infinity, alignment: .leading)
                .background(C_BG).clipShape(RoundedRectangle(cornerRadius: 7))
                .overlay(RoundedRectangle(cornerRadius: 7).stroke(C_LINE))
                .textSelection(.enabled)
        default:
            Text(l.text).font(.system(size: 12.5)).foregroundColor(C_RED)
                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                .background(C_RED.opacity(0.10)).clipShape(RoundedRectangle(cornerRadius: 7))
        }
    }
}

// ---------------------------------------------------------------- 系统
struct SystemView: View {
    @EnvironmentObject var store: Store
    @State private var msg = ""

    func docker(_ args: [String], label: String) {
        msg = "\(label)…"
        DispatchQueue.global().async {
            let out = Shell.run("docker", args, timeout: 120)
            DispatchQueue.main.async {
                msg = "\(label)：\(out.trimmingCharacters(in: .whitespacesAndNewlines).suffix(200))"
                store.refreshOverview()
            }
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                if IS_OWNER_BUILD {
                    Card("维护者模式（仅本机）") {
                        Text("仓库根目录有 .owner 文件，所以这台机器上的 App 认定为「作者本机」，不再显示使用声明。\n别人 clone 下去装的版本会自动显示完整声明。\n护栏对所有人生效（包括本机）：政府 / 教育 / 军方域名照样被拒。")
                            .font(.system(size: 12.5)).foregroundColor(C_DIM)
                    }
                }
                Card("Kali 容器") {
                    HStack(spacing: 10) {
                        Circle().fill(store.containerStatus.contains("Up") ? C_GREEN : C_RED).frame(width: 9, height: 9)
                        Text(store.containerStatus).font(MONO)
                        Spacer()
                        Button("启动 / 重启") {
                            docker(["exec", CONTAINER, "true"], label: "探活")
                            docker(["start", CONTAINER], label: "启动容器")
                        }
                        Button("停止") {
                            docker(["stop", CONTAINER], label: "停止容器")
                        }.tint(C_RED)
                        Button("刷新") { store.refreshOverview() }
                    }
                }
                Card("镜像") {
                    Text(store.imageSize).font(MONO).textSelection(.enabled)
                }
                Card("在容器里跑一条命令（只影响容器，碰不到你的 Mac）") {
                    HStack {
                        Button("看装了哪些工具") {
                            msg = Shell.run("docker", ["exec", CONTAINER, "bash", "-lc",
                                "for b in nmap sqlmap msfconsole nuclei nikto ffuf gobuster hydra hashcat john dig whois whatweb wpscan sqlmap searchsploit; do printf '%-14s ' $b; command -v $b >/dev/null && echo OK || echo 没有; done"], timeout: 120)
                        }
                        Button("看 /loot 战利品") {
                            msg = Shell.run("docker", ["exec", CONTAINER, "bash", "-lc", "ls -la /loot /loot/runs 2>/dev/null | head -40"], timeout: 120)
                        }
                        Button("容器资源占用") {
                            msg = Shell.run("docker", ["stats", "--no-stream", "--format", "{{.Name}} CPU={{.CPUPerc}} MEM={{.MemUsage}}", CONTAINER], timeout: 60)
                        }
                        Spacer()
                    }
                    if !msg.isEmpty {
                        Text(msg).font(MONO).foregroundColor(C_GREEN)
                            .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled)
                            .padding(.top, 6)
                    }
                }
                Card("PentAGI（多智能体自主渗透平台）") {
                    Text(store.pentagiUp ? "在跑 · https://localhost:8443（admin@pentagi.com / admin）" : "没在跑 · cd ~/pentagi && docker compose up -d")
                        .font(MONO).foregroundColor(store.pentagiUp ? C_GREEN : C_DIM).textSelection(.enabled)
                }
            }
            .padding(18)
        }
    }
}
