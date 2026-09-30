// ⚠️ 使用声明：仅供合法的网络安全工作 —— 你自己的资产，或你持有书面授权的目标。
//    严禁用于任何未授权的系统。相关行为由《刑法》第 285 / 286 条规制。详见 USAGE-POLICY.md
import SwiftUI
import AppKit

@main
struct SecForgeApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var store = Store()
    @StateObject private var runner = Runner()
    @StateObject private var chat = ChatEngine()

    var body: some Scene {
        WindowGroup("SecForge") {
            RootView()
                .environmentObject(store)
                .environmentObject(runner)
                .environmentObject(chat)
                .preferredColorScheme(.dark)
                .onAppear {
                    runner.db = store.vulndb
                    store.refreshOverview()
                    store.searchTools()
                    store.searchVulns()
                    ensureContainer()
                }
        }
        .defaultSize(width: 1320, height: 850)
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }

    private func ensureContainer() {
        DispatchQueue.global().async {
            _ = Shell.run("docker", ["start", CONTAINER], timeout: 120)
            DispatchQueue.main.async { store.refreshOverview() }
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }
}
