// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "SecForge",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(
            name: "SecForge",
            path: "Sources/SecForge",
            linkerSettings: [.linkedLibrary("sqlite3")]
        )
    ]
)
