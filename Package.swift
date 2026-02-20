// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "MacSecurityGuard",
    platforms: [.macOS(.v15)],
    targets: [
        .executableTarget(
            name: "MacSecurityGuard",
            path: "Sources"
        ),
        .testTarget(
            name: "MacSecurityGuardTests",
            dependencies: ["MacSecurityGuard"],
            path: "Tests"
        )
    ]
)
