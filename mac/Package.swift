// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "Sallyport",
    defaultLocalization: "en",
    platforms: [
        // macOS 14 provides @Observable, MenuBarExtra, and CryptoKit SecureEnclave.
        // Secure Enclave and Touch ID require a signed app bundle; see README.md.
        .macOS(.v14)
    ],
    products: [
        .library(name: "SallyportKit", targets: ["SallyportKit"]),
        .library(name: "SallyportVault", targets: ["SallyportVault"]),
        .library(name: "SallyportCLI", targets: ["SallyportCLI"]),
        .executable(name: "sallyport-app", targets: ["SallyportApp"]),
        .executable(name: "sp", targets: ["sp"]),
    ],
    dependencies: [
        // Sparkle updates the directly distributed app. build-app.sh embeds and
        // signs Sparkle.framework.
        .package(url: "https://github.com/sparkle-project/Sparkle", from: "2.9.4"),
    ],
    targets: [
        // Shared view-free models and utilities.
        .target(
            name: "SallyportKit",
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        // In-process vault core: storage, cryptography, authorization, sessions,
        // provenance, channel execution, and audit.
        .target(
            name: "SallyportVault",
            dependencies: ["SallyportKit"],
            swiftSettings: [
                .swiftLanguageMode(.v6),
                .enableUpcomingFeature("StrictConcurrency"),
            ]
        ),
        // Library target for testing CLI framing, timeouts, and socket paths.
        .target(
            name: "SallyportCLI",
            dependencies: ["SallyportKit"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .executableTarget(
            name: "sp",
            dependencies: ["SallyportCLI"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // SwiftUI app, in-process vault runtime, approvals, and management UI.
        .executableTarget(
            name: "SallyportApp",
            dependencies: [
                "SallyportKit", "SallyportVault",
                .product(name: "Sparkle", package: "Sparkle"),
            ],
            resources: [
                .process("Resources/Localizable.xcstrings"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ],
            // build-app.sh copies Sparkle.framework into Contents/Frameworks.
            // This rpath loads it from the bundle instead of the .build path.
            linkerSettings: [
                .unsafeFlags(["-Xlinker", "-rpath", "-Xlinker", "@executable_path/../Frameworks"])
            ]
        ),
        .testTarget(
            name: "SallyportKitTests",
            // Tests AppModel together with the engine and store types it uses.
            dependencies: ["SallyportKit", "SallyportApp", "SallyportVault"],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
        .testTarget(
            name: "SallyportVaultTests",
            dependencies: ["SallyportVault"],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        ),
        .testTarget(
            name: "SallyportCLITests",
            dependencies: ["SallyportCLI"],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
    ]
)
