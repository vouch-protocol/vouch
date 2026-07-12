// swift-tools-version:5.7
import PackageDescription

// VouchCore: the Swift SDK for the Vouch Protocol (#32).
//
// A thin, idiomatic layer over the UniFFI bindings to the canonical Rust core
// (`vouch-core`), so iOS and macOS verify credentials with the exact same bytes
// as every other platform. The native code ships as an XCFramework built by
// `build-xcframework.sh`; the generated UniFFI binding (`vouch_core.swift`)
// imports its `vouch_coreFFI` module.
let package = Package(
    name: "VouchCore",
    platforms: [
        .iOS(.v13),
        .macOS(.v12),
    ],
    products: [
        .library(name: "VouchCore", targets: ["VouchCore"]),
    ],
    targets: [
        // The compiled Rust core + the C FFI module header, built locally by
        // build-xcframework.sh (run on macOS or CI). The hosted release below is
        // produced by .github/workflows/swift-xcframework.yml, so consumers need
        // no local Mac. To rebuild locally, swap back to a `path:` binaryTarget.
        .binaryTarget(
            name: "vouch_coreFFI",
            url: "https://github.com/vouch-protocol/vouch/releases/download/swift-v0.1.0/vouch_coreFFI.xcframework.zip",
            checksum: "307ecf0f5ba2e31b3d04cc2db23d9b4858fffb4161fed04b0c4ef127279e83dc"
        ),
        .target(
            name: "VouchCore",
            dependencies: ["vouch_coreFFI"],
            path: "Sources/VouchCore"
        ),
        .testTarget(
            name: "VouchCoreTests",
            dependencies: ["VouchCore"],
            path: "Tests/VouchCoreTests",
            // The shared cross-language robotics interop fixture, bundled so the
            // curated-robotics interop tests load it via Bundle.module. The file
            // is a symlink to the canonical test-vectors/robotics/vector.json.
            resources: [.process("Resources/vector.json")]
        ),
    ]
)
