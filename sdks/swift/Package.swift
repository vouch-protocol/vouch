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
        // build-xcframework.sh (run on macOS or CI). For distribution, replace
        // `path:` with `url:`/`checksum:` to host a binary release.
        .binaryTarget(
            name: "vouch_coreFFI",
            path: "Frameworks/vouch_coreFFI.xcframework"
        ),
        .target(
            name: "VouchCore",
            dependencies: ["vouch_coreFFI"],
            path: "Sources/VouchCore"
        ),
        .testTarget(
            name: "VouchCoreTests",
            dependencies: ["VouchCore"],
            path: "Tests/VouchCoreTests"
        ),
    ]
)
