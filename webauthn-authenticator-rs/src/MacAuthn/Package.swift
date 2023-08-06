// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "MacAuthn",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "MacAuthn",
            type: .static,
            targets: ["MacAuthn"]),
    ],
    dependencies: [
        .package(url: "https://github.com/Brendonovich/swift-rs", from: "1.0.5")
    ],
    targets: [
        .target(
            name: "MacAuthn",
            dependencies: [
                .product(
                    name: "SwiftRs",
                    package: "swift-rs"
                ),
            ]),
    ]
)
