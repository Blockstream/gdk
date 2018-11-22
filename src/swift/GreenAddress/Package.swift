// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "GreenAddress",
    dependencies: [
        .package(url: "https://github.com/mxcl/PromiseKit", from: "6.0.0")
    ],
    targets: [
        .target(
            name: "GreenAddress",
            dependencies: ["PromiseKit"]),
        .testTarget(
            name: "GreenAddressTests",
            dependencies: ["GreenAddress"])
    ]
)
