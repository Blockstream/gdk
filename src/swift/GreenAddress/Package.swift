// swift-tools-version:4.0
import PackageDescription

let package = Package(
    name: "GreenAddress",
    products: [
        .library(name: "GreenAddress", targets: ["GreenAddress"]),
    ],
    dependencies: [
        .package(url: "https://github.com/mxcl/PromiseKit", .exact("6.10.0")),
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
