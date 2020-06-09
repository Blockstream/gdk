// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "GreenAddress",
    products: [
        .library(name: "GreenAddress", targets: ["GreenAddress"])
    ],
    targets: [
        .target(name: "GreenAddress")
    ]
)
