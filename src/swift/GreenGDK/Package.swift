// swift-tools-version:5.0
import PackageDescription

let package = Package(
    name: "GreenGDK",
    products: [
        .library(name: "GreenGDK", targets: ["GreenGDK"])
    ],
    targets: [
        .target(name: "GreenGDK")
    ]
)
