// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "VaporSecurityHeaders",
    products: [
        .library(name: "VaporSecurityHeaders", targets: ["VaporSecurityHeaders"]),
    ],
    dependencies: [
    	.package(url: "https://github.com/vapor/vapor.git", .branch("beta")),
    	.package(url: "https://github.com/vapor/engine.git", .branch("beta")),
    ],
    targets: [
        .target(name: "VaporSecurityHeaders", dependencies: ["Vapor", "HTTP"]),
        .testTarget(name: "VaporSecurityHeadersTests", dependencies: ["VaporSecurityHeaders"]),
    ]
)
