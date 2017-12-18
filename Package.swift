// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "VaporSecurityHeaders",
    products: [
        .library(name: "VaporSecurityHeaders", targets: ["VaporSecurityHeaders"]),
    ],
    dependencies: [
    	.package(url: "https://github.com/vapor/vapor.git", .exact("3.0.0-alpha.12")),
    ],
    targets: [
        .target(name: "VaporSecurityHeaders", dependencies: ["Vapor", "HTTP"]),
        .testTarget(name: "VaporSecurityHeadersTests", dependencies: ["VaporSecurityHeaders"]),
    ]
)
