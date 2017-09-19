// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "VaporSecurityHeaders",
    products: [
        .library(name: "VaporSecurityHeaders", targets: ["VaporSecurityHeaders"]),
    ],
    dependencies: [
    	.package(url: "https://github.com/vapor/vapor.git", .upToNextMajor(from: "2.2.0")),
    ],
    targets: [
        .target(name: "VaporSecurityHeaders", dependencies: ["Vapor"]),
        .testTarget(name: "VaporSecurityHeadersTests", dependencies: ["VaporSecurityHeaders"]),
    ]
)
