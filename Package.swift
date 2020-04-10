// swift-tools-version:5.2

import PackageDescription

let package = Package(
    name: "VaporSecurityHeaders",
    platforms: [
       .macOS(.v10_15)
    ],
    products: [
        .library(name: "VaporSecurityHeaders", targets: ["VaporSecurityHeaders"]),
    ],
    dependencies: [
    	.package(url: "https://github.com/vapor/vapor.git", from: "4.0.0"),
    ],
    targets: [
        .target(name: "VaporSecurityHeaders", dependencies: [
            .product(name: "Vapor", package: "vapor")
        ]),
        .testTarget(name: "VaporSecurityHeadersTests", dependencies: ["VaporSecurityHeaders"]),
    ]
)
