import PackageDescription

let package = Package(
    name: "VaporSecurityHeaders",
    dependencies: [
    	.Package(url: "https://github.com/vapor/vapor.git", majorVersion: 2),
    ]
)
