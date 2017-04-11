import PackageDescription

let package = Package(
    name: "VaporSecurityHeaders",
    dependencies: [
    	.Package(url: "https://github.com/vapor/vapor.git", Version(2,0,0, prereleaseIdentifiers: ["beta"])),
    ]
)
