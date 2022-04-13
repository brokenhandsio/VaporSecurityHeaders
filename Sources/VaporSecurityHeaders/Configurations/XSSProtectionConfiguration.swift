import Vapor

public struct XSSProtectionConfiguration: SecurityHeaderConfiguration {
    public init () {}

    func setHeader(on response: Response, from request: Request) {
        response.headers.replaceOrAdd(name: .xssProtection, value: "0")
    }
}
