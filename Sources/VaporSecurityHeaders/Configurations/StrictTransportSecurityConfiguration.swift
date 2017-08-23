import HTTP

public struct StrictTransportSecurityConfiguration: SecurityHeaderConfiguration {

    private let maxAge: Int
    private let includeSubdomains: Bool
    private let preload: Bool

    public init(maxAge: Int = 31536000, includeSubdomains: Bool = true, preload: Bool = true) {
        self.maxAge = maxAge
        self.includeSubdomains = includeSubdomains
        self.preload = preload
    }

    func setHeader(on response: Response, from request: Request) {
        var headerValue = "max-age=\(maxAge);"
        if includeSubdomains {
            headerValue += " includeSubDomains;"
        }
        if preload {
            headerValue += " preload"
        }

        response.headers[HeaderKey.strictTransportSecurity] = headerValue
    }
}
