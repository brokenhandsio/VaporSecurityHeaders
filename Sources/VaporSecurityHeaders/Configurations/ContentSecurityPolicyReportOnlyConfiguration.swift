import HTTP

public struct ContentSecurityPolicyReportOnlyConfiguration: SecurityHeaderConfiguration {

    private let value: String

    public init(value: String) {
        self.value = value
    }

    func setHeader(on response: Response, from request: Request) {
        response.headers[HeaderKey.contentSecurityPolicyReportOnly] = value
    }
}
