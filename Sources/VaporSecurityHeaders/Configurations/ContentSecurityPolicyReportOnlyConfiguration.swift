import Vapor

public struct ContentSecurityPolicyReportOnlyConfiguration: SecurityHeaderConfiguration {

    private let value: String

    public init(value: String) {
        self.value = value
    }

    func setHeader(on response: Response, from request: Request) {
        response.headers.replaceOrAdd(name: HTTPHeaders.contentSecurityPolicyReportOnly, value: value)
    }
}
