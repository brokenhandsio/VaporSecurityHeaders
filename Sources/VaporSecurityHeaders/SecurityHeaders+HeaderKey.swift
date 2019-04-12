import Vapor

public extension HTTPHeaderName {

    static let contentSecurityPolicy = HTTPHeaderName("Content-Security-Policy")
    static let xXssProtection = HTTPHeaderName("X-XSS-Protection")
    static let xContentTypeOptions = HTTPHeaderName("X-Content-Type-Options")
    static let contentSecurityPolicyReportOnly = HTTPHeaderName("Content-Security-Policy-Report-Only")
    static let referrerPolicy = HTTPHeaderName("Referrer-Policy")
}
