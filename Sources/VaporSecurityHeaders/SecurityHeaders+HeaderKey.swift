import Vapor

public extension HTTPHeaders {

    static let contentSecurityPolicy = HTTPHeaders.Name("Content-Security-Policy")
    static let xXssProtection = HTTPHeaders.Name("X-XSS-Protection")
    static let xContentTypeOptions = HTTPHeaders.Name("X-Content-Type-Options")
    static let contentSecurityPolicyReportOnly = HTTPHeaders.Name("Content-Security-Policy-Report-Only")
    static let referrerPolicy = HTTPHeaders.Name("Referrer-Policy")
}

