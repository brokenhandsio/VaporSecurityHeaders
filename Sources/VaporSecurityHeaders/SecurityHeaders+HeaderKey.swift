import Vapor

public extension HTTPHeaderName {

    public static let contentSecurityPolicy = HTTPHeaderName("Content-Security-Policy")
    public static let xXssProtection = HTTPHeaderName("X-XSS-Protection")
    public static let xContentTypeOptions = HTTPHeaderName("X-Content-Type-Options")
    public static let contentSecurityPolicyReportOnly = HTTPHeaderName("Content-Security-Policy-Report-Only")
    public static let referrerPolicy = HTTPHeaderName("Referrer-Policy")
}
