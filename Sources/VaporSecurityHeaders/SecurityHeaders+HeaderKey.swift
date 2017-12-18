import Vapor

public extension HTTPHeaders {

    public static let contentSecurityPolicy = Name("Content-Security-Policy")
    public static let xXssProtection = Name("X-XSS-Protection")
    public static let xContentTypeOptions = Name("X-Content-Type-Options")
    public static let contentSecurityPolicyReportOnly = Name("Content-Security-Policy-Report-Only")
    public static let referrerPolicy = Name("Referrer-Policy")
}
