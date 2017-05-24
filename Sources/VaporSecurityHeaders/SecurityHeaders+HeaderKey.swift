import HTTP

public extension HeaderKey {
    static public var contentSecurityPolicy: HeaderKey {
        return HeaderKey("content-security-policy")
    }
    
    static public var xXssProtection: HeaderKey {
        return HeaderKey("x-xss-protection")
    }
    
    static public var xFrameOptions: HeaderKey {
        return HeaderKey("x-frame-options")
    }
    
    static public var xContentTypeOptions: HeaderKey {
        return HeaderKey("x-content-type-options")
    }
    
    static public var contentSecurityPolicyReportOnly: HeaderKey {
        return HeaderKey("content-security-policy-report-only")
    }
    
    static public var referrerPolicy: HeaderKey {
        return HeaderKey("referrer-policy")
    }
}
