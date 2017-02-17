import HTTP

public extension HeaderKey {
    static public var contentSecurityPolicy: HeaderKey {
        return HeaderKey("Content-Security-Policy")
    }
    
    static public var xXssProtection: HeaderKey {
        return HeaderKey("X-XSS-Protection")
    }
    
    static public var xFrameOptions: HeaderKey {
        return HeaderKey("X-Frame-Options")
    }
    
    static public var xContentTypeOptions: HeaderKey {
        return HeaderKey("X-Content-Type-Options")
    }
    
    static public var contentSecurityPolicyReportOnly: HeaderKey {
        return HeaderKey("Content-Security-Policy-Report-Only")
    }
}
