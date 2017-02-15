import HTTP

protocol SecurityHeaderConfiguration {
    func setHeader(on response: Response)
}

struct SecurityHeaders: Middleware {
    
    private let enableHSTS: Bool
    private let configurations: [SecurityHeaderConfiguration]
    
    init(api: Bool, enableHSTS: Bool = false) {
        if api {
            self.init(contentTypeConfiguration: ContentTypeOptionsConfiguration(option: .nosniff),
                      contentSecurityPolicyConfiguration: ContentSecurityPolicyConfiguration(value: "default-src 'none'"),
                      frameOptionsConfiguration: FrameOptionsConfiguration(option: .deny),
                      xssProtectionConfiguration: XssProtectionConfiguration(option: .block),
                      enableHSTS: enableHSTS)
        }
        else {
            self.init(enableHSTS: enableHSTS)
        }
    }
    
    init(contentTypeConfiguration: ContentTypeOptionsConfiguration = ContentTypeOptionsConfiguration(option: .nosniff),
         contentSecurityPolicyConfiguration: ContentSecurityPolicyConfiguration = ContentSecurityPolicyConfiguration(value: "default-src 'self'"),
         frameOptionsConfiguration: FrameOptionsConfiguration = FrameOptionsConfiguration(option: .deny),
         xssProtectionConfiguration: XssProtectionConfiguration = XssProtectionConfiguration(option: .block),
         enableHSTS: Bool = false) {
        configurations = [contentTypeConfiguration, contentSecurityPolicyConfiguration, frameOptionsConfiguration, xssProtectionConfiguration]
        self.enableHSTS = enableHSTS
    }
    
    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let response = try next.respond(to: request)
        
        if enableHSTS {
            response.headers[HeaderKey.strictTransportSecurity] = "max-age=31536000; includeSubdomains; preload"
        }
        
        for spec in configurations {
            spec.setHeader(on: response)
        }
        
        return response
    }
}

struct StrictTransportSecurityConfiguration: SecurityHeaderConfiguration {
    func setHeader(on response: Response) {
        
    }
}

struct XssProtectionConfiguration: SecurityHeaderConfiguration {
    
    enum Options {
        case disable
        case enable
        case block
    }
    
    private let option: Options
    
    init(option: Options) {
        self.option = option
    }
    
    func setHeader(on response: Response) {
        switch option {
        case .disable:
            response.headers[HeaderKey.xXssProtection] = "0"
        case .enable:
            response.headers[HeaderKey.xXssProtection] = "1"
        case .block:
            response.headers[HeaderKey.xXssProtection] = "1; mode=block"
        }
    }
}

struct FrameOptionsConfiguration: SecurityHeaderConfiguration {
    
    enum Options {
        case deny
        case sameOrigin
        case allow(from: String)
    }
    
    private let option: Options
    
    init(option: Options) {
        self.option = option
    }
    
    func setHeader(on response: Response) {
        switch option {
        case .deny:
            response.headers[HeaderKey.xFrameOptions] = "DENY"
        case .sameOrigin:
            response.headers[HeaderKey.xFrameOptions] = "SAMEORIGIN"
        case .allow(let from):
            response.headers[HeaderKey.xFrameOptions] = "ALLOW-FROM \(from)"
        }
    }
}

struct ContentSecurityPolicyConfiguration: SecurityHeaderConfiguration {
    
    private let value: String
    
    init(value: String) {
        self.value = value
    }

    func setHeader(on response: Response) {
        response.headers[HeaderKey.contentSecurityPolicy] = value
    }
}


struct ContentTypeOptionsConfiguration: SecurityHeaderConfiguration {
    
    private let option: Options
    
    init(option: Options) {
        self.option = option
    }
    
    enum Options {
        case nosniff
        case none
    }
    
    func setHeader(on response: Response) {
        switch option {
        case .nosniff:
            response.headers[HeaderKey.xContentTypeOptions] = "nosniff"
        default:
            break
        }
    }
}

// MARK: - HeaderKey

extension HeaderKey {
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
}
