import HTTP

protocol SecurityHeaderConfiguration {
    func setHeader(on response: Response)
}

struct SecurityHeaders: Middleware {
    
    private var configurations: [SecurityHeaderConfiguration]
    
    static func api(hstsConfiguration: StrictTransportSecurityConfiguration? = nil, serverConfiguration: ServerConfiguration? = nil) -> SecurityHeaders {
        return SecurityHeaders(contentTypeConfiguration: ContentTypeOptionsConfiguration(option: .nosniff),
                  contentSecurityPolicyConfiguration: ContentSecurityPolicyConfiguration(value: "default-src 'none'"),
                  frameOptionsConfiguration: FrameOptionsConfiguration(option: .deny),
                  xssProtectionConfiguration: XssProtectionConfiguration(option: .block),
                  hstsConfiguration: hstsConfiguration,
                  serverConfiguration: serverConfiguration)
    }
    
    init(contentTypeConfiguration: ContentTypeOptionsConfiguration = ContentTypeOptionsConfiguration(option: .nosniff),
         contentSecurityPolicyConfiguration: ContentSecurityPolicyConfiguration = ContentSecurityPolicyConfiguration(value: "default-src 'self'"),
         frameOptionsConfiguration: FrameOptionsConfiguration = FrameOptionsConfiguration(option: .deny),
         xssProtectionConfiguration: XssProtectionConfiguration = XssProtectionConfiguration(option: .block),
         hstsConfiguration: StrictTransportSecurityConfiguration? = nil,
         serverConfiguration: ServerConfiguration? = nil) {
        configurations = [contentTypeConfiguration, contentSecurityPolicyConfiguration, frameOptionsConfiguration, xssProtectionConfiguration]
        
        if let hstsConfiguration = hstsConfiguration {
            configurations.append(hstsConfiguration)
        }
        
        if let serverConfiguration = serverConfiguration {
            configurations.append(serverConfiguration)
        }
    }
    
    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let response = try next.respond(to: request)
        
        for spec in configurations {
            spec.setHeader(on: response)
        }
        
        return response
    }
}

struct ServerConfiguration: SecurityHeaderConfiguration {
    private let value: String
    
    init(value: String) {
        self.value = value
    }
    
    func setHeader(on response: Response) {
        response.headers[HeaderKey.server] = value
    }
}

struct StrictTransportSecurityConfiguration: SecurityHeaderConfiguration {
    
    private let maxAge: Int
    private let includeSubdomains: Bool
    private let preload: Bool
    
    init(maxAge: Int = 31536000, includeSubdomains: Bool = true, preload: Bool = true) {
        self.maxAge = maxAge
        self.includeSubdomains = includeSubdomains
        self.preload = preload
    }
    
    func setHeader(on response: Response) {
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
