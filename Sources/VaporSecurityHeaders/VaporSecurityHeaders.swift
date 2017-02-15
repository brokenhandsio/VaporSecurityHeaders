import HTTP

protocol SecurityHeaderSpecification {
    func setHeader(on response: Response)
}

struct SecurityHeaders: Middleware {
    
    private let enableHSTS: Bool
    private let specifications: [SecurityHeaderSpecification]
    
    init(api: Bool, enableHSTS: Bool = false) {
        if api {
            self.init(contentTypeSpecification: ContentTypeOptionsSpec(option: .nosniff),
                      contentSecurityPolicySpecification: ContentSecurityPolicySpec(value: "default-src 'none'"),
                      frameOptionsSpecification: FrameOptionsSpec(option: .deny),
                      enableHSTS: enableHSTS)
        }
        else {
            self.init(enableHSTS: enableHSTS)
        }
    }
    
    init(contentTypeSpecification: ContentTypeOptionsSpec = ContentTypeOptionsSpec(option: .nosniff),
         contentSecurityPolicySpecification: ContentSecurityPolicySpec = ContentSecurityPolicySpec(value: "default-src 'self'"),
         frameOptionsSpecification: FrameOptionsSpec = FrameOptionsSpec(option: .deny),
         enableHSTS: Bool = false) {
        specifications = [contentTypeSpecification, contentSecurityPolicySpecification, frameOptionsSpecification]
        self.enableHSTS = enableHSTS
    }
    
    enum HeaderNames {
        case cto
        case csp
        case xfo
        case xssProtection
        case hsts
    }
    
    
    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let response = try next.respond(to: request)

        response.headers[HeaderKey.contentSecurityPolicy] = getHeader(for: .csp)
        response.headers[HeaderKey.xFrameOptions] = getHeader(for: .xfo)
        response.headers[HeaderKey.xXssProtection] = getHeader(for: .xssProtection)
        
        if enableHSTS {
            response.headers[HeaderKey.strictTransportSecurity] = getHeader(for: .hsts)
        }
        
        for spec in specifications {
            spec.setHeader(on: response)
        }
        
        return response
    }
    
    private func getHeader(for headerName: HeaderNames) -> String {
        switch headerName {
        case .xssProtection:
            return "1; mode=block"
        case .hsts:
            return "max-age=31536000; includeSubdomains; preload"
        default:
            return ""
        }
    }
}

struct FrameOptionsSpec: SecurityHeaderSpecification {
    
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

struct ContentSecurityPolicySpec: SecurityHeaderSpecification {
    
    private let value: String
    
    init(value: String) {
        self.value = value
    }

    func setHeader(on response: Response) {
        response.headers[HeaderKey.contentSecurityPolicy] = value
    }
}


struct ContentTypeOptionsSpec: SecurityHeaderSpecification {
    
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
