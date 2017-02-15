import HTTP

struct SecurityHeaders: Middleware {
    
    private let isApi: Bool
    private let enableHSTS: Bool
    
    init(api: Bool = false, enableHSTS: Bool = false) {
        self.isApi = api
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
        
        response.headers[HeaderKey.xContentTypeOptions] = getHeader(for: .cto)
        response.headers[HeaderKey.contentSecurityPolicy] = getHeader(for: .csp)
        response.headers[HeaderKey.xFrameOptions] = getHeader(for: .xfo)
        response.headers[HeaderKey.xXssProtection] = getHeader(for: .xssProtection)
        
        if enableHSTS {
            response.headers[HeaderKey.strictTransportSecurity] = getHeader(for: .hsts)
        }
        
        return response
    }
    
    private func getHeader(for headerName: HeaderNames) -> String {
        switch headerName {
        case .cto:
            return "nosniff"
        case .csp:
            if isApi {
                return "default-src 'none'"
            }
            else {
                return "default-src 'self'"
            }
        case .xfo:
            return "deny"
        case .xssProtection:
            return "1; mode=block"
        case .hsts:
            return "max-age=31536000; includeSubdomains; preload"
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
