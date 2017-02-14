import HTTP

struct SecurityHeaders: Middleware {
    
    private let isApi: Bool
    private let enableHSTS: Bool
    
    init(api: Bool = false, enableHSTS: Bool = false) {
        self.isApi = api
        self.enableHSTS = enableHSTS
    }
    
    enum HeaderNames: String {
        case cto = "X-Content-Type-Options"
        case csp = "Content-Security-Policy"
        case xfo = "X-Frame-Options"
        case xssProtection = "X-XSS-Protection"
        case hsts = "Strict-Transport-Security"
    }
    
    
    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let response = try next.respond(to: request)
        
        response.headers[HeaderKey(HeaderNames.cto.rawValue)] = getHeader(for: .cto)
        response.headers[HeaderKey(HeaderNames.csp.rawValue)] = getHeader(for: .csp)
        response.headers[HeaderKey(HeaderNames.xfo.rawValue)] = getHeader(for: .xfo)
        response.headers[HeaderKey(HeaderNames.xssProtection.rawValue)] = getHeader(for: .xssProtection)
        
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
