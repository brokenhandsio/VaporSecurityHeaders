import HTTP
import VaporSecurityHeaders

struct StubFileMiddleware: Middleware {
    var cspConfig: ContentSecurityPolicyConfiguration?
    init(cspConfig: ContentSecurityPolicyConfiguration? = nil) {
        self.cspConfig = cspConfig
    }
    
    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        request.contentSecurityPolicy = self.cspConfig
        
        let body = "Hello World!".bytes
        var headers: [HeaderKey: String] = [:]
        headers["ETag"] = "1491512490-\(body.count)"
        headers["Content-Type"] = "text/plain"
        return Response(status: .ok, headers: headers, body: .data(body))
    }
}
