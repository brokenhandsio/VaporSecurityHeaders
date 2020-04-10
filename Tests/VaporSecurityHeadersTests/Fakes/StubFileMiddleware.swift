import Vapor
import VaporSecurityHeaders

struct StubFileMiddleware: Middleware {
    var cspConfig: ContentSecurityPolicyConfiguration?
    init(cspConfig: ContentSecurityPolicyConfiguration? = nil) {
        self.cspConfig = cspConfig
    }
    
    func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {
        if request.url.path == "/file" {
            request.contentSecurityPolicy = self.cspConfig

            let body = Response.Body(string: "Hello World!")
            var headers = HTTPHeaders()
            headers.add(name: .eTag, value: "1491512490-\(body.count)")
            headers.add(name: .contentType, value: "text/plain")
            let response = Response(status: .ok, headers: headers, body: body)
            return request.eventLoop.future(response)
        }
        else {
            return next.respond(to: request)
        }
    }
}

