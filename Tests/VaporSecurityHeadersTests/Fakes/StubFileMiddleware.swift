import Vapor
import HTTP
import VaporSecurityHeaders

struct StubFileMiddleware: Middleware, Service {
    var cspConfig: ContentSecurityPolicyConfiguration?
    init(cspConfig: ContentSecurityPolicyConfiguration? = nil) {
        self.cspConfig = cspConfig
    }

    func respond(to request: Request, chainingTo next: Responder) throws -> Future<Response> {
//        if request.http.uri.path == "/file/" {
////            request.contentSecurityPolicy = self.cspConfig
//
//            let body = try "Hello World!".makeBody()
//            var headers = HTTPHeaders()
//            headers[.eTag] = "1491512490-\(body.count ?? 0)"
//            headers[.contentType] = "text/plain"
//            let httpResponse = HTTPResponse(status: .ok, headers: headers, body: body)
//            return Future(Response(http: httpResponse, using: request))
//        }
//        else {
            return try next.respond(to: request)
//        }
//
    }
}

