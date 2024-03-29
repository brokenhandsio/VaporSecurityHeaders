import Vapor

public class HTTPSRedirectMiddleware: Middleware {

    let allowedHosts: [String]?
    
    public init(allowedHosts: [String]? = nil) {
        self.allowedHosts = allowedHosts
    }
    
    public func respond(to request: Request, chainingTo next: Responder) -> EventLoopFuture<Response> {
        if request.application.environment == .development {
            return next.respond(to: request)
        }

        let proto = request.headers.first(name: "X-Forwarded-Proto")
            ?? request.url.scheme
            ?? "http"

        guard proto == "https" else {
            guard let host = request.headers.first(name: .host) else {
                return request.eventLoop.makeFailedFuture(Abort(.badRequest))
            }
            
            if let allowedHosts = allowedHosts {
                guard allowedHosts.contains(host) else {
                    return request.eventLoop.makeFailedFuture(Abort(.badRequest))
                }
            }
            
            let httpsURL = "https://" + host + "\(request.url)"
            return request.redirect(to: "\(httpsURL)", redirectType: .permanent).encodeResponse(for: request)
        }
        return next.respond(to: request)
    }
}
