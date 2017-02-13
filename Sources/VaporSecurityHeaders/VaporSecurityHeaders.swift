import HTTP

struct SecurityHeaders: Middleware {
    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let response = try next.respond(to: request)
        
        response.headers["X-Content-Type-Options"] = "nosniff"
        
        return response
    }
}
