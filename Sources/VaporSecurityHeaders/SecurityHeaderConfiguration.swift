import Vapor

protocol SecurityHeaderConfiguration {
    func setHeader(on response: Response, from request: Request)
}
