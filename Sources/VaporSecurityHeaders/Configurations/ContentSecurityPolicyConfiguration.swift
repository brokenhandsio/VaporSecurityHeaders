import Vapor

public struct ContentSecurityPolicyConfiguration: SecurityHeaderConfiguration {

    private let value: String

    public init(value: String) {
        self.value = value
    }

    func setHeader(on response: Response, from request: Request) {
//        if let requestCsp = request.contentSecurityPolicy {
//            response.headers[HTTPHeaders.contentSecurityPolicy] = requestCsp.value
//        } else {
            response.http.headers[HTTPHeaders.contentSecurityPolicy] = value
//        }
    }
}

//extension Request {
//
//    public var contentSecurityPolicy: ContentSecurityPolicyConfiguration? {
//        get {
//            return extend.storage["cspConfig"] as? ContentSecurityPolicyConfiguration
//        }
//        set {
//            extend.storage["cspConfig"] = newValue
//        }
//    }
//}

