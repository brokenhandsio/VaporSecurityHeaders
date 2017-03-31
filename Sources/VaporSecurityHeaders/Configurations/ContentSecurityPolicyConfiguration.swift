import HTTP

public struct ContentSecurityPolicyConfiguration: SecurityHeaderConfiguration {
    
    private let value: String
    
    public init(value: String) {
        self.value = value
    }
    
    func setHeader(on response: Response, from request: Request) {
        if let requestCsp = request.contentSecurityPolicy {
            response.headers[HeaderKey.contentSecurityPolicy] = requestCsp.value
        }
        else {
            response.headers[HeaderKey.contentSecurityPolicy] = value
        }
    }
}

extension Request {
    
    public var contentSecurityPolicy: ContentSecurityPolicyConfiguration? {
        get {
            return storage["cspConfig"] as? ContentSecurityPolicyConfiguration
        }
        set {
            storage["cspConfig"] = newValue
        }
    }
}
