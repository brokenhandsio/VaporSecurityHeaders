import HTTP

struct ContentSecurityPolicyConfiguration: SecurityHeaderConfiguration {
    
    private let value: String
    
    init(value: String) {
        self.value = value
    }
    
    func setHeader(on response: Response) {
        response.headers[HeaderKey.contentSecurityPolicy] = value
    }
}
