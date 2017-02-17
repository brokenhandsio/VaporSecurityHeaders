import HTTP

public struct ContentSecurityPolicyConfiguration: SecurityHeaderConfiguration {
    
    private let value: String
    
    public init(value: String) {
        self.value = value
    }
    
    func setHeader(on response: Response) {
        response.headers[HeaderKey.contentSecurityPolicy] = value
    }
}
