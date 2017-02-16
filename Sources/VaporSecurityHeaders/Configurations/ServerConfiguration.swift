import HTTP

struct ServerConfiguration: SecurityHeaderConfiguration {
    private let value: String
    
    init(value: String) {
        self.value = value
    }
    
    func setHeader(on response: Response) {
        response.headers[HeaderKey.server] = value
    }
}
