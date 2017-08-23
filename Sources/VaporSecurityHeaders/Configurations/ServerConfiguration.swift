import HTTP

public struct ServerConfiguration: SecurityHeaderConfiguration {
    private let value: String

    public init(value: String) {
        self.value = value
    }

    func setHeader(on response: Response, from request: Request) {
        response.headers[HeaderKey.server] = value
    }
}
