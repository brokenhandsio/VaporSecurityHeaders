import HTTP
import Vapor

public struct ServerConfiguration: SecurityHeaderConfiguration {
    private let value: String

    public init(value: String) {
        self.value = value
    }

    func setHeader(on response: Response, from request: Request) {
        response.http.headers.replaceOrAdd(name: .server, value: value)
    }
}
