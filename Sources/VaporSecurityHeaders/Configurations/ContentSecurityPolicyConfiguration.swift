import Vapor

public struct ContentSecurityPolicyConfiguration: SecurityHeaderConfiguration {

    private let value: String

    public init(value: String) {
        self.value = value
    }

    func setHeader(on response: Response, from request: Request) {
        if let requestCSP = request.contentSecurityPolicy {
            response.http.headers.replaceOrAdd(name: .contentSecurityPolicy, value: requestCSP.value)
        } else {
            response.http.headers.replaceOrAdd(name: .contentSecurityPolicy, value: value)
        }
    }
}

public class CSPRequestConfiguration: Service {
    var configuration: ContentSecurityPolicyConfiguration?
    public init() {}
}

extension Request {
    public var contentSecurityPolicy: ContentSecurityPolicyConfiguration? {
        get {
            if let requestConfig = try? privateContainer.make(CSPRequestConfiguration.self) {
                return requestConfig.configuration
            } else {
                return nil
            }
        }
        set {
            if let requestConfig = try? privateContainer.make(CSPRequestConfiguration.self) {
                requestConfig.configuration = newValue
            }
        }
    }
}
