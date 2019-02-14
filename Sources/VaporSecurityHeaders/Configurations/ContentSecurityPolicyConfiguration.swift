import Vapor
import Foundation

public struct ContentSecurityPolicyConfiguration: SecurityHeaderConfiguration {

    private let value: String

    public init(value: ContentSecurityPolicy) {
        self.value = value.value
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

public struct CSPReportTo: Codable {
    var group: String?
    var max_age: Int
    var endpoints: [CSPReportToEndpoint]
    var include_subdomains: Bool?
}

public struct CSPReportToEndpoint: Codable {
    var url: String
}

public struct CSPKeywords {
    static let all = "*"
    static let none = "'none'"
    static let `self` = "'self'"
    static let strictDynamic = "'strict-dynamic'"
    static let unsafeEval = "'unsafe-eval'"
    static let unsafeHashedAttributes = "'unsafe-hashed-attributes'"
    static let unsafeInline = "'unsafe-inline'"
}

public class ContentSecurityPolicy {
    private var policy: [String] = []

    var value: String {
        return policy.joined(separator: "; ")
    }

    func set(value: String) -> ContentSecurityPolicy {
        policy.append(value)
        return self
    }

    func baseUri(sources: String...) -> ContentSecurityPolicy {
        policy.append("base-uri \(sources.joined(separator: " "))")
        return self
    }

    func blockAllMixedContent() -> ContentSecurityPolicy {
        policy.append("block-all-mixed-content")
        return self
    }

    func connectSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("connect-src \(sources.joined(separator: " "))")
        return self
    }

    func defaultSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("default-src \(sources.joined(separator: " "))")
        return self
    }

    func fontSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("font-src \(sources.joined(separator: " "))")
        return self
    }

    func formAction(sources: String...) -> ContentSecurityPolicy {
        policy.append("form-action \(sources.joined(separator: " "))")
        return self
    }

    func frameAncestors(sources: String...) -> ContentSecurityPolicy {
        policy.append("frame-ancestors \(sources.joined(separator: " "))")
        return self
    }

    func frameSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("frame-src \(sources.joined(separator: " "))")
        return self
    }

    func imgSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("img-src \(sources.joined(separator: " "))")
        return self
    }

    func manifestSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("manifest-src \(sources.joined(separator: " "))")
        return self
    }

    func mediaSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("media-src \(sources.joined(separator: " "))")
        return self
    }

    func objectSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("object-src \(sources.joined(separator: " "))")
        return self
    }

    func pluginTypes(types: String...) -> ContentSecurityPolicy {
        policy.append("plugin-types \(types.joined(separator: " "))")
        return self
    }

    func requireSriFor(values: String...) -> ContentSecurityPolicy {
        policy.append("require-sri-for \(values.joined(separator: " "))")
        return self
    }

    func reportTo(reportToObject: CSPReportTo) -> ContentSecurityPolicy {
        let encoder = JSONEncoder()
        let data = try! encoder.encode(reportToObject)
        guard let jsonString = String(data: data, encoding: .utf8) else { return self }
        policy.append("report-to \(String(describing: jsonString))")
        return self
    }

    func reportUri(uri: String) -> ContentSecurityPolicy {
        policy.append("report-uri \(uri)")
        return self
    }

    func sandbox(values: String...) -> ContentSecurityPolicy {
        policy.append("sandbox \(values.joined(separator: " "))")
        return self
    }

    func scriptSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("script-src \(sources.joined(separator: " "))")
        return self
    }
    
    func styleSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("style-src \(sources.joined(separator: " "))")
        return self
    }

    func upgradeInsecureRequests() -> ContentSecurityPolicy {
        policy.append("upgrade-insecure-requests")
        return self
    }

    func workerSrc(sources: String...) -> ContentSecurityPolicy {
        policy.append("worker-src \(sources.joined(separator: " "))")
        return self
    }
}
