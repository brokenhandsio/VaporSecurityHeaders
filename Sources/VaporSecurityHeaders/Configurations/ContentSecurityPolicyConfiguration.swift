import Vapor
import Foundation

public struct ContentSecurityPolicyConfiguration: SecurityHeaderConfiguration {
    private let value: String

    public init(value: String) {
        self.value = value
    }

    public init(value: ContentSecurityPolicy) {
        self.value = value.value
    }

    func setHeader(on response: Response, from request: Request) {
        if let requestCSP = request.contentSecurityPolicy {
            response.headers.replaceOrAdd(name: .contentSecurityPolicy, value: requestCSP.value)
        } else {
            response.headers.replaceOrAdd(name: .contentSecurityPolicy, value: value)
        }
    }
}

extension ContentSecurityPolicyConfiguration: StorageKey {
    public typealias Value = Self
}

extension Request {
    
    public var contentSecurityPolicy: ContentSecurityPolicyConfiguration? {
        get {
            return self.storage[ContentSecurityPolicyConfiguration.self]
        }
        set {
            self.storage[ContentSecurityPolicyConfiguration.self] = newValue
        }
    }
}

public struct CSPReportTo: Codable {
    private let group: String?
    private let max_age: Int
    private let endpoints: [CSPReportToEndpoint]
    private let include_subdomains: Bool?

    public init(group: String? = nil, max_age: Int,
                endpoints: [CSPReportToEndpoint], include_subdomains: Bool? = nil) {
        self.group = group
        self.max_age = max_age
        self.endpoints = endpoints
        self.include_subdomains = include_subdomains
    }
}

public struct CSPReportToEndpoint: Codable {
    private let url: String

    public init(url: String) {
        self.url = url
    }
}

extension CSPReportToEndpoint: Equatable {
    public static func == (lhs: CSPReportToEndpoint, rhs: CSPReportToEndpoint) -> Bool {
        return lhs.url == rhs.url
    }
}

extension CSPReportTo: Equatable {
    public static func == (lhs: CSPReportTo, rhs: CSPReportTo) -> Bool {
        return lhs.group == rhs.group &&
            lhs.max_age == rhs.max_age &&
            lhs.endpoints == rhs.endpoints &&
            lhs.include_subdomains == rhs.include_subdomains
    }
}

public struct CSPKeywords {
    public static let all = "*"
    public static let none = "'none'"
    public static let `self` = "'self'"
    public static let strictDynamic = "'strict-dynamic'"
    public static let unsafeEval = "'unsafe-eval'"
    public static let unsafeHashedAttributes = "'unsafe-hashed-attributes'"
    public static let unsafeInline = "'unsafe-inline'"
}

public class ContentSecurityPolicy {
    private var policy: [String] = []

    var value: String {
        return policy.joined(separator: "; ")
    }

    @discardableResult
    public func set(value: String) -> ContentSecurityPolicy {
        policy.append(value)
        return self
    }
    
    @discardableResult
    public func baseUri(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "base-uri")
        return self
    }
    
    @discardableResult
    public func baseUri(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "base-uri")
        return self
    }

    @discardableResult
    public func blockAllMixedContent() -> ContentSecurityPolicy {
        policy.append("block-all-mixed-content")
        return self
    }
    
    @discardableResult
    public func childSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "child-src")
        return self
    }
    
    @discardableResult
    public func childSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "child-src")
        return self
    }

    @discardableResult
    public func connectSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "connect-src")
        return self
    }
    
    @discardableResult
    public func connectSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "connect-src")
        return self
    }

    @discardableResult
    public func defaultSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "default-src")
        return self
    }
    
    @discardableResult
    public func defaultSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "default-src")
        return self
    }

    @discardableResult
    public func fontSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "font-src")
        return self
    }
    
    @discardableResult
    public func fontSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "font-src")
        return self
    }

    @discardableResult
    public func formAction(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "form-action")
        return self
    }
    
    @discardableResult
    public func formAction(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "form-action")
        return self
    }

    @discardableResult
    public func frameAncestors(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "frame-ancestors")
        return self
    }
    
    @discardableResult
    public func frameAncestors(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "frame-ancestors")
        return self
    }

    @discardableResult
    public func frameSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "frame-src")
        return self
    }
    
    @discardableResult
    public func frameSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "frame-src")
        return self
    }

    @discardableResult
    public func imgSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "img-src")
        return self
    }
    
    @discardableResult
    public func imgSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "img-src")
        return self
    }

    @discardableResult
    public func manifestSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "manifest-src")
        return self
    }
    
    @discardableResult
    public func manifestSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "manifest-src")
        return self
    }

    @discardableResult
    public func mediaSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "media-src")
        return self
    }
    
    @discardableResult
    public func mediaSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "media-src")
        return self
    }

    @discardableResult
    public func objectSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "object-src")
        return self
    }
    
    @discardableResult
    public func objectSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "object-src")
        return self
    }

    @discardableResult
    public func pluginTypes(types: String...) -> ContentSecurityPolicy {
        join(sources: types, to: "plugin-types")
        return self
    }
    
    @discardableResult
    public func pluginTypes(types: [String]) -> ContentSecurityPolicy {
        join(sources: types, to: "plugin-types")
        return self
    }

    @discardableResult
    public func requireSriFor(values: String...) -> ContentSecurityPolicy {
        join(sources: values, to: "require-sri-for")
        return self
    }
    
    @discardableResult
    public func requireSriFor(values: [String]) -> ContentSecurityPolicy {
        join(sources: values, to: "require-sri-for")
        return self
    }

    @discardableResult
    public func reportTo(reportToObject: CSPReportTo) -> ContentSecurityPolicy {
        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(reportToObject) else { return self }
        guard let jsonString = String(data: data, encoding: .utf8) else { return self }
        policy.append("report-to \(String(describing: jsonString))")
        return self
    }

    @discardableResult
    public func reportUri(uri: String) -> ContentSecurityPolicy {
        policy.append("report-uri \(uri)")
        return self
    }

    @discardableResult
    public func sandbox(values: String...) -> ContentSecurityPolicy {
        join(sources: values, to: "sandbox")
        return self
    }
    
    @discardableResult
    public func sandbox(values: [String]) -> ContentSecurityPolicy {
        join(sources: values, to: "sandbox")
        return self
    }

    @discardableResult
    public func scriptSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "script-src")
        return self
    }
    
    @discardableResult
    public func scriptSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "script-src")
        return self
    }

    @discardableResult
    public func styleSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "style-src")
        return self
    }
    
    @discardableResult
    public func styleSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "style-src")
        return self
    }

    @discardableResult
    public func upgradeInsecureRequests() -> ContentSecurityPolicy {
        policy.append("upgrade-insecure-requests")
        return self
    }

    @discardableResult
    public func workerSrc(sources: String...) -> ContentSecurityPolicy {
        join(sources: sources, to: "worker-src")
        return self
    }
    
    @discardableResult
    public func workerSrc(sources: [String]) -> ContentSecurityPolicy {
        join(sources: sources, to: "worker-src")
        return self
    }

    private func join(sources: [String], to directive: String) {
        policy.append("\(directive) \(sources.joined(separator: " "))")
    }
    
    private func join(sources: String..., to directive: String) {
        policy.append("\(directive) \(sources.joined(separator: " "))")
    }
    
    public init() {}
}
