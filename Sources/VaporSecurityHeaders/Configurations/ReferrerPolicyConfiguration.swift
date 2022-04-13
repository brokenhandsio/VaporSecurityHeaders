import Vapor

public struct ReferrerPolicyConfiguration: SecurityHeaderConfiguration {

    public enum Directive: String {
        case empty = ""
        case noReferrer = "no-referrer"
        case noReferrerWhenDowngrade = "no-referrer-when-downgrade"
        case sameOrigin = "same-origin"
        case origin = "origin"
        case strictOrigin = "strict-origin"
        case originWhenCrossOrigin = "origin-when-cross-origin"
        case strictOriginWhenCrossOrigin = "strict-origin-when-cross-origin"
        case unsafeUrl = "unsafe-url"
    }

    private let directives: [Directive]

    public init(_ directive: Directive) {
        self.directives = [directive]
    }

    public init(_ directives: [Directive]) {
        self.directives = directives
    }

    func setHeader(on response: Response, from request: Request) {
        response.headers.replaceOrAdd(name: .referrerPolicy, value: directives.map({ $0.rawValue }).joined(separator: ", "))
    }
}
