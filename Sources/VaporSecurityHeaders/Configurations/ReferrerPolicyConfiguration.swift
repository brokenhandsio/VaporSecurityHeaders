import Vapor

public struct ReferrerPolicyConfiguration: SecurityHeaderConfiguration {

    public enum Options: String {
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

    private let option: Options

    public init(_ option: Options) {
        self.option = option
    }

    func setHeader(on response: Response, from request: Request) {
        response.headers.replaceOrAdd(name: HTTPHeaders.referrerPolicy, value: option.rawValue)
    }
}
