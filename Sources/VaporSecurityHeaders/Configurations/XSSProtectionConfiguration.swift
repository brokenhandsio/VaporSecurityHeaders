import Vapor

public struct XSSProtectionConfiguration: SecurityHeaderConfiguration {

    public enum Options {
        case disable
        case enable
        case block
        case report(uri: String)
    }

    private let option: Options

    public init(option: Options) {
        self.option = option
    }

    func setHeader(on response: Response, from request: Request) {
        switch option {
        case .disable:
            response.http.headers.replaceOrAdd(name: .xXssProtection, value: "0")
        case .enable:
            response.http.headers.replaceOrAdd(name: .xXssProtection, value: "1")
        case .block:
            response.http.headers.replaceOrAdd(name: .xXssProtection, value: "1; mode=block")
        case .report(let uri):
            response.http.headers.replaceOrAdd(name: .xXssProtection, value: "1; report=\(uri)")
        }
    }
}
