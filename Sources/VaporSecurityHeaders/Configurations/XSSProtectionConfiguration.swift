import HTTP

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
            response.headers[HeaderKey.xXssProtection] = "0"
        case .enable:
            response.headers[HeaderKey.xXssProtection] = "1"
        case .block:
            response.headers[HeaderKey.xXssProtection] = "1; mode=block"
        case .report(let uri):
            response.headers[HeaderKey.xXssProtection] = "1; report=\(uri)"
        }
    }
}
