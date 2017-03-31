import HTTP

public struct XssProtectionConfiguration: SecurityHeaderConfiguration {
    
    public enum Options {
        case disable
        case enable
        case block
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
        }
    }
}
