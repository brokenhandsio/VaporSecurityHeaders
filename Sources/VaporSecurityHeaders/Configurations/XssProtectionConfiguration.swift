import HTTP

struct XssProtectionConfiguration: SecurityHeaderConfiguration {
    
    enum Options {
        case disable
        case enable
        case block
    }
    
    private let option: Options
    
    init(option: Options) {
        self.option = option
    }
    
    func setHeader(on response: Response) {
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
