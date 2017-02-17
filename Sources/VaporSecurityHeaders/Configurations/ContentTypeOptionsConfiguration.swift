import HTTP

public struct ContentTypeOptionsConfiguration: SecurityHeaderConfiguration {
    
    private let option: Options
    
    public init(option: Options) {
        self.option = option
    }
    
    public enum Options {
        case nosniff
        case none
    }
    
    func setHeader(on response: Response) {
        switch option {
        case .nosniff:
            response.headers[HeaderKey.xContentTypeOptions] = "nosniff"
        default:
            break
        }
    }
}
