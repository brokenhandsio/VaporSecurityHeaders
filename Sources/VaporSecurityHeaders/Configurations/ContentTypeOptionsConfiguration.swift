import HTTP

struct ContentTypeOptionsConfiguration: SecurityHeaderConfiguration {
    
    private let option: Options
    
    init(option: Options) {
        self.option = option
    }
    
    enum Options {
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
