import Vapor

public struct ContentTypeOptionsConfiguration: SecurityHeaderConfiguration {

    private let option: Options

    public init(option: Options) {
        self.option = option
    }

    public enum Options {
        case nosniff
        case none
    }

    func setHeader(on response: Response, from request: Request) {
        switch option {
        case .nosniff:
            response.http.headers[HTTPHeaders.xContentTypeOptions] = "nosniff"
        default:
            break
        }
    }
}
