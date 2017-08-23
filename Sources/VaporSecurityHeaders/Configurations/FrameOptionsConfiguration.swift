import HTTP

public struct FrameOptionsConfiguration: SecurityHeaderConfiguration {

    public enum Options {
        case deny
        case sameOrigin
        case allow(from: String)
    }

    private let option: Options

    public init(option: Options) {
        self.option = option
    }

    func setHeader(on response: Response, from request: Request) {
        switch option {
        case .deny:
            response.headers[HeaderKey.xFrameOptions] = "DENY"
        case .sameOrigin:
            response.headers[HeaderKey.xFrameOptions] = "SAMEORIGIN"
        case .allow(let from):
            response.headers[HeaderKey.xFrameOptions] = "ALLOW-FROM \(from)"
        }
    }
}
