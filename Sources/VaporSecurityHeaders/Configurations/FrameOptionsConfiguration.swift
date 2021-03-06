import Vapor

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
            response.headers.replaceOrAdd(name: .xFrameOptions, value: "DENY")
        case .sameOrigin:
            response.headers.replaceOrAdd(name: .xFrameOptions, value: "SAMEORIGIN")
        case .allow(let from):
            response.headers.replaceOrAdd(name: .xFrameOptions, value: "ALLOW-FROM \(from)")
        }
    }
}
