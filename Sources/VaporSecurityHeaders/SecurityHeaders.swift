import HTTP
import Vapor

public struct SecurityHeaders {

    var configurations: [SecurityHeaderConfiguration]

    init(contentTypeConfiguration: ContentTypeOptionsConfiguration = ContentTypeOptionsConfiguration(option: .nosniff),
         contentSecurityPolicyConfiguration: ContentSecurityPolicyConfiguration = ContentSecurityPolicyConfiguration(value: ContentSecurityPolicy().defaultSrc(sources: CSPKeywords.`self`)),
         frameOptionsConfiguration: FrameOptionsConfiguration = FrameOptionsConfiguration(option: .deny),
         xssProtectionConfiguration: XSSProtectionConfiguration = XSSProtectionConfiguration(option: .block),
         hstsConfiguration: StrictTransportSecurityConfiguration? = nil,
         serverConfiguration: ServerConfiguration? = nil,
         contentSecurityPolicyReportOnlyConfiguration: ContentSecurityPolicyReportOnlyConfiguration? = nil,
         referrerPolicyConfiguration: ReferrerPolicyConfiguration? = nil) {
        configurations = [contentTypeConfiguration, contentSecurityPolicyConfiguration, frameOptionsConfiguration, xssProtectionConfiguration]

        if let hstsConfiguration = hstsConfiguration {
            configurations.append(hstsConfiguration)
        }

        if let serverConfiguration = serverConfiguration {
            configurations.append(serverConfiguration)
        }

        if let contentSecurityPolicyReportOnlyConfiguration = contentSecurityPolicyReportOnlyConfiguration {
            configurations.append(contentSecurityPolicyReportOnlyConfiguration)
        }

        if let referrerPolicyConfiguration = referrerPolicyConfiguration {
            configurations.append(referrerPolicyConfiguration)
        }
    }

}

extension SecurityHeaders: Middleware, Service {

    public func respond(to request: Request, chainingTo next: Responder) throws -> Future<Response> {
        let response = try next.respond(to: request)

        return response.map(to: Response.self) { response in
            for spec in self.configurations {
                spec.setHeader(on: response, from: request)
            }

            return response
        }
    }
}
