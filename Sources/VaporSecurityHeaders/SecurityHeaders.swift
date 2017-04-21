import HTTP
import Vapor

public struct SecurityHeaders {
    
    var configurations: [SecurityHeaderConfiguration]
    
    init(contentTypeConfiguration: ContentTypeOptionsConfiguration = ContentTypeOptionsConfiguration(option: .nosniff),
                contentSecurityPolicyConfiguration: ContentSecurityPolicyConfiguration = ContentSecurityPolicyConfiguration(value: "default-src 'self'"),
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

extension SecurityHeaders: Middleware {
    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let response = try next.respond(to: request)
        
        for spec in configurations {
            spec.setHeader(on: response, from: request)
        }
        
        return response
    }
}
