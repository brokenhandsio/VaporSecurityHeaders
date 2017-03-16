import HTTP

public struct SecurityHeaders: Middleware {
    
    private var configurations: [SecurityHeaderConfiguration]
    
    public static func api(hstsConfiguration: StrictTransportSecurityConfiguration? = nil, serverConfiguration: ServerConfiguration? = nil) -> SecurityHeaders {
        return SecurityHeaders(contentTypeConfiguration: ContentTypeOptionsConfiguration(option: .nosniff),
                  contentSecurityPolicyConfiguration: ContentSecurityPolicyConfiguration(value: "default-src 'none'"),
                  frameOptionsConfiguration: FrameOptionsConfiguration(option: .deny),
                  xssProtectionConfiguration: XssProtectionConfiguration(option: .block),
                  hstsConfiguration: hstsConfiguration,
                  serverConfiguration: serverConfiguration)
    }
    
    public init(contentTypeConfiguration: ContentTypeOptionsConfiguration = ContentTypeOptionsConfiguration(option: .nosniff),
         contentSecurityPolicyConfiguration: ContentSecurityPolicyConfiguration = ContentSecurityPolicyConfiguration(value: "default-src 'self'"),
         frameOptionsConfiguration: FrameOptionsConfiguration = FrameOptionsConfiguration(option: .deny),
         xssProtectionConfiguration: XssProtectionConfiguration = XssProtectionConfiguration(option: .block),
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
    
    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        let response = try next.respond(to: request)
        
        setHeaders(response: response)
        
        return response
    }
    
    public func setHeaders(response: Response) {
        for spec in configurations {
            spec.setHeader(on: response)
        }
    }
}
