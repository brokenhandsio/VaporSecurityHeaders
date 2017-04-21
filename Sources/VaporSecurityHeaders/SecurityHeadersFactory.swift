public class SecurityHeadersFactory {
    var contentTypeOptions = ContentTypeOptionsConfiguration(option: .nosniff)
    var contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: "default-src 'self'")
    var frameOptions = FrameOptionsConfiguration(option: .deny)
    var xssProtection = XSSProtectionConfiguration(option: .block)
    var hsts: StrictTransportSecurityConfiguration? = nil
    var server: ServerConfiguration? = nil
    var referrerPolicy: ReferrerPolicyConfiguration? = nil
    var contentSecurityPolicyReportOnly: ContentSecurityPolicyReportOnlyConfiguration? = nil
    
    public static func api() -> SecurityHeadersFactory {
        let apiFactory = SecurityHeadersFactory()
        apiFactory.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: "default-src 'none'")
        return apiFactory
    }
    
    @discardableResult public func with(contentTypeOptions configuration: ContentTypeOptionsConfiguration) -> SecurityHeadersFactory {
        contentTypeOptions = configuration
        return self
    }
    
    @discardableResult public func with(contentSecurityPolicy configuration: ContentSecurityPolicyConfiguration) -> SecurityHeadersFactory {
        contentSecurityPolicy = configuration
        return self
    }
    
    @discardableResult public func with(frameOptions configuration: FrameOptionsConfiguration) -> SecurityHeadersFactory {
        frameOptions = configuration
        return self
    }
    
    @discardableResult public func with(XSSProtection configuration: XSSProtectionConfiguration) -> SecurityHeadersFactory {
        xssProtection = configuration
        return self
    }
    
    @discardableResult public func with(strictTransportSecurity configuration: StrictTransportSecurityConfiguration) -> SecurityHeadersFactory {
        hsts = configuration
        return self
    }
    
    @discardableResult public func with(server configuration: ServerConfiguration) -> SecurityHeadersFactory {
        server = configuration
        return self
    }
    
    @discardableResult public func with(referrerPolicy configuration: ReferrerPolicyConfiguration) -> SecurityHeadersFactory {
        referrerPolicy = configuration
        return self
    }
    
    @discardableResult public func with(contentSecurityPolicyReportOnly configuration: ContentSecurityPolicyReportOnlyConfiguration) -> SecurityHeadersFactory {
        contentSecurityPolicyReportOnly = configuration
        return self
    }
    
    public func build() -> SecurityHeaders {
        return SecurityHeaders(contentTypeConfiguration: contentTypeOptions,
                               contentSecurityPolicyConfiguration: contentSecurityPolicy,
                               frameOptionsConfiguration: frameOptions,
                               xssProtectionConfiguration: xssProtection,
                               hstsConfiguration: hsts,
                               serverConfiguration: server,
                               contentSecurityPolicyReportOnlyConfiguration: contentSecurityPolicyReportOnly,
                               referrerPolicyConfiguration: referrerPolicy)
    }
    
    
}
