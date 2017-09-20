import XCTest

import Vapor
import HTTP

import VaporSecurityHeaders

class HeaderTests: XCTestCase {
    
    // MARK: - All Tests

    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testDefaultHeaders", testDefaultHeaders),
        ("testDefaultHeadersWithHSTS", testDefaultHeadersWithHSTS),
        ("testAllHeadersForApi", testAllHeadersForApi),
        ("testAPIHeadersWithHSTS", testAPIHeadersWithHSTS),
        ("testHeadersWithContentTypeOptionsTurnedOff", testHeadersWithContentTypeOptionsTurnedOff),
        ("testHeadersWithContentTypeOptionsNosniff", testHeadersWithContentTypeOptionsNosniff),
        ("testHeaderWithFrameOptionsDeny", testHeaderWithFrameOptionsDeny),
        ("testHeaderWithFrameOptionsSameOrigin", testHeaderWithFrameOptionsSameOrigin),
        ("testHeaderWithFrameOptionsAllowFrom", testHeaderWithFrameOptionsAllowFrom),
        ("testHeaderWithXssProtectionDisable", testHeaderWithXssProtectionDisable),
        ("testHeaderWithXssProtectionEnable", testHeaderWithXssProtectionEnable),
        ("testHeaderWithXssProtectionBlock", testHeaderWithXssProtectionBlock),
        ("testHeaderWithHSTSwithMaxAge", testHeaderWithHSTSwithMaxAge),
        ("testHeadersWithHSTSwithSubdomains", testHeadersWithHSTSwithSubdomains),
        ("testHeadersWithHSTSwithPreload", testHeadersWithHSTSwithPreload),
        ("testHeadersWithHSTSwithPreloadAndSubdomain", testHeadersWithHSTSwithPreloadAndSubdomain),
        ("testHeadersWithHSTSwithSubdomainsFalse", testHeadersWithHSTSwithSubdomainsFalse),
        ("testHeadersWithHSTSwithPreloadFalse", testHeadersWithHSTSwithPreloadFalse),
        ("testHeadersWithHSTSwithSubdomainAndPreloadFalse", testHeadersWithHSTSwithSubdomainAndPreloadFalse),
        ("testHeadersWithServerValue", testHeadersWithServerValue),
        ("testHeadersWithCSP", testHeadersWithCSP),
        ("testHeadersWithReportOnlyCSP", testHeadersWithReportOnlyCSP),
        ("testHeadersWithReferrerPolicyEmpty", testHeadersWithReferrerPolicyEmpty),
        ("testHeadersWithReferrerPolicyNoReferrer", testHeadersWithReferrerPolicyNoReferrer),
        ("testHeadersWithReferrerPolicyNoReferrerWhenDowngrade", testHeadersWithReferrerPolicyNoReferrerWhenDowngrade),
        ("testHeadersWithReferrerPolicySameOrigin", testHeadersWithReferrerPolicySameOrigin),
        ("testHeadersWithReferrerPolicyOrigin", testHeadersWithReferrerPolicyOrigin),
        ("testHeadersWithReferrerPolicyStrictOrigin", testHeadersWithReferrerPolicyStrictOrigin),
        ("testHeadersWithReferrerPolicyOriginWhenCrossOrigin", testHeadersWithReferrerPolicyOriginWhenCrossOrigin),
        ("testHeadersWithReferrerPolicyStrictOriginWhenCrossOrigin", testHeadersWithReferrerPolicyStrictOriginWhenCrossOrigin),
        ("testHeadersWithReferrerPolicyUnsafeUrl", testHeadersWithReferrerPolicyUnsafeUrl),
        ("testApiPolicyWithAddedReferrerPolicy", testApiPolicyWithAddedReferrerPolicy),
        ("testCustomCSPOnSingleRoute", testCustomCSPOnSingleRoute),
        ("testDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute", testDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute),
        ("testAbortMiddleware", testAbortMiddleware),
        ("testMockFileMiddleware", testMockFileMiddleware),
        ("testMockFileMiddlewareDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute", testMockFileMiddlewareDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute),
        ("testBuildWorks", testBuildWorks),
    ]
    
    // MARK: - Properties

    private var request: Request!
    private var routeRequest: Request!
    private var abortRequest: Request!

    // MARK: - Overrides
    
    override func setUp() {
        request = Request(method: .get, uri: "/test/")
        routeRequest = Request(method: .get, uri: "/route/")
        abortRequest = Request(method: .get, uri: "/abort/")
    }
    
    // MARK: - Tests
    
    func testLinuxTestSuiteIncludesAllTests() {
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
            let thisClass = type(of: self)
            let linuxCount = thisClass.allTests.count
            let darwinCount = Int(thisClass
                .defaultTestSuite.testCaseCount)
            XCTAssertEqual(linuxCount, darwinCount,
                           "\(darwinCount - linuxCount) tests are missing from allTests")
        #endif
    }

    func testDefaultHeaders() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let drop = try makeTestDroplet(securityHeadersToAdd: SecurityHeadersFactory())
        let response = try drop.respond(to: request)

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
    }

    func testDefaultHeadersWithHSTS() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubDomains; preload"

        let drop = try makeTestDroplet(securityHeadersToAdd: SecurityHeadersFactory().with(strictTransportSecurity: StrictTransportSecurityConfiguration()))
        let response = try drop.respond(to: request)

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers[HeaderKey.strictTransportSecurity])
    }

    func testAllHeadersForApi() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let drop = try makeTestDroplet(securityHeadersToAdd: SecurityHeadersFactory.api())
        let response = try drop.respond(to: request)

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
    }

    func testAPIHeadersWithHSTS() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubDomains; preload"

        let drop = try makeTestDroplet(securityHeadersToAdd: SecurityHeadersFactory.api().with(strictTransportSecurity: StrictTransportSecurityConfiguration()))
        let response = try drop.respond(to: request)

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithContentTypeOptionsTurnedOff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .none)
        let factory = SecurityHeadersFactory().with(contentTypeOptions: contentTypeConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertNil(response.headers[HeaderKey.xContentTypeOptions])
    }

    func testHeadersWithContentTypeOptionsNosniff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .nosniff)
        let factory = SecurityHeadersFactory().with(contentTypeOptions: contentTypeConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("nosniff", response.headers[HeaderKey.xContentTypeOptions])
    }

    func testHeaderWithFrameOptionsDeny() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .deny)
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("DENY", response.headers[HeaderKey.xFrameOptions])
    }

    func testHeaderWithFrameOptionsSameOrigin() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .sameOrigin)
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("SAMEORIGIN", response.headers[HeaderKey.xFrameOptions])
    }

    func testHeaderWithFrameOptionsAllowFrom() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .allow(from: "https://test.com"))
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("ALLOW-FROM https://test.com", response.headers[HeaderKey.xFrameOptions])
    }

    func testHeaderWithXssProtectionDisable() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .disable)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("0", response.headers[HeaderKey.xXssProtection])
    }

    func testHeaderWithXssProtectionEnable() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .enable)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("1", response.headers[HeaderKey.xXssProtection])
    }

    func testHeaderWithXssProtectionBlock() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .block)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("1; mode=block", response.headers[HeaderKey.xXssProtection])
    }

    func testHeaderWithHSTSwithMaxAge() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomains() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreload() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, preload: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreloadAndSubdomain() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: true, preload: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomainsFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("max-age=30; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreloadFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, preload: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains;", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomainAndPreloadFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: false, preload: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("max-age=30;", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithServerValue() throws {
        let serverConfig = ServerConfiguration(value: "brokenhands.io")
        let factory = SecurityHeadersFactory().with(server: serverConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual("brokenhands.io", response.headers[HeaderKey.server])
    }

    func testHeadersWithCSP() throws {
        let csp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style;"
        let cspConfig = ContentSecurityPolicyConfiguration(value: csp)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual(csp, response.headers[HeaderKey.contentSecurityPolicy])
    }

    func testHeadersWithReportOnlyCSP() throws {
        let csp = "default-src https:; report-uri https://csp-report.brokenhands.io"
        let cspConfig = ContentSecurityPolicyReportOnlyConfiguration(value: csp)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicyReportOnly: cspConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)

        XCTAssertEqual(csp, response.headers[HeaderKey.contentSecurityPolicyReportOnly])
    }

    func testHeadersWithReferrerPolicyEmpty() throws {
        let expected = ""
        let referrerConfig = ReferrerPolicyConfiguration(.empty)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyNoReferrer() throws {
        let expected = "no-referrer"
        let referrerConfig = ReferrerPolicyConfiguration(.noReferrer)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyNoReferrerWhenDowngrade() throws {
        let expected = "no-referrer-when-downgrade"
        let referrerConfig = ReferrerPolicyConfiguration(.noReferrerWhenDowngrade)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicySameOrigin() throws {
        let expected = "same-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.sameOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyOrigin() throws {
        let expected = "origin"
        let referrerConfig = ReferrerPolicyConfiguration(.origin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyStrictOrigin() throws {
        let expected = "strict-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyOriginWhenCrossOrigin() throws {
        let expected = "origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.originWhenCrossOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyStrictOriginWhenCrossOrigin() throws {
        let expected = "strict-origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOriginWhenCrossOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyUnsafeUrl() throws {
        let expected = "unsafe-url"
        let referrerConfig = ReferrerPolicyConfiguration(.unsafeUrl)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testApiPolicyWithAddedReferrerPolicy() throws {
        let expected = "strict-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOrigin)
        let factory = SecurityHeadersFactory.api().with(referrerPolicy: referrerConfig)
        let drop = try makeTestDroplet(securityHeadersToAdd: factory)
        let response = try drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testCustomCSPOnSingleRoute() throws {
        let expectedCsp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style;"
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> ResponseRepresentable = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: expectedCsp)
            return "Different CSP!"
        }
        let drop = try makeTestDroplet(securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler)
        let response = try drop.respond(to: routeRequest)

        XCTAssertEqual(expectedCsp, response.headers[HeaderKey.contentSecurityPolicy])
    }

    func testDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute() throws {
        let differentCsp = "default-src 'none'; script-src test;"
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> ResponseRepresentable = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: differentCsp)
            return "Different CSP!"
        }
        let drop = try makeTestDroplet(securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler)
        _ = try drop.respond(to: routeRequest)
        let response = try drop.respond(to: request)

        XCTAssertEqual("default-src 'none'", response.headers[HeaderKey.contentSecurityPolicy])
    }

    func testAbortMiddleware() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let drop = try makeTestDroplet(securityHeadersToAdd: SecurityHeadersFactory.api())
        let response = try drop.respond(to: abortRequest)

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
    }

    func testMockFileMiddleware() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let securityHeaders = SecurityHeadersFactory.api().build()
        let middlewareArray: [Middleware] = [securityHeaders, StubFileMiddleware()]
        
        let drop = try Droplet(middleware: middlewareArray)
        
        drop.get("abort") { req in
            throw Abort.badRequest
        }
        
        let response = try drop.respond(to: abortRequest)

        XCTAssertEqual("Hello World!", response.body.bytes?.makeString())
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
    }

    func testMockFileMiddlewareDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'; script-src test;"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let securityHeaders = SecurityHeadersFactory.api().build()
        let middlewareArray: [Middleware] = [securityHeaders, StubFileMiddleware(cspConfig: ContentSecurityPolicyConfiguration(value: expectedCSPHeaderValue))]
        
        let drop = try Droplet(middleware: middlewareArray)
        
        drop.get("abort") { req in
            throw Abort.badRequest
        }
        
        let response = try drop.respond(to: abortRequest)

        XCTAssertEqual("Hello World!", response.body.bytes?.makeString())
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
    }
    
    func testBuildWorks() throws {
        let config = try Config()
        let securityHeaders = SecurityHeadersFactory().build()
        
        let middlewareArray: [Middleware] = [securityHeaders, ErrorMiddleware.init(.test, try config.resolveLog())]
        
        let drop = try Droplet(middleware: middlewareArray)
        
        drop.get("test") { req in
            return "TEST"
        }
        
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        
        let response = try drop.respond(to: request)
        
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
    }
    
    // MARK: - Private functions

    private func makeTestDroplet(securityHeadersToAdd: SecurityHeadersFactory, routeHandler: ((Request) throws -> ResponseRepresentable)? = nil) throws -> Droplet {
        var config = try Config()
        try config.set("droplet.middleware", ["vapor-security-headers", "error"])
        
        
        config.addConfigurable(middleware: securityHeadersToAdd.builder(), name: "vapor-security-headers")
        
        let errorReturner: (Config) throws -> ErrorMiddleware = { config in
            return ErrorMiddleware(.test, try config.resolveLog())
        }
        config.addConfigurable(middleware: errorReturner, name: "error")
        
        let drop = try Droplet(config)

        drop.get("test") { req in
            return "TEST"
        }

        if let routeHandler = routeHandler {
            drop.get("route", handler: routeHandler)
        }

        drop.get("abort") { req in
            throw Abort.badRequest
        }

        return drop
    }

}
