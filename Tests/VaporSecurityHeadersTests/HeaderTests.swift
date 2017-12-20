import XCTest

@testable import Vapor
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
    ]
    
    // MARK: - Properties

    private var request: HTTPRequest!
    private var routeRequest: HTTPRequest!
    private var abortRequest: HTTPRequest!
    private var fileRequest: HTTPRequest!

    // MARK: - Overrides
    
    override func setUp() {
        request = HTTPRequest(method: .get, uri: "/test/")
        routeRequest = HTTPRequest(method: .get, uri: "/route/")
        abortRequest = HTTPRequest(method: .get, uri: "/abort/")
        fileRequest = HTTPRequest(method: .get, uri: "/file/")
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

        let response = try makeTestResponse(for: request, securityHeadersToAdd: SecurityHeadersFactory())

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HTTPHeaders.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HTTPHeaders.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HTTPHeaders.xXssProtection])
    }

    func testDefaultHeadersWithHSTS() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubDomains; preload"

        let response = try makeTestResponse(for: request, securityHeadersToAdd: SecurityHeadersFactory().with(strictTransportSecurity: StrictTransportSecurityConfiguration()))

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HTTPHeaders.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HTTPHeaders.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HTTPHeaders.xXssProtection])
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers[.strictTransportSecurity])
    }

    func testAllHeadersForApi() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let response = try makeTestResponse(for: request, securityHeadersToAdd: SecurityHeadersFactory.api())

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HTTPHeaders.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HTTPHeaders.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HTTPHeaders.xXssProtection])
    }

    func testAPIHeadersWithHSTS() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubDomains; preload"

        let response = try makeTestResponse(for: request, securityHeadersToAdd: SecurityHeadersFactory.api().with(strictTransportSecurity: StrictTransportSecurityConfiguration()))

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HTTPHeaders.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HTTPHeaders.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HTTPHeaders.xXssProtection])
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers[.strictTransportSecurity])
    }

    func testHeadersWithContentTypeOptionsTurnedOff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .none)
        let factory = SecurityHeadersFactory().with(contentTypeOptions: contentTypeConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertNil(response.headers[HTTPHeaders.xContentTypeOptions])
    }

    func testHeadersWithContentTypeOptionsNosniff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .nosniff)
        let factory = SecurityHeadersFactory().with(contentTypeOptions: contentTypeConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("nosniff", response.headers[HTTPHeaders.xContentTypeOptions])
    }

    func testHeaderWithFrameOptionsDeny() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .deny)
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("DENY", response.headers[.xFrameOptions])
    }

    func testHeaderWithFrameOptionsSameOrigin() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .sameOrigin)
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("SAMEORIGIN", response.headers[.xFrameOptions])
    }

    func testHeaderWithFrameOptionsAllowFrom() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .allow(from: "https://test.com"))
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("ALLOW-FROM https://test.com", response.headers[.xFrameOptions])
    }

    func testHeaderWithXssProtectionDisable() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .disable)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("0", response.headers[HTTPHeaders.xXssProtection])
    }

    func testHeaderWithXssProtectionEnable() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .enable)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("1", response.headers[HTTPHeaders.xXssProtection])
    }

    func testHeaderWithXssProtectionBlock() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .block)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("1; mode=block", response.headers[HTTPHeaders.xXssProtection])
    }

    func testHeaderWithHSTSwithMaxAge() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomains() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreload() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, preload: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreloadAndSubdomain() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: true, preload: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomainsFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; preload", response.headers[.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreloadFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, preload: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains;", response.headers[.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomainAndPreloadFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: false, preload: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30;", response.headers[.strictTransportSecurity])
    }

    func testHeadersWithServerValue() throws {
        let serverConfig = ServerConfiguration(value: "brokenhands.io")
        let factory = SecurityHeadersFactory().with(server: serverConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("brokenhands.io", response.headers[.server])
    }

    func testHeadersWithCSP() throws {
        let csp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style;"
        let cspConfig = ContentSecurityPolicyConfiguration(value: csp)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[HTTPHeaders.contentSecurityPolicy])
    }

    func testHeadersWithReportOnlyCSP() throws {
        let csp = "default-src https:; report-uri https://csp-report.brokenhands.io"
        let cspConfig = ContentSecurityPolicyReportOnlyConfiguration(value: csp)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicyReportOnly: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[HTTPHeaders.contentSecurityPolicyReportOnly])
    }

    func testHeadersWithReferrerPolicyEmpty() throws {
        let expected = ""
        let referrerConfig = ReferrerPolicyConfiguration(.empty)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyNoReferrer() throws {
        let expected = "no-referrer"
        let referrerConfig = ReferrerPolicyConfiguration(.noReferrer)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyNoReferrerWhenDowngrade() throws {
        let expected = "no-referrer-when-downgrade"
        let referrerConfig = ReferrerPolicyConfiguration(.noReferrerWhenDowngrade)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testHeadersWithReferrerPolicySameOrigin() throws {
        let expected = "same-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.sameOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyOrigin() throws {
        let expected = "origin"
        let referrerConfig = ReferrerPolicyConfiguration(.origin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyStrictOrigin() throws {
        let expected = "strict-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyOriginWhenCrossOrigin() throws {
        let expected = "origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.originWhenCrossOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyStrictOriginWhenCrossOrigin() throws {
        let expected = "strict-origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOriginWhenCrossOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyUnsafeUrl() throws {
        let expected = "unsafe-url"
        let referrerConfig = ReferrerPolicyConfiguration(.unsafeUrl)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testApiPolicyWithAddedReferrerPolicy() throws {
        let expected = "strict-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOrigin)
        let factory = SecurityHeadersFactory.api().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[HTTPHeaders.referrerPolicy])
    }

    func testCustomCSPOnSingleRoute() throws {
        let expectedCsp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style;"
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> Future<String> = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: expectedCsp)
            return Future("Different CSP!")
        }
        let response = try makeTestResponse(for: routeRequest, securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler)

        XCTAssertEqual(expectedCsp, response.headers[HTTPHeaders.contentSecurityPolicy])
    }

    func testDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute() throws {
        let differentCsp = "default-src 'none'; script-src test;"
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> Future<String> = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: differentCsp)
            return Future("Different CSP!")
        }
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler)

        XCTAssertEqual("default-src 'none'", response.headers[HTTPHeaders.contentSecurityPolicy])
    }

    func testAbortMiddleware() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let response = try makeTestResponse(for: abortRequest, securityHeadersToAdd: SecurityHeadersFactory.api())

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HTTPHeaders.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HTTPHeaders.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HTTPHeaders.xXssProtection])
    }

    func testMockFileMiddleware() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let response = try makeTestResponse(for: fileRequest, securityHeadersToAdd: SecurityHeadersFactory.api(), fileMiddleware: StubFileMiddleware())

        XCTAssertEqual("Hello World!", String(data: response.body.data!, encoding: String.Encoding.utf8))
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HTTPHeaders.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HTTPHeaders.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HTTPHeaders.xXssProtection])
    }

    func testMockFileMiddlewareDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'; script-src test;"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let response = try makeTestResponse(for: fileRequest, securityHeadersToAdd: SecurityHeadersFactory.api(), fileMiddleware: StubFileMiddleware(cspConfig: ContentSecurityPolicyConfiguration(value: expectedCSPHeaderValue)))

        XCTAssertEqual("Hello World!", String(data: response.body.data!, encoding: String.Encoding.utf8))
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HTTPHeaders.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HTTPHeaders.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HTTPHeaders.xXssProtection])
    }
    
    // MARK: - Private functions

    private func makeTestResponse(for request: HTTPRequest, securityHeadersToAdd: SecurityHeadersFactory, routeHandler: ((Request) throws -> Future<String>)? = nil, fileMiddleware: StubFileMiddleware? = nil) throws -> Response {

        var services = Services.default()
        var middlewareConfig = MiddlewareConfig()

        if let fileMiddleware = fileMiddleware {
            middlewareConfig.use(StubFileMiddleware.self)
            services.register { worker in
                fileMiddleware
            }
        }

        middlewareConfig.use(ErrorMiddleware.self)
        services.register { worker in
            return try ErrorMiddleware(environment: worker.environment, log: worker.make(for: ErrorMiddleware.self))
        }
        middlewareConfig.use(SecurityHeaders.self)
        services.register { worker in
            securityHeadersToAdd.build()
        }
        services.register { worker in
            middlewareConfig
        }

        let app = try Application(services: services)

        let router = try app.make(Router.self)
        router.get("test") { req in
            return Future("TEST")
        }

        if let routeHandler = routeHandler {
            router.get("route", use: routeHandler)
        }

        router.get("abort") { req -> Future<Response> in
            throw Abort(.badRequest)
        }

        let responder = try app.make(Responder.self)

        let middleware = try app.make(MiddlewareConfig.self).resolve(for: app)
        let responderWithMiddleware = middleware.makeResponder(chainedto: responder)

        let wrappedRequest = Request(http: request, using: app)
        return try responderWithMiddleware.respond(to: wrappedRequest).blockingAwait()
    }

}

struct ResponseData: Content {
    let string: String
}
