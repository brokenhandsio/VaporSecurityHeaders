import XCTest

@testable import Vapor
import HTTP

import VaporSecurityHeaders

struct MockFileMiddleware: Middleware {
    var cspConfig: ContentSecurityPolicyConfiguration?
    init(cspConfig: ContentSecurityPolicyConfiguration? = nil) {
        self.cspConfig = cspConfig
    }

    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        request.contentSecurityPolicy = self.cspConfig

        let body = "Hello World!".bytes
        var headers: [HeaderKey: String] = [:]
        headers["ETag"] = "1491512490-\(body.count)"
        headers["Content-Type"] = "text/plain"
        return Response(status: .ok, headers: headers, body: .data(body))
    }
}

class HeaderTests: XCTestCase {

    static var allTests = [
        ("testDefaultHeaders", testDefaultHeaders),
        ("testAllHeadersForApi", testAllHeadersForApi),
        ("testAPIHeadersWithHSTS", testAPIHeadersWithHSTS),
        ("testDefaultHeadersWithHSTS", testDefaultHeadersWithHSTS),
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
        ("testCustomCSPOnSingleRoute", testCustomCSPOnSingleRoute),
        ("testDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute", testDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute),
        ("testAbortMiddleware", testAbortMiddleware),
        ("testMockFileMiddleware", testMockFileMiddleware),
        ("testMockFileMiddlewareDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute", testMockFileMiddlewareDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute)
    ]

    private var request: Request!
    private var routeRequest: Request!
    private var abortRequest: Request!

    override func setUp() {
        request = try! Request(method: .get, uri: "/test/")
        routeRequest = try! Request(method: .get, uri: "/route/")
        abortRequest = try! Request(method: .get, uri: "/abort/")
    }

    func testDefaultHeaders() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders())
        let response = drop.respond(to: request)

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

        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders(hstsConfiguration: StrictTransportSecurityConfiguration()))
        let response = drop.respond(to: request)

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

        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders.api())
        let response = drop.respond(to: request)

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

        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders.api(hstsConfiguration: StrictTransportSecurityConfiguration()))
        let response = drop.respond(to: request)

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithContentTypeOptionsTurnedOff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .none)
        let middleware = SecurityHeaders(contentTypeConfiguration: contentTypeConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertNil(response.headers[HeaderKey.xContentTypeOptions])
    }

    func testHeadersWithContentTypeOptionsNosniff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .nosniff)
        let middleware = SecurityHeaders(contentTypeConfiguration: contentTypeConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("nosniff", response.headers[HeaderKey.xContentTypeOptions])
    }

    func testHeaderWithFrameOptionsDeny() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .deny)
        let middleware = SecurityHeaders(frameOptionsConfiguration: frameOptionsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("DENY", response.headers[HeaderKey.xFrameOptions])
    }

    func testHeaderWithFrameOptionsSameOrigin() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .sameOrigin)
        let middleware = SecurityHeaders(frameOptionsConfiguration: frameOptionsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("SAMEORIGIN", response.headers[HeaderKey.xFrameOptions])
    }

    func testHeaderWithFrameOptionsAllowFrom() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .allow(from: "https://test.com"))
        let middleware = SecurityHeaders(frameOptionsConfiguration: frameOptionsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("ALLOW-FROM https://test.com", response.headers[HeaderKey.xFrameOptions])
    }

    func testHeaderWithXssProtectionDisable() throws {
        let xssProtectionConfig = XssProtectionConfiguration(option: .disable)
        let middleware = SecurityHeaders(xssProtectionConfiguration: xssProtectionConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("0", response.headers[HeaderKey.xXssProtection])
    }

    func testHeaderWithXssProtectionEnable() throws {
        let xssProtectionConfig = XssProtectionConfiguration(option: .enable)
        let middleware = SecurityHeaders(xssProtectionConfiguration: xssProtectionConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("1", response.headers[HeaderKey.xXssProtection])
    }

    func testHeaderWithXssProtectionBlock() throws {
        let xssProtectionConfig = XssProtectionConfiguration(option: .block)
        let middleware = SecurityHeaders(xssProtectionConfiguration: xssProtectionConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("1; mode=block", response.headers[HeaderKey.xXssProtection])
    }

    func testHeaderWithHSTSwithMaxAge() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30)
        let middleware = SecurityHeaders(hstsConfiguration: hstsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomains() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: true)
        let middleware = SecurityHeaders(hstsConfiguration: hstsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreload() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, preload: true)
        let middleware = SecurityHeaders(hstsConfiguration: hstsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreloadAndSubdomain() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: true, preload: true)
        let middleware = SecurityHeaders(hstsConfiguration: hstsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomainsFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: false)
        let middleware = SecurityHeaders(hstsConfiguration: hstsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("max-age=30; preload", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithPreloadFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, preload: false)
        let middleware = SecurityHeaders(hstsConfiguration: hstsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("max-age=30; includeSubDomains;", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithHSTSwithSubdomainAndPreloadFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: false, preload: false)
        let middleware = SecurityHeaders(hstsConfiguration: hstsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("max-age=30;", response.headers[HeaderKey.strictTransportSecurity])
    }

    func testHeadersWithServerValue() throws {
        let serverConfig = ServerConfiguration(value: "brokenhands.io")
        let middleware = SecurityHeaders(serverConfiguration: serverConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual("brokenhands.io", response.headers[HeaderKey.server])
    }

    func testHeadersWithCSP() throws {
        let csp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style;"
        let cspConfig = ContentSecurityPolicyConfiguration(value: csp)
        let middleware = SecurityHeaders(contentSecurityPolicyConfiguration: cspConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual(csp, response.headers[HeaderKey.contentSecurityPolicy])
    }

    func testHeadersWithReportOnlyCSP() throws {
        let csp = "default-src https:; report-uri https://csp-report.brokenhands.io"
        let cspConfig = ContentSecurityPolicyReportOnlyConfiguration(value: csp)
        let middleware = SecurityHeaders(contentSecurityPolicyReportOnlyConfiguration: cspConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)

        XCTAssertEqual(csp, response.headers[HeaderKey.contentSecurityPolicyReportOnly])
    }

    func testHeadersWithReferrerPolicyEmpty() throws {
        let expected = ""
        let referrerConfig = ReferrerPolicyConfiguration(.empty)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyNoReferrer() throws {
        let expected = "no-referrer"
        let referrerConfig = ReferrerPolicyConfiguration(.noReferrer)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyNoReferrerWhenDowngrade() throws {
        let expected = "no-referrer-when-downgrade"
        let referrerConfig = ReferrerPolicyConfiguration(.noReferrerWhenDowngrade)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicySameOrigin() throws {
        let expected = "same-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.sameOrigin)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyOrigin() throws {
        let expected = "origin"
        let referrerConfig = ReferrerPolicyConfiguration(.origin)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyStrictOrigin() throws {
        let expected = "strict-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOrigin)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyOriginWhenCrossOrigin() throws {
        let expected = "origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.originWhenCrossOrigin)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyStrictOriginWhenCrossOrigin() throws {
        let expected = "strict-origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOriginWhenCrossOrigin)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testHeadersWithReferrerPolicyUnsafeUrl() throws {
        let expected = "unsafe-url"
        let referrerConfig = ReferrerPolicyConfiguration(.unsafeUrl)
        let middleware = SecurityHeaders(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testApiPolicyWithAddedReffererPolicy() throws {
        let expected = "strict-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOrigin)
        let middleware = SecurityHeaders.api(referrerPolicyConfiguration: referrerConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = drop.respond(to: request)
        XCTAssertEqual(expected, response.headers[HeaderKey.referrerPolicy])
    }

    func testCustomCSPOnSingleRoute() throws {
        let expectedCsp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style;"
        let middleware = SecurityHeaders.api()
        let cspSettingRouteHandler: (Request) throws -> ResponseRepresentable = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: expectedCsp)
            return "Different CSP!"
        }
        let drop = try makeTestDroplet(middlewareToAdd: middleware, routeHandler: cspSettingRouteHandler)
        let response = drop.respond(to: routeRequest)

        XCTAssertEqual(expectedCsp, response.headers[HeaderKey.contentSecurityPolicy])
    }

    func testDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute() throws {
        let differentCsp = "default-src 'none'; script-src test;"
        let middleware = SecurityHeaders.api()
        let cspSettingRouteHandler: (Request) throws -> ResponseRepresentable = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: differentCsp)
            return "Different CSP!"
        }
        let drop = try makeTestDroplet(middlewareToAdd: middleware, routeHandler: cspSettingRouteHandler)
        _ = drop.respond(to: routeRequest)
        let response = drop.respond(to: request)

        XCTAssertEqual("default-src 'none'", response.headers[HeaderKey.contentSecurityPolicy])
    }

    func testAbortMiddleware() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders.api())
        let response = drop.respond(to: abortRequest)

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

        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders.api())
        drop.middleware.append(MockFileMiddleware())
        let response = drop.respond(to: abortRequest)

        XCTAssertEqual("Hello World!", try response.body.bytes?.string())
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

        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders.api())
        drop.middleware.append(MockFileMiddleware(cspConfig: ContentSecurityPolicyConfiguration(value: expectedCSPHeaderValue)))
        let response = drop.respond(to: abortRequest)

        XCTAssertEqual("Hello World!", try response.body.bytes?.string())
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
    }

    private func makeTestDroplet(middlewareToAdd: Middleware, routeHandler: ((Request) throws -> ResponseRepresentable)? = nil) throws -> Droplet {
        let drop = try Droplet()
        drop.middleware.insert(middlewareToAdd, at: 0)

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
