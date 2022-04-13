import XCTest

@testable import Vapor

import VaporSecurityHeaders

class HeaderTests: XCTestCase {

    // MARK: - Properties

    private var application: Application!
    private var eventLoopGroup: EventLoopGroup!
    private var request: Request!
    private var routeRequest: Request!
    private var abortRequest: Request!
    private var fileRequest: Request!

    // MARK: - Overrides

    override func setUp() {
        eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        application = Application(.testing, .shared(eventLoopGroup))
        request = Request(application: application, method: .GET, url: URI(string: "/test/"), on: eventLoopGroup.next())
        routeRequest = Request(application: application, method: .GET, url: URI(string: "/route/"), on: eventLoopGroup.next())
        abortRequest = Request(application: application, method: .GET, url: URI(string: "/abort/"), on: eventLoopGroup.next())
        fileRequest = Request(application: application, method: .GET, url: URI(string: "/file/"), on: eventLoopGroup.next())
    }
    
    override func tearDownWithError() throws {
        application.shutdown()
        try eventLoopGroup.syncShutdownGracefully()
    }

    // MARK: - Tests

    func testDefaultHeaders() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let response = try makeTestResponse(for: request, securityHeadersToAdd: SecurityHeadersFactory())

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[.xContentTypeOptions].first)
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions].first)
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[.xssProtection].first)
    }

    func testDefaultHeadersWithHSTS() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubDomains; preload"

        let response = try makeTestResponse(for: request, securityHeadersToAdd: SecurityHeadersFactory().with(strictTransportSecurity: StrictTransportSecurityConfiguration()))

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[.xContentTypeOptions].first)
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions].first)
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[.xssProtection].first)
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers[.strictTransportSecurity].first)
    }

    func testAllHeadersForApi() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let response = try makeTestResponse(for: request, securityHeadersToAdd: SecurityHeadersFactory.api())

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[.xContentTypeOptions].first)
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions].first)
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[.xssProtection].first)
    }

    func testAPIHeadersWithHSTS() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubDomains; preload"

        let response = try makeTestResponse(for: request, securityHeadersToAdd: SecurityHeadersFactory.api().with(strictTransportSecurity: StrictTransportSecurityConfiguration()))

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[.xContentTypeOptions].first)
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions].first)
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[.xssProtection].first)
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers[.strictTransportSecurity].first)
    }

    func testHeadersWithContentTypeOptionsTurnedOff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .none)
        let factory = SecurityHeadersFactory().with(contentTypeOptions: contentTypeConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertNil(response.headers[.xContentTypeOptions].first)
    }

    func testHeadersWithContentTypeOptionsNosniff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .nosniff)
        let factory = SecurityHeadersFactory().with(contentTypeOptions: contentTypeConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("nosniff", response.headers[.xContentTypeOptions].first)
    }

    func testHeaderWithFrameOptionsDeny() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .deny)
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("DENY", response.headers[.xFrameOptions].first)
    }

    func testHeaderWithFrameOptionsSameOrigin() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .sameOrigin)
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("SAMEORIGIN", response.headers[.xFrameOptions].first)
    }

    func testHeaderWithFrameOptionsAllowFrom() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .allow(from: "https://test.com"))
        let factory = SecurityHeadersFactory().with(frameOptions: frameOptionsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("ALLOW-FROM https://test.com", response.headers[.xFrameOptions].first)
    }

    func testHeaderWithXssProtectionDisable() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .disable)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("0", response.headers[.xssProtection].first)
    }

    func testHeaderWithXssProtectionEnable() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .enable)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("1", response.headers[.xssProtection].first)
    }

    func testHeaderWithXssProtectionBlock() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .block)
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("1; mode=block", response.headers[.xssProtection].first)
    }

    func testHeaderWithXssProtectionReport() throws {
        let xssProtectionConfig = XSSProtectionConfiguration(option: .report(uri: "https://test.com"))
        let factory = SecurityHeadersFactory().with(XSSProtection: xssProtectionConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("1; report=https://test.com", response.headers[.xssProtection].first)
    }

    func testHeaderWithHSTSwithMaxAge() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[.strictTransportSecurity].first)
    }

    func testHeadersWithHSTSwithSubdomains() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[.strictTransportSecurity].first)
    }

    func testHeadersWithHSTSwithPreload() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, preload: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[.strictTransportSecurity].first)
    }

    func testHeadersWithHSTSwithPreloadAndSubdomain() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: true, preload: true)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains; preload", response.headers[.strictTransportSecurity].first)
    }

    func testHeadersWithHSTSwithSubdomainsFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; preload", response.headers[.strictTransportSecurity].first)
    }

    func testHeadersWithHSTSwithPreloadFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, preload: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30; includeSubDomains;", response.headers[.strictTransportSecurity].first)
    }

    func testHeadersWithHSTSwithSubdomainAndPreloadFalse() throws {
        let hstsConfig = StrictTransportSecurityConfiguration(maxAge: 30, includeSubdomains: false, preload: false)
        let factory = SecurityHeadersFactory().with(strictTransportSecurity: hstsConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("max-age=30;", response.headers[.strictTransportSecurity].first)
    }

    func testHeadersWithServerValue() throws {
        let serverConfig = ServerConfiguration(value: "brokenhands.io")
        let factory = SecurityHeadersFactory().with(server: serverConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual("brokenhands.io", response.headers[.server].first)
    }

    func testHeadersWithCSP() throws {
        let csp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style"
        let cspBuilder = ContentSecurityPolicy()
            .defaultSrc(sources: CSPKeywords.none)
            .scriptSrc(sources: "https://static.brokenhands.io")
            .styleSrc(sources: "https://static.brokenhands.io")
            .imgSrc(sources: "https://static.brokenhands.io")
            .fontSrc(sources: "https://static.brokenhands.io")
            .connectSrc(sources: "https://*.brokenhands.io")
            .formAction(sources: CSPKeywords.`self`)
            .upgradeInsecureRequests()
            .blockAllMixedContent()
            .requireSriFor(values: "script", "style")
        let cspConfig = ContentSecurityPolicyConfiguration(value: cspBuilder)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[.contentSecurityPolicy].first)
    }
    
    func testNonVariadicHeadersWithCSP() throws {
        let csp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style"
        let cspBuilder = ContentSecurityPolicy()
            .defaultSrc(sources: CSPKeywords.none)
            .scriptSrc(sources: ["https://static.brokenhands.io"])
            .styleSrc(sources: ["https://static.brokenhands.io"])
            .imgSrc(sources: ["https://static.brokenhands.io"])
            .fontSrc(sources: ["https://static.brokenhands.io"])
            .connectSrc(sources: ["https://*.brokenhands.io"])
            .formAction(sources: CSPKeywords.`self`)
            .upgradeInsecureRequests()
            .blockAllMixedContent()
            .requireSriFor(values: "script", "style")
        let cspConfig = ContentSecurityPolicyConfiguration(value: cspBuilder)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[.contentSecurityPolicy].first)
    }

    func testHeadersWithStringCSP() throws {
        let csp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style"
        let cspConfig = ContentSecurityPolicyConfiguration(value: csp)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[.contentSecurityPolicy].first)
    }

    func testHeadersWithSetCSP() throws {
        let csp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style"
        let cspBuilder = ContentSecurityPolicy().set(value: csp)
        let cspConfig = ContentSecurityPolicyConfiguration(value: cspBuilder)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[.contentSecurityPolicy].first)
    }

    func testHeadersWithReportToCSP() throws {
        let reportToEndpoint = CSPReportToEndpoint(url: "https://csp-report.brokenhands.io/csp-reports")
        let reportToValue = CSPReportTo(group: "vapor-csp", max_age: 10886400, endpoints: [reportToEndpoint], include_subdomains: true)
        let cspValue = ContentSecurityPolicy()
            .defaultSrc(sources: CSPKeywords.none)
            .scriptSrc(sources: "https://static.brokenhands.io")
            .reportTo(reportToObject: reportToValue)
        let cspConfig = ContentSecurityPolicyConfiguration(value: cspValue)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        guard let cspResponseHeader = response.headers[.contentSecurityPolicy].first else {
            XCTFail("Expected a CSP Response Header")
            return
        }
        let replacedCSPHeader = cspResponseHeader.replacingOccurrences(of: "default-src 'none'; script-src https://static.brokenhands.io; report-to", with: "")
        guard let reportToJson = replacedCSPHeader.data(using: .utf8) else {
            XCTFail("Expected String CSP Response Header")
            return
        }
        let decoder = JSONDecoder()
        guard let reportToData = try? decoder.decode(CSPReportTo.self, from: reportToJson) else {
            XCTFail("Expected JSON CSP Response Header")
            return
        }

        XCTAssertEqual(reportToValue, reportToData)
    }

    func testHeadersWithExhaustiveCSP() throws {
        let csp = "base-uri 'self'; frame-ancestors 'none'; frame-src 'self'; manifest-src https://brokenhands.io; object-src 'self'; plugin-types application/pdf; report-uri https://csp-report.brokenhands.io; sandbox allow-forms allow-scripts; worker-src https://brokenhands.io; media-src https://brokenhands.io"
        let cspBuilder = ContentSecurityPolicy()
            .baseUri(sources: CSPKeywords.`self`)
            .frameAncestors(sources: CSPKeywords.none)
            .frameSrc(sources: CSPKeywords.`self`)
            .manifestSrc(sources: "https://brokenhands.io")
            .objectSrc(sources: CSPKeywords.`self`)
            .pluginTypes(types: "application/pdf")
            .reportUri(uri: "https://csp-report.brokenhands.io")
            .sandbox(values: "allow-forms", "allow-scripts")
            .workerSrc(sources: "https://brokenhands.io")
            .mediaSrc(sources: "https://brokenhands.io")
        let cspConfig = ContentSecurityPolicyConfiguration(value: cspBuilder)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[.contentSecurityPolicy].first)
    }
    
    func testNonVariadicHeadersWithExhaustiveCSP() throws {
        let csp = "base-uri 'self'; frame-ancestors 'none'; frame-src 'self'; manifest-src https://brokenhands.io; object-src 'self'; plugin-types application/pdf; report-uri https://csp-report.brokenhands.io; sandbox allow-forms allow-scripts; worker-src https://brokenhands.io; media-src https://brokenhands.io"
        let cspBuilder = ContentSecurityPolicy()
            .baseUri(sources: [CSPKeywords.`self`])
            .frameAncestors(sources: [CSPKeywords.none])
            .frameSrc(sources: [CSPKeywords.`self`])
            .manifestSrc(sources: ["https://brokenhands.io"])
            .objectSrc(sources: [CSPKeywords.`self`])
            .pluginTypes(types: ["application/pdf"])
            .reportUri(uri: "https://csp-report.brokenhands.io")
            .sandbox(values: ["allow-forms", "allow-scripts"])
            .workerSrc(sources: ["https://brokenhands.io"])
            .mediaSrc(sources: ["https://brokenhands.io"])
        let cspConfig = ContentSecurityPolicyConfiguration(value: cspBuilder)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[.contentSecurityPolicy].first)
    }
    
    func testCombineVariadicNonVariadicHeadersWithExhaustiveCSP() throws {
        let csp = "base-uri 'self'; frame-ancestors 'none'; frame-src 'self'; manifest-src https://brokenhands.io; object-src 'self'; plugin-types application/pdf; report-uri https://csp-report.brokenhands.io; sandbox allow-forms allow-scripts; worker-src https://brokenhands.io; media-src https://brokenhands.io"
        let cspBuilder = ContentSecurityPolicy()
            .baseUri(sources: CSPKeywords.`self`)
            .frameAncestors(sources: [CSPKeywords.none])
            .frameSrc(sources: [CSPKeywords.`self`])
            .manifestSrc(sources: ["https://brokenhands.io"])
            .objectSrc(sources: CSPKeywords.`self`)
            .pluginTypes(types: ["application/pdf"])
            .reportUri(uri: "https://csp-report.brokenhands.io")
            .sandbox(values: ["allow-forms", "allow-scripts"])
            .workerSrc(sources: "https://brokenhands.io")
            .mediaSrc(sources: ["https://brokenhands.io"])
        let cspConfig = ContentSecurityPolicyConfiguration(value: cspBuilder)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[.contentSecurityPolicy].first)
    }

    func testHeadersWithReportOnlyCSP() throws {
        let csp = "default-src https:; report-uri https://csp-report.brokenhands.io"
        let cspConfig = ContentSecurityPolicyReportOnlyConfiguration(value: csp)
        let factory = SecurityHeadersFactory().with(contentSecurityPolicyReportOnly: cspConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)

        XCTAssertEqual(csp, response.headers[.contentSecurityPolicyReportOnly].first)
    }

    func testHeadersWithReferrerPolicyEmpty() throws {
        let expected = ""
        let referrerConfig = ReferrerPolicyConfiguration(.empty)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicyNoReferrer() throws {
        let expected = "no-referrer"
        let referrerConfig = ReferrerPolicyConfiguration(.noReferrer)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicyNoReferrerWhenDowngrade() throws {
        let expected = "no-referrer-when-downgrade"
        let referrerConfig = ReferrerPolicyConfiguration(.noReferrerWhenDowngrade)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicySameOrigin() throws {
        let expected = "same-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.sameOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicyOrigin() throws {
        let expected = "origin"
        let referrerConfig = ReferrerPolicyConfiguration(.origin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicyStrictOrigin() throws {
        let expected = "strict-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicyOriginWhenCrossOrigin() throws {
        let expected = "origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.originWhenCrossOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicyStrictOriginWhenCrossOrigin() throws {
        let expected = "strict-origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOriginWhenCrossOrigin)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicyUnsafeUrl() throws {
        let expected = "unsafe-url"
        let referrerConfig = ReferrerPolicyConfiguration(.unsafeUrl)
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testHeadersWithReferrerPolicyFallbacks() throws {
        let expected = "no-referrer, strict-origin-when-cross-origin"
        let referrerConfig = ReferrerPolicyConfiguration([.noReferrer, .strictOriginWhenCrossOrigin])
        let factory = SecurityHeadersFactory().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testApiPolicyWithAddedReferrerPolicy() throws {
        let expected = "strict-origin"
        let referrerConfig = ReferrerPolicyConfiguration(.strictOrigin)
        let factory = SecurityHeadersFactory.api().with(referrerPolicy: referrerConfig)
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory)
        XCTAssertEqual(expected, response.headers[.referrerPolicy].first)
    }

    func testCustomCSPOnSingleRoute() throws {
        let expectedCsp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; child-src 'self'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style"
        let cspBuilder = ContentSecurityPolicy()
            .defaultSrc(sources: CSPKeywords.none)
            .scriptSrc(sources: "https://static.brokenhands.io")
            .styleSrc(sources: "https://static.brokenhands.io")
            .imgSrc(sources: "https://static.brokenhands.io")
            .fontSrc(sources: "https://static.brokenhands.io")
            .connectSrc(sources: "https://*.brokenhands.io")
            .childSrc(sources: CSPKeywords.`self`)
            .formAction(sources: CSPKeywords.`self`)
            .upgradeInsecureRequests()
            .blockAllMixedContent()
            .requireSriFor(values: "script", "style")
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> String = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: cspBuilder)
            return "Different CSP!"
        }
        let response = try makeTestResponse(for: routeRequest, securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler)

        XCTAssertEqual(expectedCsp, response.headers[.contentSecurityPolicy].first)
    }
    
    func testNonVariadicCustomCSPOnSingleRoute() throws {
        let expectedCsp = "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; child-src 'self'; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style"
        let cspBuilder = ContentSecurityPolicy()
            .defaultSrc(sources: [CSPKeywords.none])
            .scriptSrc(sources: ["https://static.brokenhands.io"])
            .styleSrc(sources: ["https://static.brokenhands.io"])
            .imgSrc(sources: ["https://static.brokenhands.io"])
            .fontSrc(sources: ["https://static.brokenhands.io"])
            .connectSrc(sources: ["https://*.brokenhands.io"])
            .childSrc(sources: [CSPKeywords.`self`])
            .formAction(sources: [CSPKeywords.`self`])
            .upgradeInsecureRequests()
            .blockAllMixedContent()
            .requireSriFor(values: ["script", "style"])
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> String = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: cspBuilder)
            return "Different CSP!"
        }
        let response = try makeTestResponse(for: routeRequest, securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler)

        XCTAssertEqual(expectedCsp, response.headers[.contentSecurityPolicy].first)
    }

    func testCustomCSPDoesntAffectSecondRoute() throws {
        let customCSP = ContentSecurityPolicy()
            .defaultSrc(sources: CSPKeywords.none)
            .scriptSrc(sources: "https://static.brokenhands.io")
            .styleSrc(sources: "https://static.brokenhands.io")
            .imgSrc(sources: "https://static.brokenhands.io")
            .fontSrc(sources: "https://static.brokenhands.io")
            .connectSrc(sources: "https://*.brokenhands.io")
            .formAction(sources: CSPKeywords.`self`)
            .upgradeInsecureRequests()
            .blockAllMixedContent()
            .requireSriFor(values: "script", "style")
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> String = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: customCSP)
            return "Different CSP!"
        }
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler, initialRequest: routeRequest)
        let expectedCSPHeaderValue = "default-src 'none'"

        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
    }
    
    func testNonVariadicCustomCSPDoesntAffectSecondRoute() throws {
        let customCSP = ContentSecurityPolicy()
            .defaultSrc(sources: [CSPKeywords.none])
            .scriptSrc(sources: ["https://static.brokenhands.io"])
            .styleSrc(sources: ["https://static.brokenhands.io"])
            .imgSrc(sources: ["https://static.brokenhands.io"])
            .fontSrc(sources: ["https://static.brokenhands.io"])
            .connectSrc(sources: ["https://*.brokenhands.io"])
            .formAction(sources: [CSPKeywords.`self`])
            .upgradeInsecureRequests()
            .blockAllMixedContent()
            .requireSriFor(values: ["script", "style"])
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> String = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: customCSP)
            return "Different CSP!"
        }
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler, initialRequest: routeRequest)
        let expectedCSPHeaderValue = "default-src 'none'"

        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
    }

    func testDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute() throws {
        let differentCsp = ContentSecurityPolicy()
            .defaultSrc(sources: CSPKeywords.none)
            .scriptSrc(sources: "test")
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> String = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: differentCsp)
            return "Different CSP!"
        }
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler)

        XCTAssertEqual("default-src 'none'", response.headers[.contentSecurityPolicy].first)
    }
    
    func testNonVariadicDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute() throws {
        let differentCsp = ContentSecurityPolicy()
            .defaultSrc(sources: [CSPKeywords.none])
            .scriptSrc(sources: ["test"])
        let factory = SecurityHeadersFactory.api()
        let cspSettingRouteHandler: (Request) throws -> String = { req in
            req.contentSecurityPolicy = ContentSecurityPolicyConfiguration(value: differentCsp)
            return "Different CSP!"
        }
        let response = try makeTestResponse(for: request, securityHeadersToAdd: factory, routeHandler: cspSettingRouteHandler)

        XCTAssertEqual("default-src 'none'", response.headers[.contentSecurityPolicy].first)
    }

    func testAbortMiddleware() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let response = try makeTestResponse(for: abortRequest, securityHeadersToAdd: SecurityHeadersFactory.api())

        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[.xContentTypeOptions].first)
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions].first)
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[.xssProtection].first)
    }

    func testStubFileMiddleware() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let response = try makeTestResponse(for: fileRequest, securityHeadersToAdd: SecurityHeadersFactory.api(), fileMiddleware: StubFileMiddleware())

        XCTAssertEqual("Hello World!", String(data: response.body.data!, encoding: String.Encoding.utf8))
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[.xContentTypeOptions].first)
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions].first)
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[.xssProtection].first)
    }

    func testStubFileMiddlewareDifferentRequestReturnsDefaultCSPWhenSettingCustomCSPOnRoute() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'; script-src test"
        let csp = ContentSecurityPolicy()
            .defaultSrc(sources: CSPKeywords.none)
            .scriptSrc(sources: "test")
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"

        let response = try makeTestResponse(for: fileRequest, securityHeadersToAdd: SecurityHeadersFactory.api(), fileMiddleware: StubFileMiddleware(cspConfig: ContentSecurityPolicyConfiguration(value: csp)))

        XCTAssertEqual("Hello World!", String(data: response.body.data!, encoding: String.Encoding.utf8))
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[.xContentTypeOptions].first)
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[.contentSecurityPolicy].first)
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[.xFrameOptions].first)
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[.xssProtection].first)
    }

    // MARK: - Private functions

    private func makeTestResponse(for request: Request, securityHeadersToAdd: SecurityHeadersFactory, routeHandler: ((Request) throws -> String)? = nil, fileMiddleware: StubFileMiddleware? = nil, initialRequest: Request? = nil) throws -> Response {

        application.middleware = Middlewares()
        application.middleware.use(securityHeadersToAdd.build())
        application.middleware.use(ErrorMiddleware.default(environment: request.application.environment))
        
        if let fileMiddleware = fileMiddleware {
            application.middleware.use(fileMiddleware)
        }

        application.routes.get("test") { req in
            return "TEST"
        }

        if let routeHandler = routeHandler {
            application.routes.get("route", use: routeHandler)
        }

        application.routes.get("abort") { req -> EventLoopFuture<Response> in
            throw Abort(.badRequest)
        }

        if let dummyRequest = initialRequest {
            _ = try application.responder.respond(to: dummyRequest).wait()
        }

        return try application.responder.respond(to: request).wait()
    }

}

struct ResponseData: Content {
    let string: String
}
