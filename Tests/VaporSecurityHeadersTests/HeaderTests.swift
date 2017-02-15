import XCTest

@testable import Vapor
import HTTP

@testable import VaporSecurityHeaders

class HeaderTests: XCTestCase {

    static var allTests = [
        ("testDefaultHeaders", testDefaultHeaders),
        ("testAllHeadersForApi", testAllHeadersForApi),
        ("testAPIHeadersWithHSTS", testAPIHeadersWithHSTS),
        ("testDefaultHeadersWithHSTS", testDefaultHeadersWithHSTS)
    ]
    
    private var request: Request!
    
    override func setUp() {
        request  = try! Request(method: .get, uri: "/test/")
    }

    func testDefaultHeaders() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "DENY"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        
        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders())
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
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubdomains; preload"
        
        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders(enableHSTS: true))
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
        
        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders(api: true))
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
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubdomains; preload"
        
        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders(api: true, enableHSTS: true))
        let response = try drop.respond(to: request)
        
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers[HeaderKey.xContentTypeOptions])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers[HeaderKey.contentSecurityPolicy])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers[HeaderKey.xFrameOptions])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers[HeaderKey.xXssProtection])
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers[HeaderKey.strictTransportSecurity])
    }
    
    /*
    func testAPIHeadersWithHSTSandHPKP() throws {
        
    }
    
    func testAPIHeadersWithHPKP() throws {
        
    }
    */
    
    /*
    func testDefaultHeadersWithHSTSandHPKP() throws {
        
    }
    
    func testDefaultHeadersWithHPKP() throws {
        
    }
    */
    
    func testHeadersWithContentTypeOptionsTurnedOff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .none)
        let middleware = SecurityHeaders(contentTypeConfiguration: contentTypeConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = try drop.respond(to: request)
        
        XCTAssertNil(response.headers[HeaderKey.xContentTypeOptions])
    }
    
    func testHeadersWithContentTypeOptionsNosniff() throws {
        let contentTypeConfig = ContentTypeOptionsConfiguration(option: .nosniff)
        let middleware = SecurityHeaders(contentTypeConfiguration: contentTypeConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = try drop.respond(to: request)
        
        XCTAssertEqual("nosniff", response.headers[HeaderKey.xContentTypeOptions])
    }
    
    func testHeaderWithFrameOptionsDeny() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .deny)
        let middleware = SecurityHeaders(frameOptionsConfiguration: frameOptionsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = try drop.respond(to: request)
        
        XCTAssertEqual("DENY", response.headers[HeaderKey.xFrameOptions])
    }
    
    func testHeaderWithFrameOptionsSameOrigin() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .sameOrigin)
        let middleware = SecurityHeaders(frameOptionsConfiguration: frameOptionsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = try drop.respond(to: request)
        
        XCTAssertEqual("SAMEORIGIN", response.headers[HeaderKey.xFrameOptions])
    }
    
    func testHeaderWithFrameOptionsAllowFrom() throws {
        let frameOptionsConfig = FrameOptionsConfiguration(option: .allow(from: "https://test.com"))
        let middleware = SecurityHeaders(frameOptionsConfiguration: frameOptionsConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = try drop.respond(to: request)
        
        XCTAssertEqual("ALLOW-FROM https://test.com", response.headers[HeaderKey.xFrameOptions])
    }
    
    func testHeaderWithXssProtectionDisable() throws {
        let xssProtectionConfig = XssProtectionConfiguration(option: .disable)
        let middleware = SecurityHeaders(xssProtectionConfiguration: xssProtectionConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = try drop.respond(to: request)
        
        XCTAssertEqual("0", response.headers[HeaderKey.xXssProtection])
    }
    
    func testHeaderWithXssProtectionEnable() throws {
        let xssProtectionConfig = XssProtectionConfiguration(option: .enable)
        let middleware = SecurityHeaders(xssProtectionConfiguration: xssProtectionConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = try drop.respond(to: request)
        
        XCTAssertEqual("1", response.headers[HeaderKey.xXssProtection])
    }
    
    func testHeaderWithXssProtectionBlock() throws {
        let xssProtectionConfig = XssProtectionConfiguration(option: .block)
        let middleware = SecurityHeaders(xssProtectionConfiguration: xssProtectionConfig)
        let drop = try makeTestDroplet(middlewareToAdd: middleware)
        let response = try drop.respond(to: request)
        
        XCTAssertEqual("1; mode=block", response.headers[HeaderKey.xXssProtection])
    }
    
    
    private func makeTestDroplet(middlewareToAdd: Middleware) throws -> Droplet {
        let drop = Droplet(arguments: ["dummy/path/", "prepare"])
        drop.middleware.append(middlewareToAdd)
        
        drop.get("test") { req in
            return "TEST"
        }
        
        try drop.runCommands()
        
        return drop
    }

}
