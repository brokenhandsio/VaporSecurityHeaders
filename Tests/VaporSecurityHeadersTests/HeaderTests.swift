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
        let expectedXFOHeaderValue = "deny"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        
        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders())
        let response = try drop.respond(to: request)
        
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers["X-Content-Type-Options"])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers["Content-Security-Policy"])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers["X-Frame-Options"])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers["X-XSS-Protection"])
    }
    
    func testDefaultHeadersWithHSTS() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'self'"
        let expectedXFOHeaderValue = "deny"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubdomains; preload"
        
        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders(enableHSTS: true))
        let response = try drop.respond(to: request)
        
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers["X-Content-Type-Options"])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers["Content-Security-Policy"])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers["X-Frame-Options"])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers["X-XSS-Protection"])
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers["Strict-Transport-Security"])
    }
    
    func testAllHeadersForApi() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "deny"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        
        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders(api: true))
        let response = try drop.respond(to: request)
        
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers["X-Content-Type-Options"])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers["Content-Security-Policy"])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers["X-Frame-Options"])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers["X-XSS-Protection"])
    }
    
    func testAPIHeadersWithHSTS() throws {
        let expectedXCTOHeaderValue = "nosniff"
        let expectedCSPHeaderValue = "default-src 'none'"
        let expectedXFOHeaderValue = "deny"
        let expectedXSSProtectionHeaderValue = "1; mode=block"
        let expectedHSTSHeaderValue = "max-age=31536000; includeSubdomains; preload"
        
        let drop = try makeTestDroplet(middlewareToAdd: SecurityHeaders(api: true, enableHSTS: true))
        let response = try drop.respond(to: request)
        
        XCTAssertEqual(expectedXCTOHeaderValue, response.headers["X-Content-Type-Options"])
        XCTAssertEqual(expectedCSPHeaderValue, response.headers["Content-Security-Policy"])
        XCTAssertEqual(expectedXFOHeaderValue, response.headers["X-Frame-Options"])
        XCTAssertEqual(expectedXSSProtectionHeaderValue, response.headers["X-XSS-Protection"])
        XCTAssertEqual(expectedHSTSHeaderValue, response.headers["Strict-Transport-Security"])
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
