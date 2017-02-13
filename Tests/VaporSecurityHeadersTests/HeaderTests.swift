import XCTest

@testable import Vapor
import HTTP

@testable import VaporSecurityHeaders

class HeaderTests: XCTestCase {

    static var allTests = [
        ("testContentTypeOptionsHeaderSet", testContentTypeOptionsHeaderSet),
    ]

    func testContentTypeOptionsHeaderSet() throws {
        let expectedHeaderValue = "nosniff"
        let drop = try makeTestDroplet()
        let request = try! Request(method: .get, uri: "/test/")
        let response = try drop.respond(to: request)
        
        XCTAssertEqual(expectedHeaderValue, response.headers["X-Content-Type-Options"])
    }
    
    private func makeTestDroplet() throws -> Droplet {
        let drop = Droplet(arguments: ["dummy/path/", "prepare"])
        drop.middleware.append(SecurityHeaders())
        
        drop.get("test") { req in
            return "TEST"
        }
        
        try drop.runCommands()
        
        return drop
    }

}
