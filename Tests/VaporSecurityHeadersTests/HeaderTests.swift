import XCTest

@testable import VaporSecurityHeaders

class HeaderTests: XCTestCase {

    static var allTests = [
        ("testContentTypeOptionsHeaderSet", testContentTypeOptionsHeaderSet),
    ]

    func testContentTypeOptionsHeaderSet() {
        let expectedHeaderValue = "nosniff"
    }

}
