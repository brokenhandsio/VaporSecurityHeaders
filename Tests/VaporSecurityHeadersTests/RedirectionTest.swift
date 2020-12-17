import XCTest

@testable import Vapor

import VaporSecurityHeaders

class RedirectionTest: XCTestCase {

    // MARK: - Properties

    private var application: Application!
    private var eventLoopGroup: EventLoopGroup!
    private var request: Request!

    override func setUp() {
        eventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        application = Application(.testing, .shared(eventLoopGroup))
    }

    override func tearDownWithError() throws {
        application.shutdown()
        try eventLoopGroup.syncShutdownGracefully()
    }
    
    func testRedirectionMiddleware() throws {
        let expectedRedirectStatus: HTTPStatus = HTTPResponseStatus(statusCode: 301, reasonPhrase: "Moved permanently")
        let expectedNoRedirectStatus: HTTPStatus = HTTPResponseStatus(statusCode: 200, reasonPhrase: "Ok")
        let requestURL = Request(application: application, method: .GET, url: URI(string: "/testRedirection"), on: eventLoopGroup.next())
        requestURL.headers.add(name: .host, value: "localhost:8080")
        let responseRedirected = try makeTestResponse(for: requestURL, withRedirection: true)
        let response = try makeTestResponse(for: requestURL, withRedirection: false)
        XCTAssertEqual(expectedRedirectStatus, responseRedirected.status)
        XCTAssertEqual(expectedNoRedirectStatus, response.status)
    }
    
    private func makeTestResponse(for request: Request, withRedirection: Bool, routeHandler: ((Request) throws -> String)? = nil) throws -> Response {

        application.middleware = Middlewares()
        
        if withRedirection == true {
        application.middleware.use(SecurityHeadersFactory().redirectMiddleware)
        }
        
        application.routes.get("testRedirection") { req in
            return "TESTREDIRECTION"
        }

        return try application.responder.respond(to: request).wait()
    }
}
