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
        request = Request(application: application, method: .GET, on: eventLoopGroup.next())
    }

    override func tearDownWithError() throws {
        application.shutdown()
        try eventLoopGroup.syncShutdownGracefully()
    }

    func testWithRedirectionMiddleware() throws {
        let expectedRedirectStatus: HTTPStatus = HTTPResponseStatus(statusCode: 301, reasonPhrase: "Moved permanently")
        request.headers.add(name: .host, value: "localhost:8080")
        let responseRedirected = try makeTestResponse(for: request, withRedirection: true)
        XCTAssertEqual(expectedRedirectStatus, responseRedirected.status)
    }
    func testWithoutRedirectionMiddleware() throws {
        let expectedNoRedirectStatus: HTTPStatus = HTTPResponseStatus(statusCode: 200, reasonPhrase: "Ok")
        request.headers.add(name: .host, value: "localhost:8080")
        let response = try makeTestResponse(for: request, withRedirection: false)
        XCTAssertEqual(expectedNoRedirectStatus, response.status)
    }
    private func makeTestResponse(for request: Request, withRedirection: Bool, routeHandler: ((Request) throws -> String)? = nil) throws -> Response {
        application.middleware = Middlewares()
        if withRedirection == true {
        application.middleware.use(SecurityHeadersFactory().redirectMiddleware)
        }
        try routes(application)
        return try application.responder.respond(to: request).wait()
    }
    
    func routes(_ app: Application) throws {
        try app.register(collection: RouteController())
    }
    
    struct RouteController: RouteCollection {
        func boot(routes: RoutesBuilder) throws {
            routes.get(use: testing)
        }
        func testing(req: Request) throws -> String {
            return "Test"
        }
    }
}
