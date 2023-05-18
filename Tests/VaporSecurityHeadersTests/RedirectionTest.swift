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
    
    func testWithRedirectMiddlewareWithAllowedHost() throws {
        let expectedRedirectStatus: HTTPStatus = HTTPResponseStatus(statusCode: 301, reasonPhrase: "Moved permanently")
        request.headers.add(name: .host, value: "localhost:8080")
        let responseRedirected = try makeTestResponse(for: request, withRedirection: true, allowedHosts: ["localhost:8081", "example.com"])
        XCTAssertEqual(expectedRedirectStatus, responseRedirected.status)
    }
    
    func testWithRedirectMiddlewareWithDisallowedHost() throws {
        let expectedRedirectStatus: HTTPStatus = HTTPResponseStatus(statusCode: 400, reasonPhrase: "Bad request")
        request.headers.add(name: .host, value: "localhost:8080")
        let responseRedirected = try makeTestResponse(for: request, withRedirection: true, allowedHosts: ["localhost:8081", "example.com"])
        XCTAssertEqual(expectedRedirectStatus, responseRedirected.status)
    }
    
    func testWithoutRedirectionMiddleware() throws {
        let expectedNoRedirectStatus: HTTPStatus = HTTPResponseStatus(statusCode: 200, reasonPhrase: "Ok")
        request.headers.add(name: .host, value: "localhost:8080")
        let response = try makeTestResponse(for: request, withRedirection: false)
        XCTAssertEqual(expectedNoRedirectStatus, response.status)
    }
    
    func testOnDevelopmentEnvironment() throws {
        let expectedStatus: HTTPStatus = HTTPResponseStatus(statusCode: 200, reasonPhrase: "Ok")
        request.headers.add(name: .host, value: "localhost:8080")
        let response = try makeTestResponse(for: request, withRedirection: true, environment: .development)
        XCTAssertEqual(expectedStatus, response.status)
    }
    
    func testWithoutHost() throws {
        let expectedOutcome: String = "Abort.400: Bad Request"
        do {
            _ = try makeTestResponse(for: request, withRedirection: true)
        } catch (let error) {
            XCTAssertEqual(expectedOutcome, error.localizedDescription)
        }
    }
    
    func testWithProtoSet() throws {
        let expectedStatus: HTTPStatus = HTTPResponseStatus(statusCode: 200, reasonPhrase: "Ok")
        request.headers.add(name: .xForwardedProto, value: "https")
        let response = try makeTestResponse(for: request, withRedirection: true)
        XCTAssertEqual(expectedStatus, response.status)
    }
    
    private func makeTestResponse(for request: Request, withRedirection: Bool, environment: Environment? = nil, allowedHosts: [String] = []) throws -> Response {
        application.middleware = Middlewares()
        if let environment = environment {
            application.environment = environment
        }
        if withRedirection == true {
        application.middleware.use(HTTPSRedirectMiddleware(allowedHosts: allowedHosts))
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
