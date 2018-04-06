<p align="center">
    <img src="https://user-images.githubusercontent.com/9938337/29741110-2e0ae9ca-8a5e-11e7-8fbf-58b256d4dd57.png" alt="Vapor Security Headers">
    <br>
    <br>
    <a href="https://swift.org">
        <img src="http://img.shields.io/badge/Swift-4.1-brightgreen.svg" alt="Language">
    </a>
    <a href="https://travis-ci.org/brokenhandsio/VaporSecurityHeaders">
        <img src="https://travis-ci.org/brokenhandsio/VaporSecurityHeaders.svg?branch=master" alt="Build Status">
    </a>
    <a href="https://codecov.io/gh/brokenhandsio/VaporSecurityHeaders">
        <img src="https://codecov.io/gh/brokenhandsio/VaporSecurityHeaders/branch/master/graph/badge.svg" alt="Code Coverage">
    </a>
    <a href="https://raw.githubusercontent.com/brokenhandsio/VaporSecurityHeaders/master/LICENSE">
        <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
    </a>
</p>

A Middleware library for adding security headers to your Vapor application.

# Features

Easily add headers to all your responses for improving the security of your site for you and your users. Currently supports:

* Content-Security-Policy
* Content-Security-Policy-Report-Only
* X-XSS-Protection
* X-Frame-Options
* X-Content-Type-Options
* Strict-Transport-Security (HSTS)
* Server
* Referrer Policy

These headers will *help* prevent cross-site scripting attacks, SSL downgrade attacks, content injection attacks, click-jacking etc. They will not help for any attacks directly against your server, but they will help your users and help secure sensitive information (CSRF tokens). Please note that this library does not guarantee anything and nothing is ever completely secure.

# Usage

To use Vapor Security Headers, just register the middleware with your services and add it to your `MiddlewareConfig`. Vapor Security Headers makes this easy to do with a `builder` function on the factory. In `configure.swift` add:

```swift
services.register(securityHeadersToAdd.build())
let securityHeadersFactory = SecurityHeadersFactory()

var middlewareConfig = MiddlewareConfig()
middlewareConfig.use(SecurityHeaders.self)
// ...
services.register(middlewareConfig)
```

The default factory will add default values to your site for Content-Security-Policy, X-XSS-Protection, X-Frame-Options and X-Content-Type-Options.

***Note:*** You should ensure you set the security headers as the first middleware in your `MiddlewareConfig` to make sure the headers get added to all responses

If you want to add your own values, it is easy to do using the factory. For instance, to add a content security policy configuration, just do:

```swift
let cspValue = "default-src 'none'; script-src https://static.brokenhands.io;"
let cspConfig = ContentSecurityPolicyConfiguration(value: cspValue)
let securityHeadersMiddlewareFactory = SecurityHeadersFactory().with(contentSecurityPolicy: cspConfig)
```

You will need to add it as a dependency in your `Package.swift` file:

```swift
dependencies: [
    ...,
    .package(url: "https://github.com/brokenhandsio/VaporSecurityHeaders.git", from: "2.0.0")
]
```

Each different header has its own configuration and options, details of which can be found below.

You can test your site by visiting the awesome [Security Headers](https://securityheaders.io) (no affiliation) websites

## API Headers

If you are running an API you can choose a default configuration for that by creating it with:

```swift
let securityHeaders = SecurityHeadersFactory.api()
```

## Manual Initialisation

You can also build the middleware manually like so:

```swift
let securityHeadersMiddleware = SecurityHeadersFactory().build()
```

# Server Configuration

## Vapor

If you are running Vapor on it's own (i.e. not as a CGI application or behind and reverse proxy) then you do not need to do anything more to get it running!

## Nginx, Apache and 3rd Party Services

Both web servers should pass on the response headers from Vapor without issue when running as a reverse proxy. Some servers and providers (such as Heroku) will inject their own headers or block certain headers (such as HSTS to stop you locking out their whole site). You will need to check with your provider to see what is enabled and allowed.

# Security Header Information

## Content-Security-Policy

Content Security Policy is one of the most effective tools for protecting against cross-site scripting attacks. In essence it is a way of whitelisting sources for content so that you only load from known and trusted sources. For more information about CSP, read Scott Helme's [awesome blog post](https://scotthelme.co.uk/content-security-policy-an-introduction/) which tells you how to configure it and what to use.

The Vapor Security Headers package will set a default CSP of `default-src: 'self'`, which means that you can load images, scripts, fonts, CSS etc **only** from your domain. It also means that you cannot have any inline Javascript or CSS, which is one of the most effective measures you can take in protecting your site, and will wipe out a large proportion of content-injection attacks.

The API default CSP is `default-src: 'none'` as an API should only return data and never be loading scripts or images to display!

I plan on massively improving creating the CSP configurations, but for now to configure your CSP you can add it to your `ContentSecurityPolicyConfiguration` like so:

```swift
let cspConfig = ContentSecurityPolicyConfiguration(value: "default-src 'none'; script-src https://static.brokenhands.io; style-src https://static.brokenhands.io; img-src https://static.brokenhands.io; font-src https://static.brokenhands.io; connect-src https://*.brokenhands.io; form-action 'self'; upgrade-insecure-requests; block-all-mixed-content; require-sri-for script style; report-uri https://csp-report.brokenhands.io")
let securityHeaders = SecurityHeaders(contentSecurityPolicyConfiguration: cspConfig)
```

This policy means that by default everything is blocked, however:

* Scripts can be loaded from `https://static.brokenhands.io`
* CSS can be loaded from `https://static.brokenhands.io`
* Images can be loaded from `https://static.brokenhands.io`
* Fonts can be loaded from `https://static.brokenhands.io`
* Any JS connections can only be made to any `brokenhands.io` subdomain over HTTPS
* Form actions go only go to the same site
* Any HTTP requests will be sent over HTTPS
* Any attempts to load HTTP content will be blocked
* Any scripts and style links must have [SRI](https://scotthelme.co.uk/subresource-integrity/) values
* Any policy violations will be sent to `https://csp-report.brokenhands.io`

Check out [https://report-uri.io/](https://report-uri.io/) for a free tool to send all of your CSP reports to.

### Page Specific CSP

Vapor Security Headers also supports setting the CSP on a route or request basis. If the middleware has been added to the `MiddlewareConfig`, you can override the CSP for a request. This allows you to have a strict default CSP, but allow content from extra sources when required, such as only allowing the Javascript for blog comments on the blog page. Create a separate `ContentSecurityPolicyConfiguration` and then add it to the request. For example, inside a route handler, you could do:

```swift
let pageSpecificCSPVaue = "default-src 'none'; script-src https://comments.disqus.com;"
let pageSpecificCSP = ContentSecurityPolicyConfiguration(value: pageSpecificCSPValue)
request.contentSecurityPolicy = pageSpecificCSP
```

You must also enable the `CSPRequestConfiguration` service for this to work. In `configure.swift` add:

```swift
services.register { _ in
    return CSPRequestConfiguration()
}
```

## Content-Security-Policy-Report-Only

Content-Security-Policy-Report-Only works in exactly the same way as Content-Security-Policy except that any violations will not block content, but they will be reported back to you. This is extremely useful for testing a CSP before rolling it out over your site. You can run both side by side - so for example have a fairly simply policy under Content-Security-Policy but test a more restrictive policy over Content-Security-Policy-Report-Only. The great thing about this is that your users do all your testing for you!

To configure this, just pass in your policy to the `ContentSecurityPolicyReportOnlyConfiguration`:

```swift
let cspConfig = ContentSecurityPolicyReportOnlyConfiguration(value: "default-src https:; report-uri https://csp-report.brokenhands.io")
let securityHeaders = SecurityHeaders(contentSecurityPolicyReportOnlyConfiguration: cspConfig)
```

The [above blog post](https://scotthelme.co.uk/content-security-policy-an-introduction/) goes into more details about this.

## X-XSS-Protection

X-XSS-Protection configures the browser's cross-site scripting filter. The recommended, and default, setting is `.block` which blocks the response if the browser detects an attack. This can be configured with:

```swift
let xssProtectionConfig = XssProtectionConfiguration(option: .block)
```

To just enable the protection:

```swift
let xssProtectionConfig = XssProtectionConfiguration(option: .enable)
```

To sanitise the page and report the violation:

```swift
let xssProtectionConfig = XssProtectionConfiguration(option: .report("https://report-uri.com"))
```

Or to disable:

```swift
let xssProtectionConfig = XssProtectionConfiguration(option: .disable)
```

## X-Content-Type-Options

X-Content-Type-Options stops a browser from trying to MIME-sniff content types from requests and makes sure that the declared content type is used. It only has one option, which is `nosniff`. To use this, set your `ContentTypeOptionsConfiguration` as so (this is set by default on any `SecurityHeaders` object):

```swift
let contentTypeConfig = ContentTypeOptionsConfiguration(option: .nosniff)
```

To disable it:

```swift
let contentTypeConfig = ContentTypeOptionsConfiguration(option: .none)
```

## X-Frame-Options

The X-Frame-Options header is for click-jacking attacks and tells the browser whether your site can be framed. To stop your site from being framed completely (the default setting):

```swift
let frameOptionsConfig = FrameOptionsConfiguration(option: .deny)
```

To allow you to frame your own site:

```swift
let frameOptionsConfig = FrameOptionsConfiguration(option: .sameOrigin)
```

To allow a specific site to frame yours, use:

```swift
let frameOptionsConfig = FrameOptionsConfiguration(option: .allow(from: "https://mytrustedsite.com"))
```

## Strict-Transport-Security

Strict-Transport-Security is an improvement over 301/302 redirects or HTTPS forwarding. Browsers will default to HTTP when you navigate to an address but HSTS (HTTP Strict Transport Security) tells the browser that it should always connect over HTTPS, so all future requests will be HTTPS, even if you click on an HTTP link. By default this is not turned on with the Security Headers library as it can cause issues if you haven't got HTTPS set up properly. If you specify this header and then at a future date you don't renew your SSL certificate or disable SSL then the browser will refuse to load your site! However, it is highly recommended as it ensures that all connections are over HTTPS, even if a user clicks on an HTTP link.

The default configuration is `max-age=31536000; includeSubDomains; preload`. This tells the browser to force HTTPS for a year, and for *every* subdomain as well. So if you specify this, make sure you have SSL properly configured for all subdomains, e.g. `test.mysite.com`, `dev.mysite.com` etc.

The `preload` tag tells Chrome that you want to be preloaded. This will add you to the preload list, which means that the browser will automatically know you want an HTTPS connection before you have even visited the site, so removes the initial HTTP handshake the first time you specify the header. However, this has now been superseded and you should now submit your site at [https://hstspreload.org](https://hstspreload.org). This will add your site to Chrome's source to preload it in the future and it is the list that other browsers use as well. Note that it is difficult to remove yourself from the list (and can take months to get it rolled out to the browsers), so by submitting your site you are effectively guaranteeing working HTTPS for the rest of the life of your site. However, these days it shouldn't be a problem - use [Let's Encrypt](https://letsencrypt.org)! **Note**: You should be careful about using this on deployment sites such as Heroku as it may cause issues.

To use the Strict-Transport-Security header, you can configure and add it as so (default values are shown):

```swift
let strictTransportSecurityConfig = StrictTransportSecurityConfiguration(maxAge: 31536000, includeSubdomains: true, preload: true)
let securityHeaders = SecurityHeaders(hstsConfiguration: strictTransportSecurityConfig)
```

## Server

The Server header is usually hidden from responses in order to not give away what type of server you are running and what version you are using. This is to stop attackers from scanning your site and using known vulnerabilities against it easily. By default Vapor does not show the server header in responses for this reason.

However, it can be fun to add in a custom server configuration for a bit of personalisation, such as your website name, or company name (look at Github's response) and the `ServerConfiguraiton` is to allow this. So, for example, if I wanted my `Server` header to be `brokenhands.io`, I would configure it like:

```swift
let serverConfig = ServerConfiguration(value: "brokenhands.io")
let securityHeaders = SecurityHeaders(serverConfiguration: serverConfig)
```

## Referrer Policy

The Referrer Policy is the latest header to have been introduced (the spec can be found [here](https://www.w3.org/TR/referrer-policy/)). It basically defines when the `Referrer` header can be sent with a request. You may want to not send the header when going from HTTPS to HTTP for example.

The different options are:

* ""
* "no-referrer"
* "no-referrer-when-downgrade"
* "same-origin"
* "origin"
* "strict-origin"
* "origin-when-cross-origin"
* "strict-origin-when-cross-origin"
* "unsafe-url"

I won't go into details about each one, I will point you in the direction of a far better explanation [by Scott Helme](https://scotthelme.co.uk/a-new-security-header-referrer-policy/).
