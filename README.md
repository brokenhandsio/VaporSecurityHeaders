# Vapor Security Headers

[![Language](https://img.shields.io/badge/Swift-3-brightgreen.svg)](http://swift.org)
[![Build Status](https://travis-ci.org/brokenhandsio/VaporSecurityHeaders.svg?branch=master)](https://travis-ci.org/brokenhandsio/VaporSecurityHeaders)
[![codecov](https://codecov.io/gh/brokenhandsio/VaporSecurityHeaders/branch/master/graph/badge.svg)](https://codecov.io/gh/brokenhandsio/VaporSecurityHeaders)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/brokenhandsio/VaporSecurityHeaders/master/LICENSE)

A Middleware library for adding security headers to your Vapor application.

# Features

Easily add headers to all your responses for improving the security of your site for you and your users. Currently supports:

* Content-Security-Policy
* X-XSS-Protection
* X-Frame-Options
* X-Content-Type-Options
* Strict-Transport-Security (HSTS)
* Server

These headers will *help* prevent cross-site scripting attacks, SSL downgrade attacks, content injection attacks, click-jacking etc. They will not help for any attacks directly against your server, but they will help your users and help secure sensitive information (CSRF tokens). Please note that this library does not guarantee anything and nothing is ever completely secure.

# Usage

To use Vapor Security Headers, just add the middleware to your `Droplet` and all the responses will have the headers added:

```swift
import VaporSecurityHeaders
let securityHeaders = SecurityHeaders()
let drop = Droplet()
drop.middleware.append(securityHeaders)
```

This will add default values to your site for Content-Security-Policy, X-XSS-Protection, X-Frame-Options and X-Content-Type-Options. If you are running an API you can choose a default configuration for that by creating it with:

```swift
let securityHeaders = SecurityHeaders.api()
```

Each different header has its own configuration and options, details of which can be found below.

You can test your site by visiting the awesome [Security Headers](https://securityheaders.io) (no affiliation) websites

# Roadmap

The following features are on the roadmap to be implemented:

* Content-Security-Policy-Report-Only Header
* HPKP
* Per page Content Security Policies

# Server Configuration

## Vapor

If you are running Vapor on it's own (i.e. not as a CGI application or behind and reverse proxy) then you do not need to do anything more to get it running!

## Nginx and Apache

Both web servers should pass on the response headers from Vapor without issue when running as a reverse proxy.

# Security Header Information

## Content-Security-Policy

## X-XSS-Protection

X-XSS-Protection configures the browser's cross-site scripting filter. The recommended, and default, setting is `.block` which blocks the response if the browser detects an attack. This can be configured with:

```swift
let xssProtectionConfig = XssProtectionConfiguration(option: .block)
```

To just enable the protection:

```swift
let xssProtectionConfig = XssProtectionConfiguration(option: .enable)
```

Or to disable:
```swift
let xssProtectionConfig = XssProtectionConfiguration(option: .disable)
```

## X-Content-Type-Options

X-Content-Type-Options stops a browser from trying to MIME-sniff content types from requests and makes sure that the declared content type is used. It only has one option, which is `nosniff`. To use this, set your `ContentTypeOptionsConfiguration` as so (this is set by default on any `SecurityHeaders` object):

```swift
let contentTypeConfig = ContentTypeOptionsConfiguration(option: .nosniff)
```

To disable it:

```swift
let contentTypeConfig = ContentTypeOptionsConfiguration(option: .none)
```

## X-Frame-Options

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

## Public-Key-Pins

Coming soon

## Report-Uri

TODO
