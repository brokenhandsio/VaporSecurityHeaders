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

* Server
* Content-Security-Policy-Report-Only Header
* HPKP
* Per page Content Security Policies

# Server Configuration

## Vapor

If you are running Vapor on it's own (i.e. not as a CGI application or behind and reverse proxy) then you do not need to do anything more to get it running!

## Nginx

TODO (if anyone could test it that would be awesome!)

## Apache

TODO (if anyone could test it that would be awesome!)

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

## Public-Key-Pins

Coming soon

## Report-Uri

TODO
