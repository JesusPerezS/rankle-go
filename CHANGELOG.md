# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- Additional CMS detection (Wix, Squarespace)
- GraphQL endpoint detection
- API endpoint discovery
- WebSocket detection

## [1.0.0] - 2025-11-19

### 🎉 Initial Release

#### Features
- **HTTP/HTTPS Analysis** - Status codes, response times, server headers
- **CMS Detection** - WordPress, Drupal, Joomla, Magento, Shopify
- **CDN Detection** - 20+ providers (Cloudflare, Akamai, Fastly, etc.)
- **WAF Detection** - 15+ solutions (Imperva, Sucuri, ModSecurity, etc.)
- **Cloud Provider Detection** - AWS, Azure, GCP, DigitalOcean, etc.
- **Technology Stack** - JavaScript libraries (jQuery, React, Vue, Angular, Bootstrap)
- **DNS Analysis** - Complete DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA)
- **Subdomain Discovery** - Via Certificate Transparency logs (crt.sh)
- **TLS/SSL Analysis** - Certificate details, protocols, cipher suites
- **Security Headers** - Audit of HTTP security headers
- **Output Formats** - JSON and human-readable text

#### Technical
- Go 1.23+ support
- 100% Go standard library (zero external dependencies)
- Docker multi-platform builds (Linux, macOS, Windows)
- Pre-commit hooks with golangci-lint (20+ linters)
- Comprehensive test suite with race detector
- Clean architecture with modular design
- Godoc documentation for all exported symbols

#### Documentation
- Comprehensive README with examples
- Security policy (SECURITY.md)
- Code of Conduct (CODE_OF_CONDUCT.md)
- MIT License
- Contributing guidelines
- API documentation
- CI/CD integration examples

#### Supported Platforms
- Linux (amd64, arm64)
- macOS (amd64, arm64/M1/M2)
- Windows (amd64)

---

## Legend

- `Added` - New features
- `Changed` - Changes in existing functionality
- `Deprecated` - Soon-to-be removed features
- `Removed` - Removed features
- `Fixed` - Bug fixes
- `Security` - Security fixes

---

[Unreleased]: https://github.com/javicosvml/rankle-go/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/javicosvml/rankle-go/releases/tag/v1.0.0
