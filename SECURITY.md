# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do NOT create public GitHub issues for security vulnerabilities.**

To report a security vulnerability, please email:

📧 **security@rankle-go.example.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your name/handle for credit (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Release**: 1-90 days depending on severity

### Disclosure Policy

- We will acknowledge receipt of your report within 48 hours
- We will confirm the vulnerability and determine its impact
- We will release a fix as soon as possible
- We will publicly disclose the vulnerability after a fix is released
- We will credit you in the release notes (unless you prefer to remain anonymous)

## Security Best Practices

### For Users

✅ **Do:**
- Always use the latest version
- Verify checksums of downloaded binaries
- Only scan authorized targets
- Respect robots.txt and rate limits
- Review output before sharing

❌ **Don't:**
- Scan targets without authorization
- Use for malicious purposes
- Share scan results with unauthorized parties
- Run with elevated privileges unless necessary

### For Developers

✅ **Do:**
- Validate all inputs
- Handle errors properly
- Use safe string operations
- Review dependencies (we use standard library only)
- Follow secure coding practices
- Write security tests

❌ **Don't:**
- Ignore error returns
- Use unsafe operations
- Store sensitive data
- Skip input validation
- Add unnecessary dependencies

## Known Considerations

This tool is designed for **passive reconnaissance** and should be used responsibly:

- TLS verification is disabled by default for broad compatibility
- DNS resolution uses system resolver
- No built-in rate limiting (users should add delays)
- HTTP requests follow redirects by default
- Timeout values are configurable

## Security Features

- ✅ No data persistence (no databases)
- ✅ No external API calls (except to target)
- ✅ No telemetry or tracking
- ✅ Local execution only
- ✅ Zero external dependencies
- ✅ Open source (full code review possible)

## Vulnerability Disclosure History

No vulnerabilities have been reported yet.

## Contact

- **Security Issues**: security@rankle-go.example.com
- **General Issues**: [GitHub Issues](https://github.com/javicosvml/rankle-go/issues)
- **Private Inquiries**: contact@rankle-go.example.com

---

**Thank you for helping keep Rankle and our users safe!** 🛡️
