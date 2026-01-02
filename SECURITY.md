# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.3.x   | :white_check_mark: |
| 1.2.x   | :white_check_mark: |
| < 1.2   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please email: **security@vouch-protocol.org**

Or use GitHub's private vulnerability reporting:
1. Go to the [Security tab](https://github.com/vouch-protocol/vouch/security)
2. Click "Report a vulnerability"
3. Fill out the form with details

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

| Action | Timeframe |
|--------|-----------|
| Acknowledgment | 48 hours |
| Initial assessment | 1 week |
| Fix timeline provided | 2 weeks |
| Security advisory published | After fix is released |

### Disclosure Policy

- We follow [responsible disclosure](https://en.wikipedia.org/wiki/Responsible_disclosure)
- We will credit reporters (unless you prefer anonymity)
- We aim to fix critical vulnerabilities within 30 days

## Security Best Practices

When using Vouch Protocol:

1. **Protect private keys** - Never commit keys to source control
2. **Use environment variables** - Store `VOUCH_PRIVATE_KEY` securely
3. **Rotate keys** - Regenerate keys periodically
4. **Verify signatures** - Always verify tokens server-side
5. **Check expiration** - Tokens have short expiry for security

## Known Security Considerations

- **Ed25519 keys**: We use EdDSA (Ed25519) for cryptographic signing
- **JWT structure**: Tokens follow JWS compact serialization
- **No symmetric keys**: We only support asymmetric cryptography

## Security Updates

Security updates are released as patch versions (e.g., 1.3.x). 

Subscribe to [GitHub releases](https://github.com/vouch-protocol/vouch/releases) for notifications.
