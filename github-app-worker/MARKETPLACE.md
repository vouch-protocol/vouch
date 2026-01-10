# GitHub Marketplace Listing Content

## Short Description (up to 150 chars)
Enforce cryptographic identity on every Pull Request. Zero-config verification of signed commits.

## Full Description

### What is Vouch Gatekeeper?

Vouch Gatekeeper is a GitHub App that enforces cryptographic identity verification on every Pull Request. It ensures that all code contributions come from verified, trusted sources by checking GPG signatures against registered identities.

### Key Features

🔐 **Cryptographic Verification** - Validates GPG/SSH signatures on all commits
🏢 **Organization Trust** - Automatically trusts org members with signed commits
⚡ **Zero Configuration** - Works immediately after installation with sensible defaults
✅ **Check Runs** - Clear pass/fail status on every PR
🤖 **Bot Friendly** - Allows Dependabot, Renovate, and other trusted bots

### How It Works

1. **Install the app** on your repositories
2. **Open a Pull Request** with signed commits
3. **Vouch Gatekeeper verifies** each commit's signature
4. **Check run shows** pass/fail status before merge

### Policy Options

**Zero-Config (Default):** Any organization member with properly signed commits is automatically trusted.

**Explicit Policy:** Configure `.github/vouch-policy.yml` to specify exactly which users and organizations are allowed.

### Why Vouch Gatekeeper?

- **Prevent impersonation** - Ensure commits actually come from who they claim to be from
- **Supply chain security** - Know the cryptographic identity of every code contribution
- **Compliance ready** - Maintain audit trail of verified identities
- **Open source** - Fully transparent, auditable code

### Getting Started

1. Install Vouch Gatekeeper on your repositories
2. Ensure contributors sign their commits with GPG
3. That's it! Every PR will now be verified

### Support

- 📖 [Documentation](https://github.com/vouch-protocol/vouch-protocol)
- 🐛 [Report Issues](https://github.com/vouch-protocol/vouch-protocol/issues)
- 💬 [Discussions](https://github.com/vouch-protocol/vouch-protocol/discussions)

---

## Categories
- Security
- Code quality
- Continuous integration

## Pricing
Free

## Support URL
https://github.com/vouch-protocol/vouch-protocol/issues

## Documentation URL
https://github.com/vouch-protocol/vouch-protocol#readme
