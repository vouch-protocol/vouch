# OpenSSF Badge Application Guide

This guide provides the answers for the OpenSSF Best Practices Badge (Silver Level) application for Vouch Protocol.

Copy and paste these answers into the application form.

---

## 🟢 Basics

| Field | Answer | URL / Note |
|-------|--------|------------|
| **Project website** | `https://vouch-protocol.com` | |
| **Project implementation** | `https://github.com/vouch-protocol/vouch` | |
| **Project description** | The Identity & Reputation Standard for AI Agents | |
| **People interacted with** | `Met` | GitHub issues & Discord |
| **Floss license** | `Apache-2.0` | Client license |
| **Floss license OSI** | `Met` | |
| **Documentation** | `Met` | `https://github.com/vouch-protocol/vouch#readme` |
| **Documentation basics** | `Met` | |
| **Documentation interface** | `Met` | |
| **Sites https** | `Met` | `https://vouch-protocol.com` |
| **Sites https redirect** | `Met` | |
| **Repo public** | `Met` | |
| **Repo track** | `Met` | |
| **Repo interim** | `Met` | |
| **Repo distributed** | `Met` | git |
| **Release notes** | `Met` | `https://github.com/vouch-protocol/vouch/releases` |
| **DCO** | `Met` | `docs/openssf-silver-application.md` (See DCO section) |
| **Governance** | `Met` | `https://github.com/vouch-protocol/vouch/blob/main/GOVERNANCE.md#governance-model` |
| **Code of Conduct** | `Met` | `https://github.com/vouch-protocol/vouch/blob/main/CODE_OF_CONDUCT.md` |
| **Roles & Responsibilities** | `Met` | `https://github.com/vouch-protocol/vouch/blob/main/GOVERNANCE.md#roles--responsibilities` |
| **Access Continuity** | `Met` | `https://github.com/vouch-protocol/vouch/blob/main/GOVERNANCE.md#access-continuity-bus-factor` |
| **Bus Factor** | `Met` | `https://github.com/vouch-protocol/vouch/blob/main/GOVERNANCE.md#access-continuity-bus-factor` |

---

## 🟢 Change Control

| Field | Answer | URL / Note |
|-------|--------|------------|
| **Public version control** | `Met` | git |
| **Unique version numbering** | `Met` | SemVer (e.g. 1.4.0) |
| **Release tags** | `Met` | git tags |
| **Release notes vulgarity** | `Met` | We don't use vulgarity |

---

## 🟢 Reporting

| Field | Answer | URL / Note |
|-------|--------|------------|
| **Bug reporting process** | `Met` | `https://github.com/vouch-protocol/vouch/issues` |
| **Vulnerability reporting process** | `Met` | `https://github.com/vouch-protocol/vouch/blob/main/SECURITY.md` |
| **Reporting archive** | `Met` | GitHub Issues are archived |
| **Vulnerability response process** | `Met` | Defined in SECURITY.md |

---

## 🟢 Quality

| Field | Answer | URL / Note |
|-------|--------|------------|
| **Build** | `Met` | Standard python build tools |
| **Build tools** | `Met` | `setuptools`, `pip` |
| **Automated build** | `Met` | GitHub Actions |
| **Test** | `Met` | `pytest` |
| **Test invocation** | `Met` | `pytest tests/` |
| **Test automated** | `Met` | GitHub Actions |
| **Test policy** | `Met` | `CONTRIBUTING.md` requires tests |
| **Test coverage** | `Met` | `https://codecov.io/gh/vouch-protocol/vouch` |
| **Code style** | `Met` | `CONTRIBUTING.md` (PEP 8) |
| **Code style enforced** | `Met` | `ruff`, `black` in CI |

---

## 🟢 Security

| Field | Answer | URL / Note |
|-------|--------|------------|
| **Secure development** | `Met` | `SECURITY.md` |
| **Know common errors** | `Met` | Developers trained in crypto hygiene |
| **Fixed defaults** | `Met` | Secure-by-default (e.g., strong crypto) |
| **Signed releases** | `Met` | Releases signed via Vouch Gatekeeper |
| **Vulnerability report credit** | `Met` | `SECURITY.md` (Disclosure Policy) |
| **Vulnerability response process** | `Met` | `SECURITY.md` |
| **Update easy** | `Met` | `pip install --upgrade vouch-protocol` |
| **Cryptographic algorithms** | `Met` | We use standard, modern algorithms (Ed25519) |
| **Cryptographic library** | `Met` | `cryptography` (OpenSSL backend) |
| **No broken crypto** | `Met` | No MD5/SHA1 used |

---

## 🟢 Analysis (Silver)

| Field | Answer | URL / Note |
|-------|--------|------------|
| **Static code analysis** | `Met` | `ruff`, `mypy` |
| **Dynamic analysis** | `Met` | `pytest` (runtime verification) |

---

## 📝 Silver-Specific Fields

For the specific Silver questions (DCO, 2FA, etc.), refer to:
`docs/openssf-silver-application.md`

That document contains the detailed justifications you need to copy-paste for the "Justification" text boxes.
