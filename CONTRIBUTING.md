# Contributing to Vouch Protocol

Thank you for your interest in contributing to Vouch Protocol! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [DCO Sign-Off](#dco-sign-off)

## Code of Conduct

This project follows our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create a branch** for your changes
4. **Make your changes** with tests
5. **Submit a pull request**

## How to Contribute

### Reporting Bugs

- Check if the bug is already reported in [Issues](https://github.com/vouch-protocol/vouch/issues)
- If not, create a new issue with:
  - Clear title and description
  - Steps to reproduce
  - Expected vs actual behavior
  - Python version and OS

### Suggesting Features

- Open a [Discussion](https://github.com/vouch-protocol/vouch/discussions) first
- Describe the use case and expected behavior
- If approved, create an issue to track implementation

### Security Vulnerabilities

Please see our [Security Policy](SECURITY.md) for reporting security issues. **Do not** open public issues for security vulnerabilities.

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/vouch.git
cd vouch

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

## Pull Request Process

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes** and add tests

3. **Run tests** to ensure everything passes:
   ```bash
   pytest tests/ -v
   ```

4. **Commit with DCO sign-off** (required):
   ```bash
   git commit -s -m "feat: Add your feature description"
   ```

5. **Push** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request** against `main`

### Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
type(scope): description

[optional body]

Signed-off-by: Your Name <your.email@example.com>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only
- `test`: Adding tests
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `chore`: Maintenance tasks

## Coding Standards

- **Python**: Follow [PEP 8](https://pep8.org/)
- **Type hints**: Use type annotations for function signatures
- **Docstrings**: Use Google-style docstrings
- **Tests**: All new features must include tests
- **Coverage**: Aim for >80% code coverage

### Example Code Style

```python
def verify_token(token: str, public_key: str) -> tuple[bool, Optional[Passport]]:
    """
    Verify a Vouch-Token.
    
    Args:
        token: The JWS compact serialized token.
        public_key: JWK JSON string of the public key.
        
    Returns:
        Tuple of (is_valid, Passport or None).
    """
    ...
```

## DCO Sign-Off

All contributions must include a Developer Certificate of Origin (DCO) sign-off.

### What is DCO?

The DCO is a lightweight way to certify that you wrote or have the right to submit your contribution. You do this by adding a `Signed-off-by` line to your commit message.

### How to Sign

Add `-s` flag when committing:

```bash
git commit -s -m "Your commit message"
```

This adds:
```
Signed-off-by: Your Name <your.email@example.com>
```

### Fixing Unsigned Commits

If you forgot to sign:

```bash
git commit --amend -s
git push --force-with-lease
```

## Questions?

- Open a [Discussion](https://github.com/vouch-protocol/vouch/discussions)
- Join our [Discord](https://discord.gg/VxgYkjdph)
- Check the [Documentation](https://github.com/vouch-protocol/vouch#readme)

---

Thank you for contributing to Vouch Protocol! 🙏
