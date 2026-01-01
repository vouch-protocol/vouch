---
description: Release vouch-protocol to GitHub and PyPI (weekend only)
---

# Weekend Release Workflow

**IMPORTANT**: Only run this workflow on weekends (Saturday/Sunday) to avoid conflict of interest with employer.

## Pre-flight Checks

1. Verify it's the weekend:
```bash
date +%A
# Should output: Saturday or Sunday
```

2. Run all tests to confirm everything passes:
// turbo
```bash
cd /home/rampy/vouch-protocol && pytest tests/ -v --tb=short
```

3. Verify the security tests pass:
// turbo
```bash
cd /home/rampy/vouch-protocol && python tests/red_team.py
```

## Build Package

4. Clean and rebuild the package:
// turbo
```bash
cd /home/rampy/vouch-protocol && rm -rf dist/*.whl dist/*.tar.gz && python -m build
```

5. Verify the build artifacts:
// turbo
```bash
ls -la /home/rampy/vouch-protocol/dist/
```

## Git Commit & Push

6. Stage all changes and commit:
```bash
cd /home/rampy/vouch-protocol && git add -A && git status
```

7. Create the release commit:
```bash
cd /home/rampy/vouch-protocol && git commit -m "v1.2.0: Key revocation, reputation scoring, cloud KMS, TypeScript SDK

NEW FEATURES:
- Key revocation registry (memory + Redis + HTTP backends)
- Reputation engine with scoring, decay, slashing, history
- Cloud KMS providers (AWS KMS, GCP Cloud KMS, Azure Key Vault)
- Complete TypeScript SDK matching Python API

TESTS: 98 Python tests passing"
```

8. Push to GitHub:
```bash
cd /home/rampy/vouch-protocol && git push origin main
```

## PyPI Upload

9. Upload to PyPI:
```bash
cd /home/rampy/vouch-protocol && twine upload dist/vouch_protocol-1.2.0*
```

10. Verify the release:
// turbo
```bash
pip index versions vouch-protocol
```

## Post-Release

11. Create GitHub release (optional):
- Go to https://github.com/vouch-protocol/vouch/releases
- Click "Create a new release"
- Tag: v1.2.0
- Title: v1.2.0 - Key Revocation, Reputation, Cloud KMS, TypeScript SDK
