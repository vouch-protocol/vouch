# Release Process

This document describes the release process for Vouch Protocol.

## Versioning

Vouch Protocol follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0) - Breaking API changes
- **MINOR** (0.X.0) - New features, backward compatible
- **PATCH** (0.0.X) - Bug fixes, backward compatible

## Release Cadence

- **Patch releases**: As needed for security/bug fixes
- **Minor releases**: Monthly or as features are ready
- **Major releases**: Announced in advance with migration guide

## Release Checklist

### Pre-Release

1. [ ] All tests passing (`pytest tests/`)
2. [ ] Coverage meets threshold (90%+)
3. [ ] CHANGELOG.md updated
4. [ ] Version bumped in `vouch/__init__.py`
5. [ ] Version bumped in `pyproject.toml`
6. [ ] Documentation updated

### Release

1. [ ] Create release branch: `release/vX.Y.Z`
2. [ ] Final review and testing
3. [ ] Tag release: `git tag vX.Y.Z`
4. [ ] Push tag: `git push origin vX.Y.Z`
5. [ ] GitHub Actions builds and publishes to PyPI

### Post-Release

1. [ ] Verify PyPI package: `pip install vouch-protocol==X.Y.Z`
2. [ ] Create GitHub Release with release notes
3. [ ] Announce on Discord
4. [ ] Update documentation site if needed

## PyPI Publishing

Releases are automatically published to PyPI via GitHub Actions when a version tag is pushed:

```yaml
on:
  push:
    tags:
      - 'v*'
```

## Hotfix Process

For critical security fixes:

1. Create hotfix branch from latest release tag
2. Apply minimal fix
3. Release as patch version
4. Cherry-pick to main branch

## Release History

See [CHANGELOG.md](CHANGELOG.md) for detailed release history.

## Contact

Release questions: ram@vouch-protocol.com
