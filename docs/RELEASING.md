# Releasing and publishing

Each language SDK publishes from its own tag-triggered GitHub Actions workflow,
so you release one ecosystem at a time by pushing a tag. Every workflow can also
be run by hand from the Actions tab (workflow_dispatch).

## Tag conventions

| Push this tag | Workflow | Publishes |
|---|---|---|
| `rust-vX.Y.Z` | publish-crates.yml | `vouch-core`, `vouch-core-uniffi` to crates.io |
| `dotnet-vX.Y.Z` | publish-nuget.yml | `VouchProtocol.Core` to NuGet.org |
| `jvm-vX.Y.Z` | publish-maven.yml | `com.vouchprotocol:vouch-core` to Maven Central |
| `swift-vX.Y.Z` | swift-xcframework.yml | VouchCore XCFramework to GitHub Releases |
| `c-vX.Y.Z` | publish-c.yml | native libs + `vouch_core.h` to GitHub Releases |
| `npm-vX.Y.Z` | publish-npm.yml | `core-wasm`, `sdk`, `api-client` to npm |
| `py-vX.Y.Z` | publish-pypi.yml | `vouch-protocol`, `vouch-api-client`, `vouch-sdk` to PyPI |

Example: `git tag rust-v0.1.1 && git push origin rust-v0.1.1`.

Bump the version in the relevant manifest (Cargo.toml, .csproj, build.gradle.kts,
package.json, pyproject.toml) before tagging. The npm and PyPI workflows skip
versions that already exist, so re-running is safe.

## Required repository secrets

Add these under Settings, Secrets and variables, Actions:

| Secret | Used by | Where to get it |
|---|---|---|
| `CARGO_REGISTRY_TOKEN` | crates | crates.io, Account Settings, API Tokens |
| `NUGET_API_KEY` | nuget | nuget.org, API Keys |
| `CENTRAL_USERNAME`, `CENTRAL_PASSWORD` | maven | Sonatype Central Portal user token |
| `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `GPG_KEY_ID` | maven | your release GPG key (Central requires signed artifacts) |
| `NPM_TOKEN` | npm | npmjs.com, Access Tokens, Automation |
| `PYPI_API_TOKEN` | pypi | pypi.org, Account, API tokens |

C/C++ and Swift use the built-in `GITHUB_TOKEN`, so they need no extra secret.

## One-time setup

- **Maven Central**: verify the `com.vouchprotocol` namespace once in the Central
  Portal before the first `jvm-v*` release.
- **Swift Package Index**: submit `https://github.com/vouch-protocol/vouch` once at
  swiftpackageindex.com/add-a-package so the package is discoverable.

## Already published

npm (`@vouch-protocol-official/sdk`, `/api-client`, `/core-wasm`) and PyPI
(`vouch-protocol`, `vouch-api-client`, `vouch-sdk`) are live. These workflows make
future releases a single tag push instead of a manual upload.
