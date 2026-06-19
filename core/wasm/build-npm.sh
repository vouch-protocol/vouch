#!/usr/bin/env bash
#
# Reproducible build + npm packaging for the Vouch Protocol core WASM engine.
#
# wasm-pack regenerates pkg/package.json from Cargo.toml on every build, which
# overwrites the scoped npm name and publish metadata. This script rebuilds
# (web target, runs in browser + Node) and re-applies the npm publish metadata +
# README + LICENSE, so `cd pkg && npm publish` produces a correct package.
#
# Usage:  ./build-npm.sh [version]      # default version: 0.1.0
#
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

NPM_NAME="@vouch-protocol-official/core-wasm"
NPM_VERSION="${1:-0.1.0}"

echo "==> wasm-pack build (target=web, release)"
wasm-pack build --target web --release

echo "==> rewriting pkg/package.json -> ${NPM_NAME}@${NPM_VERSION}"
node - "$NPM_NAME" "$NPM_VERSION" <<'NODE'
const fs = require('fs');
const [name, version] = process.argv.slice(2);
const p = 'pkg/package.json';
const pj = JSON.parse(fs.readFileSync(p, 'utf8'));
pj.name = name;
pj.version = version;
pj.description =
  'Vouch Protocol canonical core (WASM): JCS canonicalization, Ed25519, ' +
  'did:key/multikey, Data Integrity (eddsa-jcs-2022), credentials, delegation, ' +
  'dual-proof ML-DSA-44, and BitstringStatusList revocation. One byte-exact ' +
  'Rust implementation shared across every Vouch SDK.';
pj.homepage = 'https://vouch-protocol.com';
pj.repository = {
  type: 'git',
  url: 'https://github.com/vouch-protocol/vouch',
  directory: 'core/wasm',
};
pj.license = 'Apache-2.0';
pj.publishConfig = { access: 'public' };
const want = ['vouch_core_wasm_bg.wasm', 'vouch_core_wasm.js', 'vouch_core_wasm.d.ts',
              'vouch_core_wasm_bg.wasm.d.ts', 'README.md', 'LICENSE'];
pj.files = Array.from(new Set([...(pj.files || []), ...want]));
fs.writeFileSync(p, JSON.stringify(pj, null, 2) + '\n');
console.log(JSON.stringify({ name: pj.name, version: pj.version, license: pj.license, files: pj.files }, null, 2));
NODE

echo "==> copying LICENSE + README into pkg/"
cp ../../LICENSE pkg/LICENSE 2>/dev/null || echo "(no top-level LICENSE found; skipping)"
cp README.npm.md pkg/README.md

echo "==> pkg/ contents:"
ls -la pkg/
echo "==> done. To publish:  (cd $(pwd)/pkg && npm publish)"
