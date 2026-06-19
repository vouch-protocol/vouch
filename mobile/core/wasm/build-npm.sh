#!/usr/bin/env bash
#
# Reproducible build + npm packaging for the Vouch Sonic WASM engine.
#
# wasm-pack regenerates pkg/package.json from Cargo.toml on every build, which
# overwrites the scoped npm name and publish metadata. This script rebuilds
# (web target) and then re-applies the npm publish metadata + README + LICENSE,
# so `cd pkg && npm publish` produces a correct, current package every time.
#
# Usage:
#   ./build-npm.sh [version]        # default version: 1.0.0
#
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

NPM_NAME="@vouch-protocol-official/sonic-wasm"
NPM_VERSION="${1:-1.0.0}"

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
  'Vouch Sonic Engine - inaudible spread-spectrum audio watermark embed/detect ' +
  '+ voice features (WASM, browser + Node.js)';
pj.homepage = 'https://vouch-protocol.com';
pj.repository = {
  type: 'git',
  url: 'https://github.com/vouch-protocol/vouch',
  directory: 'mobile/core/wasm',
};
pj.license = 'Apache-2.0';
pj.publishConfig = { access: 'public' };
const want = ['vouch_sonic_wasm_bg.wasm', 'vouch_sonic_wasm.js', 'vouch_sonic_wasm.d.ts',
              'vouch_sonic_wasm_bg.wasm.d.ts', 'README.md', 'LICENSE'];
pj.files = Array.from(new Set([...(pj.files || []), ...want]));
fs.writeFileSync(p, JSON.stringify(pj, null, 2) + '\n');
console.log(JSON.stringify({ name: pj.name, version: pj.version, license: pj.license, files: pj.files }, null, 2));
NODE

echo "==> copying LICENSE + README into pkg/"
cp ../../../LICENSE pkg/LICENSE
cp README.npm.md pkg/README.md

echo "==> pkg/ contents:"
ls -la pkg/
echo "==> done. To publish:  (cd $(pwd)/pkg && npm publish)"
