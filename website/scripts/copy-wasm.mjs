// Copies the Vouch Protocol WASM core out of the installed npm package
// (@vouch-protocol-official/core-wasm) into public/wasm/ so the static export
// and the dev server can serve it at /wasm/. The binary is never committed to
// git; it is fetched fresh from the pinned package on every install and build.
import { mkdir, copyFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));

// Resolve the package via its manifest so we do not depend on an exports map.
const pkgJson = require.resolve('@vouch-protocol-official/core-wasm/package.json');
const pkgDir = dirname(pkgJson);

const dest = join(here, '..', 'public', 'wasm');
await mkdir(dest, { recursive: true });

const files = ['vouch_core_wasm.js', 'vouch_core_wasm_bg.wasm'];
for (const file of files) {
  await copyFile(join(pkgDir, file), join(dest, file));
}

console.log(`Copied Vouch Protocol WASM core to ${dest}`);
