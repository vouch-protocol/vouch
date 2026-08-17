// Copies the repository-root funding.json manifest into public/ so the static
// export and the dev server serve it at /funding.json. The repo root is the
// single source of truth; the copy is never committed to git, so the published
// manifest cannot drift from the one in the repository.
//
// The manifest is parsed before it is written so a malformed edit fails the
// build here rather than on the directory crawler that reads the live URL.
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

const source = join(here, '..', '..', 'funding.json');
const dest = join(here, '..', 'public', 'funding.json');

const raw = await readFile(source, 'utf8');
JSON.parse(raw);
await writeFile(dest, raw);

console.log(`Copied the Vouch Protocol funding manifest to ${dest}`);
