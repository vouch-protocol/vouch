// Checks a published site directory (docs/ by default) and fails when it holds
// an HTML page that is not on the current build.
//
// Every .html file must be one of:
//   - a page from the current Next.js export (its stylesheets all exist),
//   - a redirect page written by scripts/postbuild.mjs (its target exists),
//   - a self-styled certificate page under c/ or i/.
//
// Anything else is a leftover: a hand-written page from an earlier design, or
// a page from an older build whose route no longer exists. Both keep serving an
// outdated look at a working address, so the deploy stops here instead.
//
// Usage: node scripts/check-pages.mjs [site-directory]
import { access, readFile, readdir } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const site = resolve(process.argv[2] ?? join(here, '..', '..', 'docs'));

// Certificate pages are generated one per person with their own embedded
// styles and are not part of the Next.js build.
const SELF_STYLED = ['c/', 'i/'];

async function exists(path) {
    try {
        await access(path);
        return true;
    } catch {
        return false;
    }
}

async function htmlFiles(dir) {
    const found = [];
    for (const entry of await readdir(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
            if (entry.name === '_next' || entry.name === 'node_modules') continue;
            found.push(...(await htmlFiles(full)));
        } else if (entry.name.endsWith('.html')) {
            found.push(full);
        }
    }
    return found;
}

const problems = [];
let built = 0;
let redirected = 0;
let selfStyled = 0;

for (const file of await htmlFiles(site)) {
    const path = relative(site, file).split(sep).join('/');
    const html = await readFile(file, 'utf8');

    const redirect = html.match(/<meta name="vouch-redirect" content="([^"]+)">/);
    if (redirect) {
        if (await exists(join(site, redirect[1], 'index.html'))) {
            redirected += 1;
        } else {
            problems.push(`${path}: redirects to ${redirect[1]}, which does not exist`);
        }
        continue;
    }

    const stylesheets = [...new Set(html.match(/\/_next\/static\/css\/[a-f0-9]+\.css/g) ?? [])];
    if (stylesheets.length > 0) {
        const missing = [];
        for (const sheet of stylesheets) {
            if (!(await exists(join(site, sheet)))) missing.push(sheet);
        }
        if (missing.length === 0) {
            built += 1;
        } else {
            problems.push(`${path}: from an older build (missing ${missing.join(', ')})`);
        }
        continue;
    }

    if (SELF_STYLED.some((prefix) => path.startsWith(prefix))) {
        selfStyled += 1;
        continue;
    }

    problems.push(`${path}: not produced by the site build`);
}

if (problems.length > 0) {
    console.error(`${problems.length} page(s) in ${site} are not on the current build:`);
    for (const problem of problems) console.error(`  ${problem}`);
    console.error(
        'Move the page into website/src/app, add a redirect for it in website/site.config.json, or delete the file.',
    );
    process.exit(1);
}

console.log(
    `All pages in ${site} are current: ${built} built, ${redirected} redirects, ${selfStyled} certificate pages.`,
);
