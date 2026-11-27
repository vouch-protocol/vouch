// Runs after `next build` and adds the files the static export does not
// produce on its own:
//
//   1. Redirect pages for the old `.html` addresses listed in site.config.json,
//      so links and bookmarks to them land on the current page.
//   2. sitemap.xml, built from the pages that were actually exported.
//   3. robots.txt, pointing at that sitemap.
//
// Everything is derived from the export and from site.config.json, so there is
// no hand-kept copy of any of these files to fall out of date.
import { access, mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, '..', 'out');

const config = JSON.parse(await readFile(join(here, '..', 'site.config.json'), 'utf8'));
const siteUrl = String(config.siteUrl).replace(/\/+$/, '');
if (!/^https:\/\/[a-z0-9.-]+$/.test(siteUrl)) {
    throw new Error(`site.config.json siteUrl is not a plain https origin: ${config.siteUrl}`);
}

// Pages that are exported but are not part of the site's own navigation:
// the not-found page and the per-person certificate pages.
const SITEMAP_EXCLUDE = ['/404/', '/c/', '/i/'];

async function exists(path) {
    try {
        await access(path);
        return true;
    } catch {
        return false;
    }
}

async function walk(dir) {
    const found = [];
    for (const entry of await readdir(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
            if (entry.name === '_next') continue;
            found.push(...(await walk(full)));
        } else {
            found.push(full);
        }
    }
    return found;
}

function redirectPage(target) {
    const quoted = JSON.stringify(target);
    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="vouch-redirect" content="${target}">
<title>Vouch Protocol</title>
<link rel="canonical" href="${siteUrl}${target}">
<meta http-equiv="refresh" content="0; url=${target}">
<script>location.replace(${quoted} + location.search + location.hash);</script>
</head>
<body>
<p>This page has moved to <a href="${target}">${target}</a>.</p>
</body>
</html>
`;
}

// 1. Redirect pages.
const redirects = Object.entries(config.legacyRedirects ?? {});
for (const [from, to] of redirects) {
    if (!/^\/(?:[a-z0-9-]+\/)*[a-z0-9-]+\.html$/.test(from)) {
        throw new Error(`Redirect source must be an absolute .html path: ${from}`);
    }
    if (!/^\/(?:[a-z0-9-]+\/)+$/.test(to)) {
        throw new Error(`Redirect target must be an absolute path ending in a slash: ${to}`);
    }
    if (!(await exists(join(out, to, 'index.html')))) {
        throw new Error(`Redirect ${from} points at ${to}, which was not exported`);
    }
    const dest = join(out, from);
    if (await exists(dest)) {
        throw new Error(`Redirect ${from} would overwrite a page the build exported`);
    }
    await mkdir(dirname(dest), { recursive: true });
    await writeFile(dest, redirectPage(to));
}

// 2. Sitemap, from the exported pages.
const pages = (await walk(out))
    .filter((file) => file.endsWith(`${sep}index.html`) || file === join(out, 'index.html'))
    .map((file) => {
        const dir = relative(out, dirname(file)).split(sep).join('/');
        return dir === '' ? '/' : `/${dir}/`;
    })
    .filter((path) => !SITEMAP_EXCLUDE.some((prefix) => path.startsWith(prefix)))
    .sort();

if (!pages.includes('/')) {
    throw new Error('The export has no home page; refusing to write a sitemap');
}

const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${pages.map((path) => `  <url><loc>${siteUrl}${path}</loc></url>`).join('\n')}
</urlset>
`;
await writeFile(join(out, 'sitemap.xml'), sitemap);

// 3. robots.txt.
const robots = `# Vouch Protocol - robots.txt
# ${siteUrl}

User-agent: *
Allow: /

# Sitemap
Sitemap: ${siteUrl}/sitemap.xml

# Crawl-delay for politeness
Crawl-delay: 1
`;
await writeFile(join(out, 'robots.txt'), robots);

console.log(
    `Wrote ${redirects.length} redirect pages, a sitemap with ${pages.length} pages, and robots.txt for ${siteUrl}`,
);
