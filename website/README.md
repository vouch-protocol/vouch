# Vouch Protocol Website

The marketing and documentation site for [Vouch Protocol](https://vouch-protocol.com).

Lives in `vouch-protocol/website/`. Next.js 14 (App Router) + Tailwind + TypeScript. Built as a static export and deployed automatically to GitHub Pages by `.github/workflows/deploy-website.yml` on every push to `main` that touches `website/**`. CNAME `vouch-protocol.com` is served from `vouch-protocol/docs/`, where the workflow writes the built output.

## Stack

- Next.js 14.2 with App Router, static export (`output: 'export'`)
- React 18
- Tailwind CSS 3
- TypeScript 5
- Self-hosted Google Fonts (Source Serif 4, JetBrains Mono) via CDN
- Google Analytics (same property as the legacy site, `G-JHPT5HRW2F`)

## Theme

**Standards-Document Classicism** with the **Burgundy** palette:

- Parchment background `#FAF7EE`
- Navy ink `#0F172A`
- Burgundy accent `#7C2D3A`
- Source Serif 4 for body and headings, JetBrains Mono for code, eyebrows, and small caps

Layout signatures: drop caps on lede paragraphs, marginalia sidebars on FAQ and Help pages, classical numbered Q&A entries (no accordion), double-rule footer divider, small-caps section eyebrows.

## Project layout

```
src/
├── app/
│  ├── layout.tsx        Root layout: nav, footer, fonts, GA
│  ├── page.tsx         Landing page
│  ├── globals.css       Tailwind + classicism utilities
│  ├── faq/
│  │  ├── page.tsx       FAQ hero + container
│  │  ├── FAQClient.tsx    Search + marginalia + Q&A renderer
│  │  └── faq-data.ts     All Q&A content (single source of truth)
│  ├── help/
│  │  ├── page.tsx       Help hero + container
│  │  ├── HelpClient.tsx    Search + marginalia + article renderer
│  │  └── help-data.ts     All long-form guide content
│  └── support/
│    └── page.tsx       Channels, checklist, quick links
├── components/
│  ├── Nav.tsx         Top nav with mobile menu
│  └── Footer.tsx        Five-column footer with double-rule top
public/
└── assets/
  ├── vouch-logo-icon.jpg   Favicon
  ├── vouch-logo-full.png   OG image
  └── vouch_icon.svg      Scalable logo
previews/
├── theme-1-classicism.html   Standalone theme 1 preview
├── theme-2-blueprint.html    Standalone theme 2 preview
├── theme-3-vault.html      Standalone theme 3 preview
├── theme-1-palette-variations.html Palette switcher for theme 1
└── README.md
```

## Development

```bash
npm install
npm run dev
```

Then open <http://localhost:3000>.

## Build

```bash
npm run build
```

This produces a static export in `out/`. With `output: 'export'` and `trailingSlash: true` set in `next.config.mjs`, every route renders to a directory with an `index.html`, suitable for GitHub Pages.

## Deploy (GitHub Pages, no infra change)

The site at `vouch-protocol.com` is served from `vouch-protocol/docs/` via GitHub Pages. To publish:

```bash
npm run export-to-docs
```

That builds and copies the static output to `../vouch-protocol/docs/`. Then commit and push from the `vouch-protocol` repo.

**The export will overwrite** existing files in `docs/` (the legacy `index.html`, `demo.html`, `cps.html`, etc.). Before publishing for the first time, decide whether to:

- A. Archive the legacy pages to `docs/legacy/` first, then export
- B. Adapt the Next.js export to write only specific routes (custom build script)
- C. Move the legacy pages into the Next.js project as additional routes

The `docs/blog/` directory is on a separate CNAME (`blog.vouch-protocol.com`) and is untouched by this export.

## Editing content

**FAQ entries:** edit `src/app/faq/faq-data.ts`. Each entry has `q`, `a` (markdown-lite: `[text](url)`, backtick code, double-asterisk bold, double-newline paragraphs, triple-backtick code blocks), optional `helpLinks`, optional `meta`.

**Help articles:** edit `src/app/help/help-data.ts`. Each article has `id`, `title`, `summary`, `body` (richer markdown-lite: same inline syntax plus `##` headings, `|` tables, `-` bullets, `1.` ordered lists).

**Landing page:** `src/app/page.tsx`.

**Support page:** `src/app/support/page.tsx`.

**Nav links and footer link groups:** `src/components/Nav.tsx`, `src/components/Footer.tsx`.

**Brand colors and typography:** `tailwind.config.ts` and `src/app/globals.css`.

## Why these choices

- **Classicism**: signals "serious open standard specification, not a SaaS product page" to standards reviewers.
- **Burgundy**: most academic-traditional of the six classicism palettes considered.
- **Source Serif 4 + JetBrains Mono**: serif body anchors the standards-document feel; mono for eyebrows, code, and metadata gives technical precision without breaking the typographic register.
- **Static export to GH Pages**: no infra change, no Vercel migration, no DNS change. The site builds locally and ships via the existing pages workflow.
- **All content in `*-data.ts` files**: keeps the renderers small, makes the content auditable (every claim is grep-able), and lets future contributors edit copy without touching React.
