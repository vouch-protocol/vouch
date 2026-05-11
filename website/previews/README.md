# Vouch Protocol Website - Theme Previews

Three standalone HTML mockups, one per theme direction. Each shows the same content (nav + hero + feature grid + FAQ snippet + footer) in its theme's styling so you're comparing aesthetic, not copy.

## How to view

Each file is self-contained (web fonts load from Google Fonts CDN). Pick any one:

**Option 1: Open directly in browser**

```
file:///home/rampy/vouch-website/previews/theme-1-classicism.html
file:///home/rampy/vouch-website/previews/theme-2-blueprint.html
file:///home/rampy/vouch-website/previews/theme-3-vault.html
```

Or from Windows Explorer, navigate to `\\wsl$\Ubuntu\home\rampy\vouch-website\previews\` and double-click each file.

**Option 2: Local server (recommended for consistent rendering)**

```
cd /home/rampy/vouch-website/previews
python3 -m http.server 8765
```

Then open in browser:

- http://localhost:8765/theme-1-classicism.html
- http://localhost:8765/theme-2-blueprint.html
- http://localhost:8765/theme-3-vault.html

## What each theme demonstrates

### Theme 1 - Standards Document Classicism (`theme-1-classicism.html`)

- Cream parchment background, navy ink, burgundy accent
- Source Serif 4 + JetBrains Mono
- Drop cap on the lede paragraph
- Marginalia sidebar in the FAQ section
- Small-caps eyebrows, double-rule footer divider
- No accordion in the FAQ, every Q&A always visible as numbered entries
- Vibe: "this is a finely typeset specification"

### Theme 2 - Engineering Blueprint (`theme-2-blueprint.html`)

- Dark navy with faint blueprint grid background
- Blueprint cyan accent, drafting orange for emphasis
- Space Grotesk + IBM Plex Mono throughout
- Schematic strip on the hero showing the four-layer protocol stack
- Callout numbers `[01]`, `[02]`, etc. on feature cards
- Drafting-style metadata tables, dashed dividers
- Vibe: "drafted by an engineer who treats agent identity like network engineering"

### Theme 3 - Sovereign Brutalism (`theme-3-vault.html`)

- Graphite background, brass-gold accent, off-white text
- Fraunces (display serif) + Inter + JetBrains Mono
- Thick double-borders on panels (no glass blur)
- Decorative seal-glyph divider between sections
- Heavy section borders with floating audience-tag labels
- Working accordion behavior in the FAQ (click to expand)
- Vibe: "sovereign protocol infrastructure, not a SaaS dashboard"

## After you pick

Once you tell me which theme, I'll:

1. Apply the chosen theme's design tokens (palette, typography, layout signatures) to the Next.js project I started in `vouch-website/src/`
2. Throw out the generic dark+indigo styling I started with
3. Resume writing the FAQ content (single page, audience-tagged sections per your earlier answer)
4. Build the Help/Guides page next
5. Set up the static export so it deploys to `vouch-protocol/docs/` via GH Pages without infra changes

If you want hybrid (e.g., "Theme 3 palette but Theme 1's serif headings"), just say so and I'll mix.
