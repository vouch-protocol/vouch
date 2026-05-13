import type { Config } from "tailwindcss";

/**
 * Helper to consume an `R G B` CSS variable as a Tailwind color.
 * Lets utilities like `bg-parchment/20` keep working via the / alpha syntax.
 */
const v = (token: string) => `rgb(var(--color-${token}) / <alpha-value>)`;

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        'parchment': v('parchment'),
        'parchment-warm': v('parchment-warm'),
        'parchment-deep': v('parchment-deep'),
        'ink': v('ink'),
        'ink-soft': v('ink-soft'),
        'ink-faint': v('ink-faint'),
        'burgundy': v('burgundy'),
        'burgundy-dark': v('burgundy-dark'),
        'burgundy-light': v('burgundy-light'),
        'rule': v('rule'),
        'rule-light': v('rule-light'),
      },
      fontFamily: {
        serif: ['"Source Serif 4"', 'Source Serif Pro', 'Georgia', 'serif'],
        sans: ['"Source Serif 4"', 'Source Serif Pro', 'Georgia', 'serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'monospace'],
        display: ['"Source Serif 4"', 'Source Serif Pro', 'Georgia', 'serif'],
      },
      fontSize: {
        // Tighter scale for serif body
        'eyebrow': ['0.7rem', { lineHeight: '1', letterSpacing: '0.18em' }],
        'eyebrow-tight': ['0.7rem', { lineHeight: '1', letterSpacing: '0.14em' }],
        'small-caps': ['0.65rem', { lineHeight: '1', letterSpacing: '0.18em' }],
      },
      borderWidth: {
        '3': '3px',
      },
      maxWidth: {
        'prose-narrow': '620px',
        'prose': '680px',
        'prose-wide': '760px',
      },
      letterSpacing: {
        'widest-2': '0.22em',
        'wider-2': '0.16em',
      },
    },
  },
  plugins: [],
};

export default config;
