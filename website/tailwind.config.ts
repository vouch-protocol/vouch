import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // Classicism: Burgundy palette
        'parchment': '#FAF7EE',
        'parchment-warm': '#F2EBD9',
        'parchment-deep': '#EFE9D5',
        'ink': '#0F172A',
        'ink-soft': '#334155',
        'ink-faint': '#64748B',
        'burgundy': '#7C2D3A',
        'burgundy-dark': '#5C1F2C',
        'burgundy-light': '#9B4051',
        'rule': '#D9CFB6',
        'rule-light': '#E8DFC9',
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
