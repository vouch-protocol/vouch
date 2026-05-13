# Vouch Chat Widget

Drop-in React component that renders the Vouch website assistant. Pure
React 18+, no extra dependencies beyond what the parent site already
ships.

## Files

- `components/VouchChat.tsx` — the chat widget itself
- `components/CredentialCard.tsx` — pretty-prints a Vouch credential
- `components/styles.css` — base styling (uses CSS variables for theming)

## Use in the Next.js website

```tsx
'use client';

import { VouchChat } from '@/components/vouch-chat/VouchChat';
import '@/components/vouch-chat/styles.css';

export default function HelpPage() {
    return (
        <div style={{ height: '70vh' }}>
            <VouchChat apiBase={process.env.NEXT_PUBLIC_VOUCH_AGENT_URL ?? 'http://localhost:8000'} />
        </div>
    );
}
```

## Theming

Override CSS variables on the parent element to match your site:

```css
.vouch-chat {
    --vouch-accent: #2f1cd9;
    --vouch-surface: #ffffff;
    --vouch-border: #e2e2e8;
    --vouch-bubble-bg: #f5f5f9;
    --vouch-cred-bg: #fafaff;
}
```

Dark mode: flip the variables under a `[data-theme="dark"]` selector
or wrap with your existing theme provider.

## Embedded mode (iframe / mobile WebView)

Wrap the widget in a tiny page and serve it from the agent backend at
`/embed`. The mobile app's WebView points at that page.

```tsx
// pages/embed.tsx (kept inside the agent backend repo if you prefer)
export default function Embed() {
    return <VouchChat apiBase="" placeholder="Ask the Vouch agent..." />;
}
```

`apiBase=""` makes the widget call relative URLs (`/chat`), which is
correct when the page is served from the same host as the backend.

## Events

The widget streams Server-Sent Events from `POST /chat`:

- `event: meta` — `{ sources, credential? }` arrives first
- `event: token` — `{ text }` arrives many times as the LLM streams
- `event: error` — `{ error }` if the upstream call fails
- `event: done` — empty payload, signals the stream finished

No framework hooks are required; the implementation parses SSE manually
so it works in any React-compatible setup.

## Accessibility

- The input has `aria-label="Ask the Vouch assistant"`.
- The chat region uses semantic ordering (user above assistant).
- Color contrast: default palette meets WCAG AA on white and dark
  backgrounds. Override the CSS variables to match your site's tokens.
