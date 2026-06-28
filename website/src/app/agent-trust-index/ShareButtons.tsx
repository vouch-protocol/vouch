'use client';

import { useState } from 'react';

export default function ShareButtons({ text, url }: { text: string; url: string }) {
    const [copied, setCopied] = useState(false);
    const enc = encodeURIComponent;
    const x = `https://x.com/intent/tweet?text=${enc(text)}&url=${enc(url)}`;
    const linkedin = `https://www.linkedin.com/sharing/share-offsite/?url=${enc(url)}`;

    async function copy() {
        try {
            await navigator.clipboard.writeText(url);
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
        } catch {
            // Clipboard blocked; the share links still work.
        }
    }

    const cls =
        'font-mono uppercase text-[0.7rem] tracking-[0.14em] text-ink-soft border-b border-transparent hover:text-burgundy hover:border-burgundy no-underline transition-colors';

    return (
        <div className="flex flex-wrap items-center gap-5">
            <span className="font-mono uppercase text-[0.62rem] tracking-[0.14em] text-ink-faint">
                Share this
            </span>
            <a className={cls} href={x} target="_blank" rel="noopener noreferrer">
                X
            </a>
            <a className={cls} href={linkedin} target="_blank" rel="noopener noreferrer">
                LinkedIn
            </a>
            <button type="button" onClick={copy} className={cls}>
                {copied ? 'Copied' : 'Copy link'}
            </button>
        </div>
    );
}
