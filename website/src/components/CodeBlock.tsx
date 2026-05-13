'use client';

import { useState } from 'react';

type Props = {
    /** Raw code text to render. Whitespace preserved. */
    code: string;
    /** Optional language label shown top-left. */
    language?: string;
    /** Override Tailwind classes on the <pre>. */
    className?: string;
};

/**
 * Code block with a Copy button. The button copies the raw `code` prop
 * exactly (not the rendered text), so highlighters / line numbers cannot
 * pollute the clipboard.
 */
export default function CodeBlock({ code, language, className = '' }: Props) {
    const [copied, setCopied] = useState(false);

    async function copy() {
        try {
            await navigator.clipboard.writeText(code);
            setCopied(true);
            setTimeout(() => setCopied(false), 1600);
        } catch {
            /* clipboard unavailable */
        }
    }

    return (
        <div className="relative group my-4">
            {(language || true) && (
                <div className="absolute top-2 left-3 flex items-center gap-2 pointer-events-none">
                    {language && (
                        <span className="font-mono uppercase text-[0.62rem] tracking-[0.18em] text-parchment/50">
                            {language}
                        </span>
                    )}
                </div>
            )}
            <button
                type="button"
                onClick={copy}
                aria-label={copied ? 'Copied' : 'Copy code'}
                className="absolute top-1.5 right-2 z-10 px-2 py-1 text-[0.7rem] font-mono uppercase tracking-wider border border-parchment/30 text-parchment/80 hover:text-parchment hover:border-parchment/60 transition-colors bg-transparent opacity-70 group-hover:opacity-100"
            >
                {copied ? '✓ Copied' : 'Copy'}
            </button>
            <pre className={`text-sm ${className} ${language ? 'pt-7' : ''}`}>
                <code>{code}</code>
            </pre>
        </div>
    );
}
