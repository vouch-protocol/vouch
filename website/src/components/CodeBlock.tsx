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
 * Code block with a clipboard-icon Copy button. The button copies the raw
 * `code` prop exactly (not the rendered text), so highlighters or line
 * numbers cannot pollute the clipboard. Icon flips to a checkmark for
 * ~1.6 seconds after a successful copy.
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
            {language && (
                <div className="absolute top-2 left-3 flex items-center gap-2 pointer-events-none">
                    <span className="font-mono uppercase text-[0.62rem] tracking-[0.18em] text-parchment/50">
                        {language}
                    </span>
                </div>
            )}
            <button
                type="button"
                onClick={copy}
                aria-label={copied ? 'Copied to clipboard' : 'Copy code to clipboard'}
                title={copied ? 'Copied' : 'Copy'}
                className="absolute top-2 right-2 z-10 p-1 text-burgundy hover:text-burgundy-dark focus:text-burgundy-dark focus:outline-none transition-colors bg-transparent border-0"
            >
                {copied ? (
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="w-4 h-4 text-emerald-success"
                        aria-hidden="true"
                    >
                        <path d="m4.5 12.75 6 6 9-13.5" />
                    </svg>
                ) : (
                    <svg
                        xmlns="http://www.w3.org/2000/svg"
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.6"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        className="w-4 h-4"
                        aria-hidden="true"
                    >
                        <rect x="9" y="9" width="11" height="11" rx="1.5" />
                        <path d="M5 15V5a1.5 1.5 0 0 1 1.5-1.5H15" />
                    </svg>
                )}
            </button>
            <pre className={`text-sm ${className} ${language ? 'pt-7' : ''}`}>
                <code>{code}</code>
            </pre>
        </div>
    );
}
