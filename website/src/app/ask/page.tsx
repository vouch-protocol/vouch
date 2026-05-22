'use client';

/**
 * /ask — direct-link entry point to the Vouch Assistant.
 *
 * Linkable from anywhere as `vouch-protocol.com/ask` (no need to tell readers
 * to "click the bottom-right tab"). Renders a full-screen chat experience
 * with the same backend the side-panel widget uses.
 *
 * If the backend has not been deployed for this build (no
 * NEXT_PUBLIC_VOUCH_AGENT_URL), the AgentChat surface degrades gracefully
 * via its existing API_NOT_CONFIGURED handling — no Chrome PNA prompt,
 * just a "coming soon" message.
 */

import { useEffect } from 'react';
import AgentChat from '@/components/AgentChat';

const RAW_API_BASE =
    (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_VOUCH_AGENT_URL) || '';

const API_NOT_CONFIGURED =
    !RAW_API_BASE || /^https?:\/\/(localhost|127\.0\.0\.1)/i.test(RAW_API_BASE);

const API_BASE = API_NOT_CONFIGURED ? '' : RAW_API_BASE;

export default function AskPage() {
    useEffect(() => {
        document.title = 'Ask the Vouch Assistant';
    }, []);

    return (
        <main className="min-h-screen bg-parchment text-ink flex flex-col">
            <header className="px-6 py-5 border-b border-rule bg-parchment-warm flex items-baseline justify-between">
                <div className="flex items-baseline gap-3">
                    <a href="/" className="font-serif font-semibold text-[1.15rem] tracking-tight text-ink no-underline hover:text-burgundy transition-colors">
                        Vouch Assistant
                    </a>
                    <span className="hidden sm:inline font-mono uppercase text-[0.65rem] tracking-[0.18em] text-burgundy">
                        Signs every action
                    </span>
                </div>
                <a
                    href="/"
                    className="font-mono uppercase text-[0.7rem] tracking-[0.16em] text-ink-soft hover:text-ink no-underline"
                >
                    ← vouch-protocol.com
                </a>
            </header>

            <div className="flex-1 flex flex-col">
                {API_NOT_CONFIGURED ? (
                    <ComingSoon />
                ) : (
                    <AgentChat apiBase={API_BASE} />
                )}
            </div>

            <footer className="px-6 py-4 border-t border-rule-light text-center text-[0.78rem] text-ink-faint space-y-1">
                <div>
                    Replies are themselves Vouch-signed. Email{' '}
                    <a className="text-burgundy" href="mailto:ask@vouch-protocol.com">ask@vouch-protocol.com</a>
                    {' '}for the same answers by mail.
                </div>
                <div className="text-[0.7rem]">
                    We log conversations to improve answers. IPs are truncated, never stored at full precision. See{' '}
                    <a className="text-ink-soft border-b border-ink-faint" href="/privacy">privacy</a>.
                </div>
            </footer>
        </main>
    );
}

function ComingSoon() {
    return (
        <div className="flex-1 flex items-center justify-center px-6 py-16">
            <div className="max-w-prose text-center">
                <p className="font-mono uppercase text-[0.72rem] tracking-[0.2em] text-burgundy mb-4">
                    Coming online soon
                </p>
                <h1 className="font-serif text-[1.8rem] leading-tight mb-4">
                    The Vouch Assistant is being deployed.
                </h1>
                <p className="text-ink-soft mb-6 leading-relaxed">
                    In the meantime, try one of these working channels:
                </p>
                <ul className="font-mono uppercase text-[0.72rem] tracking-[0.14em] space-y-3 text-ink-soft">
                    <li>
                        <a className="border-b border-burgundy text-burgundy no-underline" href="mailto:ask@vouch-protocol.com">
                            ask@vouch-protocol.com
                        </a>
                        <span className="block normal-case tracking-normal text-[0.85rem] text-ink-faint mt-1 font-serif italic">
                            replies within a minute, Vouch-signed
                        </span>
                    </li>
                    <li>
                        <a className="border-b border-ink text-ink no-underline" href="https://github.com/vouch-protocol/vouch">
                            github.com/vouch-protocol/vouch
                        </a>
                        <span className="block normal-case tracking-normal text-[0.85rem] text-ink-faint mt-1 font-serif italic">
                            source + issues
                        </span>
                    </li>
                    <li>
                        <a className="border-b border-ink text-ink no-underline" href="/docs">
                            vouch-protocol.com/docs
                        </a>
                        <span className="block normal-case tracking-normal text-[0.85rem] text-ink-faint mt-1 font-serif italic">
                            self-serve reference
                        </span>
                    </li>
                </ul>
            </div>
        </div>
    );
}
