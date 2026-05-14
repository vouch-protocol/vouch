'use client';

import { useEffect, useState } from 'react';
import AgentChat from './AgentChat';

const RAW_API_BASE =
    (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_VOUCH_AGENT_URL) || '';

/**
 * True when no public backend has been configured for this build.
 * In that case we render the panel in "coming soon" mode rather than
 * letting the chat widget attempt a fetch to localhost (which would
 * trigger Chrome's Private Network Access prompt for every visitor and
 * then fail with "Failed to fetch").
 */
const API_NOT_CONFIGURED =
    !RAW_API_BASE || /^https?:\/\/(localhost|127\.0\.0\.1)/i.test(RAW_API_BASE);

const API_BASE = API_NOT_CONFIGURED ? '' : RAW_API_BASE;

type Size = 'panel' | 'full';

export default function AgentPanel() {
    const [open, setOpen] = useState(false);
    const [size, setSize] = useState<Size>('panel');

    useEffect(() => {
        const onOpen = () => setOpen(true);
        const onKey = (e: KeyboardEvent) => {
            if (e.key === 'Escape') setOpen(false);
        };
        window.addEventListener('vouch-agent:open', onOpen as EventListener);
        window.addEventListener('keydown', onKey);
        return () => {
            window.removeEventListener('vouch-agent:open', onOpen as EventListener);
            window.removeEventListener('keydown', onKey);
        };
    }, []);

    return (
        <>
            {/* Floating "open" affordance — a discreet bordered tab, classicism, not a SaaS bubble. */}
            {!open && (
                <button
                    type="button"
                    onClick={() => setOpen(true)}
                    aria-label="Open Vouch assistant"
                    title="Ask the Vouch assistant"
                    className="hidden md:inline-flex fixed bottom-8 right-8 z-30 items-center gap-2 bg-parchment text-ink border border-ink px-3.5 py-2 font-mono uppercase text-[0.7rem] tracking-[0.16em] shadow-sm hover:bg-ink hover:text-parchment transition-colors"
                >
                    <span aria-hidden="true" className="inline-block w-1.5 h-1.5 rounded-full bg-burgundy" />
                    Ask the assistant
                </button>
            )}

            {/* Backdrop (only in panel mode, only on small screens we make it dismissable by tap) */}
            {open && (
                <div
                    className="fixed inset-0 z-40 bg-ink/30 backdrop-blur-sm md:hidden"
                    onClick={() => setOpen(false)}
                    aria-hidden="true"
                />
            )}

            {/* Sliding panel */}
            {open && (
                <aside
                    role="dialog"
                    aria-label="Vouch assistant"
                    className={`fixed z-50 bg-parchment border border-rule shadow-2xl flex flex-col transition-all
                        ${size === 'full'
                            ? 'inset-4 md:inset-10'
                            : 'inset-0 md:inset-y-4 md:right-4 md:left-auto md:w-[480px]'
                        }`}
                >
                    {/* Header: mirrors the site wordmark — serif name + mono small-caps tagline. */}
                    <div className="flex items-center justify-between px-5 py-4 border-b border-rule bg-parchment-warm">
                        <div className="flex items-baseline gap-3">
                            <span className="font-serif font-semibold text-[1.05rem] tracking-tight text-ink">Vouch Assistant</span>
                            <span className="hidden sm:inline font-mono uppercase text-[0.62rem] tracking-[0.18em] text-burgundy">Signs every action</span>
                        </div>
                        <div className="flex items-center gap-1">
                            <button
                                type="button"
                                onClick={() => setSize(size === 'full' ? 'panel' : 'full')}
                                aria-label={size === 'full' ? 'Shrink to side panel' : 'Expand to full screen'}
                                title={size === 'full' ? 'Shrink' : 'Expand'}
                                className="w-8 h-8 inline-flex items-center justify-center text-ink-soft hover:text-burgundy transition-colors"
                            >
                                {size === 'full' ? (
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M4 14h6v6M20 10h-6V4M14 10l7-7M3 21l7-7" />
                                    </svg>
                                ) : (
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                                        <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" />
                                    </svg>
                                )}
                            </button>
                            <button
                                type="button"
                                onClick={() => setOpen(false)}
                                aria-label="Close assistant"
                                title="Close"
                                className="w-8 h-8 inline-flex items-center justify-center text-ink-soft hover:text-burgundy transition-colors"
                            >
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
                                    <path d="M18 6 6 18M6 6l12 12" />
                                </svg>
                            </button>
                        </div>
                    </div>

                    <div className="flex-1 min-h-0">
                        {API_NOT_CONFIGURED ? <ComingSoonBody /> : <AgentChat apiBase={API_BASE} />}
                    </div>
                </aside>
            )}
        </>
    );
}

/**
 * Rendered when no hosted backend has been configured. We deliberately do not
 * make any network call, so visitors do not see Chrome's Private Network Access
 * prompt or a "Failed to fetch" error. Instead we explain the situation and
 * point at the self-host guide.
 */
function ComingSoonBody() {
    return (
        <div className="h-full flex flex-col">
            <div className="flex-1 overflow-y-auto px-5 py-6 text-ink-soft">
                <p className="font-serif text-[1.05rem] leading-relaxed mb-4 text-ink">
                    The hosted Vouch Assistant is not live yet.
                </p>
                <p className="text-[0.95rem] leading-relaxed mb-5">
                    We are rolling out the public chat endpoint after the protocol's W3C Credentials
                    Community Group incubation lands. Until then, the assistant runs locally against
                    your own LLM key.
                </p>

                <div className="border-l-2 border-burgundy pl-4 py-2 mb-6">
                    <div className="eyebrow mb-2">Run it locally</div>
                    <p className="text-[0.9rem] leading-relaxed">
                        The full backend, chat widget, and dev sidecar are open source under
                        {' '}<a href="https://github.com/vouch-protocol/vouch/tree/main/website-agent" target="_blank" rel="noopener noreferrer" className="text-burgundy underline decoration-1 underline-offset-2 hover:text-burgundy-dark">website-agent/</a>.
                        Three commands: start the dev sidecar, start the FastAPI backend with your
                        Anthropic / OpenAI / Gemini key, open the standalone Next.js harness.
                    </p>
                </div>

                <div className="space-y-3 text-[0.9rem]">
                    <p>
                        Meanwhile, the same canonical knowledge is available through four other
                        surfaces that run on{' '}<em>your</em>{' '}AI tool subscription, not ours:
                    </p>
                    <ul className="list-disc pl-5 space-y-2">
                        <li>
                            <strong>Claude Skill</strong>: drop the
                            {' '}<a href="https://github.com/vouch-protocol/vouch/tree/main/claude-skill" target="_blank" rel="noopener noreferrer" className="text-burgundy underline decoration-1 underline-offset-2 hover:text-burgundy-dark">claude-skill/</a>{' '}
                            folder into <code className="font-mono text-[0.8rem]">~/.claude/skills/</code>.
                        </li>
                        <li>
                            <strong>OpenAI Custom GPT</strong>: paste the configuration from
                            {' '}<a href="https://github.com/vouch-protocol/vouch/tree/main/openai-gpt" target="_blank" rel="noopener noreferrer" className="text-burgundy underline decoration-1 underline-offset-2 hover:text-burgundy-dark">openai-gpt/</a>{' '}
                            into ChatGPT's GPT builder.
                        </li>
                        <li>
                            <strong>Gemini Gem</strong>: paste the configuration from
                            {' '}<a href="https://github.com/vouch-protocol/vouch/tree/main/gemini-gem" target="_blank" rel="noopener noreferrer" className="text-burgundy underline decoration-1 underline-offset-2 hover:text-burgundy-dark">gemini-gem/</a>{' '}
                            into Gemini's Gem creator.
                        </li>
                    </ul>
                </div>

                <p className="text-[0.85rem] text-ink-faint leading-relaxed mt-6">
                    Or read the{' '}<a href="/help/" className="underline decoration-1 underline-offset-2 hover:text-burgundy">guides</a>,{' '}
                    <a href="/faq/" className="underline decoration-1 underline-offset-2 hover:text-burgundy">FAQ</a>, or{' '}
                    <a href="https://github.com/vouch-protocol/vouch" target="_blank" rel="noopener noreferrer" className="underline decoration-1 underline-offset-2 hover:text-burgundy">source on GitHub</a>{' '}
                    directly.
                </p>
            </div>
        </div>
    );
}
