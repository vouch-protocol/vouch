'use client';

import { useEffect, useRef, useState } from 'react';

type Source = { source: string; score: number };
type Credential = Record<string, unknown> & {
    id?: string;
    issuer?: string;
    credentialSubject?: { intent?: Record<string, unknown> };
    proof?: { cryptosuite?: string; verificationMethod?: string; proofValue?: string };
};
type Message = {
    role: 'user' | 'assistant';
    text: string;
    sources?: Source[];
    credential?: Credential;
};

type Props = {
    apiBase: string;
    initialPrompt?: string;
};

type Part = { type: 'text' | 'code'; content: string; language?: string };

// Languages we'll auto-detect for unfenced or partially-fenced code.
const KNOWN_LANGS = new Set([
    'python', 'py', 'javascript', 'js', 'typescript', 'ts', 'jsx', 'tsx',
    'go', 'golang', 'rust', 'rs', 'java', 'kotlin', 'swift', 'c', 'cpp', 'csharp',
    'bash', 'sh', 'shell', 'zsh', 'fish', 'powershell',
    'json', 'yaml', 'yml', 'toml', 'xml', 'html', 'css', 'scss',
    'sql', 'graphql', 'dockerfile', 'makefile', 'ruby', 'rb', 'php',
]);

// Tokens that strongly suggest a line is code, not prose.
const CODE_INDICATORS = [
    /^(\s*)(import|from|def|class|return|elif|else:|try:|except|finally:|async\s|await\s)/,
    /^(\s*)(const|let|var|function|interface|type\s+\w+\s*=)/,
    /^(\s*)(public|private|protected|static|void|int|string|bool|long|float)\s/,
    /^(\s*)(#include|using\s+namespace|namespace\s|template<)/,
    /^(\s*)\w+\s*=\s*[A-Z][\w.]+\(/,                  // signer = Signer.generate(...)
    /^(\s*)[a-zA-Z_][\w.]*\([\w"',\s.={}\[\]]+\)\s*$/, // bare function call line
    /^(\s*)(#|\/\/)\s/,                                // line comment
    /^\s{2,}["']?\w+["']?:\s/,                         // indented key: value (dict / JSON)
    /^\s*[{}[\]],?\s*$/,                               // bracket-only line
];

function looksLikeCode(text: string): boolean {
    // Need 3+ non-empty lines, with the majority looking code-y.
    const lines = text.split('\n').map((l) => l.trimEnd());
    const nonEmpty = lines.filter((l) => l.trim() !== '');
    if (nonEmpty.length < 3) return false;
    let hits = 0;
    for (const line of nonEmpty) {
        if (CODE_INDICATORS.some((re) => re.test(line))) hits++;
    }
    return hits >= Math.max(3, Math.floor(nonEmpty.length / 2));
}

/**
 * Walk-based parser that tolerates Gemini's common mistakes:
 *  - opening fence without trailing newline
 *  - missing closing fence (treated as code until end of message)
 *  - adjacent fences without separator
 *  - duplicated language tag appearing as the first content line of a fence
 *  - unfenced code prose immediately after a real code block
 */
function renderMessageBody(text: string): Part[] {
    const parts: Part[] = [];
    let i = 0;

    const flushText = (raw: string, sawCodeBefore: boolean) => {
        if (!raw) return;
        // If the previous part was a real code block AND this prose looks like code,
        // promote it to a code block (this is the Gemini-"forgot-to-fence" case).
        if (sawCodeBefore && looksLikeCode(raw)) {
            // Strip a duplicated language identifier as the first line.
            const lines = raw.split('\n');
            let lang: string | undefined;
            if (lines.length > 0 && KNOWN_LANGS.has(lines[0].trim().toLowerCase())) {
                lang = lines[0].trim().toLowerCase();
                lines.shift();
            }
            parts.push({ type: 'code', language: lang, content: lines.join('\n').replace(/^\n+|\n+$/g, '') });
            return;
        }
        // Otherwise keep as prose, but still strip a stray standalone language line
        // at the top (Gemini sometimes echoes "python" before continuing in prose).
        const lines = raw.split('\n');
        if (lines.length > 1 && KNOWN_LANGS.has(lines[0].trim().toLowerCase())) {
            lines.shift();
        }
        parts.push({ type: 'text', content: lines.join('\n') });
    };

    let textBuf = '';
    let lastWasCode = false;

    while (i < text.length) {
        if (text.startsWith('```', i)) {
            flushText(textBuf, lastWasCode);
            textBuf = '';
            i += 3;

            // Read optional language tag: a single alphanumeric/hyphen/underscore token.
            const langMatch = text.slice(i).match(/^[a-zA-Z0-9_-]+/);
            const lang = langMatch ? langMatch[0] : '';
            i += lang.length;
            // Skip optional spaces/tabs on the opening line.
            while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i++;
            // Skip a single newline if present.
            if (text[i] === '\n') i++;

            // Find the closing fence.
            const closeIdx = text.indexOf('```', i);
            const content = (closeIdx === -1 ? text.slice(i) : text.slice(i, closeIdx)).replace(/\n+$/, '');

            // Strip a duplicated language tag inside the code body, e.g. fence said
            // ```python and the first line of content is also "python".
            const contentLines = content.split('\n');
            let effectiveLang = lang || undefined;
            if (
                contentLines.length > 0 &&
                contentLines[0].trim() &&
                (KNOWN_LANGS.has(contentLines[0].trim().toLowerCase()) ||
                    contentLines[0].trim().toLowerCase() === (lang || '').toLowerCase())
            ) {
                if (!effectiveLang) effectiveLang = contentLines[0].trim().toLowerCase();
                contentLines.shift();
            }
            parts.push({ type: 'code', language: effectiveLang, content: contentLines.join('\n') });
            lastWasCode = true;

            if (closeIdx === -1) {
                i = text.length;
            } else {
                i = closeIdx + 3;
                if (text[i] === '\n') i++;
            }
            continue;
        }
        textBuf += text[i];
        i++;
    }
    flushText(textBuf, lastWasCode);

    if (parts.length === 0) parts.push({ type: 'text', content: text });
    return parts;
}

function CodeFence({ code, language }: { code: string; language?: string }) {
    const [copied, setCopied] = useState(false);
    async function copy() {
        try {
            await navigator.clipboard.writeText(code);
            setCopied(true);
            setTimeout(() => setCopied(false), 1600);
        } catch {
            /* no clipboard */
        }
    }
    return (
        <div className="relative group my-2">
            <button
                type="button"
                onClick={copy}
                aria-label={copied ? 'Copied to clipboard' : 'Copy code to clipboard'}
                title={copied ? 'Copied' : 'Copy'}
                className="absolute top-2 right-2 z-10 p-1 text-burgundy hover:text-burgundy-dark focus:text-burgundy-dark focus:outline-none transition-colors bg-transparent border-0"
            >
                {copied ? (
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5 text-emerald-success" aria-hidden="true">
                        <path d="m4.5 12.75 6 6 9-13.5" />
                    </svg>
                ) : (
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" className="w-3.5 h-3.5" aria-hidden="true">
                        <rect x="9" y="9" width="11" height="11" rx="1.5" />
                        <path d="M5 15V5a1.5 1.5 0 0 1 1.5-1.5H15" />
                    </svg>
                )}
            </button>
            {language && (
                <span className="absolute top-1.5 left-3 font-mono uppercase text-[0.6rem] tracking-[0.18em] text-parchment/50 pointer-events-none">
                    {language}
                </span>
            )}
            <pre className={`text-[0.78rem] leading-relaxed ${language ? 'pt-6' : ''}`}>
                <code>{code}</code>
            </pre>
        </div>
    );
}

function CredentialView({ credential }: { credential: Credential }) {
    const [expanded, setExpanded] = useState(false);
    const intent = credential.credentialSubject?.intent ?? {};
    const proof = credential.proof ?? {};
    const id = String(credential.id ?? '');
    const truncated = id.length > 28 ? id.slice(0, 16) + '...' + id.slice(-8) : id;
    return (
        <div className="mt-3 p-3 border border-rule bg-parchment-warm text-[0.78rem]">
            <div className="flex items-center gap-2 mb-2">
                <span className="font-mono uppercase text-[0.6rem] tracking-[0.18em] text-burgundy">Vouch Credential</span>
                <span className="font-mono text-ink-faint text-[0.7rem]" title={id}>{truncated}</span>
            </div>
            <dl className="grid grid-cols-[90px_1fr] gap-x-3 gap-y-1">
                <dt className="text-ink-faint">Issuer</dt>
                <dd className="break-all">{String(credential.issuer ?? '')}</dd>
                <dt className="text-ink-faint">Action</dt>
                <dd>{String(intent.action ?? '')}</dd>
                <dt className="text-ink-faint">Target</dt>
                <dd>{String(intent.target ?? '')}</dd>
                <dt className="text-ink-faint">Resource</dt>
                <dd className="break-all font-mono text-[0.7rem]">{String(intent.resource ?? '')}</dd>
                <dt className="text-ink-faint">Suite</dt>
                <dd className="font-mono text-[0.7rem]">{String(proof.cryptosuite ?? '')}</dd>
            </dl>
            <button
                type="button"
                onClick={() => setExpanded((v) => !v)}
                className="mt-2 font-mono uppercase text-[0.65rem] tracking-[0.18em] text-ink-faint hover:text-burgundy"
            >
                {expanded ? 'Hide JSON' : 'Show raw JSON'}
            </button>
            {expanded && (
                <pre className="mt-2 text-[0.7rem] max-h-72">
                    <code>{JSON.stringify(credential, null, 2)}</code>
                </pre>
            )}
        </div>
    );
}

export default function AgentChat({ apiBase, initialPrompt }: Props) {
    const [messages, setMessages] = useState<Message[]>(() =>
        initialPrompt ? [{ role: 'assistant', text: initialPrompt }] : [],
    );
    const [draft, setDraft] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const scrollRef = useRef<HTMLDivElement | null>(null);

    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [messages]);

    async function send(override?: string) {
        const text = (override ?? draft).trim();
        if (!text || busy) return;
        setError(null);
        setBusy(true);
        setMessages((prev) => [...prev, { role: 'user', text }, { role: 'assistant', text: '' }]);
        setDraft('');

        try {
            const resp = await fetch(`${apiBase}/chat`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ message: text }),
            });
            if (!resp.ok || !resp.body) throw new Error(`agent returned ${resp.status}`);
            const reader = resp.body.getReader();
            const decoder = new TextDecoder();
            let buf = '';
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                buf += decoder.decode(value, { stream: true });
                let idx;
                while ((idx = buf.indexOf('\n\n')) !== -1) {
                    const block = buf.slice(0, idx);
                    buf = buf.slice(idx + 2);
                    handleEvent(block);
                }
            }
        } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
        } finally {
            setBusy(false);
        }
    }

    function handleEvent(block: string) {
        const lines = block.split('\n');
        let event = 'message';
        let data = '';
        for (const line of lines) {
            if (line.startsWith('event:')) event = line.slice(6).trim();
            else if (line.startsWith('data:')) data += line.slice(5).trim();
        }
        if (!data) return;
        try {
            const parsed = JSON.parse(data);
            if (event === 'meta') {
                setMessages((prev) => {
                    const next = [...prev];
                    const last = next[next.length - 1];
                    if (last && last.role === 'assistant') {
                        last.sources = parsed.sources ?? last.sources;
                        last.credential = parsed.credential ?? last.credential;
                    }
                    return next;
                });
            } else if (event === 'token') {
                setMessages((prev) => {
                    const next = [...prev];
                    const last = next[next.length - 1];
                    if (last && last.role === 'assistant') {
                        last.text += parsed.text ?? '';
                    }
                    return next;
                });
            } else if (event === 'error') {
                setError(parsed.error ?? 'unknown agent error');
            }
        } catch {
            /* skip malformed frames */
        }
    }

    return (
        <div className="flex flex-col h-full">
            <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-4 space-y-4">
                {messages.length === 0 && (
                    <div className="py-10 px-2 text-ink-soft">
                        <p className="font-serif text-[1.05rem] leading-relaxed mb-4">
                            Hello. I help developers integrate the Vouch Protocol.
                        </p>
                        <p className="text-[0.92rem] leading-relaxed mb-5 text-ink-faint">
                            I can explain the wire format, walk through SDK examples in Python, TypeScript, or Go,
                            debug verification errors, and sign a real Vouch credential to demonstrate any flow you ask
                            about.
                        </p>
                        <div className="grid gap-2 text-[0.85rem]">
                            {[
                                'Show me a Python quickstart for signing a credential.',
                                'My verifier returns verificationMethod_not_found. What does that mean?',
                                'Walk me through enabling hybrid post-quantum signatures.',
                                'Sign a sample credential so I can see the proof structure.',
                            ].map((s) => (
                                <button
                                    key={s}
                                    type="button"
                                    onClick={() => void send(s)}
                                    disabled={busy}
                                    className="text-left px-3 py-2 border border-rule text-ink-soft hover:border-burgundy hover:text-burgundy transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    {s}
                                </button>
                            ))}
                        </div>
                    </div>
                )}
                {messages.map((m, i) => (
                    <div key={i} className={m.role === 'user' ? 'flex justify-end' : 'flex justify-start'}>
                        <div className={`max-w-[92%] ${m.role === 'user' ? 'order-2' : ''}`}>
                            <div
                                className={`px-3 py-2 text-[0.92rem] leading-relaxed whitespace-pre-wrap ${
                                    m.role === 'user'
                                        ? 'bg-burgundy text-parchment'
                                        : 'bg-parchment-warm text-ink'
                                }`}
                            >
                                {renderMessageBody(m.text || (m.role === 'assistant' && busy && i === messages.length - 1 ? '...' : '')).map((part, j) =>
                                    part.type === 'code' ? (
                                        <CodeFence key={j} code={part.content} language={part.language} />
                                    ) : (
                                        <span key={j}>{part.content}</span>
                                    ),
                                )}
                            </div>
                            {m.credential && <CredentialView credential={m.credential} />}
                            {m.sources && m.sources.length > 0 && (
                                <div className="mt-2 flex flex-wrap gap-1.5">
                                    {m.sources.map((s, j) => (
                                        <span
                                            key={j}
                                            className="font-mono text-[0.65rem] uppercase tracking-wider px-2 py-0.5 border border-rule text-ink-faint"
                                            title={`relevance ${s.score}`}
                                        >
                                            {s.source}
                                        </span>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                ))}
                {error && (
                    <div className="text-burgundy text-[0.85rem] border border-burgundy/40 px-3 py-2">
                        {error}
                    </div>
                )}
            </div>

            <div className="border-t border-rule bg-parchment-warm">
                <form
                    className="px-4 pt-3 pb-2 flex gap-3 items-stretch"
                    onSubmit={(e) => {
                        e.preventDefault();
                        void send();
                    }}
                >
                    <div className="flex-1 flex items-center gap-2 border-b border-ink-faint focus-within:border-ink transition-colors">
                        <span aria-hidden="true" className="font-mono text-burgundy text-[0.85rem] select-none">›</span>
                        <input
                            className="flex-1 bg-transparent text-ink placeholder:text-ink-faint font-serif text-[0.98rem] py-2 focus:outline-none"
                            value={draft}
                            onChange={(e) => setDraft(e.target.value)}
                            placeholder={busy ? 'Thinking…' : 'Ask anything about Vouch'}
                            disabled={busy}
                            aria-label="Ask the Vouch assistant"
                        />
                    </div>
                    <button
                        type="submit"
                        disabled={busy || !draft.trim()}
                        className="font-mono uppercase text-[0.7rem] tracking-[0.16em] text-ink border border-ink px-4 py-2 transition-colors hover:bg-ink hover:text-parchment disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent disabled:hover:text-ink"
                    >
                        {busy ? '…' : 'Ask'}
                    </button>
                </form>
                <p className="px-4 pb-3 text-[0.7rem] text-ink-faint leading-snug">
                    AI-generated. Verify against the{' '}
                    <a href="/help/" className="underline decoration-1 underline-offset-2 hover:text-burgundy">guides</a>,{' '}
                    <a href="/faq/" className="underline decoration-1 underline-offset-2 hover:text-burgundy">FAQ</a>, or the{' '}
                    <a href="https://github.com/vouch-protocol/vouch" target="_blank" rel="noopener noreferrer" className="underline decoration-1 underline-offset-2 hover:text-burgundy">source on GitHub</a>.
                </p>
            </div>
        </div>
    );
}
