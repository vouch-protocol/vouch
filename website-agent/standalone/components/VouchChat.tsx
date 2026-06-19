import { useEffect, useRef, useState } from 'react';
import { CredentialCard } from './CredentialCard';

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
    placeholder?: string;
    initialPrompt?: string;
    className?: string;
};

export function VouchChat({
    apiBase,
    placeholder = 'Ask anything about Vouch Protocol...',
    initialPrompt,
    className,
}: Props) {
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

    async function send() {
        const text = draft.trim();
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
            if (!resp.ok || !resp.body) {
                throw new Error(`agent returned ${resp.status}`);
            }
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
        <div className={['vouch-chat', className].filter(Boolean).join(' ')}>
            <div className="vouch-chat__scroll" ref={scrollRef}>
                {messages.map((m, i) => (
                    <div key={i} className={`vouch-chat__msg vouch-chat__msg--${m.role}`}>
                        <div className="vouch-chat__bubble">{m.text || (m.role === 'assistant' && busy && i === messages.length - 1 ? '...' : null)}</div>
                        {m.credential && <CredentialCard credential={m.credential} />}
                        {m.sources && m.sources.length > 0 && (
                            <div className="vouch-chat__sources">
                                {m.sources.map((s, j) => (
                                    <span key={j} className="vouch-chat__source">
                                        {s.source} <span className="vouch-chat__score">{s.score.toFixed(2)}</span>
                                    </span>
                                ))}
                            </div>
                        )}
                    </div>
                ))}
                {error && <div className="vouch-chat__error">Error: {error}</div>}
            </div>
            <form
                className="vouch-chat__form"
                onSubmit={(e) => {
                    e.preventDefault();
                    void send();
                }}
            >
                <input
                    className="vouch-chat__input"
                    type="text"
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    placeholder={placeholder}
                    disabled={busy}
                    aria-label="Ask the Vouch assistant"
                />
                <button type="submit" disabled={busy || !draft.trim()} className="vouch-chat__send">
                    {busy ? 'Thinking...' : 'Ask'}
                </button>
            </form>
        </div>
    );
}
