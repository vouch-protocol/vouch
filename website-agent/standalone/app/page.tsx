'use client';

import { useEffect, useState } from 'react';
import { VouchChat } from '../components/VouchChat';
import '../components/styles.css';

const API_BASE = process.env.NEXT_PUBLIC_VOUCH_AGENT_URL ?? 'http://localhost:8000';

export default function Home() {
    const [health, setHealth] = useState<{ ok: boolean; sidecar_ok: boolean; knowledge_chunks: number } | null>(null);
    const [err, setErr] = useState<string | null>(null);

    useEffect(() => {
        let cancelled = false;
        async function probe() {
            try {
                const r = await fetch(`${API_BASE}/healthz`);
                if (!r.ok) throw new Error(`status ${r.status}`);
                const json = await r.json();
                if (!cancelled) setHealth(json);
            } catch (e) {
                if (!cancelled) setErr(e instanceof Error ? e.message : String(e));
            }
        }
        void probe();
        return () => {
            cancelled = true;
        };
    }, []);

    return (
        <main className="page">
            <header className="page__header">
                <h1>Vouch Website Agent (local)</h1>
                <p>Talks to <code>{API_BASE}</code>. Sign actions are routed through the dev sidecar at <code>127.0.0.1:8877</code>.</p>
            </header>

            <div className="page__status">
                {err && <span style={{ color: '#b30021' }}>Backend unreachable: {err}</span>}
                {!err && !health && <span>Probing backend...</span>}
                {health && (
                    <>
                        <span>backend: {health.ok ? 'ok' : 'down'}</span>
                        <span>sidecar: {health.sidecar_ok ? 'ok' : 'down'}</span>
                        <span>knowledge chunks: {health.knowledge_chunks}</span>
                    </>
                )}
            </div>

            <div className="page__chat">
                <VouchChat
                    apiBase={API_BASE}
                    initialPrompt="Hi. I am the Vouch Protocol assistant running on your local machine. Ask me about credentials, DIDs, hybrid PQ, the Heartbeat Protocol, or any verification error you are hitting."
                />
            </div>
        </main>
    );
}
