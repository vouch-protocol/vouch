'use client';

import { useState } from 'react';

const ENDPOINT =
    process.env.NEXT_PUBLIC_GRADER_ENDPOINT || 'https://grade.vouch-protocol.com';

const GRADE_COLOR: Record<string, string> = {
    A: '#22c55e',
    B: '#84cc16',
    C: '#eab308',
    D: '#f97316',
    F: '#ef4444',
};

type Report = {
    domain: string;
    grade: string;
    score: number;
    fixes: string[];
    signals: { did?: string | null; method?: string | null; pq_ready?: boolean; has_revocation?: boolean };
};

export default function GradeChecker() {
    const [domain, setDomain] = useState('');
    const [report, setReport] = useState<Report | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    async function check(e: React.FormEvent) {
        e.preventDefault();
        const d = domain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        if (!d) return;
        setLoading(true);
        setError(null);
        setReport(null);
        try {
            const resp = await fetch(`${ENDPOINT}/grade?domain=${encodeURIComponent(d)}`);
            if (!resp.ok) throw new Error('Could not grade that domain.');
            const data = (await resp.json()) as Report;
            if (!data || !data.grade) throw new Error('Could not grade that domain.');
            setReport(data);
        } catch {
            setError('Could not reach the grader, or that domain has no resolvable DID. Try the CLI below.');
        } finally {
            setLoading(false);
        }
    }

    return (
        <div>
            <form onSubmit={check} className="flex flex-wrap gap-2 mb-4">
                <input
                    type="text"
                    value={domain}
                    onChange={(ev) => setDomain(ev.target.value)}
                    placeholder="agent.yourdomain.com"
                    aria-label="Your agent's domain"
                    className="flex-1 min-w-[220px] border border-rule bg-parchment px-3 py-2 font-mono text-[0.9rem] text-ink focus:border-burgundy focus:outline-none"
                />
                <button type="submit" className="btn-primary" disabled={loading}>
                    {loading ? 'Grading...' : 'Grade my agent'}
                </button>
            </form>

            {error && <p className="text-burgundy text-[0.9rem] mb-2">{error}</p>}

            {report && (
                <div className="border border-rule bg-parchment p-5">
                    <div className="flex items-baseline gap-3 mb-3">
                        <span
                            className="font-serif font-semibold text-[2rem] leading-none"
                            style={{ color: GRADE_COLOR[report.grade] || '#9ca3af' }}
                        >
                            {report.grade}
                        </span>
                        <span className="font-mono text-ink-soft">{report.score}/100</span>
                        <span className="font-mono text-[0.85rem] text-ink-soft">{report.domain}</span>
                    </div>
                    {report.signals?.did && (
                        <p className="text-[0.85rem] text-ink-soft mb-1">identity: {report.signals.did}</p>
                    )}
                    {report.signals?.method && (
                        <p className="text-[0.85rem] text-ink-soft mb-3">key: {report.signals.method}</p>
                    )}
                    {report.fixes && report.fixes.length > 0 && (
                        <>
                            <p className="font-mono uppercase text-[0.62rem] tracking-[0.14em] text-burgundy mb-2">
                                To raise your grade
                            </p>
                            <ol className="list-decimal pl-5 space-y-1.5">
                                {report.fixes.map((f, i) => (
                                    <li key={i} className="text-[0.9rem] text-ink-soft leading-relaxed">
                                        {f}
                                    </li>
                                ))}
                            </ol>
                        </>
                    )}
                </div>
            )}
        </div>
    );
}
