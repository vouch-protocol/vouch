'use client';

import { useState } from 'react';
import type { AtiAgent } from './ati-data';

const GRADE_COLOR: Record<string, string> = {
    A: '#1f7a4d',
    B: '#3f7d5c',
    C: '#b8860b',
    D: '#b5651d',
    F: '#7c2d3a',
};

const FILTERS = ['All', 'A', 'B', 'C', 'D'];

export default function AtiLeaderboard({ agents }: { agents: AtiAgent[] }) {
    const [filter, setFilter] = useState('All');
    const shown = filter === 'All' ? agents : agents.filter((a) => a.grade === filter);

    return (
        <div>
            <div className="flex gap-2 flex-wrap mb-4">
                {FILTERS.map((f) => {
                    const count = f === 'All' ? agents.length : agents.filter((a) => a.grade === f).length;
                    return (
                        <button
                            key={f}
                            type="button"
                            onClick={() => setFilter(f)}
                            className={`font-mono uppercase text-[0.65rem] tracking-[0.1em] border px-3 py-1.5 transition-colors ${
                                filter === f
                                    ? 'bg-ink text-parchment border-ink'
                                    : 'bg-parchment-warm text-ink border-rule hover:border-burgundy'
                            }`}
                        >
                            {f} ({count})
                        </button>
                    );
                })}
            </div>

            <div className="border border-rule max-h-[520px] overflow-auto">
                <table className="w-full text-[0.9rem]">
                    <thead>
                        <tr className="bg-parchment-deep border-b border-rule">
                            {['Grade', 'Score', 'Agent', 'Domain', 'Method'].map((h, i) => (
                                <th
                                    key={h}
                                    className={`font-mono uppercase text-[0.6rem] tracking-[0.12em] text-ink-faint p-2.5 sticky top-0 bg-parchment-deep ${
                                        i === 1 ? 'text-right' : 'text-left'
                                    }`}
                                >
                                    {h}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {shown.map((a, i) => (
                            <tr key={`${a.name}-${i}`} className="border-b border-rule-light last:border-0 align-top">
                                <td className="p-2.5 whitespace-nowrap">
                                    <span
                                        className="inline-block min-w-[22px] text-center rounded text-white font-mono font-bold text-[0.72rem] px-1.5 py-0.5"
                                        style={{ background: GRADE_COLOR[a.grade] || '#7c2d3a' }}
                                    >
                                        {a.grade}
                                    </span>
                                </td>
                                <td className="p-2.5 text-right font-mono tabular-nums whitespace-nowrap">{a.score}</td>
                                <td className="p-2.5">{a.name}</td>
                                <td className="p-2.5 text-ink-soft break-all">{a.domains}</td>
                                <td className="p-2.5 text-ink-soft whitespace-nowrap">{a.method}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
            <p className="text-ink-faint text-[0.85rem] mt-2">{shown.length} agents shown.</p>
        </div>
    );
}
