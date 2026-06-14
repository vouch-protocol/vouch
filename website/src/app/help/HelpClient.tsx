'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import type { HelpSection } from './help-data';
import CodeBlock from '@/components/CodeBlock';
import OSCodeBlock from '@/components/OSCodeBlock';

/**
 * Render markdown-lite content: paragraphs, **bold**, `code`, code fences,
 * [text](url), pipe tables, bullet and ordered lists.
 *
 * Code fences are extracted FIRST as a single unit (so internal blank lines
 * are preserved), then the remaining text is split on blank lines and each
 * piece is rendered as a heading / list / table / paragraph.
 */
function renderBody(body: string): React.ReactNode {
    const trimmed = body.trim();
    const segments: Array<
        | { kind: 'code'; content: string; lang?: string }
        | { kind: 'text'; content: string }
    > = [];
    const fenceRegex = /```(\w+)?\n([\s\S]*?)\n```/g;
    let lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = fenceRegex.exec(trimmed)) !== null) {
        if (match.index > lastIndex) {
            segments.push({ kind: 'text', content: trimmed.slice(lastIndex, match.index) });
        }
        segments.push({ kind: 'code', content: match[2], lang: match[1] });
        lastIndex = match.index + match[0].length;
    }
    if (lastIndex < trimmed.length) {
        segments.push({ kind: 'text', content: trimmed.slice(lastIndex) });
    }
    if (segments.length === 0) {
        segments.push({ kind: 'text', content: trimmed });
    }

    const isUnix = (l?: string) =>
        ['bash', 'sh', 'shell', 'console', 'zsh'].includes((l || '').toLowerCase());
    const isWin = (l?: string) =>
        ['powershell', 'pwsh', 'ps1', 'ps'].includes((l || '').toLowerCase());

    const out: React.ReactNode[] = [];
    for (let si = 0; si < segments.length; si++) {
        const seg = segments[si];
        if (seg.kind === 'code') {
            // OS-paired block: a macOS/Linux fence immediately followed by a
            // Windows (PowerShell) fence (ignoring a whitespace-only gap)
            // renders as one tabbed block.
            if (isUnix(seg.lang)) {
                let j = si + 1;
                if (
                    j < segments.length &&
                    segments[j].kind === 'text' &&
                    segments[j].content.trim() === ''
                ) {
                    j++;
                }
                const next = segments[j];
                if (next && next.kind === 'code' && isWin(next.lang)) {
                    out.push(
                        <OSCodeBlock key={`s${si}`} unix={seg.content} windows={next.content} />
                    );
                    si = j;
                    continue;
                }
            }
            out.push(
                <CodeBlock key={`s${si}`} code={seg.content} language={seg.lang} />
            );
            continue;
        }
        const blocks = seg.content.split(/\n\n+/).map((b) => b.trim()).filter(Boolean);
        blocks.forEach((block, bi) => {
            out.push(renderTextBlock(block, `s${si}-b${bi}`));
        });
    }
    return out;
}

function renderTextBlock(block: string, key: string): React.ReactNode {
    // Heading
    const h2 = block.match(/^## (.+)$/);
    if (h2) {
        return (
            <h3 key={key} className="font-serif font-semibold text-[1.3rem] tracking-tight mt-10 mb-4 pb-2 border-b border-rule-light">
                {h2[1]}
            </h3>
        );
    }

    const h3 = block.match(/^### (.+)$/);
    if (h3) {
        return (
            <h4 key={key} className="font-serif font-semibold text-[1.1rem] mt-6 mb-3">
                {h3[1]}
            </h4>
        );
    }

    // Table (pipe syntax with at least two rows)
    if (block.includes('\n|') && block.split('\n').every((l) => l.trim().startsWith('|'))) {
        const rows = block.split('\n').filter((l) => l.trim());
        const header = rows[0].split('|').slice(1, -1).map((c) => c.trim());
        const bodyRows = rows.slice(2).map((r) => r.split('|').slice(1, -1).map((c) => c.trim()));
        return (
            <div key={key} className="my-5 overflow-x-auto">
                <table className="w-full text-[0.92rem]">
                    <thead>
                        <tr className="border-b-2 border-ink">
                            {header.map((h, i) => (
                                <th key={i} className="text-left py-2 pr-4 font-serif font-semibold">{h}</th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {bodyRows.map((row, ri) => (
                            <tr key={ri} className="border-b border-rule-light">
                                {row.map((cell, ci) => (
                                    <td key={ci} className="py-2 pr-4 align-top">{renderInline(cell)}</td>
                                ))}
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        );
    }

    // Bullet list
    if (block.split('\n').every((l) => /^[-*]\s/.test(l.trim()))) {
        const items = block.split('\n').map((l) => l.replace(/^[-*]\s/, '').trim());
        return (
            <ul key={key} className="list-disc list-outside ml-5 my-4 space-y-1.5 text-ink-soft">
                {items.map((item, i) => (
                    <li key={i} className="leading-relaxed">{renderInline(item)}</li>
                ))}
            </ul>
        );
    }

    // Ordered list
    if (block.split('\n').every((l) => /^\d+\.\s/.test(l.trim()))) {
        const items = block.split('\n').map((l) => l.replace(/^\d+\.\s/, '').trim());
        return (
            <ol key={key} className="list-decimal list-outside ml-5 my-4 space-y-1.5 text-ink-soft">
                {items.map((item, i) => (
                    <li key={i} className="leading-relaxed">{renderInline(item)}</li>
                ))}
            </ol>
        );
    }

    // Plain paragraph
    return (
        <p key={key} className="text-ink-soft leading-relaxed my-3">
            {renderInline(block)}
        </p>
    );
}

/** Inline markdown: **bold**, `code`, [text](url) */
function renderInline(text: string): React.ReactNode {
    const parts = text.split(/(\[[^\]]+\]\([^)]+\)|`[^`]+`|\*\*[^*]+\*\*)/g);
    return parts.map((part, i) => {
        const linkMatch = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
        if (linkMatch) {
            const isExternal = linkMatch[2].startsWith('http');
            return isExternal ? (
                <a key={i} href={linkMatch[2]} target="_blank" rel="noopener noreferrer" className="prose-link">
                    {linkMatch[1]}
                </a>
            ) : (
                <Link key={i} href={linkMatch[2]} className="prose-link">
                    {linkMatch[1]}
                </Link>
            );
        }
        const codeMatch = part.match(/^`([^`]+)`$/);
        if (codeMatch) return <code key={i}>{codeMatch[1]}</code>;
        const strongMatch = part.match(/^\*\*([^*]+)\*\*$/);
        if (strongMatch) return <strong key={i}>{strongMatch[1]}</strong>;
        return <React.Fragment key={i}>{part}</React.Fragment>;
    });
}

export default function HelpClient({ sections }: { sections: HelpSection[] }) {
    const [search, setSearch] = useState('');

    const query = search.toLowerCase().trim();

    const filteredSections = useMemo(() => {
        if (!query) return sections;
        return sections
            .map((section) => ({
                ...section,
                articles: section.articles.filter(
                    (article) =>
                        article.title.toLowerCase().includes(query) ||
                        article.summary.toLowerCase().includes(query) ||
                        article.body.toLowerCase().includes(query)
                ),
            }))
            .filter((section) => section.articles.length > 0);
    }, [sections, query]);

    const totalArticles = filteredSections.reduce((sum, s) => sum + s.articles.length, 0);

    return (
        <div className="grid lg:grid-cols-[240px_1fr] gap-12 lg:gap-16">
            {/* Marginalia */}
            <aside className="lg:sticky lg:top-8 lg:self-start lg:max-h-[calc(100vh-4rem)] lg:overflow-y-auto">
                <div className="eyebrow mb-3 border-b border-rule pb-2">Help &amp; Guides</div>
                <nav>
                    {sections.map((section) => (
                        <div key={section.id} className="mb-4">
                            <a href={`#${section.id}`} className="marginalia-link !text-burgundy">
                                {section.title}
                            </a>
                            <div className="ml-3 mt-1 space-y-1">
                                {section.articles.map((article) => (
                                    <a
                                        key={article.id}
                                        href={`#${article.id}`}
                                        className="block font-serif text-[0.85rem] text-ink-soft hover:text-burgundy no-underline"
                                    >
                                        {article.title}
                                    </a>
                                ))}
                            </div>
                        </div>
                    ))}
                </nav>

                <div className="mt-6 border-t border-rule pt-4">
                    <label className="block">
                        <span className="eyebrow-faint mb-2 block">Search</span>
                        <input
                            type="text"
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            placeholder="..."
                            className="w-full bg-parchment-warm border border-rule px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:outline-none focus:border-burgundy font-serif"
                        />
                    </label>
                    {query && (
                        <p className="font-mono text-[0.7rem] text-ink-faint mt-2">
                            {totalArticles} article{totalArticles !== 1 ? 's' : ''}
                        </p>
                    )}
                </div>
            </aside>

            {/* Main content */}
            <div className="min-w-0">
                {filteredSections.length === 0 ? (
                    <div className="text-center py-16">
                        <p className="font-serif italic text-ink-faint mb-3">No guides match your search.</p>
                        <button
                            onClick={() => setSearch('')}
                            className="font-mono uppercase text-[0.7rem] tracking-wider text-burgundy hover:text-burgundy-dark"
                        >
                            Clear search
                        </button>
                    </div>
                ) : (
                    filteredSections.map((section, si) => (
                        <section key={section.id} id={section.id} className="mb-20 scroll-mt-8">
                            <div className="eyebrow mb-2">Part {romanNumeral(si + 1)}</div>
                            <h2 className="font-serif font-semibold text-[1.85rem] tracking-tight mb-3 pb-3 border-b-2 border-ink">
                                {section.title}
                            </h2>
                            <p className="text-ink-soft leading-relaxed mb-10 max-w-prose">
                                {section.description}
                            </p>

                            {section.articles.map((article) => (
                                <article
                                    key={article.id}
                                    id={article.id}
                                    className="mt-12 first:mt-0 scroll-mt-8"
                                >
                                    <div className="eyebrow-faint mb-2">Guide</div>
                                    <h3 className="font-serif font-semibold text-[1.55rem] tracking-tight mb-2">
                                        {article.title}
                                    </h3>
                                    <p className="font-serif italic text-ink-faint mb-6">{article.summary}</p>
                                    <div className="max-w-prose-wide">
                                        {renderBody(article.body)}
                                    </div>
                                </article>
                            ))}
                        </section>
                    ))
                )}
            </div>
        </div>
    );
}

function romanNumeral(n: number): string {
    const ROMANS = ['I', 'II', 'III', 'IV', 'V', 'VI', 'VII', 'VIII', 'IX', 'X'];
    return ROMANS[n - 1] || String(n);
}
