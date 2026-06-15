'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import type { FAQSection } from './faq-data';
import CodeBlock from '@/components/CodeBlock';
import OSCodeBlock from '@/components/OSCodeBlock';

/**
 * Render a FAQ answer. Supports code fences (extracted first so internal
 * blank lines are preserved), paragraphs, inline `code`, **bold**, and
 * [text](url) links.
 */
function renderAnswer(text: string): React.ReactNode {
    const trimmed = text.trim();
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

    const out: React.ReactNode[] = [];
    const isUnix = (l?: string) =>
        ['bash', 'sh', 'shell', 'console', 'zsh'].includes((l || '').toLowerCase());
    const isWin = (l?: string) =>
        ['powershell', 'pwsh', 'ps1', 'ps'].includes((l || '').toLowerCase());
    for (let si = 0; si < segments.length; si++) {
        const seg = segments[si];
        if (seg.kind === 'code') {
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
            out.push(<CodeBlock key={`s${si}`} code={seg.content} language={seg.lang} />);
            continue;
        }
        const paragraphs = seg.content.split(/\n\n+/).map((p) => p.trim()).filter(Boolean);
        paragraphs.forEach((paragraph, pi) => {
            const parts = paragraph.split(/(\[[^\]]+\]\([^)]+\)|`[^`]+`|\*\*[^*]+\*\*)/g);
            out.push(
                <p key={`s${si}-p${pi}`}>
                    {parts.map((part, i) => {
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
                    })}
                </p>
            );
        });
    }
    return out;
}

export default function FAQClient({ sections }: { sections: FAQSection[] }) {
    const [search, setSearch] = useState('');

    const query = search.toLowerCase().trim();

    const filteredSections = useMemo(() => {
        if (!query) return sections;
        return sections
            .map((section) => ({
                ...section,
                items: section.items.filter(
                    (item) =>
                        item.q.toLowerCase().includes(query) ||
                        item.a.toLowerCase().includes(query) ||
                        section.audience.toLowerCase().includes(query) ||
                        section.title.toLowerCase().includes(query)
                ),
            }))
            .filter((section) => section.items.length > 0);
    }, [sections, query]);

    const totalResults = filteredSections.reduce((sum, s) => sum + s.items.length, 0);

    return (
        <div className="grid lg:grid-cols-[220px_1fr] gap-12 lg:gap-16">
            {/* Marginalia / table of contents */}
            <aside className="lg:sticky lg:top-8 lg:self-start lg:max-h-[calc(100vh-4rem)] lg:overflow-y-auto">
                <div className="eyebrow mb-3 border-b border-rule pb-2">In this section</div>
                <nav>
                    {sections.map((section) => (
                        <a key={section.id} href={`#${section.id}`} className="marginalia-link">
                            {section.audience}
                        </a>
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
                            {totalResults} result{totalResults !== 1 ? 's' : ''}
                        </p>
                    )}
                </div>
            </aside>

            {/* Main FAQ column */}
            <div className="min-w-0">
                {filteredSections.length === 0 ? (
                    <div className="text-center py-16">
                        <p className="font-serif italic text-ink-faint mb-3">No questions match your search.</p>
                        <button
                            onClick={() => setSearch('')}
                            className="font-mono uppercase text-[0.7rem] tracking-wider text-burgundy hover:text-burgundy-dark"
                        >
                            Clear search
                        </button>
                    </div>
                ) : (
                    filteredSections.map((section, sectionIndex) => (
                        <section key={section.id} id={section.id} className="mb-16 scroll-mt-8">
                            <div className="eyebrow mb-2">{section.audience}</div>
                            <h2 className="font-serif font-semibold text-[1.65rem] tracking-tight mb-2 pb-3 border-b-2 border-ink">
                                {section.title}
                            </h2>

                            {section.items.map((item, itemIndex) => {
                                // Roman numerals up to xx for entries within a section
                                const ROMANS = ['i', 'ii', 'iii', 'iv', 'v', 'vi', 'vii', 'viii', 'ix', 'x',
                                                'xi', 'xii', 'xiii', 'xiv', 'xv', 'xvi', 'xvii', 'xviii', 'xix', 'xx'];
                                const numeral = ROMANS[itemIndex] || `${itemIndex + 1}`;
                                const slug = `${section.id}-${itemIndex + 1}`;
                                return (
                                    <article
                                        key={slug}
                                        id={slug}
                                        className="mt-7 pt-7 first:mt-6 first:pt-0 border-t border-rule-light first:border-t-0 scroll-mt-8"
                                    >
                                        <div className="font-mono text-[0.7rem] tracking-wider text-ink-faint mb-1">
                                            {numeral}.
                                        </div>
                                        <h3 className="font-serif font-semibold text-[1.1rem] text-ink mb-3">
                                            {item.q}
                                        </h3>
                                        <div className="text-ink-soft leading-relaxed space-y-3 [&_p]:m-0 [&_pre]:my-3">
                                            {renderAnswer(item.a)}
                                        </div>

                                        {item.meta && (
                                            <div className="footnote mt-3">- {item.meta}</div>
                                        )}

                                        {item.helpLinks && item.helpLinks.length > 0 && (
                                            <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5">
                                                {item.helpLinks.map((link) => (
                                                    <Link
                                                        key={link.href}
                                                        href={link.href}
                                                        className="font-mono text-[0.7rem] tracking-wider text-burgundy hover:text-burgundy-dark no-underline"
                                                    >
                                                        → {link.label}
                                                    </Link>
                                                ))}
                                            </div>
                                        )}
                                    </article>
                                );
                            })}
                        </section>
                    ))
                )}
            </div>
        </div>
    );
}
