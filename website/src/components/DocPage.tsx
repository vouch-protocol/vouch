import type { ReactNode } from 'react';

/**
 * Shared shell for long-form reference documents (terms, CA practice
 * statements, ceremony records). Keeps them on the site theme so they follow
 * every future redesign along with the rest of the pages.
 */
export function DocPage({
    eyebrow,
    title,
    lede,
    meta,
    children,
}: {
    eyebrow?: string;
    title: string;
    lede?: ReactNode;
    meta?: string[];
    children: ReactNode;
}) {
    return (
        <div className="min-h-screen bg-parchment text-ink">
            <div className="max-w-prose mx-auto px-6 py-16 md:py-24 leading-relaxed">
                {eyebrow ? <p className="eyebrow mb-3">{eyebrow}</p> : null}
                <h1 className="font-serif text-[2.2rem] md:text-[2.6rem] leading-tight tracking-tight mb-4">
                    {title}
                </h1>
                {lede ? <p className="font-serif italic text-ink-soft text-[1.05rem] mb-6">{lede}</p> : null}
                {meta && meta.length > 0 ? (
                    <ul className="flex flex-wrap gap-x-6 gap-y-2 list-none font-mono text-[0.7rem] tracking-[0.12em] uppercase text-ink-faint pb-6 mb-2 border-b border-rule">
                        {meta.map((item) => (
                            <li key={item}>{item}</li>
                        ))}
                    </ul>
                ) : null}
                {children}
            </div>
        </div>
    );
}

export function DocSection({ num, title, children }: { num?: string; title: string; children: ReactNode }) {
    return (
        <section className="my-10">
            <h2 className="font-serif text-[1.4rem] font-semibold tracking-tight mb-3">
                {num ? <span className="font-mono text-burgundy text-[0.85rem] mr-3">{num}</span> : null}
                {title}
            </h2>
            <div className="space-y-3 text-ink leading-relaxed [&_a]:text-burgundy [&_a]:no-underline [&_a]:border-b [&_a]:border-current [&_ul]:list-disc [&_ul]:pl-5 [&_ul]:space-y-1 [&_h3]:font-serif [&_h3]:text-[1.1rem] [&_h3]:font-semibold [&_h3]:mt-6 [&_h3]:mb-2 [&_code]:font-mono [&_code]:text-[0.88em] [&_code]:bg-parchment-warm [&_code]:px-1 [&_code]:py-0.5 [&_code]:rounded-sm [&_code]:break-words">
                {children}
            </div>
        </section>
    );
}

/** Two-column field/value table, used for certificate profiles. */
export function DocTable({ rows }: { rows: Array<[string, ReactNode]> }) {
    return (
        <div className="overflow-x-auto my-4">
            <table className="w-full text-left text-[0.92rem] border-collapse">
                <thead>
                    <tr className="border-b-2 border-ink">
                        <th className="py-2 pr-4 font-mono text-[0.68rem] tracking-[0.14em] uppercase text-ink-faint font-normal w-[34%]">
                            Field
                        </th>
                        <th className="py-2 font-mono text-[0.68rem] tracking-[0.14em] uppercase text-ink-faint font-normal">
                            Value
                        </th>
                    </tr>
                </thead>
                <tbody>
                    {rows.map(([field, value]) => (
                        <tr key={field} className="border-b border-rule align-top">
                            <td className="py-2 pr-4 text-ink-soft">{field}</td>
                            <td className="py-2">{value}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

/** Titled step or sub-procedure inside a section. */
export function DocStep({ badge, title, children }: { badge?: string; title: string; children: ReactNode }) {
    return (
        <div className="border-l-2 border-burgundy pl-4 py-1 my-4">
            <h4 className="font-serif text-[1.02rem] font-semibold mb-1">
                {badge ? (
                    <span className="font-mono text-[0.66rem] tracking-[0.14em] uppercase text-burgundy mr-3">
                        {badge}
                    </span>
                ) : null}
                {title}
            </h4>
            {children}
        </div>
    );
}

export function DocNav({ links }: { links: Array<{ label: string; href: string }> }) {
    return (
        <nav className="mt-12 pt-6 border-t border-rule flex flex-wrap gap-x-6 gap-y-2 font-mono text-[0.72rem] tracking-[0.12em] uppercase">
            {links.map((link) => (
                <a key={link.href} href={link.href} className="text-burgundy no-underline border-b border-current">
                    {link.label}
                </a>
            ))}
        </nav>
    );
}
