import fs from 'node:fs';
import path from 'node:path';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Prior Art Disclosures',
    description:
        'The Vouch Protocol defensive disclosure series: published prior art on how AI agents and robots prove who they are, show who allowed them to act, stay within safe limits, and can be stopped.',
};

// The listing is read from the disclosure files at build time, so a newly
// published disclosure shows up here on the next deploy with no second place
// to update.
const DISCLOSURES_DIR = path.join(process.cwd(), '..', 'docs', 'disclosures');
const GITHUB_BASE = 'https://github.com/vouch-protocol/vouch/blob/main/docs/disclosures/';

interface Disclosure {
    id: string;
    num: number;
    file: string;
    title: string;
    published: string | null;
    category: string | null;
}

function field(head: string, name: string): string | null {
    const match = head.match(new RegExp(`\\*\\*${name}:?\\*\\*:?[ \\t]*(.+)`));
    return match ? match[1].trim() : null;
}

function plain(text: string): string {
    return text
        .replace(/\s*[\u2013\u2014]\s*/g, ' - ')
        .replace(/\s+/g, ' ')
        .trim();
}

function loadDisclosures(): Disclosure[] {
    const entries: Disclosure[] = [];
    for (const file of fs.readdirSync(DISCLOSURES_DIR)) {
        const name = file.match(/^PAD-(\d+)-.+\.md$/);
        if (!name) continue;
        const head = fs.readFileSync(path.join(DISCLOSURES_DIR, file), 'utf8').slice(0, 6000);
        const heading = head.match(/^#\s+(.+)$/m);
        if (!heading) {
            throw new Error(`Disclosure ${file} has no top-level heading`);
        }
        const title = heading[1].replace(/^PAD-\d+\s*[:\-]\s*/, '').replace(/^Defensive Disclosure:\s*/, '');
        const category = field(head, 'Category');
        entries.push({
            id: `PAD-${name[1]}`,
            num: Number(name[1]),
            file,
            title: plain(title),
            published: field(head, 'Publication Date'),
            category: category ? plain(category) : null,
        });
    }
    if (entries.length === 0) {
        throw new Error(`No disclosures found in ${DISCLOSURES_DIR}`);
    }
    return entries.sort((a, b) => a.num - b.num);
}

// "December 28, 2025" -> "December 2025". Returns null for a date it cannot read.
function monthAndYear(published: string | null): { time: number; label: string } | null {
    if (!published) return null;
    const time = Date.parse(`${published} UTC`);
    if (Number.isNaN(time)) return null;
    const label = new Date(time).toLocaleDateString('en-US', { month: 'long', year: 'numeric', timeZone: 'UTC' });
    return { time, label };
}

// Column tracks for the register. Below `lg` each entry is stacked; from `lg`
// the published date gets its own column; from `xl` the category does too.
const COLUMNS =
    'lg:grid lg:gap-x-8 lg:grid-cols-[5.5rem_minmax(0,1fr)_9rem] xl:grid-cols-[5.5rem_minmax(0,1fr)_20rem_9rem]';

export default function DisclosuresPage() {
    const disclosures = loadDisclosures();
    const dates = disclosures
        .map((pad) => monthAndYear(pad.published))
        .filter((date): date is { time: number; label: string } => date !== null)
        .sort((a, b) => a.time - b.time);
    const facts: Array<[string, string]> = [[String(disclosures.length), 'Disclosures']];
    if (dates.length > 0) {
        facts.push([dates[0].label, 'First published'], [dates[dates.length - 1].label, 'Most recent']);
    }
    facts.push(['Apache 2.0', 'License']);

    return (
        <>
            {/* Hero */}
            <section className="border-b border-rule">
                <div className="container-wide py-16 md:py-20">
                    <div className="grid gap-10 lg:grid-cols-[minmax(0,1fr)_auto] lg:gap-16 lg:items-end">
                        <div>
                            <div className="eyebrow mb-5">Defensive Disclosure Series</div>
                            <h1 className="font-serif font-semibold text-ink leading-[1.1] tracking-tight mb-5 text-[clamp(2rem,4.2vw,3rem)]">
                                Prior Art Disclosures
                            </h1>
                            <p className="text-ink-soft text-[1.05rem] leading-relaxed max-w-prose">
                                These disclosures describe how AI agents and robots can prove who they are, show
                                who allowed them to act, stay within safe limits, and be stopped when something
                                goes wrong. Each one is published as prior art, so the idea stays free for
                                everyone to use.
                            </p>
                        </div>
                        <dl className="grid grid-cols-2 gap-x-6 gap-y-6 sm:gap-x-10">
                            {facts.map(([value, label]) => (
                                <div key={label} className="border-t-2 border-ink pt-3 flex flex-col-reverse">
                                    <dt className="font-mono uppercase text-[0.66rem] tracking-[0.16em] text-ink-faint mt-1">
                                        {label}
                                    </dt>
                                    <dd className="font-serif text-[1.15rem] sm:text-[1.35rem] leading-tight text-ink sm:whitespace-nowrap">
                                        {value}
                                    </dd>
                                </div>
                            ))}
                        </dl>
                    </div>
                </div>
            </section>

            {/* Register */}
            <section>
                <div className="container-wide py-12 md:py-16">
                    <div
                        aria-hidden="true"
                        className={`hidden ${COLUMNS} pb-3 border-b-2 border-ink font-mono uppercase text-[0.66rem] tracking-[0.16em] text-ink-faint`}
                    >
                        <span>No.</span>
                        <span>Title</span>
                        <span className="hidden xl:block">Category</span>
                        <span>Published</span>
                    </div>
                    <ol className="list-none">
                        {disclosures.map((pad) => (
                            <li
                                key={pad.id}
                                id={pad.id}
                                className={`py-4 lg:py-3.5 border-b border-rule-light scroll-mt-24 lg:items-baseline ${COLUMNS}`}
                            >
                                <p className="font-mono text-[0.7rem] tracking-[0.14em] text-burgundy mb-1 lg:mb-0">
                                    {pad.id}
                                </p>
                                <p className="font-serif text-[1.08rem] leading-snug">
                                    <a
                                        href={`${GITHUB_BASE}${pad.file}`}
                                        className="text-ink no-underline border-b border-rule hover:text-burgundy hover:border-burgundy transition-colors"
                                    >
                                        {pad.title}
                                    </a>
                                </p>
                                {pad.published || pad.category ? (
                                    <p className="text-[0.85rem] leading-snug text-ink-faint mt-1 lg:mt-0 lg:contents">
                                        {pad.published ? (
                                            <span className="lg:col-start-3 lg:row-start-1 xl:col-start-4 lg:whitespace-nowrap">
                                                {pad.published}
                                            </span>
                                        ) : null}
                                        {pad.published && pad.category ? (
                                            <span aria-hidden="true" className="lg:hidden">
                                                {' · '}
                                            </span>
                                        ) : null}
                                        {pad.category ? (
                                            <span className="lg:col-start-2 lg:row-start-2 lg:mt-1 xl:col-start-3 xl:row-start-1 xl:mt-0">
                                                {pad.category}
                                            </span>
                                        ) : null}
                                    </p>
                                ) : null}
                            </li>
                        ))}
                    </ol>
                </div>
            </section>
        </>
    );
}
