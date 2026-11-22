import fs from 'node:fs';
import path from 'node:path';
import type { Metadata } from 'next';
import { DocPage } from '@/components/DocPage';

export const metadata: Metadata = {
    title: 'Prior Art Disclosures',
    description:
        'The Vouch Protocol defensive disclosure series: published prior art for AI agent identity, attestation, and verification mechanisms.',
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

export default function DisclosuresPage() {
    const disclosures = loadDisclosures();
    return (
        <DocPage
            eyebrow="Defensive Disclosure Series"
            title="Prior Art Disclosures"
            lede="Technical specifications for AI agent identity, attestation, and verification. Each one is published as prior art, so the idea stays free for everyone to use."
            meta={[`${disclosures.length} disclosures`, 'Apache 2.0']}
        >
            <ol className="list-none mt-8">
                {disclosures.map((pad) => (
                    <li key={pad.id} id={pad.id} className="py-4 border-b border-rule-light">
                        <p className="font-mono text-[0.7rem] tracking-[0.14em] text-burgundy mb-1">{pad.id}</p>
                        <p className="font-serif text-[1.08rem] leading-snug">
                            <a
                                href={`${GITHUB_BASE}${pad.file}`}
                                className="text-ink no-underline border-b border-rule hover:text-burgundy hover:border-burgundy transition-colors"
                            >
                                {pad.title}
                            </a>
                        </p>
                        {pad.published || pad.category ? (
                            <p className="text-[0.85rem] text-ink-faint mt-1">
                                {[pad.published, pad.category].filter(Boolean).join(' · ')}
                            </p>
                        ) : null}
                    </li>
                ))}
            </ol>
        </DocPage>
    );
}
