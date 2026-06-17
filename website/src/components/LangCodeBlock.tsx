'use client';

import { useState } from 'react';
import CodeBlock from './CodeBlock';

/**
 * A code block with one tab per language, so a single example can show the
 * same flow across SDKs without stacking three blocks. Tab styling matches
 * OSCodeBlock so the two controls read as one family.
 */

export type LangVariant = {
    /** Tab label, e.g. "Python". */
    label: string;
    /** Language hint shown top-left inside the block. */
    language: string;
    /** Source for this language. */
    code: string;
};

export default function LangCodeBlock({ variants }: { variants: LangVariant[] }) {
    const [active, setActive] = useState(0);

    return (
        <div>
            <div className="flex flex-wrap border-b border-rule" role="tablist" aria-label="Language">
                {variants.map((variant, i) => (
                    <button
                        key={variant.label}
                        type="button"
                        role="tab"
                        aria-selected={active === i}
                        onClick={() => setActive(i)}
                        className={`font-mono uppercase text-[0.62rem] tracking-[0.16em] px-3 py-1.5 border-b-2 transition-colors ${
                            active === i
                                ? 'border-burgundy text-ink'
                                : 'border-transparent text-ink-faint hover:text-ink-soft'
                        }`}
                    >
                        {variant.label}
                    </button>
                ))}
            </div>
            <CodeBlock language={variants[active].language} code={variants[active].code} bare />
        </div>
    );
}
