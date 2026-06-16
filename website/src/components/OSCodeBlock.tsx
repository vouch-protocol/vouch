'use client';

import CodeBlock from './CodeBlock';
import { useOSPreference, type OS } from './os-preference';

/**
 * A code block with macOS/Linux and Windows (PowerShell) variants behind tabs.
 * The chosen OS is shared with the global OSSwitcher in the nav and every other
 * OSCodeBlock (see ./os-preference), so a developer picks their OS once, from
 * anywhere, and every command follows. The choice persists across pages.
 *
 * macOS and Linux share a tab because the command text is identical on both.
 */

type Props = {
  /** macOS / Linux command text. */
  unix: string;
  /** Windows (PowerShell) command text. */
  windows: string;
  /** Optional className forwarded to the inner <pre>. */
  className?: string;
};

export default function OSCodeBlock({ unix, windows, className }: Props) {
  const [os, setOS] = useOSPreference();

  function tab(label: string, value: OS) {
    const active = os === value;
    return (
      <button
        type="button"
        onClick={() => setOS(value)}
        aria-pressed={active}
        className={`font-mono uppercase text-[0.62rem] tracking-[0.16em] px-3 py-1.5 border-b-2 transition-colors ${
          active
            ? 'border-burgundy text-ink'
            : 'border-transparent text-ink-faint hover:text-ink-soft'
        }`}
      >
        {label}
      </button>
    );
  }

  return (
    <div className="my-4">
      <div className="flex gap-1 border-b border-rule">
        {tab('macOS / Linux', 'unix')}
        {tab('Windows', 'windows')}
      </div>
      <CodeBlock code={os === 'windows' ? windows : unix} className={className} bare />
    </div>
  );
}
