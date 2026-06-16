'use client';

import { useEffect, useState } from 'react';
import CodeBlock from './CodeBlock';

/**
 * A code block with macOS/Linux and Windows (PowerShell) variants behind tabs.
 * The chosen OS is shared across every OSCodeBlock on the page and persisted to
 * localStorage, so a developer picks their OS once and every command follows.
 *
 * macOS and Linux share a tab because the command text is identical on both.
 */

type OS = 'unix' | 'windows';
const STORAGE_KEY = 'vouch-os-pref';

// Module-level current selection + subscribers, so all instances stay in sync.
let current: OS = 'unix';
const listeners = new Set<(os: OS) => void>();

function setGlobalOS(os: OS): void {
  current = os;
  try {
    localStorage.setItem(STORAGE_KEY, os);
  } catch {
    /* storage unavailable */
  }
  listeners.forEach((fn) => fn(os));
}

type Props = {
  /** macOS / Linux command text. */
  unix: string;
  /** Windows (PowerShell) command text. */
  windows: string;
  /** Optional className forwarded to the inner <pre>. */
  className?: string;
};

export default function OSCodeBlock({ unix, windows, className }: Props) {
  const [os, setOs] = useState<OS>(current);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY) as OS | null;
      if (stored === 'unix' || stored === 'windows') {
        current = stored;
      }
    } catch {
      /* storage unavailable */
    }
    setOs(current);
    const listener = (next: OS) => setOs(next);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);

  function tab(label: string, value: OS) {
    const active = os === value;
    return (
      <button
        type="button"
        onClick={() => setGlobalOS(value)}
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
