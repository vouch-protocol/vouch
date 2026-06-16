'use client';

import { useEffect, useState } from 'react';
import { useOSPreference, type OS } from './os-preference';

/**
 * Global OS selector for the nav. Sets the shared OS preference once, from
 * anywhere, so every command code block across the site shows the matching
 * variant without per-block clicking. macOS and Linux share one option because
 * their command text is identical. The choice persists across pages and visits.
 */
export default function OSSwitcher() {
  const [os, setOS] = useOSPreference();
  const [mounted, setMounted] = useState(false);

  useEffect(() => setMounted(true), []);

  // Reserve space during hydration so the nav does not shift.
  if (!mounted) {
    return <div aria-hidden="true" className="inline-block h-6 w-[150px]" />;
  }

  function opt(label: string, value: OS) {
    const active = os === value;
    return (
      <button
        type="button"
        onClick={() => setOS(value)}
        aria-pressed={active}
        title={`Show code commands for ${value === 'unix' ? 'macOS / Linux' : 'Windows'}`}
        className={`px-2 py-1 transition-colors ${
          active ? 'bg-ink text-parchment' : 'text-ink-soft hover:text-burgundy'
        }`}
      >
        {label}
      </button>
    );
  }

  return (
    <div
      role="group"
      aria-label="Operating system for code commands"
      title="Choose the OS your code commands are shown for"
      className="font-mono uppercase text-[0.58rem] tracking-[0.1em] inline-flex items-center border border-rule overflow-hidden"
    >
      {opt('macOS / Linux', 'unix')}
      {opt('Windows', 'windows')}
    </div>
  );
}
