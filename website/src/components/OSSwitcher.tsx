'use client';

import { useEffect, useRef, useState } from 'react';
import { useOSPreference, type OS } from './os-preference';

/**
 * Global OS selector for the nav. Sets the shared OS preference once, from
 * anywhere, so every command code block across the site shows the matching
 * variant without per-block clicking. macOS and Linux share one option because
 * their command text is identical. The choice persists across pages and visits.
 *
 * Rendered as a compact dropdown so it does not crowd the nav.
 */

const LABELS: Record<OS, string> = {
  unix: 'macOS / Linux',
  windows: 'Windows',
};

const TerminalIcon = () => (
  <svg
    width="13"
    height="13"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="m5 8 4 4-4 4" />
    <path d="M13 16h6" />
  </svg>
);

export default function OSSwitcher() {
  const [os, setOS] = useOSPreference();
  const [mounted, setMounted] = useState(false);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => setMounted(true), []);

  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onDocClick);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDocClick);
      document.removeEventListener('keydown', onKey);
    };
  }, []);

  // Reserve space during hydration so the nav does not shift.
  if (!mounted) {
    return <div aria-hidden="true" className="inline-block h-6 w-[118px]" />;
  }

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="listbox"
        aria-expanded={open}
        title="Choose the OS your code commands are shown for"
        className="font-mono uppercase text-[0.62rem] tracking-[0.12em] inline-flex items-center gap-1.5 whitespace-nowrap text-ink-soft hover:text-burgundy transition-colors"
      >
        <TerminalIcon />
        {LABELS[os]}
        <svg
          width="9"
          height="9"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
          className={`transition-transform ${open ? 'rotate-180' : ''}`}
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>

      {open && (
        <div
          role="listbox"
          aria-label="Operating system for code commands"
          className="absolute right-0 mt-2 min-w-[140px] bg-parchment border border-rule shadow-md z-50"
        >
          {(['unix', 'windows'] as OS[]).map((value) => (
            <button
              key={value}
              role="option"
              aria-selected={os === value}
              onClick={() => {
                setOS(value);
                setOpen(false);
              }}
              className={`block w-full text-left font-mono uppercase text-[0.62rem] tracking-[0.12em] whitespace-nowrap px-3 py-2 transition-colors ${
                os === value
                  ? 'text-burgundy bg-parchment-warm'
                  : 'text-ink-soft hover:text-burgundy hover:bg-parchment-warm'
              }`}
            >
              {LABELS[value]}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
