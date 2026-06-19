'use client';

import { useEffect, useState } from 'react';

type Mode = 'light' | 'dark';

const STORAGE_KEY = 'vouch-theme';

function applyTheme(mode: Mode) {
    document.documentElement.setAttribute('data-theme', mode);
}

const SunIcon = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <circle cx="12" cy="12" r="4.5" />
        <path d="M12 2v2.5M12 19.5V22M3.5 12h2.5M18 12h2.5M5.4 5.4l1.8 1.8M16.8 16.8l1.8 1.8M5.4 18.6l1.8-1.8M16.8 7.2l1.8-1.8" />
    </svg>
);

const MoonIcon = () => (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
        <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
);

export default function ThemeToggle() {
    const [mode, setMode] = useState<Mode>('light');
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        const raw = typeof window !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
        // Accept only 'light' or 'dark'. Anything else (including the legacy
        // 'system') falls back to 'light' so this matches the displayed icon.
        const stored: Mode = raw === 'dark' ? 'dark' : 'light';
        setMode(stored);
        applyTheme(stored);
        setMounted(true);
    }, []);

    function toggle() {
        const next: Mode = mode === 'light' ? 'dark' : 'light';
        setMode(next);
        localStorage.setItem(STORAGE_KEY, next);
        applyTheme(next);
    }

    if (!mounted) {
        // Reserve space during hydration to avoid layout shift.
        return <div aria-hidden="true" className="inline-block w-7 h-7" />;
    }

    const nextLabel = mode === 'light' ? 'dark' : 'light';
    return (
        <button
            type="button"
            onClick={toggle}
            aria-label={`Current theme: ${mode}. Switch to ${nextLabel} mode.`}
            title={`Switch to ${nextLabel} mode`}
            className="w-7 h-7 inline-flex items-center justify-center text-ink-soft hover:text-burgundy transition-colors"
        >
            {mode === 'light' ? <SunIcon /> : <MoonIcon />}
        </button>
    );
}
