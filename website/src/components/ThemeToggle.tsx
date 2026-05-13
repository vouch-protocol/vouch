'use client';

import { useEffect, useState } from 'react';

type Mode = 'light' | 'dark' | 'system';

const STORAGE_KEY = 'vouch-theme';
const ORDER: Mode[] = ['light', 'dark', 'system'];

function applyTheme(mode: Mode) {
    const root = document.documentElement;
    const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const effective = mode === 'system' ? (systemDark ? 'dark' : 'light') : mode;
    root.setAttribute('data-theme', effective);
}

function iconFor(mode: Mode) {
    if (mode === 'light') {
        return (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="4" />
                <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
            </svg>
        );
    }
    if (mode === 'dark') {
        return (
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
            </svg>
        );
    }
    // system
    return (
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="4" width="18" height="12" rx="1" />
            <path d="M8 20h8M12 16v4" />
        </svg>
    );
}

const LABEL: Record<Mode, string> = {
    light: 'Light',
    dark: 'Dark',
    system: 'System',
};

export default function ThemeToggle() {
    const [mode, setMode] = useState<Mode>('system');
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        const stored = (typeof window !== 'undefined' && (localStorage.getItem(STORAGE_KEY) as Mode | null)) || 'system';
        setMode(stored);
        applyTheme(stored);
        setMounted(true);

        const mq = window.matchMedia('(prefers-color-scheme: dark)');
        const listener = () => {
            const current = (localStorage.getItem(STORAGE_KEY) as Mode | null) || 'system';
            if (current === 'system') applyTheme('system');
        };
        mq.addEventListener('change', listener);
        return () => mq.removeEventListener('change', listener);
    }, []);

    function cycle() {
        const next = ORDER[(ORDER.indexOf(mode) + 1) % ORDER.length];
        setMode(next);
        localStorage.setItem(STORAGE_KEY, next);
        applyTheme(next);
    }

    if (!mounted) {
        return <div aria-hidden="true" className="inline-block w-7 h-7" />;
    }

    const next = ORDER[(ORDER.indexOf(mode) + 1) % ORDER.length];
    return (
        <button
            type="button"
            onClick={cycle}
            aria-label={`Theme: ${LABEL[mode]}. Click to switch to ${LABEL[next]}.`}
            title={`Theme: ${LABEL[mode]} (click for ${LABEL[next]})`}
            className="w-7 h-7 inline-flex items-center justify-center text-ink-soft hover:text-burgundy transition-colors"
        >
            {iconFor(mode)}
        </button>
    );
}
