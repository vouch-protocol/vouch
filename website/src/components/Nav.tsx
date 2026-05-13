'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState } from 'react';
import ThemeToggle from './ThemeToggle';

const LINKS = [
    { href: '/blog/', label: 'Blog' },
    { href: '/help/', label: 'Guides' },
    { href: '/faq/', label: 'FAQ' },
];

export default function Nav() {
    const pathname = usePathname();
    const [open, setOpen] = useState(false);

    return (
        <nav className="sticky top-0 z-40 bg-parchment/95 backdrop-blur supports-[backdrop-filter]:bg-parchment/80 border-b border-rule">
            <div className="container-wide flex items-center justify-between py-5">
                <Link href="/" className="flex items-baseline gap-3 no-underline text-ink">
                    <span className="font-serif font-bold text-[1.35rem] tracking-tight">Vouch Protocol</span>
                    <span className="small-caps text-burgundy hidden sm:inline">An Open Standard</span>
                </Link>

                <div className="hidden md:flex items-center gap-7">
                    {LINKS.map((link) => {
                        const isActive = pathname === link.href || (link.href !== '/' && pathname?.startsWith(link.href));
                        return (
                            <Link
                                key={link.href}
                                href={link.href}
                                className={`font-mono uppercase text-[0.7rem] tracking-[0.14em] no-underline border-b border-transparent pb-0.5 transition-colors ${
                                    isActive ? 'text-burgundy border-burgundy' : 'text-ink-soft hover:text-burgundy hover:border-burgundy'
                                }`}
                            >
                                {link.label}
                            </Link>
                        );
                    })}
                    <button
                        type="button"
                        onClick={() => window.dispatchEvent(new CustomEvent('vouch-agent:open'))}
                        className="group inline-flex items-center gap-2 font-mono uppercase text-[0.7rem] tracking-[0.14em] text-ink-soft hover:text-burgundy transition-colors no-underline border-b border-transparent hover:border-burgundy pb-0.5"
                        aria-label="Open Vouch assistant"
                    >
                        <span
                            aria-hidden="true"
                            className="inline-block w-1.5 h-1.5 rounded-full bg-burgundy group-hover:animate-pulse"
                        />
                        Ask the assistant
                    </button>
                    <ThemeToggle />
                    <a
                        href="https://github.com/vouch-protocol/vouch"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono uppercase text-[0.7rem] tracking-[0.14em] no-underline border border-ink px-3.5 py-1.5 transition-colors hover:bg-ink hover:text-parchment"
                    >
                        GitHub
                    </a>
                </div>

                <button
                    onClick={() => setOpen(!open)}
                    className="md:hidden p-2 text-ink"
                    aria-label="Toggle menu"
                >
                    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        {open ? (
                            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        ) : (
                            <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
                        )}
                    </svg>
                </button>
            </div>

            {open && (
                <div className="md:hidden border-t border-rule bg-parchment">
                    <div className="container-wide py-4 flex flex-col gap-3">
                        {LINKS.map((link) => (
                            <Link
                                key={link.href}
                                href={link.href}
                                onClick={() => setOpen(false)}
                                className="font-mono uppercase text-[0.7rem] tracking-[0.14em] text-ink-soft hover:text-burgundy no-underline py-1"
                            >
                                {link.label}
                            </Link>
                        ))}
                        <a
                            href="https://github.com/vouch-protocol/vouch"
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono uppercase text-[0.7rem] tracking-[0.14em] text-ink-soft hover:text-burgundy no-underline py-1"
                        >
                            GitHub
                        </a>
                        <button
                            type="button"
                            onClick={() => {
                                setOpen(false);
                                window.dispatchEvent(new CustomEvent('vouch-agent:open'));
                            }}
                            className="font-mono uppercase text-[0.7rem] tracking-[0.14em] text-burgundy hover:text-burgundy-dark text-left py-1"
                        >
                            Ask the assistant
                        </button>
                        <div className="pt-2"><ThemeToggle /></div>
                    </div>
                </div>
            )}
        </nav>
    );
}
