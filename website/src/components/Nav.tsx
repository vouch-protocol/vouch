'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import ThemeToggle from './ThemeToggle';
import OSSwitcher from './OSSwitcher';

// Primary pillars, always visible.
const LINKS = [
    { href: '/robotics/', label: 'Robotics' },
    { href: '/onboard/', label: 'Onboard' },
    { href: '/tools/', label: 'Tools' },
    { href: '/support/', label: 'Support' },
];

// Secondary destinations, folded into a "More" dropdown so the nav centre stays lean.
const MORE = [
    { href: '/blog/', label: 'Blog' },
    { href: '/agent-trust-index/', label: 'Index' },
];

const navLinkClass = (active: boolean) =>
    `font-mono uppercase text-[0.7rem] leading-none tracking-[0.14em] no-underline border-b pb-0.5 transition-colors ${
        active ? 'text-burgundy border-burgundy' : 'border-transparent text-ink-soft hover:text-burgundy hover:border-burgundy'
    }`;

function isActive(pathname: string | null, href: string) {
    return pathname === href || (href !== '/' && (pathname?.startsWith(href) ?? false));
}

/** "More" dropdown for the secondary links, styled to match the OS switcher. */
function MoreMenu() {
    const pathname = usePathname();
    const [open, setOpen] = useState(false);
    const ref = useRef<HTMLDivElement>(null);
    const active = MORE.some((link) => isActive(pathname, link.href));

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

    return (
        <div ref={ref} className="relative">
            <button
                type="button"
                onClick={() => setOpen((v) => !v)}
                aria-haspopup="menu"
                aria-expanded={open}
                className={`${navLinkClass(active)} inline-flex items-center gap-1`}
            >
                More
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
                <div role="menu" className="absolute right-0 mt-2 min-w-[140px] bg-parchment border border-rule shadow-md z-50">
                    {MORE.map((link) => (
                        <Link
                            key={link.href}
                            href={link.href}
                            role="menuitem"
                            onClick={() => setOpen(false)}
                            className={`block w-full text-left font-mono uppercase text-[0.7rem] tracking-[0.14em] no-underline whitespace-nowrap px-3 py-2 transition-colors ${
                                isActive(pathname, link.href)
                                    ? 'text-burgundy bg-parchment-warm'
                                    : 'text-ink-soft hover:text-burgundy hover:bg-parchment-warm'
                            }`}
                        >
                            {link.label}
                        </Link>
                    ))}
                </div>
            )}
        </div>
    );
}

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
                    {LINKS.map((link) => (
                        <Link key={link.href} href={link.href} className={navLinkClass(isActive(pathname, link.href))}>
                            {link.label}
                        </Link>
                    ))}
                    <MoreMenu />
                    <OSSwitcher />
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
                        {[...LINKS, ...MORE].map((link) => (
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
                        <div className="pt-3 flex flex-col gap-2">
                            <span className="font-mono uppercase text-[0.6rem] tracking-[0.14em] text-ink-faint">Commands for</span>
                            <OSSwitcher />
                        </div>
                        <div className="pt-2"><ThemeToggle /></div>
                    </div>
                </div>
            )}
        </nav>
    );
}
