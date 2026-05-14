import Link from 'next/link';
import Image from 'next/image';

const FOOTER_GROUPS = [
  {
    title: 'Product',
    links: [
      { label: 'FAQ', href: '/faq/' },
      { label: 'Help & Guides', href: '/help/' },
      { label: 'Support', href: '/support/' },
    ],
  },
  {
    title: 'Resources',
    links: [
      { label: 'GitHub', href: 'https://github.com/vouch-protocol/vouch', external: true },
      { label: 'Specification', href: 'https://github.com/vouch-protocol/vouch/blob/main/docs/specs/specification-executive-summary.md', external: true },
      { label: 'Test Vectors', href: 'https://github.com/vouch-protocol/vouch/tree/main/test-vectors', external: true },
      { label: 'CHANGELOG', href: 'https://github.com/vouch-protocol/vouch/blob/main/CHANGELOG.md', external: true },
    ],
  },
  {
    title: 'SDKs',
    links: [
      { label: 'Python (PyPI)', href: 'https://pypi.org/project/vouch-protocol/', external: true },
      { label: 'TypeScript (npm)', href: 'https://www.npmjs.com/package/@vouch-protocol/core', external: true },
      { label: 'Go sidecar', href: 'https://github.com/vouch-protocol/vouch/tree/main/go-sidecar', external: true },
      { label: 'Browser extension', href: 'https://github.com/vouch-protocol/vouch/tree/main/browser-extension', external: true },
    ],
  },
  {
    title: 'Community',
    links: [
      { label: 'Discord', href: 'https://discord.gg/mMqx5cG9Y', external: true },
      { label: 'GitHub issues', href: 'https://github.com/vouch-protocol/vouch/issues', external: true },
      { label: 'X / Twitter', href: 'https://x.com/Vouch_Protocol', external: true },
    ],
  },
];

export default function Footer() {
  return (
    <footer className="mt-24 pb-12">
      <div className="container-wide">
        <div className="double-rule pt-12">
          <div className="grid grid-cols-2 md:grid-cols-5 gap-8 md:gap-12">
            <div className="col-span-2 md:col-span-1">
              <Link
                href="/"
                aria-label="Vouch Protocol home"
                className="block mb-4 no-underline"
              >
                <Image
                  src="/assets/vouch-wordmark.png"
                  alt="Vouch Protocol"
                  width={1600}
                  height={629}
                  priority={false}
                  className="h-12 md:h-14 w-auto max-w-full vouch-footer-wordmark"
                />
              </Link>
              <p className="font-serif italic text-ink-faint text-[0.9rem] max-w-[280px]">
                Cryptographic identity, intent attestation, and continuous trust verification for autonomous AI agents.
              </p>
            </div>

            {FOOTER_GROUPS.map((group) => (
              <div key={group.title}>
                <h4 className="eyebrow mb-4">{group.title}</h4>
                <ul className="space-y-2.5 list-none">
                  {group.links.map((link) => (
                    <li key={link.label}>
                      {('external' in link && link.external) ? (
                        <a
                          href={link.href}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-ink-soft hover:text-burgundy text-[0.95rem] no-underline border-b border-transparent hover:border-burgundy transition-colors"
                        >
                          {link.label}
                        </a>
                      ) : (
                        <Link
                          href={link.href}
                          className="text-ink-soft hover:text-burgundy text-[0.95rem] no-underline border-b border-transparent hover:border-burgundy transition-colors"
                        >
                          {link.label}
                        </Link>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <div className="mt-12 pt-6 border-t border-rule flex flex-col md:flex-row gap-3 items-start md:items-center justify-between font-mono text-[0.7rem] tracking-[0.1em] text-ink-faint">
            <span>© 2025-2026 Ramprasad Gaddam. Licensed under Apache 2.0.</span>
            <span>An open standard specification.</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
