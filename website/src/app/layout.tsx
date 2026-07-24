import type { Metadata } from 'next';
import Script from 'next/script';
import './globals.css';
import Nav from '@/components/Nav';
import Footer from '@/components/Footer';
import BackToTop from '@/components/BackToTop';
import AgentPanel from '@/components/AgentPanel';

export const metadata: Metadata = {
  title: {
    default: 'Vouch Protocol - Identity & Accountability for AI Agents',
    template: '%s - Vouch Protocol',
  },
  description:
    'The standards-aligned cryptographic identity and accountability layer for autonomous AI agents. Verifiable Credentials with Data Integrity proofs, resource-bound delegation, the Heartbeat Protocol, and an optional post-quantum proof set.',
  metadataBase: new URL('https://vouch-protocol.com'),
  openGraph: {
    title: 'Vouch Protocol',
    description:
      'Cryptographic identity, intent attestation, and continuous trust verification for autonomous AI agents.',
    type: 'website',
    url: 'https://vouch-protocol.com',
    images: [
      {
        url: '/assets/og-image.png',
        width: 1200,
        height: 630,
        alt: 'Vouch Protocol',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    site: '@Vouch_Protocol',
    images: ['/assets/og-image.png'],
  },
  icons: {
    icon: [
      { url: '/favicon.ico', sizes: 'any' },
      { url: '/favicon-32x32.png', sizes: '32x32', type: 'image/png' },
      { url: '/favicon-16x16.png', sizes: '16x16', type: 'image/png' },
    ],
    apple: '/apple-touch-icon.png',
    other: [
      { rel: 'icon', url: '/android-chrome-192x192.png', sizes: '192x192' },
      { rel: 'icon', url: '/android-chrome-512x512.png', sizes: '512x512' },
    ],
  },
};

const GA_ID = 'G-JHPT5HRW2F';

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,500;0,8..60,600;0,8..60,700;1,8..60,400&family=JetBrains+Mono:wght@400;500;600&display=swap"
          rel="stylesheet"
        />
        {/* Inline theme bootstrap. Runs before React hydrates to prevent a flash.
            Defaults to 'light' unless the user has explicitly chosen 'dark'. The
            OS preference is intentionally ignored: the user's pick on this site
            is the source of truth. */}
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var s=localStorage.getItem('vouch-theme');var d=s==='dark'?'dark':'light';document.documentElement.setAttribute('data-theme',d);}catch(e){document.documentElement.setAttribute('data-theme','light');}})();`,
          }}
        />
      </head>
      <body>
        <Nav />
        <main>{children}</main>
        <Footer />
        <BackToTop />
        <AgentPanel />

        {/* Google Analytics (same property as the legacy site) */}
        <Script
          src={`https://www.googletagmanager.com/gtag/js?id=${GA_ID}`}
          strategy="afterInteractive"
        />
        <Script id="gtag-init" strategy="afterInteractive">
          {`
            window.dataLayer = window.dataLayer || [];
            function gtag(){dataLayer.push(arguments);}
            gtag('js', new Date());
            gtag('config', '${GA_ID}');
          `}
        </Script>
      </body>
    </html>
  );
}
