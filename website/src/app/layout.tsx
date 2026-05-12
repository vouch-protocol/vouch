import type { Metadata } from 'next';
import Script from 'next/script';
import './globals.css';
import Nav from '@/components/Nav';
import Footer from '@/components/Footer';

export const metadata: Metadata = {
  title: {
    default: 'Vouch Protocol - Identity & Accountability for AI Agents',
    template: '%s - Vouch Protocol',
  },
  description:
    'The standards-aligned cryptographic identity and accountability layer for autonomous AI agents. Verifiable Credentials with Data Integrity proofs, resource-bound delegation, the Heartbeat Protocol, and an optional hybrid post-quantum profile.',
  metadataBase: new URL('https://vouch-protocol.com'),
  openGraph: {
    title: 'Vouch Protocol',
    description:
      'Cryptographic identity, intent attestation, and continuous trust verification for autonomous AI agents.',
    type: 'website',
    url: 'https://vouch-protocol.com',
    images: ['/assets/vouch-logo-full.png'],
  },
  twitter: {
    card: 'summary_large_image',
    site: '@Vouch_Protocol',
  },
  icons: {
    icon: '/assets/vouch-logo-icon.jpg',
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
      </head>
      <body>
        <Nav />
        <main>{children}</main>
        <Footer />

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
