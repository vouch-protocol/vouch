import './globals.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
    title: 'Vouch Website Agent (local)',
    description: 'Standalone demo of the Vouch website agent and signing flow.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
        <html lang="en">
            <body>{children}</body>
        </html>
    );
}
