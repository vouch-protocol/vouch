import Link from 'next/link';
import type { Metadata } from 'next';
import { DocNav, DocPage, DocSection } from '@/components/DocPage';

export const metadata: Metadata = {
    title: 'Terms of Service',
    description:
        'Terms of Service for Vouch Protocol services: the Vouch Gatekeeper GitHub App, the browser extension, and the related APIs.',
};

export default function TermsPage() {
    return (
        <DocPage eyebrow="Legal" title="Terms of Service" meta={['Last updated: November 22, 2026']}>
            <DocSection num="1." title="Acceptance of Terms">
                <p>
                    By accessing or using Vouch Protocol services, including the Vouch Gatekeeper GitHub App, browser
                    extension, and related APIs (collectively, the &quot;Services&quot;), you agree to be bound by
                    these Terms of Service.
                </p>
            </DocSection>

            <DocSection num="2." title="Description of Services">
                <p>Vouch Protocol provides:</p>
                <ul>
                    <li>
                        <strong>Vouch Gatekeeper:</strong> A GitHub App that verifies cryptographic signatures on Pull
                        Requests
                    </li>
                    <li>
                        <strong>Browser Extension:</strong> Tools for signing and verifying text with cryptographic
                        identity
                    </li>
                    <li>
                        <strong>API Services:</strong> Signature storage and verification endpoints
                    </li>
                </ul>
            </DocSection>

            <DocSection num="3." title="User Responsibilities">
                <p>You agree to:</p>
                <ul>
                    <li>Use the Services only for lawful purposes</li>
                    <li>Maintain the security of your cryptographic keys</li>
                    <li>Not attempt to circumvent or disable security features</li>
                    <li>Not use the Services to impersonate others</li>
                </ul>
            </DocSection>

            <DocSection num="4." title="Intellectual Property">
                <p>
                    Vouch Protocol is open source software released under the Apache License 2.0. You may use, modify,
                    and distribute the software in accordance with that license. The Vouch Protocol name and logo are
                    trademarks of the project maintainers.
                </p>
            </DocSection>

            <DocSection num="5." title="Privacy">
                <p>
                    Your use of the Services is also governed by our <Link href="/privacy/">Privacy Policy</Link>. By
                    using the Services, you consent to the collection and use of information as described therein.
                </p>
            </DocSection>

            <DocSection num="6." title="Disclaimer of Warranties">
                <p>
                    THE SERVICES ARE PROVIDED &quot;AS IS&quot; WITHOUT WARRANTY OF ANY KIND. WE DO NOT GUARANTEE THAT
                    THE SERVICES WILL BE UNINTERRUPTED, ERROR-FREE, OR COMPLETELY SECURE.
                </p>
            </DocSection>

            <DocSection num="7." title="Limitation of Liability">
                <p>
                    TO THE MAXIMUM EXTENT PERMITTED BY LAW, VOUCH PROTOCOL SHALL NOT BE LIABLE FOR ANY INDIRECT,
                    INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES ARISING FROM YOUR USE OF THE SERVICES.
                </p>
            </DocSection>

            <DocSection num="8." title="Changes to Terms">
                <p>
                    We may modify these Terms at any time. Continued use of the Services after changes constitutes
                    acceptance of the modified Terms.
                </p>
            </DocSection>

            <DocSection num="9." title="Governing Law">
                <p>
                    These Terms shall be governed by and construed in accordance with applicable laws, without regard
                    to conflict of law principles.
                </p>
            </DocSection>

            <DocSection num="10." title="Contact">
                <p>
                    For questions about these Terms, please open an issue at{' '}
                    <a href="https://github.com/vouch-protocol/vouch/issues">our GitHub repository</a>.
                </p>
            </DocSection>

            <DocNav
                links={[
                    { label: 'Privacy', href: '/privacy/' },
                    { label: 'Home', href: '/' },
                ]}
            />
        </DocPage>
    );
}
