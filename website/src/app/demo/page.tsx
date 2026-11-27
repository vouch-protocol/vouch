import Link from 'next/link';
import type { Metadata } from 'next';
import { DocPage, DocSection } from '@/components/DocPage';

export const metadata: Metadata = {
    title: 'Browser Extension Demo',
    description:
        'See a signed block verified in real time by the Vouch Protocol browser extension, and what each verification badge means.',
};

// Kept byte-for-byte: the browser extension finds this block on the page and
// verifies the signature over the text and the signer line.
const SIGNED_BLOCK = `[Signed]
The Open Standard for AI Agent Identity & Accountability
---
Signed-by: vouch.protocol.official@gmail.com
Key: d564d45fb8897c0c4f03f35671c3093b968ea2da038f2c30134c27f204254798
Sig:
c5fc54410a3d5e3ead92e6f47e76abb210e8f495a3ea6406002ccb22000e754b92084fecf3c99cea97be072b64cacbefce07c023283edb84f0b3622200f78301`;

const CREDENTIAL_EXAMPLE = `{
 "@context": [
  "https://www.w3.org/ns/credentials/v2",
  "https://vouch-protocol.com/contexts/v1"
 ],
 "id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
 "type": ["VerifiableCredential", "VouchCredential"],
 "issuer": "did:web:agent.example.com",
 "validFrom": "2026-04-26T10:00:00Z",
 "validUntil": "2026-04-26T10:05:00Z",
 "credentialSubject": {
  "id": "did:web:agent.example.com",
  "vouchVersion": "1.0",
  "intent": {
   "action": "read_database",
   "target": "users_table",
   "resource": "https://api.example.com/v1/users"
  }
 },
 "proof": {
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-jcs-2022",
  "created": "2026-04-26T10:00:00Z",
  "verificationMethod": "did:web:agent.example.com#key-1",
  "proofPurpose": "assertionMethod",
  "proofValue": "z3FXQjecWufY46..."
 }
}`;

const STATES = [
    {
        name: 'New Identity',
        body: "First time seeing this signer. They've been added to your Address Book.",
    },
    {
        name: 'Verified Contact',
        body: 'Email and key match a known contact. Trusted!',
    },
    {
        name: 'Identity Changed',
        body: 'Key is different from saved contact. Possible impersonation!',
    },
];

const STEPS = [
    { title: 'Install Extension', body: 'Get the Vouch Protocol browser extension' },
    { title: 'Select Text', body: 'Highlight any text on a webpage' },
    { title: 'Sign It', body: 'Right-click and choose "Sign with Vouch"' },
    { title: 'Paste & Share', body: 'Your signed block is in clipboard!' },
];

// The site-wide <pre> style supplies the colors; these only add wrapping so the
// long key and signature lines stay inside the column.
const BLOCK_CLASS = 'whitespace-pre-wrap break-words text-[0.8rem]';

export default function ExtensionDemoPage() {
    return (
        <DocPage
            eyebrow="Browser extension"
            title="Vouch Protocol Demo"
            lede="See cryptographic signatures verified in real-time"
        >
            <DocSection title="Live Signed Block">
                <p>
                    If you have the Vouch Protocol browser extension installed, the block below will be automatically
                    verified:
                </p>
                <pre className={BLOCK_CLASS}>{SIGNED_BLOCK}</pre>
                <p className="footnote">
                    Look above. If the extension is installed, you&apos;ll see a colored badge showing the
                    verification status.
                </p>
            </DocSection>

            <DocSection title="Verification States">
                <p>
                    The extension uses Trust-On-First-Use (TOFU) like SSH. Here&apos;s what each badge means:
                </p>
                <div className="grid sm:grid-cols-3 gap-6 mt-4">
                    {STATES.map((state) => (
                        <div key={state.name} className="feature-card">
                            <h3 className="!mt-0">{state.name}</h3>
                            <p className="text-[0.92rem] text-ink-soft">{state.body}</p>
                        </div>
                    ))}
                </div>
            </DocSection>

            <DocSection title="Sign an AI Agent Action (v1.0)">
                <p>
                    The same protocol secures AI agent actions with Verifiable Credentials and Data Integrity proofs (
                    <code>eddsa-jcs-2022</code>):
                </p>
                <pre className={BLOCK_CLASS}>{CREDENTIAL_EXAMPLE}</pre>
                <p className="footnote">
                    Standards-aligned: the credential is human-readable JSON. The proof attaches as a sibling object,
                    not as a Base64-wrapped opaque payload. Optionally upgradable to a hybrid Ed25519 + ML-DSA-44
                    post-quantum signature.
                </p>
            </DocSection>

            <DocSection title="Try It Yourself">
                <p>Here&apos;s how to sign your own content:</p>
                <ol className="list-none grid sm:grid-cols-2 gap-6 mt-4">
                    {STEPS.map((step, index) => (
                        <li key={step.title} className="feature-card">
                            <p className="font-mono text-[0.7rem] tracking-[0.14em] text-burgundy mb-1">
                                {String(index + 1).padStart(2, '0')}
                            </p>
                            <h3 className="!mt-0">{step.title}</h3>
                            <p className="text-[0.92rem] text-ink-soft">{step.body}</p>
                        </li>
                    ))}
                </ol>
            </DocSection>

            <div className="mt-12 flex flex-wrap items-center gap-4">
                <a
                    href="https://github.com/vouch-protocol/vouch/tree/main/browser-extension"
                    className="btn-primary"
                >
                    Get the extension
                </a>
                <Link href="/demos/" className="btn-secondary">
                    More demos
                </Link>
            </div>
            <p className="footnote mt-4">Free. Open source. No account required.</p>
        </DocPage>
    );
}
