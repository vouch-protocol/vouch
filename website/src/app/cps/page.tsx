import Link from 'next/link';
import type { Metadata } from 'next';
import { DocNav, DocPage, DocSection, DocTable } from '@/components/DocPage';

export const metadata: Metadata = {
    title: 'Certificate Practice Statement',
    description:
        'Vouch Protocol Certificate Practice Statement (CPS) for the C2PA Certificate Authority. ECDSA P-384 CA certificates, Ed25519 leaf signing.',
    openGraph: {
        title: 'Vouch Protocol CPS',
        description: 'Certificate Practice Statement for the Vouch Protocol C2PA Certificate Authority.',
        type: 'website',
        url: '/cps/',
    },
};

export default function CpsPage() {
    return (
        <DocPage
            eyebrow="C2PA Certificate Authority"
            title="Certificate Practice Statement"
            lede="Vouch Protocol C2PA Certificate Authority"
            meta={['Version 2.0', 'March 2026', 'OID: 1.3.6.1.4.1.62558.1.1']}
        >
            <DocSection num="1." title="Overview">
                <p>
                    This Certificate Practice Statement (CPS) describes the practices and procedures of the Vouch
                    Protocol C2PA Certificate Authority (CA). The Vouch Protocol CA issues digital certificates for
                    Content Credentials signing in accordance with the C2PA Certificate Policy (OID:
                    1.3.6.1.4.1.62558.1.1).
                </p>
                <p>
                    The CA is operated by Vouch Protocol and provides certificates to subscribers including Operator
                    (vouch.example) and other entities requiring C2PA content credential signing capabilities. Vouch
                    Protocol is a member of C2PA, standards bodies, and the Linux Foundation.
                </p>
            </DocSection>

            <DocSection num="2." title="CA Organization">
                <ul>
                    <li>
                        <strong>CA Operator:</strong> Vouch Protocol (vouch-protocol.com)
                    </li>
                    <li>
                        <strong>Governing Body:</strong> Vouch Protocol Maintainers
                    </li>
                    <li>
                        <strong>CA Contact:</strong> ca@vouch-protocol.com
                    </li>
                    <li>
                        <strong>CPS Location:</strong> https://vouch-protocol.com/cps.html
                    </li>
                    <li>
                        <strong>Subscribers:</strong> Operator Weaves (vouch.example) and approved entities
                    </li>
                </ul>
            </DocSection>

            <DocSection num="3." title="Certificate Profiles">
                <h3>3.1 Trust Chain Architecture</h3>
                <p>
                    The Vouch Protocol CA operates a three-tier certificate hierarchy with ECDSA P-384 for CA
                    certificates and Ed25519 for leaf signing certificates:
                </p>
                <ul>
                    <li>Vouch Protocol Root CA (ECDSA P-384, self-signed, 20-year validity)</li>
                    <li>Vouch Protocol Intermediate CA (ECDSA P-384, signed by Root CA, 5-year validity)</li>
                    <li>Leaf Signing Certificates (Ed25519, signed by Intermediate CA, 366-day or 90-day validity)</li>
                </ul>

                <h3>3.2 Root CA Certificate</h3>
                <DocTable
                    rows={[
                        ['Subject', <code key="v">CN=Vouch Protocol Root CA, O=Vouch Protocol, C=IN</code>],
                        ['Algorithm', 'ECDSA P-384 (secp384r1)'],
                        ['Validity', '20 years'],
                        ['Key Usage', 'keyCertSign, cRLSign'],
                        ['Basic Constraints', <code key="v">CA:TRUE, pathlen:2</code>],
                        [
                            'Certificate Policies',
                            <span key="v">
                                <code>1.3.6.1.4.1.62558.1.1</code> (C2PA Certificate Policy)
                            </span>,
                        ],
                        ['Key Storage', 'Google Cloud KMS HSM (FIPS 140-2 Level 3)'],
                    ]}
                />

                <h3>3.3 Intermediate CA Certificate</h3>
                <DocTable
                    rows={[
                        ['Subject', <code key="v">CN=Vouch Protocol Intermediate CA, O=Vouch Protocol, C=IN</code>],
                        ['Algorithm', 'ECDSA P-384 (secp384r1)'],
                        ['Validity', '1,827 days (5 years)'],
                        ['Key Usage', 'keyCertSign, cRLSign, digitalSignature'],
                        ['Basic Constraints', <code key="v">CA:TRUE, pathlen:0</code>],
                        [
                            'Extended Key Usage',
                            <span key="v">
                                <code>c2pa-kp-claimSigning (1.3.6.1.4.1.62558.2.1)</code>, emailProtection
                            </span>,
                        ],
                        ['Certificate Policies', <code key="v">1.3.6.1.4.1.62558.1.1</code>],
                        ['AIA OCSP', <code key="v">https://vouch-protocol.com/api/v1/c2pa/ocsp</code>],
                        [
                            'AIA CA Issuers',
                            <code key="v">https://vouch-protocol.com/.well-known/c2pa-trust-list</code>,
                        ],
                        ['CRL Distribution', <code key="v">https://vouch-protocol.com/api/v1/c2pa/crl</code>],
                        ['Key Storage', 'Google Cloud KMS HSM (FIPS 140-2 Level 3)'],
                    ]}
                />

                <h3>3.4 Leaf Signing Certificate</h3>
                <DocTable
                    rows={[
                        ['Subject', <code key="v">CN=Vouch Protocol C2PA Signer, O=Vouch Protocol, C=IN</code>],
                        ['Algorithm', 'Ed25519 (EdDSA over Curve25519)'],
                        ['Validity', '366 days (AL1) or 90 days (AL2)'],
                        ['Key Usage', 'digitalSignature, nonRepudiation'],
                        ['Basic Constraints', <code key="v">CA:FALSE</code>],
                        [
                            'Extended Key Usage',
                            <span key="v">
                                <code>c2pa-kp-claimSigning (1.3.6.1.4.1.62558.2.1)</code>, emailProtection
                            </span>,
                        ],
                        [
                            'C2PA Assurance Level',
                            <span key="v">
                                <code>AL1 (1.3.6.1.4.1.62558.3.1)</code> or <code>AL2 (1.3.6.1.4.1.62558.3.2)</code>
                            </span>,
                        ],
                        ['C2PA CPL Record', <code key="v">1.3.6.1.4.1.62558.3.1</code>],
                        ['AIA OCSP', <code key="v">https://vouch-protocol.com/api/v1/c2pa/ocsp</code>],
                        [
                            'AIA CA Issuers',
                            <code key="v">https://vouch-protocol.com/.well-known/c2pa-trust-list</code>,
                        ],
                    ]}
                />
            </DocSection>

            <DocSection num="4." title="Key Management">
                <h3>4.1 Key Generation</h3>
                <p>
                    All CA keys (Root and Intermediate) are generated in Google Cloud KMS HSM, which is FIPS 140-2
                    Level 3 certified. Keys are generated as non-exportable asymmetric signing keys using ECDSA P-384
                    (EC_SIGN_P384_SHA384).
                </p>
                <p>
                    Leaf signing keys use Ed25519 and may be generated locally or within HSM depending on the
                    subscriber deployment model.
                </p>

                <h3>4.2 Key Storage</h3>
                <ul>
                    <li>
                        <strong>Root CA key:</strong> Google Cloud KMS HSM, non-exportable, HSM protection level
                    </li>
                    <li>
                        <strong>Intermediate CA key:</strong> Google Cloud KMS HSM, non-exportable, HSM protection
                        level
                    </li>
                    <li>
                        <strong>Leaf signing key:</strong> Subscriber-managed (environment variables, local keystore,
                        or HSM)
                    </li>
                    <li>
                        <strong>Certificate chain:</strong> Published at <code>/.well-known/c2pa-trust-list</code>
                    </li>
                </ul>

                <h3>4.3 Key Ceremony</h3>
                <p>
                    Key generation follows a formal ceremony procedure with minimum 3 participants (CA Administrator,
                    Witness, and Independent Witness). Full ceremony documentation is available at{' '}
                    <Link href="/key-ceremony/">vouch-protocol.com/key-ceremony</Link>.
                </p>
            </DocSection>

            <DocSection num="5." title="Certificate Lifecycle">
                <ul>
                    <li>
                        <strong>Root CA:</strong> 20-year validity, offline renewal ceremony with independent witness
                    </li>
                    <li>
                        <strong>Intermediate CA:</strong> Maximum 1,827 days (5 years), signed by Root during key
                        ceremony
                    </li>
                    <li>
                        <strong>Leaf AL1:</strong> Maximum 366 days, annual renewal
                    </li>
                    <li>
                        <strong>Leaf AL2:</strong> Maximum 90 days, quarterly renewal
                    </li>
                    <li>
                        <strong>Re-authentication:</strong> Maximum 398 days for certificate renewal
                    </li>
                </ul>
                <p>
                    Revoked certificates are published in the CRL at <code>/api/v1/c2pa/crl</code> and queryable via
                    OCSP at <code>/api/v1/c2pa/ocsp</code>.
                </p>
            </DocSection>

            <DocSection num="6." title="Revocation">
                <p>In the event of key compromise or certificate misuse:</p>
                <ul>
                    <li>The compromised certificate serial number is added to the revocation list</li>
                    <li>CRL and OCSP endpoints immediately reflect the revocation</li>
                    <li>A new leaf certificate is generated using the existing intermediate CA</li>
                    <li>Affected subscribers are notified via email</li>
                    <li>The trust list is updated with new certificate information</li>
                </ul>
                <p>
                    Revocation requests can be submitted to ca@vouch-protocol.com. Emergency revocation is processed
                    within 24 hours.
                </p>
            </DocSection>

            <DocSection num="7." title="Audit and Logging">
                <ul>
                    <li>All certificate issuance and revocation events are logged with timestamps</li>
                    <li>Google Cloud KMS provides built-in audit logging for all key operations</li>
                    <li>
                        Ceremony artifacts (attestations, PKI lint reports, chain verifications) are retained for 7
                        years
                    </li>
                    <li>CRL and OCSP query logs are maintained for compliance reporting</li>
                    <li>
                        C2PA signing operations are logged per subscriber with content hash and certificate serial
                        number
                    </li>
                </ul>
            </DocSection>

            <DocSection num="8." title="Compliance">
                <p>The Vouch Protocol C2PA CA operates in accordance with:</p>
                <ul>
                    <li>
                        <strong>C2PA Certificate Policy</strong> (OID: 1.3.6.1.4.1.62558.1.1)
                    </li>
                    <li>
                        <strong>C2PA Specification v2.x</strong> - Content Credentials trust model
                    </li>
                    <li>
                        <strong>FIPS 140-2 Level 3</strong> - Hardware security module certification (Google Cloud
                        KMS)
                    </li>
                    <li>
                        <strong>FIPS 186-4</strong> - Digital Signature Standard (ECDSA P-384)
                    </li>
                    <li>
                        <strong>RFC 5280</strong> - Internet X.509 PKI Certificate and CRL Profile
                    </li>
                    <li>
                        <strong>RFC 6960</strong> - Online Certificate Status Protocol (OCSP)
                    </li>
                    <li>
                        <strong>RFC 8032</strong> - Edwards-Curve Digital Signature Algorithm (Ed25519)
                    </li>
                    <li>
                        <strong>RFC 3161</strong> - Internet X.509 PKI Time-Stamp Protocol (via DigiCert TSA)
                    </li>
                </ul>
                <p>Vouch Protocol is a member of C2PA, standards bodies, and the Linux Foundation.</p>
            </DocSection>

            <DocSection num="9." title="Contact">
                <ul>
                    <li>
                        <strong>CA Operator:</strong> Vouch Protocol (vouch-protocol.com)
                    </li>
                    <li>
                        <strong>Platform Operator:</strong> Operator Weaves (vouch.example)
                    </li>
                    <li>
                        <strong>CA Email:</strong> ca@vouch-protocol.com
                    </li>
                    <li>
                        <strong>Security Reports:</strong> security@vouch-protocol.com
                    </li>
                    <li>
                        <strong>C2PA Conformance:</strong> conformance@c2pa.org
                    </li>
                    <li>
                        <strong>Trust List:</strong> vouch-protocol.com/.well-known/c2pa-trust-list
                    </li>
                </ul>
            </DocSection>

            <DocNav
                links={[
                    { label: 'Key Ceremony', href: '/key-ceremony/' },
                    { label: 'Trust List', href: 'https://vouch-protocol.com/.well-known/c2pa-trust-list' },
                    { label: 'CRL', href: 'https://vouch-protocol.com/api/v1/c2pa/crl' },
                    { label: 'Home', href: '/' },
                ]}
            />
        </DocPage>
    );
}
