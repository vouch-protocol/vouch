import type { Metadata } from 'next';
import { DocNav, DocPage, DocSection, DocStep } from '@/components/DocPage';

export const metadata: Metadata = {
    title: 'Key Ceremony Documentation',
    description:
        'Key Ceremony Documentation for the Vouch Protocol C2PA Certificate Authority. ECDSA P-384, Google Cloud KMS HSM.',
    openGraph: {
        title: 'Vouch Protocol Key Ceremony',
        description: 'Key generation ceremony procedures for the Vouch Protocol C2PA Certificate Authority.',
        type: 'website',
        url: '/key-ceremony/',
    },
};

export default function KeyCeremonyPage() {
    return (
        <DocPage
            eyebrow="C2PA Certificate Authority"
            title="Key Ceremony Documentation"
            lede="Vouch Protocol C2PA Certificate Authority"
            meta={['Version 2.0', 'March 2026']}
        >
            <DocSection num="1." title="Purpose">
                <p>
                    This document describes the key ceremony procedures for the Vouch Protocol C2PA Certificate
                    Authority (CA). The key ceremony is the process by which the CA root key, intermediate signing
                    keys, and leaf certificates are generated, secured, and activated.
                </p>
                <p>
                    CA certificates (Root and Intermediate) use ECDSA P-384 (secp384r1) as required by the C2PA
                    Certificate Policy. Leaf signing certificates use Ed25519 for high-performance content credential
                    signing. All CA key material is generated and stored in Google Cloud KMS HSM (FIPS 140-2 Level 3).
                </p>
            </DocSection>

            <DocSection num="2." title="Trust Chain Architecture">
                <p>The Vouch Protocol C2PA CA operates a three-tier certificate hierarchy:</p>
                <ul>
                    <li>
                        <strong>Vouch Protocol Root CA</strong> (ECDSA P-384) - Keys in Google Cloud KMS HSM,
                        non-exportable protection
                    </li>
                    <li>
                        <strong>Vouch Protocol Intermediate CA</strong> (ECDSA P-384) - Signs leaf certificates, keys
                        in Google Cloud KMS HSM
                    </li>
                    <li>
                        <strong>Vouch Protocol C2PA Signer</strong> (Ed25519) - Active signing certificate for content
                        credentials
                    </li>
                </ul>
                <p>
                    The root CA key is generated in HSM and never leaves the hardware boundary. The intermediate CA
                    key signs leaf certificates. Leaf certificates are used for day-to-day C2PA content credential
                    signing by subscribers such as Operator (vouch.example).
                </p>
            </DocSection>

            <DocSection num="3." title="Key Generation Procedure">
                <p>The following procedure is followed for each key generation ceremony:</p>

                <DocStep badge="Step 1" title="Environment Preparation">
                    <p>
                        A clean environment is prepared with Google Cloud SDK, OpenSSL 3.x, and the Vouch Protocol
                        ceremony script. Authenticated access to Google Cloud KMS is verified. All previous temporary
                        files are purged. Network connectivity to Google Cloud KMS API is confirmed.
                    </p>
                </DocStep>

                <DocStep badge="Step 2" title="Ceremony Participants">
                    <p>
                        Minimum 3 participants assemble: (1) CA Administrator who executes the ceremony script, (2)
                        Witness who observes and verifies each step, (3) Independent Witness who is not affiliated
                        with the CA Operator. All participants sign the ceremony attestation document.
                    </p>
                </DocStep>

                <DocStep badge="Step 3" title="Root CA Generation (One-time)">
                    <p>
                        An ECDSA P-384 asymmetric signing key is created in Google Cloud KMS with HSM protection level
                        and DESTROY scheduling. The public key is extracted via KMS API. A self-signed root
                        certificate is assembled with 20-year validity, basicConstraints CA:TRUE pathlen:2, keyUsage
                        keyCertSign+cRLSign, and C2PA Certificate Policy OID 1.3.6.1.4.1.62558.1.1. The certificate
                        TBS is signed via KMS asymmetricSign API.
                    </p>
                </DocStep>

                <DocStep badge="Step 4" title="Intermediate CA Generation">
                    <p>
                        An ECDSA P-384 key is created in KMS HSM. A certificate is assembled with 1,827-day (5-year)
                        validity, basicConstraints CA:TRUE pathlen:0, extendedKeyUsage c2pa-kp-claimSigning
                        (1.3.6.1.4.1.62558.2.1) + emailProtection. AIA extension includes OCSP responder URL and CA
                        Issuers URL. CRL Distribution Point is set. The certificate is signed by the Root CA via KMS
                        API.
                    </p>
                </DocStep>

                <DocStep badge="Step 5" title="Leaf Certificate Generation">
                    <p>
                        An Ed25519 keypair is generated locally or in HSM. A certificate is assembled with 366-day
                        (AL1) or 90-day (AL2) validity, basicConstraints CA:FALSE, keyUsage
                        digitalSignature+nonRepudiation, extendedKeyUsage c2pa-kp-claimSigning + emailProtection. C2PA
                        Assurance Level extension (1.3.6.1.4.1.62558.3) and CPL Record extension
                        (1.3.6.1.4.1.62558.4) are included. Signed by Intermediate CA via KMS API.
                    </p>
                </DocStep>

                <DocStep badge="Step 6" title="PKI Linting">
                    <p>
                        All generated certificates are validated using PKI linting tools (zlint, x509lint, certlint).
                        C2PA-specific extensions are verified for correct OIDs, criticality flags, and encoding.
                        Results are recorded in the ceremony attestation.
                    </p>
                </DocStep>

                <DocStep badge="Step 7" title="Chain Verification">
                    <p>
                        The full certificate chain is verified: Root CA self-signature, Intermediate signed by Root,
                        Leaf signed by Intermediate. Each certificate&apos;s extensions (basicConstraints, keyUsage,
                        EKU, AIA, CRL, C2PA OIDs) are independently checked. A test C2PA content credential is signed
                        and verified end-to-end.
                    </p>
                </DocStep>

                <DocStep badge="Step 8" title="Sign-off">
                    <p>
                        All three participants review and sign the ceremony attestation document. The attestation
                        includes certificate fingerprints, key IDs, verification results, and any deviations. Signed
                        attestation is archived with 7-year retention.
                    </p>
                </DocStep>
            </DocSection>

            <DocSection num="4." title="Key Storage and Protection">
                <ul>
                    <li>
                        <strong>Root CA private key:</strong> Google Cloud KMS HSM, FIPS 140-2 Level 3,
                        non-exportable, EC_SIGN_P384_SHA384
                    </li>
                    <li>
                        <strong>Intermediate CA private key:</strong> Google Cloud KMS HSM, FIPS 140-2 Level 3,
                        non-exportable, used only via KMS API
                    </li>
                    <li>
                        <strong>Leaf private key:</strong> Subscriber-managed storage (environment variables, local
                        keystore, or HSM)
                    </li>
                    <li>
                        <strong>Certificate chain:</strong> Published at <code>/.well-known/c2pa-trust-list</code>
                    </li>
                </ul>
                <p>
                    All KMS operations require IAM authentication. Key access is restricted to the ceremony service
                    account and authorized signing services. Dual control is enforced for key management operations.
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

            <DocSection num="6." title="Revocation Procedures">
                <p>In the event of key compromise or certificate misuse:</p>

                <DocStep title="Detection">
                    <p>
                        Key compromise is detected through KMS audit log monitoring, anomalous signing patterns, or
                        external reports to ca@vouch-protocol.com.
                    </p>
                </DocStep>

                <DocStep title="Immediate Response">
                    <p>
                        The compromised certificate serial number is added to the revocation list. CRL and OCSP
                        endpoints immediately reflect the revocation. For KMS-hosted keys, the key version is disabled
                        via Cloud KMS API.
                    </p>
                </DocStep>

                <DocStep title="Key Rotation">
                    <p>
                        A new leaf certificate is generated using the existing intermediate CA via KMS API signing.
                        The new certificate chain is distributed to the subscriber. The old leaf private key is
                        securely deleted.
                    </p>
                </DocStep>

                <DocStep title="Notification">
                    <p>
                        Affected subscribers are notified via email. The trust list at{' '}
                        <code>/.well-known/c2pa-trust-list</code> is updated with the new certificate information.
                    </p>
                </DocStep>
            </DocSection>

            <DocSection num="7." title="Audit Controls">
                <ul>
                    <li>Google Cloud KMS provides built-in audit logging for all key operations</li>
                    <li>KMS audit logs are exported to Cloud Logging with 7-year retention</li>
                    <li>
                        Ceremony artifacts (attestations, PKI lint reports, chain verifications) retained for 7 years
                    </li>
                    <li>Certificate issuance and revocation events logged with operator identity and timestamp</li>
                    <li>CRL and OCSP query logs maintained for compliance reporting</li>
                    <li>
                        C2PA signing operations logged per subscriber with content hash and certificate serial number
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
                        <strong>CPS:</strong> vouch-protocol.com/cps.html
                    </li>
                    <li>
                        <strong>Trust List:</strong> vouch-protocol.com/.well-known/c2pa-trust-list
                    </li>
                </ul>
            </DocSection>

            <DocNav
                links={[
                    { label: 'Certificate Practice Statement', href: '/cps/' },
                    { label: 'Trust List', href: 'https://vouch-protocol.com/.well-known/c2pa-trust-list' },
                    { label: 'CRL', href: 'https://vouch-protocol.com/api/v1/c2pa/crl' },
                    { label: 'Home', href: '/' },
                ]}
            />
        </DocPage>
    );
}
