import { useState } from 'react';

type Credential = Record<string, unknown> & {
    id?: string;
    issuer?: string;
    validFrom?: string;
    validUntil?: string;
    credentialSubject?: { intent?: Record<string, unknown> };
    proof?: { cryptosuite?: string; verificationMethod?: string; proofValue?: string };
};

type Props = {
    credential: Credential;
};

export function CredentialCard({ credential }: Props) {
    const [expanded, setExpanded] = useState(false);
    const intent = credential.credentialSubject?.intent ?? {};
    const proof = credential.proof ?? {};
    const issuer = typeof credential.issuer === 'string' ? credential.issuer : String(credential.issuer ?? '');
    const id = typeof credential.id === 'string' ? credential.id : String(credential.id ?? '');
    const truncated = id.length > 28 ? id.slice(0, 16) + '...' + id.slice(-8) : id;
    const proofValue = typeof proof.proofValue === 'string' ? proof.proofValue : '';
    const proofPreview = proofValue ? proofValue.slice(0, 32) + '...' : '';

    return (
        <div className="vouch-cred">
            <div className="vouch-cred__header">
                <span className="vouch-cred__badge">VOUCH CREDENTIAL</span>
                <span className="vouch-cred__id" title={id}>{truncated}</span>
            </div>
            <dl className="vouch-cred__fields">
                <dt>Issuer</dt>
                <dd>{issuer}</dd>
                <dt>Action</dt>
                <dd>{String(intent.action ?? '(unset)')}</dd>
                <dt>Target</dt>
                <dd>{String(intent.target ?? '(unset)')}</dd>
                <dt>Resource</dt>
                <dd className="vouch-cred__resource">{String(intent.resource ?? '(unset)')}</dd>
                <dt>Cryptosuite</dt>
                <dd>{String(proof.cryptosuite ?? '(unsigned)')}</dd>
                <dt>Signed by</dt>
                <dd className="vouch-cred__vm">{String(proof.verificationMethod ?? '')}</dd>
                {proofPreview && (
                    <>
                        <dt>proofValue</dt>
                        <dd className="vouch-cred__sig">{proofPreview}</dd>
                    </>
                )}
            </dl>
            <button type="button" className="vouch-cred__toggle" onClick={() => setExpanded((v) => !v)}>
                {expanded ? 'Hide raw JSON' : 'Show raw JSON'}
            </button>
            {expanded && <pre className="vouch-cred__raw">{JSON.stringify(credential, null, 2)}</pre>}
        </div>
    );
}
