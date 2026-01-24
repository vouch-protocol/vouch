/**
 * Example: React Component with Vouch Integration
 *
 * A ready-to-use React component for signing content.
 */

import React, { useState, useCallback } from 'react';
import {
    VouchClient,
    VouchConnectionError,
    NoKeysConfiguredError,
    UserDeniedSignatureError,
} from '@vouch-protocol/sdk';

// ============================================================================
// Types
// ============================================================================

interface SignatureResult {
    signature: string;
    timestamp: string;
    did?: string;
}

type SigningState =
    | { status: 'idle' }
    | { status: 'signing' }
    | { status: 'success'; result: SignatureResult }
    | { status: 'error'; message: string; errorType: string };

// ============================================================================
// Custom Hook: useVouchSign
// ============================================================================

function useVouchSign() {
    const [state, setState] = useState<SigningState>({ status: 'idle' });
    const [client] = useState(() => new VouchClient());

    const sign = useCallback(async (content: string, origin: string = 'react-app') => {
        setState({ status: 'signing' });

        try {
            const result = await client.sign(content, origin);
            setState({
                status: 'success',
                result: {
                    signature: result.signature,
                    timestamp: result.timestamp,
                    did: result.did,
                },
            });
            return result;

        } catch (error) {
            let message: string;
            let errorType: string;

            if (error instanceof VouchConnectionError) {
                message = 'Vouch daemon is not running. Please start it first.';
                errorType = 'connection';
            } else if (error instanceof NoKeysConfiguredError) {
                message = 'No identity configured. Please set up your Vouch identity.';
                errorType = 'no_keys';
            } else if (error instanceof UserDeniedSignatureError) {
                message = 'Signature was declined.';
                errorType = 'denied';
            } else {
                message = (error as Error).message;
                errorType = 'unknown';
            }

            setState({ status: 'error', message, errorType });
            throw error;
        }
    }, [client]);

    const reset = useCallback(() => {
        setState({ status: 'idle' });
    }, []);

    return { state, sign, reset };
}

// ============================================================================
// Sign Text Component
// ============================================================================

interface SignTextProps {
    onSigned?: (result: SignatureResult) => void;
}

function SignTextComponent({ onSigned }: SignTextProps) {
    const [content, setContent] = useState('');
    const { state, sign, reset } = useVouchSign();

    const handleSign = async () => {
        if (!content.trim()) return;

        try {
            const result = await sign(content);
            onSigned?.(result);
        } catch {
            // Error is already in state
        }
    };

    return (
        <div className="vouch-sign-text">
            <h3>📝 Sign Text</h3>

            <textarea
                value={content}
                onChange={(e) => setContent(e.target.value)}
                placeholder="Enter content to sign..."
                rows={4}
                disabled={state.status === 'signing'}
            />

            <div className="actions">
                <button
                    onClick={handleSign}
                    disabled={state.status === 'signing' || !content.trim()}
                >
                    {state.status === 'signing' ? 'Signing...' : '🔐 Sign'}
                </button>

                {state.status !== 'idle' && (
                    <button onClick={reset}>Reset</button>
                )}
            </div>

            {state.status === 'error' && (
                <div className="error">
                    ❌ {state.message}
                </div>
            )}

            {state.status === 'success' && (
                <div className="success">
                    <p>✅ Signed successfully!</p>
                    <p><strong>Signature:</strong> {state.result.signature.slice(0, 24)}...</p>
                    <p><strong>Timestamp:</strong> {state.result.timestamp}</p>
                    {state.result.did && (
                        <p><strong>DID:</strong> {state.result.did}</p>
                    )}
                </div>
            )}
        </div>
    );
}

// ============================================================================
// Sign File Component
// ============================================================================

interface SignFileProps {
    onSigned?: (signedBlob: Blob) => void;
}

function SignFileComponent({ onSigned }: SignFileProps) {
    const [file, setFile] = useState<File | null>(null);
    const [status, setStatus] = useState<'idle' | 'signing' | 'success' | 'error'>('idle');
    const [error, setError] = useState<string>('');

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        setFile(e.target.files?.[0] || null);
        setStatus('idle');
        setError('');
    };

    const handleSign = async () => {
        if (!file) return;

        setStatus('signing');
        const client = new VouchClient();

        try {
            const signedBlob = await client.signBlob(file, file.name, 'react-file-upload');
            setStatus('success');
            onSigned?.(signedBlob);

            // Auto-download
            const url = URL.createObjectURL(signedBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `signed_${file.name}`;
            a.click();
            URL.revokeObjectURL(url);

        } catch (err) {
            setStatus('error');
            setError((err as Error).message);
        }
    };

    return (
        <div className="vouch-sign-file">
            <h3>📁 Sign File</h3>

            <input
                type="file"
                onChange={handleFileChange}
                disabled={status === 'signing'}
            />

            {file && (
                <p>{file.name} ({(file.size / 1024).toFixed(1)} KB)</p>
            )}

            <button
                onClick={handleSign}
                disabled={!file || status === 'signing'}
            >
                {status === 'signing' ? 'Signing...' : '🔐 Sign File'}
            </button>

            {status === 'error' && <div className="error">❌ {error}</div>}
            {status === 'success' && <div className="success">✅ File signed and downloaded!</div>}
        </div>
    );
}

// ============================================================================
// Vouch Status Component
// ============================================================================

function VouchStatusComponent() {
    const [status, setStatus] = useState<'unknown' | 'online' | 'offline'>('unknown');
    const [identity, setIdentity] = useState<{ did: string; fingerprint: string } | null>(null);

    const checkStatus = async () => {
        const client = new VouchClient();

        try {
            await client.connect();
            setStatus('online');

            try {
                const keyInfo = await client.getPublicKey();
                setIdentity({
                    did: keyInfo.did,
                    fingerprint: keyInfo.fingerprint,
                });
            } catch {
                setIdentity(null);
            }

        } catch {
            setStatus('offline');
            setIdentity(null);
        }
    };

    React.useEffect(() => {
        checkStatus();
        const interval = setInterval(checkStatus, 30000); // Check every 30s
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="vouch-status">
            <h3>🔐 Vouch Status</h3>

            <p>
                <strong>Daemon:</strong>{' '}
                {status === 'unknown' && '⏳ Checking...'}
                {status === 'online' && '🟢 Online'}
                {status === 'offline' && '🔴 Offline'}
            </p>

            {identity && (
                <>
                    <p><strong>DID:</strong> {identity.did.slice(0, 24)}...</p>
                    <p><strong>Fingerprint:</strong> {identity.fingerprint}</p>
                </>
            )}

            {status === 'offline' && (
                <p className="hint">Run <code>vouch-bridge</code> to start the daemon</p>
            )}

            <button onClick={checkStatus}>↻ Refresh</button>
        </div>
    );
}

// ============================================================================
// Main App Component
// ============================================================================

function VouchApp() {
    return (
        <div className="vouch-app">
            <h1>Vouch React Integration</h1>

            <VouchStatusComponent />
            <hr />
            <SignTextComponent onSigned={(r) => console.log('Signed:', r)} />
            <hr />
            <SignFileComponent onSigned={(b) => console.log('Signed blob:', b.size, 'bytes')} />
        </div>
    );
}

export {
    VouchApp,
    VouchStatusComponent,
    SignTextComponent,
    SignFileComponent,
    useVouchSign,
};
