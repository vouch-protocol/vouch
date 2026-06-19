/**
 * Vouch Protocol TypeScript SDK Tests
 */

import { Signer, Verifier, generateIdentity } from '../src';

describe('Signer', () => {
    let privateKeyJwk: string;
    let publicKeyJwk: string;
    let did: string;

    beforeAll(async () => {
        const keys = await generateIdentity('test-agent.example.com');
        privateKeyJwk = keys.privateKeyJwk;
        publicKeyJwk = keys.publicKeyJwk;
        did = keys.did!;
    });

    test('should create signer with valid keys', () => {
        expect(() => {
            new Signer({ privateKey: privateKeyJwk, did });
        }).not.toThrow();
    });

    test('should throw on missing private key', () => {
        expect(() => {
            new Signer({ privateKey: '', did });
        }).toThrow('privateKey is required');
    });

    test('should throw on missing DID', () => {
        expect(() => {
            new Signer({ privateKey: privateKeyJwk, did: '' });
        }).toThrow('did is required');
    });

    test('should sign payload and return JWS token', async () => {
        const signer = new Signer({ privateKey: privateKeyJwk, did });
        const token = await signer.sign({ action: 'test' });

        expect(typeof token).toBe('string');
        expect(token.split('.')).toHaveLength(3);
    });

    test('should produce unique tokens for same payload', async () => {
        const signer = new Signer({ privateKey: privateKeyJwk, did });
        const token1 = await signer.sign({ action: 'test' });
        const token2 = await signer.sign({ action: 'test' });

        expect(token1).not.toBe(token2);
    });

    test('should return correct DID', () => {
        const signer = new Signer({ privateKey: privateKeyJwk, did });
        expect(signer.getDid()).toBe(did);
    });
});

describe('Verifier', () => {
    let privateKeyJwk: string;
    let publicKeyJwk: string;
    let did: string;
    let signer: Signer;

    beforeAll(async () => {
        const keys = await generateIdentity('test-agent.example.com');
        privateKeyJwk = keys.privateKeyJwk;
        publicKeyJwk = keys.publicKeyJwk;
        did = keys.did!;
        signer = new Signer({ privateKey: privateKeyJwk, did });
    });

    test('should verify valid token', async () => {
        const token = await signer.sign({ action: 'test' });
        const result = await Verifier.verify(token, publicKeyJwk);

        expect(result.isValid).toBe(true);
        expect(result.passport).not.toBeNull();
        expect(result.passport?.sub).toBe(did);
        expect(result.passport?.iss).toBe(did);
    });

    test('should return passport with correct payload', async () => {
        const payload = { action: 'read_database', target: 'users' };
        const token = await signer.sign(payload);
        const result = await Verifier.verify(token, publicKeyJwk);

        expect(result.passport?.payload).toEqual(payload);
    });

    test('should reject empty token', async () => {
        const result = await Verifier.verify('');

        expect(result.isValid).toBe(false);
        expect(result.passport).toBeNull();
    });

    test('should reject malformed token', async () => {
        const result = await Verifier.verify('not.a.valid.token', publicKeyJwk);

        expect(result.isValid).toBe(false);
    });

    test('should reject token with wrong public key', async () => {
        const otherKeys = await generateIdentity('other-agent.com');
        const token = await signer.sign({ action: 'test' });

        const result = await Verifier.verify(token, otherKeys.publicKeyJwk);

        expect(result.isValid).toBe(false);
    });
});

describe('Verifier with trusted roots', () => {
    let privateKeyJwk: string;
    let publicKeyJwk: string;
    let did: string;
    let signer: Signer;

    beforeAll(async () => {
        const keys = await generateIdentity('trusted-agent.example.com');
        privateKeyJwk = keys.privateKeyJwk;
        publicKeyJwk = keys.publicKeyJwk;
        did = keys.did!;
        signer = new Signer({ privateKey: privateKeyJwk, did });
    });

    test('should verify with trusted roots', async () => {
        const verifier = new Verifier({
            trustedRoots: { [did]: publicKeyJwk }
        });

        const token = await signer.sign({ action: 'test' });
        const result = await verifier.checkVouch(token);

        expect(result.isValid).toBe(true);
    });

    test('should reject unknown issuer', async () => {
        const verifier = new Verifier({
            trustedRoots: {} // No trusted roots
        });

        const token = await signer.sign({ action: 'test' });
        const result = await verifier.checkVouch(token);

        expect(result.isValid).toBe(false);
        expect(result.error).toContain('Unknown issuer');
    });

    test('should allow adding trusted roots dynamically', async () => {
        const verifier = new Verifier();
        const token = await signer.sign({ action: 'test' });

        // Should fail initially
        let result = await verifier.checkVouch(token);
        expect(result.isValid).toBe(false);

        // Add trusted root
        verifier.addTrustedRoot(did, publicKeyJwk);

        // Should succeed now
        result = await verifier.checkVouch(token);
        expect(result.isValid).toBe(true);
    });
});

describe('generateIdentity', () => {
    test('should generate unique keypairs', async () => {
        const keys1 = await generateIdentity();
        const keys2 = await generateIdentity();

        expect(keys1.privateKeyJwk).not.toBe(keys2.privateKeyJwk);
    });

    test('should generate DID with domain', async () => {
        const keys = await generateIdentity('example.com');
        expect(keys.did).toBe('did:web:example.com');
    });

    test('should return null DID without domain', async () => {
        const keys = await generateIdentity();
        expect(keys.did).toBeNull();
    });

    test('should produce valid JWK format', async () => {
        const keys = await generateIdentity();
        const jwk = JSON.parse(keys.privateKeyJwk);

        expect(jwk.kty).toBe('OKP');
        expect(jwk.crv).toBe('Ed25519');
        expect(jwk.x).toBeDefined();
        expect(jwk.d).toBeDefined(); // Private key component
    });
});
