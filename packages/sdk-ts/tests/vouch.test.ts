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

    test('should return correct DID', () => {
        const signer = new Signer({ privateKey: privateKeyJwk, did });
        expect(signer.getDid()).toBe(did);
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
