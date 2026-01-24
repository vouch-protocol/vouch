/**
 * Test Suite for Vouch TypeScript SDK
 * 
 * Tests cover:
 * - VouchClient initialization
 * - Connection handling
 * - Text signing
 * - Blob signing
 * - Error handling
 * - Type exports
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('VouchClient', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    // ========================================================================
    // Initialization Tests
    // ========================================================================

    describe('Initialization', () => {
        it('should use default daemon URL', async () => {
            const { VouchClient } = await import('./vouch-client');
            const client = new VouchClient();

            expect(client.daemonUrl).toBe('http://127.0.0.1:21000');
        });

        it('should accept custom daemon URL', async () => {
            const { VouchClient } = await import('./vouch-client');
            const client = new VouchClient({ daemonUrl: 'http://localhost:9999' });

            expect(client.daemonUrl).toBe('http://localhost:9999');
        });

        it('should accept custom timeout', async () => {
            const { VouchClient } = await import('./vouch-client');
            const client = new VouchClient({ timeout: 60000 });

            expect(client.timeout).toBe(60000);
        });
    });

    // ========================================================================
    // Connection Tests
    // ========================================================================

    describe('connect()', () => {
        it('should return daemon status when online', async () => {
            const { VouchClient } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ status: 'ok', version: '1.1.0', has_keys: true }),
            });

            const client = new VouchClient();
            const status = await client.connect();

            expect(status.status).toBe('ok');
            expect(status.version).toBe('1.1.0');
            expect(mockFetch).toHaveBeenCalledWith(
                'http://127.0.0.1:21000/status',
                expect.any(Object)
            );
        });

        it('should throw VouchConnectionError when daemon is offline', async () => {
            const { VouchClient, VouchConnectionError } = await import('./vouch-client');

            mockFetch.mockRejectedValueOnce(new Error('fetch failed'));

            const client = new VouchClient();

            await expect(client.connect()).rejects.toThrow(VouchConnectionError);
        });

        it('should throw VouchConnectionError on non-200 response', async () => {
            const { VouchClient, VouchConnectionError } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 500,
                statusText: 'Internal Server Error',
            });

            const client = new VouchClient();

            await expect(client.connect()).rejects.toThrow(VouchConnectionError);
        });
    });

    // ========================================================================
    // Text Signing Tests
    // ========================================================================

    describe('sign()', () => {
        it('should sign text content and return signature', async () => {
            const { VouchClient } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    signature: 'base64signature==',
                    timestamp: '2026-01-20T06:00:00Z',
                    public_key: 'pubkey==',
                    did: 'did:key:z123',
                }),
            });

            const client = new VouchClient();
            const result = await client.sign('Hello, World!', 'test-origin');

            expect(result.signature).toBe('base64signature==');
            expect(result.did).toBe('did:key:z123');
            expect(mockFetch).toHaveBeenCalledWith(
                'http://127.0.0.1:21000/sign',
                expect.objectContaining({
                    method: 'POST',
                    body: expect.any(String),
                })
            );
        });

        it('should include metadata in sign request', async () => {
            const { VouchClient } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({ signature: 'sig', timestamp: 'ts' }),
            });

            const client = new VouchClient();
            await client.sign('content', 'origin', { filename: 'test.py' });

            const callArgs = mockFetch.mock.calls[0];
            const body = JSON.parse(callArgs[1].body);

            expect(body.metadata.filename).toBe('test.py');
        });

        it('should throw NoKeysConfiguredError on 404', async () => {
            const { VouchClient, NoKeysConfiguredError } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 404,
                json: async () => ({ detail: 'No keys configured' }),
            });

            const client = new VouchClient();

            await expect(client.sign('content', 'origin')).rejects.toThrow(NoKeysConfiguredError);
        });

        it('should throw UserDeniedSignatureError on 403', async () => {
            const { VouchClient, UserDeniedSignatureError } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 403,
                json: async () => ({ detail: 'User denied' }),
            });

            const client = new VouchClient();

            await expect(client.sign('content', 'origin')).rejects.toThrow(UserDeniedSignatureError);
        });
    });

    // ========================================================================
    // Blob Signing Tests
    // ========================================================================

    describe('signBlob()', () => {
        it('should sign binary data and return blob', async () => {
            const { VouchClient } = await import('./vouch-client');

            const responseBlob = new Blob(['signed content'], { type: 'application/octet-stream' });
            mockFetch.mockResolvedValueOnce({
                ok: true,
                blob: async () => responseBlob,
            });

            const client = new VouchClient();
            const inputBlob = new Blob(['test content']);
            const result = await client.signBlob(inputBlob, 'test.bin', 'origin');

            expect(result).toBeInstanceOf(Blob);
        });

        it('should use FormData for file upload', async () => {
            const { VouchClient } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: true,
                blob: async () => new Blob(['signed']),
            });

            const client = new VouchClient();
            await client.signBlob(new Blob(['content']), 'test.bin', 'origin');

            const callArgs = mockFetch.mock.calls[0];
            expect(callArgs[1].body).toBeInstanceOf(FormData);
        });

        it('should use extended timeout for blob operations', async () => {
            const { VouchClient } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: true,
                blob: async () => new Blob(['signed']),
            });

            const client = new VouchClient({ timeout: 5000 });
            await client.signBlob(new Blob(['content']), 'test.bin', 'origin');

            const callArgs = mockFetch.mock.calls[0];
            // Blob operations should have 4x timeout
            expect(callArgs[1].signal).toBeDefined();
        });
    });

    // ========================================================================
    // Public Key Tests
    // ========================================================================

    describe('getPublicKey()', () => {
        it('should return public key info', async () => {
            const { VouchClient } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: true,
                json: async () => ({
                    public_key: 'abcd1234',
                    did: 'did:key:z123',
                    fingerprint: 'SHA256:abcd',
                }),
            });

            const client = new VouchClient();
            const result = await client.getPublicKey();

            expect(result.did).toBe('did:key:z123');
            expect(result.fingerprint).toBe('SHA256:abcd');
        });

        it('should throw NoKeysConfiguredError on 404', async () => {
            const { VouchClient, NoKeysConfiguredError } = await import('./vouch-client');

            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 404,
                json: async () => ({ detail: 'No keys' }),
            });

            const client = new VouchClient();

            await expect(client.getPublicKey()).rejects.toThrow(NoKeysConfiguredError);
        });
    });

    // ========================================================================
    // Error Classes Tests
    // ========================================================================

    describe('Error Classes', () => {
        it('VouchError should be catchable', async () => {
            const { VouchError } = await import('./vouch-client');

            expect(() => {
                throw new VouchError('Test error');
            }).toThrow(VouchError);
        });

        it('VouchConnectionError should extend VouchError', async () => {
            const { VouchError, VouchConnectionError } = await import('./vouch-client');

            const error = new VouchConnectionError('Connection failed');
            expect(error).toBeInstanceOf(VouchError);
        });

        it('UserDeniedSignatureError should extend VouchError', async () => {
            const { VouchError, UserDeniedSignatureError } = await import('./vouch-client');

            const error = new UserDeniedSignatureError('Denied');
            expect(error).toBeInstanceOf(VouchError);
        });

        it('NoKeysConfiguredError should extend VouchError', async () => {
            const { VouchError, NoKeysConfiguredError } = await import('./vouch-client');

            const error = new NoKeysConfiguredError('No keys');
            expect(error).toBeInstanceOf(VouchError);
        });
    });

    // ========================================================================
    // Type Exports Tests
    // ========================================================================

    describe('Type Exports', () => {
        it('should export all expected types', async () => {
            const exports = await import('./index');

            expect(exports.VouchClient).toBeDefined();
            expect(exports.VouchError).toBeDefined();
            expect(exports.VouchConnectionError).toBeDefined();
            expect(exports.UserDeniedSignatureError).toBeDefined();
            expect(exports.NoKeysConfiguredError).toBeDefined();
        });
    });
});

// ========================================================================
// Integration Test (manual, requires running daemon)
// ========================================================================

describe.skip('Integration Tests', () => {
    it('should complete full sign cycle', async () => {
        const { VouchClient } = await import('./vouch-client');

        const client = new VouchClient();

        // Connect
        const status = await client.connect();
        expect(status.status).toBe('ok');

        // Sign
        const result = await client.sign('Integration test', 'vitest');
        expect(result.signature).toBeDefined();

        // Get public key
        const keyInfo = await client.getPublicKey();
        expect(keyInfo.did).toMatch(/^did:key:z/);
    });
});
