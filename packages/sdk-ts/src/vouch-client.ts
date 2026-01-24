/**
 * Vouch SDK - TypeScript Client
 * 
 * A clean, environment-agnostic client library for communicating with the
 * Vouch Bridge Daemon. Works in both Browser (fetch) and Node.js (http).
 * 
 * @example
 * ```typescript
 * import { VouchClient } from '@vouch-protocol/sdk';
 * 
 * const client = new VouchClient();
 * 
 * if (await client.connect()) {
 *     const result = await client.sign("Hello, World!", { origin: "my-app" });
 *     console.log(result.signature);
 * }
 * ```
 * 
 * @author Ramprasad Anandam Gaddam
 * @license MIT
 */

// =============================================================================
// Types & Interfaces
// =============================================================================

/**
 * Configuration options for VouchClient.
 */
export interface VouchClientConfig {
    /** Daemon URL (default: http://127.0.0.1:21000) */
    daemonUrl?: string;

    /** Connection timeout in milliseconds (default: 5000) */
    timeout?: number;

    /** Request timeout in milliseconds (default: 120000 for media) */
    requestTimeout?: number;
}

/**
 * Response from /status endpoint.
 */
export interface DaemonStatus {
    status: string;
    version: string;
    has_keys: boolean;
    public_key_fingerprint: string | null;
}

/**
 * Response from /keys/public endpoint.
 */
export interface PublicKeyInfo {
    public_key: string;
    did: string;
    fingerprint: string;
}

/**
 * Metadata for signing requests.
 */
export interface SignMetadata {
    /** The origin/application name requesting the signature */
    origin?: string;

    /** Additional metadata to include */
    [key: string]: unknown;
}

/**
 * Response from /sign endpoint.
 */
export interface SignResult {
    signature: string;
    public_key: string;
    did: string;
    timestamp: string;
    content_hash: string;
}

/**
 * Response headers from /sign-media endpoint.
 */
export interface MediaSignResult {
    /** The signed file as a Blob (browser) or Buffer (Node.js) */
    data: Blob | Buffer;

    /** Signer's DID */
    did: string;

    /** Signature timestamp */
    timestamp: string;

    /** Content hash */
    hash: string;

    /** Suggested filename for the signed file */
    filename: string;

    /** MIME type of the signed file */
    mimeType: string;
}

// =============================================================================
// Error Classes
// =============================================================================

/**
 * Thrown when the user denies the signature request via the consent popup.
 */
export class UserDeniedSignatureError extends Error {
    constructor(message = 'User denied the signature request') {
        super(message);
        this.name = 'UserDeniedSignatureError';
    }
}

/**
 * Thrown when the daemon is not available or connection fails.
 */
export class DaemonNotAvailableError extends Error {
    constructor(message = 'Vouch Daemon is not available') {
        super(message);
        this.name = 'DaemonNotAvailableError';
    }
}

/**
 * Thrown when no keys are configured in the daemon.
 */
export class NoKeysConfiguredError extends Error {
    constructor(message = 'No keys configured. Call daemon /keys/generate first.') {
        super(message);
        this.name = 'NoKeysConfiguredError';
    }
}

// =============================================================================
// Environment Detection
// =============================================================================

const isBrowser = typeof window !== 'undefined' && typeof window.fetch === 'function';
const isNode = typeof globalThis.process !== 'undefined' &&
    globalThis.process.versions?.node !== undefined;

// =============================================================================
// VouchClient Class
// =============================================================================

/**
 * VouchClient - Main client for interacting with the Vouch Daemon.
 * 
 * Environment-agnostic: works in both Browser and Node.js.
 */
export class VouchClient {
    private config: Required<VouchClientConfig>;
    private _isConnected: boolean = false;
    private _daemonStatus: DaemonStatus | null = null;

    /**
     * Create a new VouchClient instance.
     * 
     * @param config - Optional configuration
     */
    constructor(config: VouchClientConfig = {}) {
        this.config = {
            daemonUrl: config.daemonUrl ?? 'http://127.0.0.1:21000',
            timeout: config.timeout ?? 5000,
            requestTimeout: config.requestTimeout ?? 120000,
        };
    }

    // =========================================================================
    // Connection Status
    // =========================================================================

    /**
     * Whether the client is connected to the daemon.
     */
    get isConnected(): boolean {
        return this._isConnected;
    }

    /**
     * The last known daemon status.
     */
    get daemonStatus(): DaemonStatus | null {
        return this._daemonStatus;
    }

    // =========================================================================
    // Core Methods
    // =========================================================================

    /**
     * Connect to the Vouch Daemon.
     * 
     * Attempts to connect to http://127.0.0.1:21000/status.
     * Sets isConnected based on success.
     * 
     * @returns true if connected, false if connection failed
     */
    async connect(): Promise<boolean> {
        try {
            const response = await this.fetch('/status', {
                method: 'GET',
                timeout: this.config.timeout,
            });

            if (!response.ok) {
                this._isConnected = false;
                return false;
            }

            const status = await response.json() as DaemonStatus;

            if (status.status === 'ok') {
                this._isConnected = true;
                this._daemonStatus = status;
                return true;
            }

            this._isConnected = false;
            return false;
        } catch (error) {
            // Connection refused or network error
            this._isConnected = false;
            this._daemonStatus = null;
            return false;
        }
    }

    /**
     * Sign text content with the user's private key.
     * 
     * IMPORTANT: This triggers a user consent popup in the daemon.
     * 
     * @param content - The content to sign
     * @param metadata - Optional metadata (origin, etc.)
     * @returns Signature result
     * @throws {UserDeniedSignatureError} If user denies via popup
     * @throws {DaemonNotAvailableError} If not connected
     * @throws {NoKeysConfiguredError} If no keys are configured
     */
    async sign(content: string, metadata: SignMetadata = {}): Promise<SignResult> {
        this.ensureConnected();

        const body = {
            content,
            origin: metadata.origin ?? this.detectOrigin(),
            ...metadata,
        };

        const response = await this.fetch('/sign', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
            timeout: this.config.requestTimeout,
        });

        // Handle errors
        if (response.status === 403) {
            throw new UserDeniedSignatureError();
        }

        if (response.status === 404) {
            throw new NoKeysConfiguredError();
        }

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `Signing failed: ${response.status}`);
        }

        return response.json() as Promise<SignResult>;
    }

    /**
     * Sign a binary file (image, video, audio, PDF).
     * 
     * IMPORTANT: This triggers a user consent popup with media preview.
     * 
     * @param file - The file to sign (Blob in browser, Buffer in Node.js)
     * @param filename - The filename (used for MIME detection)
     * @param metadata - Optional metadata (origin, etc.)
     * @returns The signed file with metadata
     * @throws {UserDeniedSignatureError} If user denies via popup
     * @throws {DaemonNotAvailableError} If not connected
     * @throws {NoKeysConfiguredError} If no keys are configured
     */
    async signBlob(
        file: Blob | Buffer,
        filename: string,
        metadata: SignMetadata = {}
    ): Promise<MediaSignResult> {
        this.ensureConnected();

        const origin = metadata.origin ?? this.detectOrigin();

        // Build FormData
        const formData = await this.createFormData(file, filename, origin);

        const response = await this.fetch('/sign-media', {
            method: 'POST',
            body: formData,
            timeout: this.config.requestTimeout,
        });

        // Handle errors
        if (response.status === 403) {
            throw new UserDeniedSignatureError();
        }

        if (response.status === 404) {
            throw new NoKeysConfiguredError();
        }

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `Media signing failed: ${response.status}`);
        }

        // Extract metadata from headers
        const did = response.headers.get('X-Vouch-DID') || '';
        const timestamp = response.headers.get('X-Vouch-Timestamp') || '';
        const hash = response.headers.get('X-Vouch-Hash') || '';
        const contentDisposition = response.headers.get('Content-Disposition') || '';
        const mimeType = response.headers.get('Content-Type') || 'application/octet-stream';

        // Parse filename from Content-Disposition
        const filenameMatch = contentDisposition.match(/filename="?([^"]+)"?/);
        const signedFilename = filenameMatch?.[1] || `signed_${filename}`;

        // Get file data
        let data: Blob | Buffer;
        if (isBrowser) {
            data = await response.blob();
        } else {
            const arrayBuffer = await response.arrayBuffer();
            data = Buffer.from(arrayBuffer);
        }

        return {
            data,
            did,
            timestamp,
            hash,
            filename: signedFilename,
            mimeType,
        };
    }

    /**
     * Get the user's public key and DID.
     * 
     * @returns Public key information
     * @throws {DaemonNotAvailableError} If not connected
     * @throws {NoKeysConfiguredError} If no keys are configured
     */
    async getPublicKey(): Promise<PublicKeyInfo> {
        this.ensureConnected();

        const response = await this.fetch('/keys/public', {
            method: 'GET',
            timeout: this.config.timeout,
        });

        if (response.status === 404) {
            throw new NoKeysConfiguredError();
        }

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || 'Failed to get public key');
        }

        return response.json() as Promise<PublicKeyInfo>;
    }

    /**
     * Disconnect from the daemon.
     */
    disconnect(): void {
        this._isConnected = false;
        this._daemonStatus = null;
    }

    // =========================================================================
    // Private Helpers
    // =========================================================================

    /**
     * Ensure the client is connected before making requests.
     */
    private ensureConnected(): void {
        if (!this._isConnected) {
            throw new DaemonNotAvailableError('Not connected. Call connect() first.');
        }
    }

    /**
     * Detect the origin for signing requests.
     */
    private detectOrigin(): string {
        if (isBrowser && typeof window.location !== 'undefined') {
            return window.location.origin;
        }
        if (isNode && process.env.npm_package_name) {
            return process.env.npm_package_name;
        }
        return 'vouch-sdk-ts';
    }

    /**
     * Create FormData for file uploads.
     * Works in both browser and Node.js.
     */
    private async createFormData(
        file: Blob | Buffer,
        filename: string,
        origin: string
    ): Promise<FormData> {
        const formData = new FormData();

        if (isBrowser) {
            // Browser: file is already a Blob
            formData.append('file', file as Blob, filename);
        } else {
            // Node.js: convert Buffer to Blob
            const blob = new Blob([file as Buffer], { type: this.getMimeType(filename) });
            formData.append('file', blob, filename);
        }

        formData.append('origin', origin);
        return formData;
    }

    /**
     * Get MIME type from filename extension.
     */
    private getMimeType(filename: string): string {
        const ext = filename.split('.').pop()?.toLowerCase() || '';
        const mimeTypes: Record<string, string> = {
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'png': 'image/png',
            'gif': 'image/gif',
            'webp': 'image/webp',
            'heic': 'image/heic',
            'heif': 'image/heif',
            'avif': 'image/avif',
            'mp4': 'video/mp4',
            'mov': 'video/quicktime',
            'mp3': 'audio/mpeg',
            'wav': 'audio/wav',
            'pdf': 'application/pdf',
        };
        return mimeTypes[ext] || 'application/octet-stream';
    }

    /**
     * Environment-agnostic fetch with timeout support.
     */
    private async fetch(
        path: string,
        options: RequestInit & { timeout?: number } = {}
    ): Promise<Response> {
        const url = `${this.config.daemonUrl}${path}`;
        const timeout = options.timeout ?? this.config.timeout;

        // Create AbortController for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        try {
            const response = await fetch(url, {
                ...options,
                signal: controller.signal,
            });
            return response;
        } finally {
            clearTimeout(timeoutId);
        }
    }
}

// =============================================================================
// Default Export
// =============================================================================

export default VouchClient;

// =============================================================================
// Browser Global (for non-module usage)
// =============================================================================

if (typeof window !== 'undefined') {
    (window as unknown as Record<string, unknown>).VouchClient = VouchClient;
    (window as unknown as Record<string, unknown>).UserDeniedSignatureError = UserDeniedSignatureError;
}
