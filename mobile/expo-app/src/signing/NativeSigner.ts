/**
 * NativeSigner - Bridge to Vouch Protocol signing
 * 
 * Uses:
 * - expo-crypto for Ed25519 operations
 * - expo-secure-store for key storage
 */

import * as SecureStore from 'expo-secure-store';

export interface SignerIdentity {
    did: string;
    displayName: string;
    email?: string;
    credentialType: 'FREE' | 'PRO' | 'ORG';
    organizationDid?: string; // For org-endorsed signing
}

export interface SignatureResult {
    success: boolean;
    signature?: string;
    chainId?: string;
    timestamp?: string;
    verifyUrl?: string;
    error?: string;
}

const KEY_STORAGE_KEY = 'vouch_private_key';
const DID_STORAGE_KEY = 'vouch_did';

/**
 * Generate or retrieve stored keypair
 */
export async function getOrCreateKeypair(): Promise<{ privateKey: string; did: string }> {
    // Check for existing key
    const existingKey = await SecureStore.getItemAsync(KEY_STORAGE_KEY);
    const existingDid = await SecureStore.getItemAsync(DID_STORAGE_KEY);

    if (existingKey && existingDid) {
        return { privateKey: existingKey, did: existingDid };
    }

    // Generate new keypair (would use expo-crypto)
    // For now, placeholder
    const privateKey = 'generated_key_placeholder';
    const did = `did:key:z6Mk${Date.now()}`;

    // Store securely
    await SecureStore.setItemAsync(KEY_STORAGE_KEY, privateKey);
    await SecureStore.setItemAsync(DID_STORAGE_KEY, did);

    return { privateKey, did };
}

/**
 * Sign image at capture time
 */
export async function signImage(
    imageBase64: string,
    identity: SignerIdentity
): Promise<SignatureResult> {
    try {
        const { privateKey, did } = await getOrCreateKeypair();

        // Compute hash
        const imageHash = await computeHash(imageBase64);

        // Create timestamp
        const timestamp = new Date().toISOString();

        // Generate chain ID
        const chainId = `vouch:chain:${imageHash.slice(0, 12)}`;

        // Sign payload (would use expo-crypto Ed25519)
        const signature = await signPayload(privateKey, {
            imageHash,
            did,
            displayName: identity.displayName,
            email: identity.email,
            timestamp,
            credentialType: identity.credentialType,
        });

        return {
            success: true,
            signature,
            chainId,
            timestamp,
            verifyUrl: `https://vch.sh/${imageHash.slice(0, 8)}`,
        };
    } catch (error) {
        return {
            success: false,
            error: error instanceof Error ? error.message : 'Unknown error',
        };
    }
}

/**
 * Add organization endorsement to signature chain
 */
export async function addOrgEndorsement(
    existingSignature: string,
    orgIdentity: SignerIdentity
): Promise<SignatureResult> {
    // Organization adds their signature to the chain
    // This creates: Creator -> Organization trust chain

    const { privateKey } = await getOrCreateKeypair();

    const endorsement = await signPayload(privateKey, {
        parentSignature: existingSignature,
        endorserDid: orgIdentity.did,
        endorserName: orgIdentity.displayName,
        endorsementType: 'approved',
        timestamp: new Date().toISOString(),
    });

    return {
        success: true,
        signature: endorsement,
        timestamp: new Date().toISOString(),
    };
}

// Helper functions (would be implemented with expo-crypto)
async function computeHash(data: string): Promise<string> {
    // Placeholder - would use expo-crypto
    return `hash_${data.length}_${Date.now()}`;
}

async function signPayload(privateKey: string, payload: object): Promise<string> {
    // Placeholder - would use expo-crypto Ed25519
    return `sig_${JSON.stringify(payload).length}`;
}

export default { signImage, getOrCreateKeypair, addOrgEndorsement };
