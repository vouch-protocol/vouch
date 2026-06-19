/**
 * Example: Error Handling Patterns
 *
 * Demonstrates how to gracefully handle all SDK errors.
 */

import {
    VouchClient,
    VouchError,
    VouchConnectionError,
    NoKeysConfiguredError,
    UserDeniedSignatureError,
} from '@vouch-protocol/sdk';

// ============================================================================
// Pattern 1: Specific Exception Handling
// ============================================================================

async function specificErrorHandling() {
    const client = new VouchClient();

    try {
        const result = await client.sign('Content to sign', 'error-demo');
        console.log('✅ Signed:', result.signature.slice(0, 32) + '...');

    } catch (error) {
        if (error instanceof VouchConnectionError) {
            // Daemon is not running
            console.log('❌ Connection Error:', (error as Error).message);
            console.log('   → Start the daemon: vouch-bridge');

        } else if (error instanceof NoKeysConfiguredError) {
            // No identity set up
            console.log('❌ No Keys Configured:', (error as Error).message);
            console.log('   → Generate keys via the daemon');

        } else if (error instanceof UserDeniedSignatureError) {
            // User clicked "Deny"
            console.log('⚠️ User Denied:', (error as Error).message);
            console.log('   → User chose not to sign');

        } else {
            throw error;
        }
    }
}

// ============================================================================
// Pattern 2: Hierarchical Catch
// ============================================================================

async function hierarchicalCatch() {
    const client = new VouchClient();

    try {
        return await client.sign('Content', 'hierarchical-demo');

    } catch (error) {
        if (error instanceof VouchError) {
            // Catches ALL Vouch SDK errors
            console.log(`Vouch error: ${error.constructor.name}: ${(error as Error).message}`);
            return null;
        }
        throw error;
    }
}

// ============================================================================
// Pattern 3: Retry with Backoff
// ============================================================================

async function retryWithBackoff<T>(
    fn: () => Promise<T>,
    maxRetries = 3,
    baseDelay = 1000
): Promise<T> {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            return await fn();

        } catch (error) {
            if (error instanceof VouchConnectionError) {
                if (attempt < maxRetries) {
                    const delay = baseDelay * Math.pow(2, attempt - 1);
                    console.log(`⚠️ Attempt ${attempt} failed, retrying in ${delay}ms...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                } else {
                    throw error;
                }
            } else {
                // Don't retry non-connection errors
                throw error;
            }
        }
    }
    throw new Error('Retry logic error');
}

async function retryExample() {
    const client = new VouchClient();

    const result = await retryWithBackoff(
        () => client.sign('Important content', 'retry-demo'),
        3,
        1000
    );

    console.log('✅ Succeeded after retries');
    return result;
}

// ============================================================================
// Pattern 4: Fallback to Unsigned
// ============================================================================

interface SignedContent {
    content: string;
    signature: string | null;
    signed: boolean;
    reason?: string;
}

async function signWithFallback(content: string): Promise<SignedContent> {
    const client = new VouchClient();

    try {
        const result = await client.sign(content, 'fallback-demo');
        return {
            content,
            signature: result.signature,
            signed: true,
        };

    } catch (error) {
        let reason: string;

        if (error instanceof VouchConnectionError) {
            reason = 'daemon_offline';
            console.log('⚠️ Daemon offline - proceeding without signature');

        } else if (error instanceof NoKeysConfiguredError) {
            reason = 'no_identity';
            console.log('⚠️ No identity - proceeding as anonymous');

        } else if (error instanceof UserDeniedSignatureError) {
            reason = 'user_declined';
            console.log('⚠️ User declined - proceeding unsigned');

        } else {
            throw error;
        }

        return {
            content,
            signature: null,
            signed: false,
            reason,
        };
    }
}

// ============================================================================
// Pattern 5: Type-Safe Result
// ============================================================================

type SignResult =
    | { success: true; signature: string; did: string }
    | { success: false; error: string; errorType: string };

async function signSafe(content: string): Promise<SignResult> {
    const client = new VouchClient();

    try {
        const result = await client.sign(content, 'safe-demo');
        return {
            success: true,
            signature: result.signature,
            did: result.did || '',
        };

    } catch (error) {
        return {
            success: false,
            error: (error as Error).message,
            errorType: error instanceof VouchError ? error.constructor.name : 'UnknownError',
        };
    }
}

// ============================================================================
// Pattern 6: Promise.allSettled for Batch
// ============================================================================

async function batchSignWithErrors(items: string[]) {
    const client = new VouchClient();

    const results = await Promise.allSettled(
        items.map((item, i) =>
            client.sign(item, 'batch', { index: i })
        )
    );

    const succeeded = results.filter(r => r.status === 'fulfilled');
    const failed = results.filter(r => r.status === 'rejected');

    console.log(`✅ Signed: ${succeeded.length}/${results.length}`);
    console.log(`❌ Failed: ${failed.length}/${results.length}`);

    return results;
}

// ============================================================================
// Main
// ============================================================================

async function main() {
    console.log('\n🛡️ Example 1: Specific error handling');
    await specificErrorHandling();

    console.log('\n🛡️ Example 2: Hierarchical catch');
    await hierarchicalCatch();

    console.log('\n🛡️ Example 3: Sign with fallback');
    const result = await signWithFallback('Fallback test content');
    console.log(`   Result: signed=${result.signed}`);

    console.log('\n🛡️ Example 4: Type-safe result');
    const safeResult = await signSafe('Safe test content');
    console.log(`   Success: ${safeResult.success}`);
}

main();
