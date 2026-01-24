/**
 * Example: Sign Text Content
 *
 * Demonstrates signing arbitrary text (code, documents, messages).
 */

import {
    VouchClient,
    VouchConnectionError,
    NoKeysConfiguredError,
    UserDeniedSignatureError,
} from '@vouch-protocol/sdk';

async function signBasicText() {
    const client = new VouchClient();

    const content = 'Hello, World! This text was signed by Vouch.';

    const result = await client.sign(content, 'typescript-example');

    console.log('✅ Content signed successfully!');
    console.log(`   Signature: ${result.signature.slice(0, 32)}...`);
    console.log(`   Timestamp: ${result.timestamp}`);
    console.log(`   DID: ${result.did || 'N/A'}`);
}

async function signCodeWithMetadata() {
    const client = new VouchClient();

    const code = `
function fibonacci(n: number): number {
  if (n <= 1) return n;
  return fibonacci(n - 1) + fibonacci(n - 2);
}
`;

    // Include metadata about the code
    const result = await client.sign(code, 'ide-plugin', {
        filename: 'fibonacci.ts',
        language: 'typescript',
        version: '1.0.0',
    });

    console.log('✅ Code signed with metadata!');
    console.log(`   Signature: ${result.signature.slice(0, 32)}...`);
}

async function signJsonDocument() {
    const client = new VouchClient();

    const document = {
        type: 'invoice',
        number: 'INV-2026-001',
        amount: 1500.0,
        currency: 'USD',
        items: [
            { description: 'Consulting', price: 1000 },
            { description: 'Support', price: 500 },
        ],
    };

    // Convert to JSON (sorted for reproducibility)
    const content = JSON.stringify(document, Object.keys(document).sort());

    const result = await client.sign(content, 'billing-system', {
        documentType: 'invoice',
    });

    console.log('✅ JSON document signed!');
    console.log(`   Document: ${document.type} #${document.number}`);
}

async function main() {
    try {
        console.log('\n📝 Example 1: Basic text signing');
        await signBasicText();

        console.log('\n📝 Example 2: Sign code with metadata');
        await signCodeWithMetadata();

        console.log('\n📝 Example 3: Sign JSON document');
        await signJsonDocument();

    } catch (error) {
        if (error instanceof VouchConnectionError) {
            console.log('❌ Daemon not running. Start with: vouch-bridge');
        } else if (error instanceof NoKeysConfiguredError) {
            console.log('❌ No keys configured. Generate via daemon.');
        } else if (error instanceof UserDeniedSignatureError) {
            console.log('⚠️ You declined to sign in the popup.');
        } else {
            throw error;
        }
    }
}

main();
