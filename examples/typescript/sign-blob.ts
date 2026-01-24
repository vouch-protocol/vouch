/**
 * Example: Sign Binary Data (Blob/File)
 *
 * Demonstrates signing files and binary data using the SDK.
 */

import { VouchClient, VouchConnectionError } from '@vouch-protocol/sdk';
import * as fs from 'fs';
import * as path from 'path';

// ============================================================================
// Browser Environment (using Blob/File API)
// ============================================================================

async function signBlobInBrowser() {
    const client = new VouchClient();

    // Create a Blob (simulating file input)
    const content = new TextEncoder().encode('File content to sign');
    const blob = new Blob([content], { type: 'text/plain' });

    // Sign the blob
    const signedBlob = await client.signBlob(blob, 'document.txt', 'browser-example');

    console.log('✅ Blob signed!');
    console.log(`   Original size: ${blob.size} bytes`);
    console.log(`   Signed size: ${signedBlob.size} bytes`);

    return signedBlob;
}

async function signFileFromInput(file: File) {
    /**
     * Use this with <input type="file">:
     *
     * const input = document.querySelector('input[type="file"]');
     * input.addEventListener('change', async (e) => {
     *   const file = e.target.files[0];
     *   const signed = await signFileFromInput(file);
     *   // Download or upload the signed file
     * });
     */
    const client = new VouchClient();

    const signedBlob = await client.signBlob(file, file.name, 'file-upload');

    // Create a download link
    const url = URL.createObjectURL(signedBlob);
    console.log(`✅ Signed file URL: ${url}`);

    return signedBlob;
}

// ============================================================================
// Node.js Environment (using fs)
// ============================================================================

async function signFileInNode() {
    const client = new VouchClient();

    const filePath = path.join(__dirname, 'sample.txt');

    // Create a sample file
    if (!fs.existsSync(filePath)) {
        fs.writeFileSync(filePath, 'Sample content for Node.js signing test');
    }

    // Read file as buffer
    const fileBuffer = fs.readFileSync(filePath);

    // Convert to Blob (Node.js 18+ has Blob)
    const blob = new Blob([fileBuffer], { type: 'text/plain' });

    // Sign
    const signedBlob = await client.signBlob(blob, 'sample.txt', 'node-example');

    // Convert back to buffer and save
    const signedBuffer = Buffer.from(await signedBlob.arrayBuffer());
    const outputPath = filePath.replace('.txt', '_signed.txt');
    fs.writeFileSync(outputPath, signedBuffer);

    console.log(`✅ Node.js file signed: ${outputPath}`);
    console.log(`   Original: ${fileBuffer.length} bytes`);
    console.log(`   Signed: ${signedBuffer.length} bytes`);
}

async function signLargeFile() {
    const client = new VouchClient({ timeout: 60000 }); // 60s timeout for large files

    // Create a 5MB test file
    const largeContent = Buffer.alloc(5 * 1024 * 1024, 'X');
    const blob = new Blob([largeContent]);

    console.log('Signing 5MB file...');
    const startTime = Date.now();

    const signedBlob = await client.signBlob(blob, 'large-file.bin', 'large-file-test');

    const elapsed = Date.now() - startTime;
    console.log(`✅ Large file signed in ${elapsed}ms`);
    console.log(`   Size: ${signedBlob.size} bytes`);
}

// ============================================================================
// Image Signing with C2PA
// ============================================================================

async function signImage(imagePath: string) {
    const client = new VouchClient();

    // Read the image
    const imageBuffer = fs.readFileSync(imagePath);
    const mimeType = imagePath.endsWith('.png') ? 'image/png' : 'image/jpeg';
    const blob = new Blob([imageBuffer], { type: mimeType });

    // Sign - C2PA manifest will be embedded
    const signedBlob = await client.signBlob(
        blob,
        path.basename(imagePath),
        'image-signer'
    );

    // Save
    const outputPath = imagePath.replace(/(\.\w+)$/, '_signed$1');
    const signedBuffer = Buffer.from(await signedBlob.arrayBuffer());
    fs.writeFileSync(outputPath, signedBuffer);

    console.log(`✅ Image signed with C2PA: ${outputPath}`);
    console.log(`   Original: ${imageBuffer.length} bytes`);
    console.log(`   With manifest: ${signedBuffer.length} bytes`);
}

// ============================================================================
// Main
// ============================================================================

async function main() {
    try {
        console.log('\n📦 Example 1: Sign blob (simulated)');
        await signBlobInBrowser();

        console.log('\n📦 Example 2: Sign file in Node.js');
        await signFileInNode();

        // Uncomment if you have an image
        // console.log('\n📦 Example 3: Sign image with C2PA');
        // await signImage('photo.jpg');

    } catch (error) {
        if (error instanceof VouchConnectionError) {
            console.log('❌ Daemon not running. Start with: vouch-bridge');
        } else {
            throw error;
        }
    }
}

main();
