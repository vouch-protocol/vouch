/**
 * Example: Connect to Vouch Daemon
 *
 * The simplest example - check if the daemon is running.
 */

import { VouchClient, VouchConnectionError } from '@vouch-protocol/sdk';

async function main() {
    // Create a client (uses default localhost:21000)
    const client = new VouchClient();

    try {
        // Connect to the daemon
        const status = await client.connect();

        console.log('✅ Vouch Daemon is online!');
        console.log(`   Version: ${status.version || 'unknown'}`);
        console.log(`   Has Keys: ${status.has_keys}`);

    } catch (error) {
        if (error instanceof VouchConnectionError) {
            console.log('❌ Vouch Daemon is offline!');
            console.log('   Start the daemon with: vouch-bridge');
        } else {
            throw error;
        }
    }
}

main();
