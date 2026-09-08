import { resolve } from 'node:path';

import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      // Point at the SDK's source rather than its build. Tests then exercise
      // the current source, and they sidestep a dynamic require of the
      // optional post-quantum module in the SDK's bundled ESM output.
      '@vouch-protocol-official/sdk': resolve(__dirname, '../sdk-ts/src/index.ts'),
    },
  },
  test: { globals: true, environment: 'node', include: ['src/**/*.test.ts'] },
});
