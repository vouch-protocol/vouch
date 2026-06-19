/**
 * Test-only setup: expose the Web Crypto API as a global for the Vitest
 * runner.
 *
 * The shipped SDK code resolves randomness via `globalThis.crypto`
 * (available in Node 18.19+, all browsers, and React Native with a
 * getRandomValues polyfill). Vitest executes test modules inside a sandboxed
 * module-runner context that does NOT inherit Node's `globalThis.crypto`, so
 * we inject Node's Web Crypto implementation here.
 *
 * This shim is NOT part of the published package — it only affects tests.
 */
import { webcrypto } from 'node:crypto';

if (typeof (globalThis as { crypto?: unknown }).crypto === 'undefined') {
  Object.defineProperty(globalThis, 'crypto', {
    value: webcrypto,
    configurable: true,
    enumerable: false,
    writable: false,
  });
}
