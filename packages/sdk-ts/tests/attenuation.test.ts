/**
 * The TypeScript delegation validator MUST produce the same verdicts as the
 * Rust core on the shared interop vectors.
 */
import * as fs from 'fs';
import * as path from 'path';

import { describe, it, expect } from 'vitest';

import { validateChainJson } from '../src/attenuation';

const vectorPath = path.join(process.cwd(), '..', '..', 'test-vectors', 'delegation-attenuation', 'vector.json');
const vectors = JSON.parse(fs.readFileSync(vectorPath, 'utf8'));

describe('delegation attenuation interop vectors', () => {
  for (const c of vectors.cases) {
    it(c.name, () => {
      const verdict = JSON.parse(validateChainJson(JSON.stringify(c.request)));
      expect(verdict.valid).toBe(c.expect.valid);
      if (!c.expect.valid) {
        expect(verdict.code).toBe(c.expect.code);
        for (const field of ['dimension', 'limit', 'linkIndex']) {
          if (field in c.expect) expect(verdict[field]).toBe(c.expect[field]);
        }
      }
    });
  }
});
