/**
 * Cross-implementation interop tests for JCS canonicalization.
 *
 * Reads the shared test vectors at test-vectors/jcs/vectors.json and asserts
 * that the TypeScript implementation produces byte-identical output for each.
 * The Python suite has a parallel test (tests/test_jcs_interop.py) that reads
 * the same vectors. Together they verify Python and TypeScript produce
 * identical canonical bytes, which is required for cross-language signature
 * verification.
 */

import * as fs from 'fs';
import * as path from 'path';

import { canonicalize } from '../src/jcs';

interface Vector {
    name: string;
    input: unknown;
    canonical: string;
}

const VECTOR_PATH = path.resolve(
    __dirname,
    '..',
    '..',
    '..',
    'test-vectors',
    'jcs',
    'vectors.json'
);

function loadVectors(): Vector[] {
    const raw = fs.readFileSync(VECTOR_PATH, 'utf-8');
    return (JSON.parse(raw) as { vectors: Vector[] }).vectors;
}

describe('JCS cross-implementation interop', () => {
    const vectors = loadVectors();

    for (const vec of vectors) {
        test(vec.name, () => {
            const out = new TextDecoder().decode(canonicalize(vec.input));
            expect(out).toBe(vec.canonical);
        });
    }
});
