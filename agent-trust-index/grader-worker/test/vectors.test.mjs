// Runs the shared grader vectors (test-vectors/grade/vector.json) through the
// worker's evidence checks. Run with: node --test agent-trust-index/grader-worker/test/
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { evidenceSignals, hostIsPublic, jcs } from "../evidence.js";

const vector = JSON.parse(
  readFileSync(new URL("../../../test-vectors/grade/vector.json", import.meta.url), "utf8")
);
const now = new Date(vector.now);

for (const c of vector.cases) {
  test(`grade vector: ${c.name}`, async () => {
    const fetchJson = async (u) => (u in c.documents ? c.documents[u] : null);
    const got = await evidenceSignals(c.did, c.didDocument, c.cards, fetchJson, now);
    assert.deepEqual(got, c.expected);
  });
}

test("jcs matches the shared JCS vectors", () => {
  const jv = JSON.parse(
    readFileSync(new URL("../../../test-vectors/jcs/vectors.json", import.meta.url), "utf8")
  );
  const cases = jv.vectors || jv.cases || jv;
  let checked = 0;
  for (const v of cases) {
    const input = v.input;
    const expected = v.canonical ?? v.expected ?? v.output;
    if (input === undefined || typeof expected !== "string") continue;
    assert.equal(jcs(input), expected, v.name || v.description);
    checked++;
  }
  assert.ok(checked > 0);
});

test("hostIsPublic refuses literals and internal names without a lookup", async () => {
  for (const h of ["127.0.0.1", "10.0.0.1", "[::1]", "localhost", "a.local", "metadata.internal"]) {
    assert.equal(await hostIsPublic(h), false, h);
  }
});
