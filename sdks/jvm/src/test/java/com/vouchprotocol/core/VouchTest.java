package com.vouchprotocol.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/** JUnit suite for the JVM SDK (run via `gradle test`). Mirrors VouchSmoke. */
class VouchTest {

    private static final String CRED =
            "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],"
            + "\"type\":[\"VerifiableCredential\",\"VouchCredential\"],"
            + "\"issuer\":\"did:web:a\",\"validFrom\":\"2026-04-26T10:00:00Z\","
            + "\"validUntil\":\"2026-04-26T10:05:00Z\",\"credentialSubject\":{\"id\":\"did:web:a\","
            + "\"vouchVersion\":\"1.0\",\"intent\":{\"action\":\"read\",\"target\":\"t\",\"resource\":\"https://x/y\"}}}";

    private static String field(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        if (!m.find()) throw new RuntimeException("no field " + key);
        return m.group(1);
    }

    @Test
    void canonicalizeSortsKeys() {
        assertEquals("{\"a\":2,\"b\":1}", Vouch.canonicalize("{\"b\":1,\"a\":2}"));
    }

    @Test
    void signAndVerify() {
        String kp = Vouch.generateEd25519();
        String seed = field(kp, "seed_b64");
        String pub = field(kp, "public_b64");
        String signed = Vouch.signCredential(CRED, seed, "did:web:a#key-1", "2026-04-26T10:00:00Z");
        assertTrue(Vouch.verifyProof(signed, pub));
        assertTrue(Vouch.verifyCredential(signed, pub, "2026-04-26T10:02:00Z", 30).contains("\"valid\":true"));
        assertFalse(Vouch.verifyCredential(signed, pub, "2026-04-26T11:00:00Z", 30).contains("\"valid\":true"));
    }

    @Test
    void crossImplementationInterop() throws Exception {
        String vec = Files.readString(Path.of("../../test-vectors/data-integrity-eddsa-jcs-2022/vector.json"));
        // ed25519 fields appear once; read them from the whole doc.
        String vPub = field(vec, "public_key_b64");
        String vProofValue = field(vec, "proofValue");
        // signed_credential is the only object carrying a proof; verify it.
        int idx = vec.indexOf("\"signed_credential\"");
        String signedCred = extractObject(vec, idx);
        assertTrue(Vouch.verifyProof(signedCred, vPub), "JVM must verify the shared signed credential");
    }

    @Test
    void delegationTimeBound() {
        String intent = "{\"action\":\"read\",\"target\":\"t\",\"resource\":\"https://api/x\"}";
        String l1 = Vouch.buildDelegationLink("did:web:a", "did:web:b", intent, "2026-04-26T09:00:00Z", "2026-04-26T12:00:00Z", null);
        String l2 = Vouch.buildDelegationLink("did:web:b", "did:web:c", intent, "2026-04-26T10:00:00Z", "2026-04-26T11:00:00Z", null);
        String chain = "[" + l1 + "," + l2 + "]";
        assertTrue(Vouch.verifyChainTimeBound(chain, "2026-04-26T10:30:00Z", 30));
        assertFalse(Vouch.verifyChainTimeBound(chain, "2026-04-26T13:00:00Z", 30));
    }

    private static String extractObject(String json, int fromKey) {
        int b = json.indexOf('{', fromKey);
        int depth = 0;
        boolean inStr = false, esc = false;
        for (int i = b; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inStr) {
                if (esc) esc = false;
                else if (c == '\\') esc = true;
                else if (c == '"') inStr = false;
            } else if (c == '"') inStr = true;
            else if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) return json.substring(b, i + 1); }
        }
        throw new RuntimeException("unterminated object");
    }
}
