package com.vouchprotocol.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
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
        String signed = Vouch.sign(CRED, seed, "did:web:a#key-1", "2026-04-26T10:00:00Z");
        assertTrue(Vouch.verifyProof(signed, pub));
        assertTrue(Vouch.verify(signed, pub, "2026-04-26T10:02:00Z", 30).contains("\"valid\":true"));
        assertFalse(Vouch.verify(signed, pub, "2026-04-26T11:00:00Z", 30).contains("\"valid\":true"));
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

    @Test
    void thresholdFrostCeremonyProducesValidSignature() {
        // Rust's aggregate() self-verifies before returning (see
        // vouch_core::threshold), so a completed, non-throwing ceremony is
        // itself the proof that the resulting signature is a valid, standard
        // Ed25519 signature over the message.
        String generated = Vouch.thresholdGenerateKey(2, 3);
        List<String> shares = extractArrayObjects(generated, "shares");
        assertEquals(3, shares.size());

        String share0 = shares.get(0);
        String share1 = shares.get(1);
        String id0 = field(share0, "identifier");
        String id1 = field(share1, "identifier");

        String round1_0 = Vouch.thresholdCommit(share0);
        String round1_1 = Vouch.thresholdCommit(share1);
        String commitmentsJson = "{\"" + id0 + "\":\"" + field(round1_0, "commitments")
                + "\",\"" + id1 + "\":\"" + field(round1_1, "commitments") + "\"}";

        String message = Base64.getEncoder().encodeToString(
                "charge api.bank invoices/42".getBytes(StandardCharsets.UTF_8));

        String sigShare0 = Vouch.thresholdSignShare(message, share0, field(round1_0, "nonces"), commitmentsJson);
        String sigShare1 = Vouch.thresholdSignShare(message, share1, field(round1_1, "nonces"), commitmentsJson);
        String sharesJson = "{\"" + id0 + "\":\"" + sigShare0 + "\",\"" + id1 + "\":\"" + sigShare1 + "\"}";

        String groupPublicKeyJson = extractObject(generated, generated.indexOf("\"group_public_key\""));
        String signatureB64 = Vouch.thresholdAggregate(message, commitmentsJson, sharesJson, groupPublicKeyJson);
        assertEquals(64, Base64.getDecoder().decode(signatureB64).length);
    }

    @Test
    void thresholdRejectsBadThreshold() {
        assertThrows(Vouch.VouchException.class, () -> Vouch.thresholdGenerateKey(1, 3));
    }

    @Test
    void recoverySplitAndCombineRoundtrips() {
        String secretB64 = Base64.getEncoder().encodeToString("a 32 byte secret for shamir!!!!!".getBytes(StandardCharsets.UTF_8));
        List<String> shares = extractStringArray(Vouch.recoverySplitSecret(secretB64, 3, 5));
        assertEquals(5, shares.size());

        String combined = Vouch.recoveryCombineShares(toJsonArray(shares.subList(0, 3)));
        assertEquals(secretB64, combined);

        String combinedAlt = Vouch.recoveryCombineShares(
                toJsonArray(List.of(shares.get(0), shares.get(2), shares.get(4))));
        assertEquals(secretB64, combinedAlt);
    }

    @Test
    void recoveryBelowThresholdDoesNotRevealSecret() {
        String secretB64 = Base64.getEncoder().encodeToString("another shamir secret!!".getBytes(StandardCharsets.UTF_8));
        List<String> shares = extractStringArray(Vouch.recoverySplitSecret(secretB64, 3, 5));
        String combined = Vouch.recoveryCombineShares(toJsonArray(shares.subList(0, 2)));
        assertFalse(secretB64.equals(combined));
    }

    @Test
    void recoverySplitAndRecoverIdentitySignsIdentically() {
        String kp = Vouch.generateEd25519();
        String seedB64 = field(kp, "seed_b64");
        String didKey = field(kp, "did_key");

        List<String> shares = extractStringArray(Vouch.recoverySplitIdentity(seedB64, 2, 3));
        assertEquals(3, shares.size());

        String recovered = Vouch.recoveryRecoverIdentity(toJsonArray(shares.subList(0, 2)), didKey);
        assertEquals(didKey, field(recovered, "did"));
        assertEquals(seedB64, field(recovered, "seed"));

        // The recovered seed is the original: sign with it and verify against
        // the original public key.
        String pub = field(kp, "public_b64");
        String signed = Vouch.sign(CRED, field(recovered, "seed"), didKey + "#key-1", "2026-04-26T10:00:00Z");
        assertTrue(Vouch.verifyProof(signed, pub));
    }

    @Test
    void recoveryTooFewSharesGivesWrongResultNotError() {
        String kp = Vouch.generateEd25519();
        String seedB64 = field(kp, "seed_b64");
        List<String> shares = extractStringArray(Vouch.recoverySplitIdentity(seedB64, 3, 5));
        String recovered = Vouch.recoveryRecoverIdentity(toJsonArray(shares.subList(0, 2)), "");
        assertFalse(seedB64.equals(field(recovered, "seed")));
    }

    private static List<String> extractStringArray(String json) {
        List<String> out = new ArrayList<>();
        Matcher m = Pattern.compile("\"([^\"]*)\"").matcher(json);
        while (m.find()) out.add(m.group(1));
        return out;
    }

    private static String toJsonArray(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(items.get(i)).append('"');
        }
        return sb.append(']').toString();
    }

    private static List<String> extractArrayObjects(String json, String key) {
        int arrStart = json.indexOf('[', json.indexOf("\"" + key + "\""));
        List<String> out = new ArrayList<>();
        int i = arrStart + 1;
        while (true) {
            while (json.charAt(i) == ',' || Character.isWhitespace(json.charAt(i))) i++;
            if (json.charAt(i) == ']') break;
            int objStart = i;
            int depth = 0;
            boolean inStr = false;
            boolean esc = false;
            for (; i < json.length(); i++) {
                char c = json.charAt(i);
                if (inStr) {
                    if (esc) esc = false;
                    else if (c == '\\') esc = true;
                    else if (c == '"') inStr = false;
                } else if (c == '"') inStr = true;
                else if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        i++;
                        break;
                    }
                }
            }
            out.add(json.substring(objStart, i));
        }
        return out;
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
