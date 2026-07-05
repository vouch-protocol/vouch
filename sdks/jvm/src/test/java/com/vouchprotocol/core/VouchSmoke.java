package com.vouchprotocol.core;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * JVM smoke test: exercises the Java SDK and proves cross-implementation interop
 * by verifying the shared eddsa-jcs-2022 vector through the native core. Run with
 * the JNA jar on the classpath and the native lib on jna.library.path.
 */
public final class VouchSmoke {
    private static int pass = 0, fail = 0;

    private static void ok(String name, boolean cond) {
        System.out.println("  " + (cond ? "PASS" : "FAIL") + "  " + name);
        if (cond) pass++; else fail++;
    }

    private static String field(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        if (!m.find()) throw new RuntimeException("no field " + key);
        return m.group(1);
    }

    private static String object(String json, String key) {
        int k = json.indexOf("\"" + key + "\"");
        int b = json.indexOf('{', k);
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
        throw new RuntimeException("no object " + key);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("vouch core version: " + Vouch.version());

        ok("canonicalize sorts keys", Vouch.canonicalize("{\"b\":1,\"a\":2}").equals("{\"a\":2,\"b\":1}"));

        // Native keygen works on the JVM (no Node-ESM RNG caveat).
        String kp = Vouch.generateEd25519();
        String seed = field(kp, "seed_b64");
        String pub = field(kp, "public_b64");
        ok("keygen did:key", field(kp, "did_key").startsWith("did:key:z6Mk"));

        String cred = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"],"
                + "\"type\":[\"VerifiableCredential\",\"VouchCredential\"],"
                + "\"issuer\":\"did:web:a\",\"validFrom\":\"2026-04-26T10:00:00Z\","
                + "\"validUntil\":\"2026-04-26T10:05:00Z\",\"credentialSubject\":{\"id\":\"did:web:a\","
                + "\"vouchVersion\":\"1.0\",\"intent\":{\"action\":\"read\",\"target\":\"t\",\"resource\":\"https://x/y\"}}}";
        String signed = Vouch.sign(cred, seed, "did:web:a#key-1", "2026-04-26T10:00:00Z");
        ok("sign + verify proof", Vouch.verifyProof(signed, pub));
        ok("verify within window", Vouch.verify(signed, pub, "2026-04-26T10:02:00Z", 30).contains("\"valid\":true"));

        // Cross-implementation: verify the shared vector and reproduce its proofValue.
        String vpath = args.length > 0 ? args[0]
                : "../../test-vectors/data-integrity-eddsa-jcs-2022/vector.json";
        String vec = Files.readString(Path.of(vpath));
        String vPub = field(object(vec, "ed25519"), "public_key_b64");
        String vSeed = field(object(vec, "ed25519"), "seed_b64");
        String vVm = field(vec, "verificationMethod");
        String vCreated = field(vec, "created");
        String vProofValue = field(vec, "proofValue");
        String signedCred = object(vec, "signed_credential");
        String unsignedCred = object(vec, "unsigned_credential");

        ok("verifies shared signed credential (cross-impl)", Vouch.verifyProof(signedCred, vPub));
        String proof = Vouch.buildProof(unsignedCred, vSeed, vVm, vCreated);
        ok("reproduces shared proofValue (cross-impl)", field(proof, "proofValue").equals(vProofValue));

        // Delegation: build links and validate the time-bound chain rule.
        String intent = "{\"action\":\"read\",\"target\":\"t\",\"resource\":\"https://api/x\"}";
        String l1 = Vouch.buildDelegationLink("did:web:a", "did:web:b", intent, "2026-04-26T09:00:00Z", "2026-04-26T12:00:00Z", null);
        String l2 = Vouch.buildDelegationLink("did:web:b", "did:web:c", intent, "2026-04-26T10:00:00Z", "2026-04-26T11:00:00Z", null);
        String chainJson = "[" + l1 + "," + l2 + "]";
        ok("delegation link has subject", l1.contains("\"subject\":\"did:web:b\""));
        ok("delegation chain time-bound valid", Vouch.verifyChainTimeBound(chainJson, "2026-04-26T10:30:00Z", 30));
        ok("delegation chain outside window rejected", !Vouch.verifyChainTimeBound(chainJson, "2026-04-26T13:00:00Z", 30));

        System.out.println("\nTOTAL: " + pass + " pass, " + fail + " fail");
        System.exit(fail == 0 ? 0 : 1);
    }
}
