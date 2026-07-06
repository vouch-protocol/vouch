package com.vouchprotocol.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Cross-language interop suite for the curated robotics ABI additions
 * (authorize-access, fused / wear attestation verify, wear attenuation,
 * consent-evidence verify, continuity and custody chain verify).
 *
 * Mirrors the Go sidecar robotics interop tests: it loads the pinned shared
 * interop vector ({@code test-vectors/robotics/vector.json}), which carries
 * Python-signed credentials, and confirms the JVM wrapper over the Rust core
 * reproduces the same offline decisions on the same bytes. Keys in the vector are
 * JWKs whose {@code x} is base64url-no-pad raw Ed25519 material; the wrapper's
 * {@code *PublicB64} arguments take standard base64, {@code bystanderKeys} values
 * take multibase, and {@code publicKeys} values take base64url-no-pad, so each is
 * converted from the one raw key accordingly.
 */
class VouchRoboticsCuratedTest {

    // The interop grant, request, and consent token are all minted at
    // 2026-01-01T00:00:00Z with an hour window; authorize and verify inside it.
    private static final String NOW_IN_WINDOW = "2026-01-01T00:05:00Z";

    // The consent interop capture is the raw frame the Python module hashed.
    private static final byte[] CONSENT_CAPTURE = "bystander-frame-0".getBytes(StandardCharsets.UTF_8);

    private static final Map<String, Object> VECTOR = loadVector();

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadVector() {
        // src/test/... -> module root is three parents up; the vector lives at the
        // repo's test-vectors/, four parents above the module root.
        Path module = Paths.get("").toAbsolutePath();
        Path vector = module.resolve(Paths.get("..", "..", "test-vectors", "robotics", "vector.json")).normalize();
        try {
            return Json.parseObject(new String(Files.readAllBytes(vector), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("read interop vector at " + vector, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(String key) {
        return (Map<String, Object>) VECTOR.get(key);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> arr(String key) {
        return (List<Object>) VECTOR.get(key);
    }

    /** Decode a JWK's base64url-no-pad {@code x} to raw Ed25519 public-key bytes. */
    private static byte[] rawFromJwk(Map<String, Object> jwk) {
        return Base64.getUrlDecoder().decode((String) jwk.get("x"));
    }

    /** The standard-base64 form the {@code *PublicB64} arguments expect. */
    private static String stdB64(Map<String, Object> jwk) {
        return Base64.getEncoder().encodeToString(rawFromJwk(jwk));
    }

    /** The base64url-no-pad form the handoff {@code publicKeys} values expect. */
    private static String urlB64(Map<String, Object> jwk) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(rawFromJwk(jwk));
    }

    /** The multibase ('u' + base64url-no-pad) form {@code bystanderKeys} and captures expect. */
    private static String multibase(byte[] raw) {
        return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    // ---- authorize infrastructure access --------------------------------------

    @Test
    void authorizeAccessInteropVector() {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("grant", obj("access_grant_credential"));
        params.put("request", obj("access_request_credential"));
        params.put("now", NOW_IN_WINDOW);

        String result = VouchRobotics.authorizeAccess(
                Json.write(params), stdB64(obj("access_operator_key")), stdB64(obj("access_robot_key")));
        assertTrue(result.contains("\"ok\":true"),
                "the Python-minted grant and request should authorize in the JVM: " + result);
    }

    // ---- fused-sensor provenance ----------------------------------------------

    @Test
    void verifyFusedAttestationInteropVector() {
        String subject = VouchRobotics.verifyFusedAttestation(
                Json.write(obj("fused_perception_attestation")), stdB64(obj("robot_public_key_jwk")));
        assertNotEquals("null", subject,
                "the Python-minted fused-perception attestation should verify in the JVM: " + subject);
        assertTrue(subject.contains("fusionMethod"), "subject should carry the fusion method: " + subject);
    }

    // ---- wear attestation and attenuation -------------------------------------

    @Test
    void verifyWearAttestationInteropVector() {
        // The wear_chain is an ordered history; the latest link verifies on its own.
        List<Object> chain = arr("wear_chain");
        @SuppressWarnings("unchecked")
        Map<String, Object> latest = (Map<String, Object>) chain.get(chain.size() - 1);

        String subject = VouchRobotics.verifyWearAttestation(
                Json.write(latest), stdB64(obj("robot_public_key_jwk")));
        assertNotEquals("null", subject,
                "the latest Python-minted wear attestation should verify in the JVM: " + subject);
    }

    @Test
    void attenuateForWearReproducesExpectedScope() {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("scope", obj("wear_input_scope"));
        params.put("wearLevel", VECTOR.get("wear_attenuation_level"));

        Map<String, Object> narrowed = Json.parseObject(VouchRobotics.attenuateForWear(Json.write(params)));
        Map<String, Object> expected = obj("expected_attenuated_scope");

        for (String cap : new String[] {"maxForceN", "maxSpeedMps", "maxSpeedNearHumansMps"}) {
            assertEquals(expected.get(cap), narrowed.get(cap),
                    "attenuated " + cap + " should match the pinned expected scope");
        }
    }

    // ---- bystander-consent evidence -------------------------------------------

    @Test
    void verifyConsentEvidenceInteropVector() {
        Map<String, Object> token = obj("consent_token_credential");
        String bystanderDid = (String) token.get("issuer");

        Map<String, String> bystanderKeys = new LinkedHashMap<>();
        bystanderKeys.put(bystanderDid, multibase(rawFromJwk(obj("consent_bystander_key"))));

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("evidence", obj("consent_evidence_credential"));
        params.put("captureMb", multibase(CONSENT_CAPTURE));
        params.put("consentTokens", List.of(token));
        params.put("bystanderKeys", bystanderKeys);
        params.put("now", NOW_IN_WINDOW);

        String subject = VouchRobotics.verifyConsentEvidence(
                Json.write(params), stdB64(obj("robot_public_key_jwk")));
        assertNotEquals("null", subject,
                "the Python-minted consent evidence should verify in the JVM: " + subject);
        assertTrue(subject.contains("explicit-consent"),
                "the verified evidence should carry the explicit-consent basis: " + subject);
    }

    // ---- cross-embodiment continuity ------------------------------------------

    @Test
    void verifyContinuityChainInteropVector() {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("embodiments", arr("embodiment_chain"));

        String result = VouchRobotics.verifyContinuityChain(
                Json.write(params), stdB64(obj("embodiment_agent_key")));
        assertTrue(result.contains("\"ok\":true"),
                "the Python-minted continuity chain should verify in the JVM: " + result);
    }

    // ---- physical custody handoff ---------------------------------------------

    @Test
    void verifyHandoffChainInteropVector() {
        Map<String, String> publicKeys = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : obj("custody_actor_keys").entrySet()) {
            @SuppressWarnings("unchecked")
            Map<String, Object> jwk = (Map<String, Object>) e.getValue();
            publicKeys.put(e.getKey(), urlB64(jwk));
        }

        Map<String, Object> params = new LinkedHashMap<>();
        params.put("handoffs", arr("custody_chain"));
        params.put("publicKeys", publicKeys);
        params.put("originActor", VECTOR.get("custody_origin_actor"));

        String result = VouchRobotics.verifyHandoffChain(Json.write(params));
        assertTrue(result.contains("\"ok\":true"),
                "the Python-minted custody chain should verify in the JVM: " + result);
    }
}
