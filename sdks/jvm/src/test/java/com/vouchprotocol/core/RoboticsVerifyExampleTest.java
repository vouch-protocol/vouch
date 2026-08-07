package com.vouchprotocol.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Verify-side example for the two robotics accountability flows, using only the
 * curated wrapper surface. Mirrors the producer-side Python/TypeScript/Go/Rust
 * examples (examples/robotics_ai_act_evidence_pack.py and
 * examples/robotics_vla_accountability_loop.py) from the consuming side:
 *
 * <ul>
 *   <li>Regulatory evidence pack: {@code checkConformance} maps the shared
 *       interop vector's Python-signed credential set onto all five built-in
 *       profiles, reporting CONFORMS for the EU AI Act and the EU
 *       Machinery Regulation and the exact open clause for the two profiles the
 *       set leaves gaps in; {@code buildConformanceAttestation} then signs a
 *       point-in-time attestation per profile and
 *       {@code verifyConformanceAttestation} checks it offline.</li>
 *   <li>VLA accountability loop: {@code verifyIdentity} /
 *       {@code verifyRobotCredential} authenticate the robot before trusting
 *       it (the wrapper-side analogue of provenance-on-load), and
 *       {@code checkAction} reproduces the pre-actuation scope gate, denying
 *       the over-speed and out-of-zone actions and allowing the safe ones.</li>
 * </ul>
 *
 * Keys in the vector are JWKs whose {@code x} is base64url-no-pad raw Ed25519
 * material; the wrapper's {@code *B64} arguments take standard base64.
 */
class RoboticsVerifyExampleTest {

    private static final List<String> ALL_PROFILE_IDS = List.of(
            "eu-ai-act-high-risk",
            "iso-10218",
            "iso-ts-15066",
            "eu-machinery-2023-1230",
            "ul-3300");

    /** The profiles the vector's four-credential set fully satisfies. */
    private static final java.util.Set<String> CONFORMING_PROFILE_IDS =
            java.util.Set.of("eu-ai-act-high-risk", "eu-machinery-2023-1230");

    // A fixed assessor signing seed (0x03 x 32) and its Ed25519 public key, so
    // the attestation round-trip is deterministic like the Rust core tests.
    private static final String ASSESSOR_SEED_B64 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    private static final String ASSESSOR_PUB_B64 = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";

    private static final String SCOPE =
            "{\"maxForceN\":80.0,\"maxSpeedMps\":1.5,"
            + "\"maxSpeedNearHumansMps\":0.5,\"allowedZones\":[\"cell-3\"]}";

    private static final Map<String, Object> VECTOR = loadVector();

    private static Map<String, Object> loadVector() {
        Path module = Paths.get("").toAbsolutePath();
        Path vector = module.resolve(Paths.get("..", "..", "test-vectors", "robotics", "vector.json")).normalize();
        try {
            return Json.parseObject(new String(Files.readAllBytes(vector), StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("read interop vector at " + vector, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static String robotPublicB64() {
        Map<String, Object> jwk = (Map<String, Object>) VECTOR.get("robot_public_key_jwk");
        byte[] raw = Base64.getUrlDecoder().decode((String) jwk.get("x"));
        return Base64.getEncoder().encodeToString(raw);
    }

    private static String credentialsJson() {
        return Json.write(VECTOR.get("conformance_credentials"));
    }

    @Test
    void verifiesTheRobotBeforeTrustingIt() {
        String credential = Json.write(VECTOR.get("robot_identity_credential"));

        String subject = VouchRobotics.verifyIdentity(credential, robotPublicB64());
        assertNotEquals("null", subject, "the Python-minted identity must verify");
        assertTrue(subject.contains("\"make\":\"Acme Robotics\""), subject);

        assertTrue(VouchRobotics.verifyRobotCredential(credential, robotPublicB64()),
                "the identity credential proof must verify under the robot key");
    }

    @Test
    void reportsConformanceAndGapsAcrossAllFiveProfiles() {
        for (String pid : ALL_PROFILE_IDS) {
            Map<String, Object> report = Json.parseObject(
                    VouchRobotics.checkConformance(credentialsJson(), pid));
            assertEquals(pid, report.get("profileId"));

            boolean conforms = Boolean.TRUE.equals(report.get("conforms"));
            if (CONFORMING_PROFILE_IDS.contains(pid)) {
                assertTrue(conforms, pid + " should conform: " + report);
            } else {
                // The vector's four-credential set carries no heartbeat motion
                // digest and no perception provenance, and its identity
                // credential names a hardware root without carrying the root's
                // attestation, so these profiles report the open clause.
                assertFalse(conforms, pid + " should report gaps: " + report);
            }
        }
    }

    @Test
    void signsAndVerifiesOneAttestationPerProfile() {
        for (String pid : ALL_PROFILE_IDS) {
            String report = VouchRobotics.checkConformance(credentialsJson(), pid);
            String params = "{\"issuerDid\":\"did:web:assessor.example.com\","
                    + "\"robotDid\":\"did:web:robot.example.com\","
                    + "\"report\":" + report + ","
                    + "\"validFrom\":\"2026-01-01T00:00:00Z\"}";
            String attestation = VouchRobotics.buildConformanceAttestation(ASSESSOR_SEED_B64, params);

            String subject = VouchRobotics.verifyConformanceAttestation(attestation, ASSESSOR_PUB_B64);
            assertNotEquals("null", subject, pid + " attestation must verify");
            assertTrue(subject.contains("\"profileId\":\"" + pid + "\""), subject);

            // A wrong key must not verify the attestation.
            assertEquals("null",
                    VouchRobotics.verifyConformanceAttestation(attestation, robotPublicB64()));
        }
    }

    @Test
    void vlaGateAllowsSafeAndDeniesUnsafeActions() {
        String pick = VouchRobotics.checkAction(SCOPE,
                "{\"forceN\":20.0,\"speedMps\":0.3,\"nearHumans\":true,\"zone\":\"cell-3\"}");
        assertTrue(pick.contains("\"ok\":true"), "safe pick should pass: " + pick);

        String hand = VouchRobotics.checkAction(SCOPE,
                "{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}");
        assertTrue(hand.contains("\"ok\":true"), "safe handover should pass: " + hand);

        String sprint = VouchRobotics.checkAction(SCOPE,
                "{\"speedMps\":2.5,\"nearHumans\":true,\"zone\":\"cell-3\"}");
        assertTrue(sprint.contains("\"ok\":false"), "over-speed sprint should fail: " + sprint);
        assertTrue(sprint.contains("speed_exceeded"), sprint);

        String fetch = VouchRobotics.checkAction(SCOPE,
                "{\"forceN\":15.0,\"speedMps\":0.5,\"zone\":\"loading-bay\"}");
        assertTrue(fetch.contains("\"ok\":false"), "out-of-zone fetch should fail: " + fetch);
        assertTrue(fetch.contains("zone_not_allowed"), fetch);
    }
}
