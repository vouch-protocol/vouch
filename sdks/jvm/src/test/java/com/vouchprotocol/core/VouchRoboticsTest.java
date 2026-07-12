package com.vouchprotocol.core;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** JUnit suite for the robotics helpers (run via `gradle test`). Keyless and deterministic. */
class VouchRoboticsTest {

    private static final String SCOPE =
            "{\"maxForceN\":80.0,\"maxSpeedMps\":1.5,"
            + "\"maxSpeedNearHumansMps\":0.25,\"allowedZones\":[\"cell-3\"]}";

    @Test
    void checkActionAllowsAndDenies() {
        String ok = VouchRobotics.checkAction(SCOPE,
                "{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}");
        assertTrue(ok.contains("\"ok\":true"), "compliant action should pass: " + ok);

        String bad = VouchRobotics.checkAction(SCOPE,
                "{\"speedMps\":1.2,\"nearHumans\":true,\"zone\":\"cell-3\"}");
        assertTrue(bad.contains("\"ok\":false"), "over-speed near humans should fail: " + bad);
    }

    @Test
    void checkConformanceHighRisk() {
        String credentials = "["
                + "{\"type\":[\"VerifiableCredential\",\"RobotIdentityCredential\"],"
                + "\"credentialSubject\":{\"id\":\"did:web:r\",\"make\":\"Acme\",\"model\":\"AR-7\","
                + "\"serial\":\"SN-1\",\"hardwareRoot\":{\"kind\":\"TPM\"}}},"
                + "{\"type\":[\"VerifiableCredential\",\"ModelProvenanceAttestation\"],"
                + "\"credentialSubject\":{\"id\":\"did:web:r\",\"vla\":{\"modelName\":\"M\","
                + "\"weightsHash\":\"uW\",\"safetyPolicy\":\"uP\",\"configHash\":\"uC\"}}},"
                + "{\"type\":[\"VerifiableCredential\",\"PhysicalCapabilityScope\"],"
                + "\"credentialSubject\":{\"id\":\"did:web:r\",\"physicalScope\":{\"maxForceN\":80.0,"
                + "\"maxSpeedMps\":1.5,\"maxSpeedNearHumansMps\":0.25,\"allowedZones\":[\"cell-3\"]}}},"
                + "{\"type\":[\"VerifiableCredential\",\"RobotSafetyRecordCredential\"],"
                + "\"credentialSubject\":{\"id\":\"did:web:r\",\"totalEvents\":2,\"logHead\":\"uHEAD\"}}"
                + "]";

        String report = VouchRobotics.checkConformance(credentials, "eu-ai-act-high-risk");
        assertTrue(report.contains("\"conforms\":true"), "all four requirements should be satisfied: " + report);
        assertTrue(report.contains("\"totalCount\":4"), "profile should have four requirements: " + report);
    }
}
