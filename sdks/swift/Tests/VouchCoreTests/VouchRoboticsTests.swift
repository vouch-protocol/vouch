import XCTest

@testable import VouchCore

final class VouchRoboticsTests: XCTestCase {
    private let scope = """
        {"maxForceN":80.0,"maxSpeedMps":1.5,"maxSpeedNearHumansMps":0.25,"allowedZones":["cell-3"]}
        """

    private let conformanceCredentials = """
        [{"type":["VerifiableCredential","RobotIdentityCredential"],\
        "credentialSubject":{"id":"did:web:r","make":"Acme","model":"AR-7","serial":"SN-1",\
        "hardwareRoot":{"kind":"TPM"}}},\
        {"type":["VerifiableCredential","ModelProvenanceAttestation"],\
        "credentialSubject":{"id":"did:web:r","vla":{"modelName":"M","weightsHash":"uW",\
        "safetyPolicy":"uP","configHash":"uC"}}},\
        {"type":["VerifiableCredential","PhysicalCapabilityScope"],\
        "credentialSubject":{"id":"did:web:r","physicalScope":{"maxForceN":80.0,"maxSpeedMps":1.5,\
        "maxSpeedNearHumansMps":0.25,"allowedZones":["cell-3"]}}},\
        {"type":["VerifiableCredential","RobotSafetyRecordCredential"],\
        "credentialSubject":{"id":"did:web:r","totalEvents":2,"logHead":"uHEAD"}}]
        """

    func testCheckActionAllowsWithinScope() throws {
        let report = try VouchRobotics.checkAction(
            scopeJson: scope,
            actionJson: "{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}"
        )
        XCTAssertTrue(report.contains("\"ok\":true"))
    }

    func testCheckActionRejectsOverSpeedNearHumans() throws {
        let report = try VouchRobotics.checkAction(
            scopeJson: scope,
            actionJson: "{\"speedMps\":1.2,\"nearHumans\":true,\"zone\":\"cell-3\"}"
        )
        XCTAssertTrue(report.contains("\"ok\":false"))
    }

    func testCheckConformanceReportsFullCoverage() throws {
        let report = try VouchRobotics.checkConformance(
            credentialsJson: conformanceCredentials,
            profileId: "eu-ai-act-high-risk"
        )
        XCTAssertTrue(report.contains("\"conforms\":true"))
        XCTAssertTrue(report.contains("\"totalCount\":4"))
    }

    // MARK: Curated robotics interop vector (Phases 5.16-5.20)
    //
    // Load the shared cross-language fixture and drive the seven curated
    // access/perception/wear/consent/continuity/handoff methods against the
    // exact Python-minted inputs every other SDK verifies.

    private let interopNow = "2026-01-01T00:05:00Z"

    func testAuthorizeAccessAllowsVectorRequest() throws {
        let v = try vector()
        let params = try jsonString([
            "grant": v["access_grant_credential"]!,
            "request": v["access_request_credential"]!,
            "now": interopNow,
        ])
        let result = try VouchRobotics.authorizeAccess(
            paramsJson: params,
            operatorPublicKey: try jwkPublicKey(v["access_operator_key"]!),
            robotPublicKey: try jwkPublicKey(v["access_robot_key"]!)
        )
        XCTAssertTrue(result.contains("\"ok\":true"))
    }

    func testVerifyFusedAttestationReturnsSubject() throws {
        let v = try vector()
        let subject = try VouchRobotics.verifyFusedAttestation(
            try jsonString(v["fused_perception_attestation"]!),
            publicKey: try jwkPublicKey(v["robot_public_key_jwk"]!)
        )
        XCTAssertNotEqual(subject, "null")
        XCTAssertTrue(subject.contains("occupancy-grid-v1"))
    }

    func testVerifyWearAttestationReturnsSubject() throws {
        let v = try vector()
        let chain = v["wear_chain"] as! [Any]
        let latest = try jsonString(chain.last!)
        let subject = try VouchRobotics.verifyWearAttestation(
            latest,
            publicKey: try jwkPublicKey(v["robot_public_key_jwk"]!)
        )
        XCTAssertNotEqual(subject, "null")
    }

    func testAttenuateForWearReproducesExpectedScope() throws {
        let v = try vector()
        let params = try jsonString([
            "scope": v["wear_input_scope"]!,
            "wearLevel": v["wear_attenuation_level"]!,
        ])
        let narrowed = try VouchRobotics.attenuateForWear(paramsJson: params)
        // Byte-identical to the fixture's expected scope after canonicalization.
        XCTAssertEqual(
            try Vouch.canonicalize(narrowed),
            try Vouch.canonicalize(try jsonString(v["expected_attenuated_scope"]!))
        )
    }

    func testVerifyConsentEvidenceReturnsSubject() throws {
        let v = try vector()
        let params = try jsonString(["evidence": v["consent_evidence_credential"]!])
        let subject = try VouchRobotics.verifyConsentEvidence(
            paramsJson: params,
            robotPublicKey: try jwkPublicKey(v["robot_public_key_jwk"]!)
        )
        XCTAssertNotEqual(subject, "null")
        XCTAssertTrue(subject.contains("explicit-consent"))
    }

    func testVerifyContinuityChainVerifies() throws {
        let v = try vector()
        let params = try jsonString(["embodiments": v["embodiment_chain"]!])
        let result = try VouchRobotics.verifyContinuityChain(
            paramsJson: params,
            agentPublicKey: try jwkPublicKey(v["embodiment_agent_key"]!)
        )
        XCTAssertTrue(result.contains("\"ok\":true"))
    }

    func testVerifyHandoffChainVerifies() throws {
        let v = try vector()
        // publicKeys maps each actor DID to its base64url-no-pad Ed25519 key: the
        // JWK `x` value carried straight through.
        let actorKeys = v["custody_actor_keys"] as! [String: [String: Any]]
        var publicKeys: [String: String] = [:]
        for (did, jwk) in actorKeys {
            publicKeys[did] = jwk["x"] as? String
        }
        let params = try jsonString([
            "handoffs": v["custody_chain"]!,
            "publicKeys": publicKeys,
            "originActor": v["custody_origin_actor"]!,
        ])
        let result = try VouchRobotics.verifyHandoffChain(paramsJson: params)
        XCTAssertTrue(result.contains("\"ok\":true"))
    }

    // MARK: Fixture + JSON + key helpers

    private func vector() throws -> [String: Any] {
        let url = Bundle.module.url(forResource: "vector", withExtension: "json")!
        return try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }

    /// Decode a JWK OKP Ed25519 public key (its base64url-no-pad `x` member) into
    /// the raw 32-byte key `Data` the curated wrapper expects.
    private func jwkPublicKey(_ jwk: Any) throws -> Data {
        let x = (jwk as! [String: Any])["x"] as! String
        return base64urlDecode(x)
    }

    /// Standard base64 decoding of a base64url-no-pad string.
    private func base64urlDecode(_ s: String) -> Data {
        var b64 = s.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while b64.count % 4 != 0 { b64.append("=") }
        return Data(base64Encoded: b64)!
    }

    private func jsonString(_ value: Any) throws -> String {
        String(data: try JSONSerialization.data(withJSONObject: value), encoding: .utf8)!
    }
}
