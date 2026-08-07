import XCTest

@testable import VouchCore

/// Verify-side example for the two robotics accountability flows, using only
/// the curated wrapper surface. Mirrors the producer-side
/// Python/TypeScript/Go/Rust examples (examples/robotics_ai_act_evidence_pack.py
/// and examples/robotics_vla_accountability_loop.py) from the consuming side:
///
/// - Regulatory evidence pack: `checkConformance` maps the shared interop
///   vector's Python-signed credential set onto all five built-in profiles,
///   reporting CONFORMS for the EU AI Act and the EU Machinery
///   Regulation and the exact open clause for the two profiles the set leaves
///   gaps in; `buildConformanceAttestation` then signs a point-in-time
///   attestation per profile and `verifyConformanceAttestation` checks it
///   offline.
/// - VLA accountability loop: `verifyIdentity` / `verifyRobotCredential`
///   authenticate the robot before trusting it (the wrapper-side analogue of
///   provenance-on-load), and `checkAction` reproduces the pre-actuation scope
///   gate, denying the over-speed and out-of-zone actions and allowing the
///   safe ones.
final class RoboticsVerifyExampleTests: XCTestCase {
    private let allProfileIds = [
        "eu-ai-act-high-risk",
        "iso-10218",
        "iso-ts-15066",
        "eu-machinery-2023-1230",
        "ul-3300",
    ]

    // A fixed assessor signing seed (0x03 x 32), so the attestation
    // round-trip is deterministic like the Rust core tests.
    private let assessorSeed = Data(repeating: 3, count: 32)
    // The Ed25519 public key that seed derives (base64url-no-pad).
    private let assessorPub = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY_k2NsFGFKyHN9E"

    private let scope = """
        {"maxForceN":80.0,"maxSpeedMps":1.5,"maxSpeedNearHumansMps":0.5,"allowedZones":["cell-3"]}
        """

    func testVerifiesTheRobotBeforeTrustingIt() throws {
        let v = try vector()
        let credential = try jsonString(v["robot_identity_credential"]!)
        let robotKey = try jwkPublicKey(v["robot_public_key_jwk"]!)

        let subject = try VouchRobotics.verifyIdentity(credential, robotPublicKey: robotKey)
        XCTAssertNotEqual(subject, "null", "the Python-minted identity must verify")
        XCTAssertTrue(subject.contains("\"make\":\"Acme Robotics\""))

        XCTAssertTrue(
            try VouchRobotics.verifyRobotCredential(credential, ed25519Public: robotKey),
            "the identity credential proof must verify under the robot key"
        )
    }

    func testReportsConformanceAndGapsAcrossAllFiveProfiles() throws {
        let v = try vector()
        let credentials = try jsonString(v["conformance_credentials"]!)

        for pid in allProfileIds {
            let report = try VouchRobotics.checkConformance(
                credentialsJson: credentials,
                profileId: pid
            )
            XCTAssertTrue(report.contains("\"profileId\":\"\(pid)\""))
            if pid != "eu-ai-act-high-risk" && pid != "eu-machinery-2023-1230" {
                // The vector's four-credential set carries no heartbeat motion
                // digest and no perception provenance, so exactly these two
                // profiles must report the open clause.
                XCTAssertTrue(report.contains("\"conforms\":false"), "\(pid): \(report)")
            } else {
                XCTAssertTrue(report.contains("\"conforms\":true"), "\(pid): \(report)")
            }
        }
    }

    func testSignsAndVerifiesOneAttestationPerProfile() throws {
        let v = try vector()
        let credentials = try jsonString(v["conformance_credentials"]!)
        let assessorKey = base64urlDecode(assessorPub)
        let robotKey = try jwkPublicKey(v["robot_public_key_jwk"]!)

        for pid in allProfileIds {
            let report = try VouchRobotics.checkConformance(
                credentialsJson: credentials,
                profileId: pid
            )
            let params = """
                {"issuerDid":"did:web:assessor.example.com",\
                "robotDid":"did:web:robot.example.com",\
                "report":\(report),\
                "validFrom":"2026-01-01T00:00:00Z"}
                """
            let attestation = try VouchRobotics.buildConformanceAttestation(
                signerSeed: assessorSeed,
                paramsJson: params
            )

            let subject = try VouchRobotics.verifyConformanceAttestation(
                attestation,
                publicKey: assessorKey
            )
            XCTAssertNotEqual(subject, "null", "\(pid) attestation must verify")
            XCTAssertTrue(subject.contains("\"profileId\":\"\(pid)\""))

            // A wrong key must not verify the attestation.
            XCTAssertEqual(
                try VouchRobotics.verifyConformanceAttestation(attestation, publicKey: robotKey),
                "null"
            )
        }
    }

    func testVlaGateAllowsSafeAndDeniesUnsafeActions() throws {
        let pick = try VouchRobotics.checkAction(
            scopeJson: scope,
            actionJson: "{\"forceN\":20.0,\"speedMps\":0.3,\"nearHumans\":true,\"zone\":\"cell-3\"}"
        )
        XCTAssertTrue(pick.contains("\"ok\":true"), "safe pick should pass: \(pick)")

        let hand = try VouchRobotics.checkAction(
            scopeJson: scope,
            actionJson: "{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}"
        )
        XCTAssertTrue(hand.contains("\"ok\":true"), "safe handover should pass: \(hand)")

        let sprint = try VouchRobotics.checkAction(
            scopeJson: scope,
            actionJson: "{\"speedMps\":2.5,\"nearHumans\":true,\"zone\":\"cell-3\"}"
        )
        XCTAssertTrue(sprint.contains("\"ok\":false"), "over-speed sprint should fail: \(sprint)")
        XCTAssertTrue(sprint.contains("speed_exceeded"))

        let fetch = try VouchRobotics.checkAction(
            scopeJson: scope,
            actionJson: "{\"forceN\":15.0,\"speedMps\":0.5,\"zone\":\"loading-bay\"}"
        )
        XCTAssertTrue(fetch.contains("\"ok\":false"), "out-of-zone fetch should fail: \(fetch)")
        XCTAssertTrue(fetch.contains("zone_not_allowed"))
    }

    // MARK: Fixture + JSON + key helpers

    private func vector() throws -> [String: Any] {
        let url = Bundle.module.url(forResource: "vector", withExtension: "json")!
        return try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
    }

    /// Decode a JWK OKP Ed25519 public key (its base64url-no-pad `x` member)
    /// into the raw 32-byte key `Data` the curated wrapper expects.
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
