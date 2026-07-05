import XCTest

@testable import VouchCore

final class VouchCoreTests: XCTestCase {
    private let sampleCredential = """
        {"@context":["https://www.w3.org/ns/credentials/v2"],\
        "type":["VerifiableCredential","VouchCredential"],\
        "issuer":"did:web:agent.example.com",\
        "validFrom":"2026-04-26T10:00:00Z","validUntil":"2026-04-26T10:05:00Z",\
        "credentialSubject":{"id":"did:web:agent.example.com","vouchVersion":"1.0",\
        "intent":{"action":"read","target":"t","resource":"https://api/x"}}}
        """

    func testCanonicalizeSortsKeys() throws {
        XCTAssertEqual(try Vouch.canonicalize("{\"b\":1,\"a\":2}"), "{\"a\":2,\"b\":1}")
    }

    func testDidKeyRoundtrip() throws {
        let kp = try Vouch.generateEd25519()
        XCTAssertTrue(kp.didKey.hasPrefix("did:key:z6Mk"))
        XCTAssertEqual(try Vouch.ed25519(fromDidKey: kp.didKey), kp.publicKey)
    }

    func testSignAndVerify() throws {
        let kp = try Vouch.generateEd25519()
        let signed = try Vouch.sign(
            sampleCredential,
            seed: kp.seed,
            verificationMethod: kp.didKey + "#key-1",
            created: "2026-04-26T10:00:00Z"
        )
        XCTAssertTrue(try Vouch.verifyProof(signed, publicKey: kp.publicKey))
        let result = try Vouch.verify(
            signed, publicKey: kp.publicKey, now: "2026-04-26T10:02:00Z"
        )
        XCTAssertTrue(result.valid)
        // Expired window.
        let expired = try Vouch.verify(
            signed, publicKey: kp.publicKey, now: "2026-04-26T11:00:00Z"
        )
        XCTAssertTrue(expired.proofValid)
        XCTAssertFalse(expired.timeValid)
    }

    func testDualProofRoundtrip() throws {
        let ed = try Vouch.generateEd25519()
        let ml = try Vouch.generateMldsa44()
        let signed = try VouchCore.signDual(
            credentialJson: sampleCredential,
            ed25519Seed: ed.seed,
            mldsaSecret: ml.secretKey,
            mldsaPublic: ml.publicKey,
            ed25519Vm: ed.didKey + "#key-1",
            mldsaVm: ed.didKey + "#key-2",
            created: "2026-04-26T10:00:00Z"
        )
        XCTAssertTrue(try Vouch.verifyDual(signed, ed25519PublicKey: ed.publicKey, mldsaPublicKey: ml.publicKey))
    }

    // MARK: FROST threshold signing

    func testThresholdFrostCeremonyProducesValidSignature() throws {
        // Rust's aggregate() self-verifies before returning (see
        // vouch_core::threshold), so a completed, non-throwing ceremony is
        // itself the proof that the resulting signature is a valid, standard
        // Ed25519 signature over the message.
        let generatedJson = try Vouch.thresholdGenerateKey(minSigners: 2, maxSigners: 3)
        let generated = try jsonObject(generatedJson)
        let shares = generated["shares"] as! [[String: Any]]
        XCTAssertEqual(shares.count, 3)

        let share0 = try jsonString(shares[0])
        let share1 = try jsonString(shares[1])
        let id0 = shares[0]["identifier"] as! String
        let id1 = shares[1]["identifier"] as! String

        let round1A = try jsonObject(try Vouch.thresholdCommit(share0))
        let round1B = try jsonObject(try Vouch.thresholdCommit(share1))

        let commitmentsJson = try jsonString([
            id0: round1A["commitments"] as! String,
            id1: round1B["commitments"] as! String,
        ])

        let message = "charge api.bank invoices/42".data(using: .utf8)!

        let sigShare0 = try Vouch.thresholdSignShare(
            message: message, keyShareJson: share0, noncesB64: round1A["nonces"] as! String, commitmentsJson: commitmentsJson)
        let sigShare1 = try Vouch.thresholdSignShare(
            message: message, keyShareJson: share1, noncesB64: round1B["nonces"] as! String, commitmentsJson: commitmentsJson)

        let sharesJson = try jsonString([id0: sigShare0, id1: sigShare1])
        let groupPublicKeyJson = try jsonString(generated["group_public_key"] as! [String: Any])

        let signature = try Vouch.thresholdAggregate(
            message: message, commitmentsJson: commitmentsJson, sharesJson: sharesJson, groupPublicKeyJson: groupPublicKeyJson)
        XCTAssertEqual(signature.count, 64)
    }

    func testThresholdRejectsBadThreshold() {
        XCTAssertThrowsError(try Vouch.thresholdGenerateKey(minSigners: 1, maxSigners: 3))
    }

    // MARK: Root-identity recovery by Shamir secret sharing

    func testRecoverySplitAndCombineRoundtrips() throws {
        let secretB64 = "a 32 byte secret for shamir!!!!!".data(using: .utf8)!.base64EncodedString()
        let shares = try jsonStringArray(try Vouch.recoverySplitSecret(secretB64, threshold: 3, shares: 5))
        XCTAssertEqual(shares.count, 5)

        let combined = try Vouch.recoveryCombineShares(try jsonString(Array(shares[0..<3])))
        XCTAssertEqual(combined, secretB64)

        let combinedAlt = try Vouch.recoveryCombineShares(try jsonString([shares[0], shares[2], shares[4]]))
        XCTAssertEqual(combinedAlt, secretB64)
    }

    func testRecoveryBelowThresholdDoesNotRevealSecret() throws {
        let secretB64 = "another shamir secret!!".data(using: .utf8)!.base64EncodedString()
        let shares = try jsonStringArray(try Vouch.recoverySplitSecret(secretB64, threshold: 3, shares: 5))
        let combined = try Vouch.recoveryCombineShares(try jsonString(Array(shares[0..<2])))
        XCTAssertNotEqual(combined, secretB64)
    }

    func testRecoverySplitAndRecoverIdentitySignsIdentically() throws {
        let kp = try Vouch.generateEd25519()
        let seedB64 = kp.seed.base64EncodedString()
        let didKey = kp.didKey

        let shares = try jsonStringArray(try Vouch.recoverySplitIdentity(seedB64, threshold: 2, shares: 3))
        XCTAssertEqual(shares.count, 3)

        let recovered = try jsonObject(try Vouch.recoveryRecoverIdentity(try jsonString(Array(shares[0..<2])), did: didKey))
        XCTAssertEqual(recovered["did"] as! String, didKey)
        let recoveredSeedB64 = recovered["seed"] as! String
        XCTAssertEqual(recoveredSeedB64, seedB64)

        // The recovered seed is the original: sign with it and verify against
        // the original public key.
        let recoveredSeed = Data(base64Encoded: recoveredSeedB64)!
        let signed = try Vouch.sign(
            sampleCredential, seed: recoveredSeed, verificationMethod: didKey + "#key-1", created: "2026-04-26T10:00:00Z")
        XCTAssertTrue(try Vouch.verifyProof(signed, publicKey: kp.publicKey))
    }

    func testRecoveryTooFewSharesGivesWrongResultNotError() throws {
        let kp = try Vouch.generateEd25519()
        let seedB64 = kp.seed.base64EncodedString()
        let shares = try jsonStringArray(try Vouch.recoverySplitIdentity(seedB64, threshold: 3, shares: 5))
        let recovered = try jsonObject(try Vouch.recoveryRecoverIdentity(try jsonString(Array(shares[0..<2])), did: ""))
        XCTAssertNotEqual(recovered["seed"] as! String, seedB64)
    }

    private func jsonObject(_ json: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: json.data(using: .utf8)!) as! [String: Any]
    }

    private func jsonStringArray(_ json: String) throws -> [String] {
        try JSONSerialization.jsonObject(with: json.data(using: .utf8)!) as! [String]
    }

    private func jsonString(_ value: Any) throws -> String {
        String(data: try JSONSerialization.data(withJSONObject: value), encoding: .utf8)!
    }
}
