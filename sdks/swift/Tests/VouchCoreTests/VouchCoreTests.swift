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

    func testSignAndVerifyCredential() throws {
        let kp = try Vouch.generateEd25519()
        let signed = try Vouch.signCredential(
            sampleCredential,
            seed: kp.seed,
            verificationMethod: kp.didKey + "#key-1",
            created: "2026-04-26T10:00:00Z"
        )
        XCTAssertTrue(try Vouch.verifyProof(signed, publicKey: kp.publicKey))
        let result = try Vouch.verifyCredential(
            signed, publicKey: kp.publicKey, now: "2026-04-26T10:02:00Z"
        )
        XCTAssertTrue(result.valid)
        // Expired window.
        let expired = try Vouch.verifyCredential(
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
}
