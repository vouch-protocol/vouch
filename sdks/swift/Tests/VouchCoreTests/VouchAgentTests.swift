import XCTest

@testable import VouchCore

final class VouchAgentTests: XCTestCase {
    func testDidWebMintSignVerify() throws {
        let agent = try VouchAgent.create(domain: "agent.example")
        XCTAssertEqual(agent.did, "did:web:agent.example")
        let signed = try agent.sign(action: "read", target: "did:web:files", resource: "https://files/x")
        XCTAssertTrue(try agent.verify(signed))

        let c = VouchCredentials.Credential(signed)
        XCTAssertEqual(c.action, "read")
        XCTAssertEqual(c.target, "did:web:files")
        XCTAssertEqual(c.resource, "https://files/x")
        XCTAssertEqual(c.issuer, "did:web:agent.example")
    }

    func testDidKeyWhenNoDomain() throws {
        let agent = try VouchAgent.create()
        XCTAssertTrue(agent.did.hasPrefix("did:key:"))
        let signed = try agent.sign(action: "write", target: "t", resource: "r")
        XCTAssertTrue(try agent.verify(signed))
    }

    func testDidKeyResolutionAcrossIssuers() throws {
        let a = try VouchAgent.create()
        let b = try VouchAgent.create()
        let signedByB = try b.sign(action: "read", target: "t", resource: "https://x/y")
        XCTAssertTrue(try a.verify(signedByB))
    }

    func testWrongKeyFails() throws {
        let a = try VouchAgent.create(domain: "a.example")
        let b = try VouchAgent.create(domain: "b.example")
        let signed = try a.sign(action: "read", target: "t", resource: "https://x/y")
        XCTAssertFalse(try VouchAgent.verifyWith(signed, publicKey: b.publicKey))
    }

    func testVerifyWithOwnKey() throws {
        let agent = try VouchAgent.create(domain: "agent.example")
        let signed = try agent.sign(action: "read", target: "t", resource: "https://x/y")
        XCTAssertTrue(try VouchAgent.verifyWith(signed, publicKey: agent.publicKey))
    }

    func testMissingIntentFieldThrows() {
        XCTAssertThrowsError(
            try VouchCredentials.build(
                issuerDid: "did:web:a", action: "", target: "t", resource: "https://x/y",
                validFrom: "2026-01-01T00:00:00Z", validUntil: "2026-01-01T00:05:00Z",
                credentialId: "urn:uuid:1"))
    }
}
