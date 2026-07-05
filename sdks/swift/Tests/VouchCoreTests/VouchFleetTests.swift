import XCTest

@testable import VouchCore

final class VouchFleetTests: XCTestCase {
    private func trustedRoot(_ root: VouchAgent) -> [String: Data] {
        [root.did: root.publicKey]
    }

    private func signDeviceAction(_ device: VouchAgent, grant: String, resource: String) throws -> String {
        let grantView = VouchCredentials.Credential(grant)
        return try device.sign(action: grantView.action!, target: grantView.target!, resource: resource)
    }

    func testEnrollAndVerifyChain() throws {
        let root = try VouchAgent.create(domain: "root.example")
        let device = try VouchAgent.create() // did:key

        let grant = try VouchFleet.enrollDevice(
            root: root, deviceDid: device.did, action: "charge", target: "api.bank", resource: "https://api.bank/invoices")
        let action = try signDeviceAction(device, grant: grant, resource: "https://api.bank/invoices/42")

        let result = VouchFleet.verifyDelegatedChain([grant, action], trustedRoots: trustedRoot(root))
        XCTAssertTrue(result.ok, result.reason ?? "")
        XCTAssertEqual(result.rootDid, root.did)
        XCTAssertEqual(result.leaf?.issuer, device.did)
        XCTAssertEqual(result.leaf?.resource, "https://api.bank/invoices/42")
    }

    func testUntrustedRootRejected() throws {
        let root = try VouchAgent.create(domain: "root.example")
        let device = try VouchAgent.create()
        let grant = try VouchFleet.enrollDevice(
            root: root, deviceDid: device.did, action: "charge", target: "api.bank", resource: "https://api.bank/invoices")
        let action = try signDeviceAction(device, grant: grant, resource: "https://api.bank/invoices/42")

        let result = VouchFleet.verifyDelegatedChain([grant, action], trustedRoots: [:])
        XCTAssertFalse(result.ok)
    }

    func testWrongDeviceIssuerRejected() throws {
        let root = try VouchAgent.create(domain: "root.example")
        let device = try VouchAgent.create()
        let impostor = try VouchAgent.create()
        let grant = try VouchFleet.enrollDevice(
            root: root, deviceDid: device.did, action: "charge", target: "api.bank", resource: "https://api.bank/invoices")
        let action = try signDeviceAction(impostor, grant: grant, resource: "https://api.bank/invoices/42")

        let result = VouchFleet.verifyDelegatedChain([grant, action], trustedRoots: trustedRoot(root))
        XCTAssertFalse(result.ok)
    }

    func testTamperedActionRejected() throws {
        let root = try VouchAgent.create(domain: "root.example")
        let device = try VouchAgent.create()
        let grant = try VouchFleet.enrollDevice(
            root: root, deviceDid: device.did, action: "charge", target: "api.bank", resource: "https://api.bank/invoices")
        let action = try signDeviceAction(device, grant: grant, resource: "https://api.bank/invoices/42")
            .replacingOccurrences(of: "invoices/42", with: "invoices/evil")

        let result = VouchFleet.verifyDelegatedChain([grant, action], trustedRoots: trustedRoot(root))
        XCTAssertFalse(result.ok)
    }

    func testLeafIntentPolicy() throws {
        let root = try VouchAgent.create(domain: "root.example")
        let device = try VouchAgent.create()
        let grant = try VouchFleet.enrollDevice(
            root: root, deviceDid: device.did, action: "charge", target: "api.bank", resource: "https://api.bank/invoices")
        let action = try signDeviceAction(device, grant: grant, resource: "https://api.bank/invoices/42")
        let roots = trustedRoot(root)

        let ok = VouchFleet.verifyDelegatedChain([grant, action], trustedRoots: roots, requireAction: "charge")
        XCTAssertTrue(ok.ok, ok.reason ?? "")

        let bad = VouchFleet.verifyDelegatedChain([grant, action], trustedRoots: roots, requireAction: "refund")
        XCTAssertFalse(bad.ok)
    }

    func testRevokedDeviceRejected() throws {
        let root = try VouchAgent.create(domain: "root.example")
        let device = try VouchAgent.create()
        let grant = try VouchFleet.enrollDevice(
            root: root, deviceDid: device.did, action: "charge", target: "api.bank", resource: "https://api.bank/invoices")
        let action = try signDeviceAction(device, grant: grant, resource: "https://api.bank/invoices/42")
        let roots = trustedRoot(root)

        let before = VouchFleet.verifyDelegatedChain([grant, action], trustedRoots: roots)
        XCTAssertTrue(before.ok, before.reason ?? "")

        let after = VouchFleet.verifyDelegatedChain(
            [grant, action], trustedRoots: roots, revoked: { $0 == device.did })
        XCTAssertFalse(after.ok)
    }

    func testDeviceRegistryTracksRevocation() throws {
        let root = try VouchAgent.create(domain: "root.example")
        let device = try VouchAgent.create()
        let grant = try VouchFleet.enrollDevice(
            root: root, deviceDid: device.did, action: "charge", target: "api.bank", resource: "https://api.bank/invoices")
        let action = try signDeviceAction(device, grant: grant, resource: "https://api.bank/invoices/42")
        let roots = trustedRoot(root)

        let registry = VouchFleet.DeviceRegistry()
        registry.enroll(device.did, grant: grant)
        XCTAssertEqual(registry.activeDevices().count, 1)

        let before = VouchFleet.verifyDelegatedChain(
            [grant, action], trustedRoots: roots, revoked: registry.isRevoked)
        XCTAssertTrue(before.ok, before.reason ?? "")

        registry.revoke(device.did)
        XCTAssertEqual(registry.activeDevices().count, 0)
        let after = VouchFleet.verifyDelegatedChain(
            [grant, action], trustedRoots: roots, revoked: registry.isRevoked)
        XCTAssertFalse(after.ok)
    }

    func testDidKeyLinkResolvesWithoutTrustMap() throws {
        let root = try VouchAgent.create(domain: "root.example")
        let device = try VouchAgent.create()
        let grant = try VouchFleet.enrollDevice(root: root, deviceDid: device.did, action: "read", target: "t", resource: "https://x/y")
        let action = try signDeviceAction(device, grant: grant, resource: "https://x/y/z")

        let result = VouchFleet.verifyDelegatedChain([grant, action], trustedRoots: trustedRoot(root))
        XCTAssertTrue(result.ok, result.reason ?? "")
    }
}
