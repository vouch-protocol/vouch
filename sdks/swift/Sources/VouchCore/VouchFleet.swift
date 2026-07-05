import Foundation

/// Cross-device identity by per-device keys and delegation (the OSS path).
///
/// The private key never travels. Each device mints its OWN key locally (see
/// ``VouchAgent/create(domain:defaultExpirySeconds:)``), and the user's root
/// identity delegates scoped, time-bound, revocable authority to that
/// device's DID via ``enrollDevice(root:deviceDid:action:target:resource:validSeconds:)``.
/// A device signs its own actions with its own key, chained under the root
/// grant, and ``verifyDelegatedChain(_:trustedRoots:revoked:clockSkewSeconds:requireAction:requireTarget:requireResource:)``
/// checks the whole chain. Losing a device means revoking one delegation,
/// not rotating the whole identity, and no key is ever copied between
/// devices.
///
/// Mirrors `vouch.fleet` (Python), `fleet.ts` (TypeScript), and
/// `go-sidecar/signer/fleet.go` (Go).
public enum VouchFleet {
    private static let defaultValidSeconds: Int64 = 86400
    private static let defaultClockSkewSeconds: Int64 = 30

    /// Issues a delegation grant from the root agent to a device's DID. The
    /// returned grant authorizes deviceDid to act within the given scope; the
    /// device, holding its own key, signs its actions with this grant as the
    /// parent of its own credential, chaining back to the root. The root
    /// never sees or holds the device's key.
    public static func enrollDevice(
        root: VouchAgent, deviceDid: String, action: String, target: String, resource: String,
        validSeconds: Int64 = defaultValidSeconds
    ) throws -> String {
        let now = Date()
        let validFrom = VouchAgent.iso(now)
        let validUntil = VouchAgent.iso(now.addingTimeInterval(TimeInterval(validSeconds)))
        let credentialId = "urn:uuid:\(UUID().uuidString.lowercased())"
        let unsigned = try VouchCredentials.build(
            issuerDid: root.did, action: action, target: target, resource: resource,
            delegatee: deviceDid, validFrom: validFrom, validUntil: validUntil, credentialId: credentialId
        )
        return try Vouch.sign(unsigned, seed: root.seedData, verificationMethod: "\(root.did)#key-1", created: validFrom)
    }

    /// Reports whether an identifier (a device DID or a credential id) has been revoked.
    public typealias RevocationCheck = (String) -> Bool

    /// The outcome of verifying a delegated device chain.
    public struct ChainResult {
        public let ok: Bool
        public let reason: String?
        public let leaf: VouchCredentials.Credential?
        public let rootDid: String?

        fileprivate static func fail(_ reason: String, leaf: VouchCredentials.Credential? = nil) -> ChainResult {
            ChainResult(ok: false, reason: reason, leaf: leaf, rootDid: nil)
        }
        fileprivate static func success(leaf: VouchCredentials.Credential, rootDid: String) -> ChainResult {
            ChainResult(ok: true, reason: nil, leaf: leaf, rootDid: rootDid)
        }
    }

    /// Verifies a delegation chain from a trusted root down to a leaf action.
    /// credentials is ordered root-first: [rootGrant, ...intermediateGrants,
    /// leafAction]. Every credential's Data Integrity proof and validity
    /// window are checked, each step must be authorized by the step before it
    /// (the child's issuer is the parent's delegatee), the resource may only
    /// narrow, and the validity windows must nest. trustedRoots maps an
    /// accepted root issuer DID to its public key; the first credential's
    /// issuer MUST appear there.
    public static func verifyDelegatedChain(
        _ credentials: [String],
        trustedRoots: [String: Data],
        revoked: RevocationCheck? = nil,
        clockSkewSeconds: Int64 = defaultClockSkewSeconds,
        requireAction: String? = nil,
        requireTarget: String? = nil,
        requireResource: String? = nil
    ) -> ChainResult {
        guard !credentials.isEmpty else { return .fail("empty chain") }
        let isRevoked: RevocationCheck = revoked ?? { _ in false }

        var passports: [VouchCredentials.Credential] = []
        for (index, credentialJson) in credentials.enumerated() {
            let passport = VouchCredentials.Credential(credentialJson)
            guard let issuer = passport.issuer, !issuer.isEmpty else {
                return .fail("credential \(index) has no issuer")
            }

            var key = trustedRoots[issuer]
            if index == 0 && key == nil {
                return .fail("root issuer \"\(issuer)\" is not in trusted roots")
            }
            if key == nil {
                key = VouchAgent.publicKeyForIssuer(issuer)
            }
            guard let publicKey = key else {
                return .fail("credential \(index) issuer \"\(issuer)\" key could not be resolved")
            }

            guard let result = try? Vouch.verify(
                credentialJson, publicKey: publicKey, now: VouchAgent.iso(Date()), clockSkewSeconds: clockSkewSeconds
            ), result.valid else {
                return .fail("credential \(index) failed verification")
            }

            if isRevoked(issuer) {
                return .fail("credential \(index) issuer \"\(issuer)\" is revoked")
            }
            if let id = passport.id, !id.isEmpty, isRevoked(id) {
                return .fail("credential \(index) (\(id)) is revoked")
            }
            passports.append(passport)
        }

        for i in 0..<(passports.count - 1) {
            let parent = passports[i]
            let child = passports[i + 1]

            guard let delegatee = parent.delegatee, !delegatee.isEmpty else {
                return .fail("link \(i) (grant by \"\(parent.issuer ?? "")\") names no delegatee")
            }
            if isRevoked(delegatee) {
                return .fail("link \(i): delegatee \"\(delegatee)\" is revoked")
            }
            if delegatee != child.issuer {
                return .fail("link \(i): child issuer \"\(child.issuer ?? "")\" is not the delegatee \"\(delegatee)\" the parent authorized")
            }

            if let parentResource = parent.resource, let childResource = child.resource,
               !isSubResource(childResource, parentResource) {
                return .fail("link \(i): resource \"\(childResource)\" is not within the granted \"\(parentResource)\"")
            }

            if !windowWithin(child, parent) {
                return .fail("link \(i): child validity is outside the grant window")
            }
        }

        let leaf = passports[passports.count - 1]
        if let requireAction = requireAction, requireAction != leaf.action {
            return .fail("leaf intent.action != \"\(requireAction)\"", leaf: leaf)
        }
        if let requireTarget = requireTarget, requireTarget != leaf.target {
            return .fail("leaf intent.target != \"\(requireTarget)\"", leaf: leaf)
        }
        if let requireResource = requireResource, requireResource != leaf.resource {
            return .fail("leaf intent.resource != \"\(requireResource)\"", leaf: leaf)
        }

        return .success(leaf: leaf, rootDid: passports[0].issuer ?? "")
    }

    private static func isSubResource(_ child: String, _ parent: String) -> Bool {
        if child == parent { return true }
        let trimmed = parent.hasSuffix("/") ? String(parent.dropLast()) : parent
        return child.hasPrefix(trimmed + "/")
    }

    private static func windowWithin(_ child: VouchCredentials.Credential, _ parent: VouchCredentials.Credential) -> Bool {
        guard let cFrom = child.validFrom.flatMap(parseISO8601),
              let cUntil = child.validUntil.flatMap(parseISO8601),
              let pFrom = parent.validFrom.flatMap(parseISO8601),
              let pUntil = parent.validUntil.flatMap(parseISO8601)
        else { return false }
        return cFrom >= pFrom && cUntil <= pUntil
    }

    private static func parseISO8601(_ s: String) -> Date? {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }

    /// A small in-memory record of a root's enrolled and revoked devices.
    /// Pass ``isRevoked(_:)`` straight to ``verifyDelegatedChain``, or back
    /// this with your own store (a database, a BitstringStatusList) by
    /// implementing ``RevocationCheck`` yourself; this is only the simplest
    /// default.
    public final class DeviceRegistry {
        private var enrolled: Set<String> = []
        private var revoked: Set<String> = []

        public init() {}

        /// Records a device as enrolled (the grant is not retained).
        public func enroll(_ deviceDid: String, grant: String) {
            enrolled.insert(deviceDid)
            revoked.remove(deviceDid)
        }

        /// Revokes a device. Chains issued by or delegated to it stop verifying.
        public func revoke(_ deviceDid: String) {
            revoked.insert(deviceDid)
        }

        public func isRevoked(_ identifier: String) -> Bool {
            revoked.contains(identifier)
        }

        /// Enrolled devices that have not been revoked.
        public func activeDevices() -> [String] {
            enrolled.filter { !revoked.contains($0) }.sorted()
        }
    }
}
