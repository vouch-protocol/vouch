import Foundation

/// Ergonomic developer-experience layer over ``Vouch``.
///
/// Mirrors the Agent helper in the Python and TypeScript SDKs: one value that
/// holds an identity and signs and verifies, so callers do not build credential
/// JSON or pass seeds and public keys around by hand. The credential body is
/// built in-language, the same way the other SDKs build it, and the crypto goes
/// through the Rust core. The wire format is unchanged.
///
/// ```swift
/// let agent = try VouchAgent.create(domain: "agent.example")
/// let signed = try agent.sign(action: "read", target: "did:web:files",
///                             resource: "https://files/x")
/// let ok = try agent.verify(signed)
/// ```
///
/// With a domain the identity is `did:web:<domain>`; without one it is a
/// self-certifying `did:key`.
public struct VouchAgent {
    public let did: String
    public let publicKey: Data
    private let seed: Data
    private let defaultExpirySeconds: Int64

    /// The raw seed, for same-module ergonomic layers (e.g. ``VouchFleet``).
    var seedData: Data { seed }

    private init(did: String, seed: Data, publicKey: Data, defaultExpirySeconds: Int64) {
        self.did = did
        self.seed = seed
        self.publicKey = publicKey
        self.defaultExpirySeconds = defaultExpirySeconds
    }

    /// Mint a fresh identity. With a domain it is did:web, without one did:key.
    public static func create(
        domain: String? = nil,
        defaultExpirySeconds: Int64 = 300
    ) throws -> VouchAgent {
        let kp = try Vouch.generateEd25519()
        let did: String
        if let domain = domain, !domain.isEmpty {
            did = "did:web:\(domain)"
        } else {
            did = kp.didKey
        }
        return VouchAgent(
            did: did, seed: kp.seed, publicKey: kp.publicKey,
            defaultExpirySeconds: defaultExpirySeconds
        )
    }

    /// Rehydrate an agent from stored key material (no new identity is minted).
    public static func load(did: String, seed: Data, publicKey: Data) -> VouchAgent {
        VouchAgent(did: did, seed: seed, publicKey: publicKey, defaultExpirySeconds: 300)
    }

    /// Sign an intent as a Vouch Credential, returning the signed credential JSON.
    public func sign(
        action: String,
        target: String,
        resource: String,
        validSeconds: Int64? = nil
    ) throws -> String {
        let now = Date()
        let validFrom = VouchAgent.iso(now)
        let validUntil = VouchAgent.iso(now.addingTimeInterval(TimeInterval(validSeconds ?? defaultExpirySeconds)))
        let credentialId = "urn:uuid:\(UUID().uuidString.lowercased())"
        let unsigned = try VouchCredentials.build(
            issuerDid: did, action: action, target: target, resource: resource,
            validFrom: validFrom, validUntil: validUntil, credentialId: credentialId
        )
        return try Vouch.sign(
            unsigned, seed: seed, verificationMethod: "\(did)#key-1", created: validFrom
        )
    }

    /// Verify a credential. If it was issued by this agent, it is checked against
    /// this agent's own key; otherwise the issuer key is resolved from a did:key
    /// issuer. Returns true only when the proof and the validity window are valid.
    public func verify(_ credentialJson: String) throws -> Bool {
        let issuer = VouchCredentials.Credential(credentialJson).issuer
        let pub = issuer == did ? publicKey : VouchAgent.publicKeyForIssuer(issuer)
        guard let publicKey = pub else { return false }
        return try VouchAgent.verifyWith(credentialJson, publicKey: publicKey)
    }

    /// Verify a credential against an explicit public key.
    public static func verifyWith(_ credentialJson: String, publicKey: Data) throws -> Bool {
        let result = try Vouch.verify(
            credentialJson, publicKey: publicKey, now: iso(Date()), clockSkewSeconds: 30
        )
        return result.valid
    }

    /// Resolve the Ed25519 public key for a did:key issuer. Returns nil for
    /// non-did:key issuers, which need an explicit key or a DID-document lookup.
    public static func publicKeyForIssuer(_ issuer: String?) -> Data? {
        guard let issuer = issuer, issuer.hasPrefix("did:key:") else { return nil }
        return try? Vouch.ed25519(fromDidKey: issuer)
    }

    static func iso(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
        return f.string(from: date)
    }
}

/// Builds the unsigned Vouch Credential body in-language and reads it back. The
/// shape matches the Rust core and the Python/TypeScript/Go SDKs; only the crypto
/// goes through the core, so credentials verify identically across SDKs.
public enum VouchCredentials {
    public static let vcContextV2 = "https://www.w3.org/ns/credentials/v2"
    public static let vouchContextV1 = "https://vouch-protocol.com/contexts/v1"
    public static let protocolVersion = "1.0"

    /// Construct the unsigned credential JSON. Intent fields are required.
    public static func build(
        issuerDid: String,
        action: String,
        target: String,
        resource: String,
        validFrom: String,
        validUntil: String,
        credentialId: String
    ) throws -> String {
        try build(
            issuerDid: issuerDid, action: action, target: target, resource: resource,
            delegatee: nil, validFrom: validFrom, validUntil: validUntil, credentialId: credentialId
        )
    }

    /// Construct the unsigned credential JSON with an added intent.delegatee
    /// field, used to grant another DID scoped authority (cross-device
    /// delegation; see ``VouchFleet``). Pass nil to omit it.
    public static func build(
        issuerDid: String,
        action: String,
        target: String,
        resource: String,
        delegatee: String?,
        validFrom: String,
        validUntil: String,
        credentialId: String
    ) throws -> String {
        for (name, value) in [("action", action), ("target", target), ("resource", resource)] {
            if value.isEmpty {
                throw VouchAgentError.invalidIntent(
                    "intent.\(name) is required and must be a non-empty string")
            }
        }
        var intent: [String: Any] = ["action": action, "target": target, "resource": resource]
        if let delegatee = delegatee, !delegatee.isEmpty {
            intent["delegatee"] = delegatee
        }
        let subject: [String: Any] = [
            "id": issuerDid, "vouchVersion": protocolVersion, "intent": intent,
        ]
        let vc: [String: Any] = [
            "@context": [vcContextV2, vouchContextV1],
            "id": credentialId,
            "type": ["VerifiableCredential", "VouchCredential"],
            "issuer": issuerDid,
            "validFrom": validFrom,
            "validUntil": validUntil,
            "credentialSubject": subject,
        ]
        let data = try JSONSerialization.data(withJSONObject: vc, options: [.sortedKeys])
        guard let json = String(data: data, encoding: .utf8) else {
            throw VouchAgentError.invalidIntent("could not encode credential JSON")
        }
        return json
    }

    /// A read-friendly view over a credential JSON.
    public struct Credential {
        private let root: [String: Any]

        public init(_ credentialJson: String) {
            let data = credentialJson.data(using: .utf8) ?? Data()
            root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        }

        public var action: String? { intentField("action") }
        public var target: String? { intentField("target") }
        public var resource: String? { intentField("resource") }

        /// The delegatee DID, if this credential is a delegation grant, else nil.
        public var delegatee: String? { intentField("delegatee") }

        public var id: String? { root["id"] as? String }
        public var validFrom: String? { root["validFrom"] as? String }
        public var validUntil: String? { root["validUntil"] as? String }

        public var issuer: String? {
            if let s = root["issuer"] as? String { return s }
            if let a = root["issuer"] as? [String] { return a.first }
            return nil
        }

        private func intentField(_ key: String) -> String? {
            guard let subject = root["credentialSubject"] as? [String: Any],
                  let intent = subject["intent"] as? [String: Any]
            else { return nil }
            return intent[key] as? String
        }
    }
}

/// Errors from the ergonomic layer.
public enum VouchAgentError: Error {
    case invalidIntent(String)
}
