import Foundation

/// Idiomatic robotics surface for the Vouch Protocol core on Apple platforms.
///
/// A curated set of the robot-credential operations, gathered behind a
/// discoverable namespace over the generated `VouchCore` functions. Every call
/// delegates to the canonical Rust core, so output is byte-identical to the
/// Python, TypeScript, Go, JVM, .NET, and C/C++ SDKs. JSON in, JSON out; keys are
/// raw bytes (`Data`).
public enum VouchRobotics {
    // MARK: Identity

    /// Mint a RobotIdentityCredential. `paramsJson` carries make/model/serial and
    /// the hardware root; returns the signed credential JSON.
    public static func mintIdentity(robotSeed: Data, paramsJson: String) throws -> String {
        try VouchCore.roboticsMintIdentity(robotSeed: robotSeed, paramsJson: paramsJson)
    }

    /// Verify a RobotIdentityCredential. Returns the credentialSubject JSON.
    public static func verifyIdentity(_ credentialJson: String, robotPublicKey: Data) throws -> String {
        try VouchCore.roboticsVerifyIdentity(credentialJson: credentialJson, robotPublicKey: robotPublicKey)
    }

    // MARK: Physical capability scope

    /// Check a physical action against a physical capability scope. Returns JSON
    /// `{ok, reasons}`.
    public static func checkAction(scopeJson: String, actionJson: String) throws -> String {
        try VouchCore.roboticsCheckAction(scopeJson: scopeJson, actionJson: actionJson)
    }

    // MARK: Passport

    /// Verify a scannable robot passport URI. Returns the passport summary JSON.
    public static func verifyPassport(uri: String, publicKey: Data, now: String) throws -> String {
        try VouchCore.roboticsVerifyPassportUri(uri: uri, publicKey: publicKey, nowIso: now)
    }

    // MARK: Regulatory conformance

    /// Check a set of robot credentials (a JSON array) against a named regulatory
    /// profile. Returns the deterministic report JSON.
    public static func checkConformance(credentialsJson: String, profileId: String) throws -> String {
        try VouchCore.roboticsCheckConformance(credentialsJson: credentialsJson, profileId: profileId)
    }

    /// Sign a point-in-time conformance attestation over a report. Returns the
    /// signed credential JSON.
    public static func buildConformanceAttestation(signerSeed: Data, paramsJson: String) throws -> String {
        try VouchCore.roboticsBuildConformanceAttestation(signerSeed: signerSeed, paramsJson: paramsJson)
    }

    /// Verify a conformance attestation and its bound report digest. Returns the
    /// credentialSubject JSON.
    public static func verifyConformanceAttestation(_ credentialJson: String, publicKey: Data) throws -> String {
        try VouchCore.roboticsVerifyConformanceAttestation(credentialJson: credentialJson, publicKey: publicKey)
    }

    // MARK: Post-quantum

    /// Attach a hybrid post-quantum proof (Ed25519 + ML-DSA-44) to a robot
    /// credential. Returns the re-signed credential JSON.
    public static func signPq(
        _ credentialJson: String,
        ed25519Seed: Data,
        mldsaSecret: Data,
        mldsaPublic: Data,
        created: String
    ) throws -> String {
        try VouchCore.roboticsSignPq(
            credentialJson: credentialJson,
            ed25519Seed: ed25519Seed,
            mldsaSecret: mldsaSecret,
            mldsaPublic: mldsaPublic,
            created: created
        )
    }

    /// Verify a robot credential whether it carries a classical or a hybrid proof,
    /// auto-detected from the proof. Pass the ML-DSA-44 public key for a hybrid
    /// credential, or `nil` for a classical one.
    public static func verifyRobotCredential(
        _ credentialJson: String,
        ed25519Public: Data,
        mldsa44Public: Data? = nil
    ) throws -> Bool {
        try VouchCore.roboticsVerifyRobotCredential(
            credentialJson: credentialJson,
            ed25519Public: ed25519Public,
            mldsa44Public: mldsa44Public
        )
    }

    // MARK: Robot-to-infrastructure bounded access

    /// Authorize an infrastructure access request offline against an operator
    /// grant. `paramsJson` carries `{grant, request, now?}`. Pass the operator and
    /// robot public keys. Returns the decision JSON `{ok, reasons}`.
    public static func authorizeAccess(
        paramsJson: String,
        operatorPublicKey: Data,
        robotPublicKey: Data
    ) throws -> String {
        try VouchCore.roboticsAuthorizeAccess(
            paramsJson: paramsJson,
            operatorPublicKey: operatorPublicKey,
            robotPublicKey: robotPublicKey
        )
    }

    // MARK: Fused-sensor provenance

    /// Verify a fused-sensor provenance attestation. Pass the robot public key
    /// and, optionally, the raw fused output as multibase to reproduce its hash.
    /// Returns the credentialSubject JSON, or the JSON literal `null` if invalid.
    public static func verifyFusedAttestation(
        _ credentialJson: String,
        publicKey: Data,
        fusedOutputMb: String? = nil
    ) throws -> String {
        try VouchCore.roboticsVerifyFusedAttestation(
            credentialJson: credentialJson,
            publicKey: publicKey,
            fusedOutputMb: fusedOutputMb
        )
    }

    // MARK: Wear and degradation

    /// Verify a robot wear attestation. Pass the robot public key. Returns the
    /// credentialSubject JSON, or the JSON literal `null` if invalid.
    public static func verifyWearAttestation(
        _ credentialJson: String,
        publicKey: Data
    ) throws -> String {
        try VouchCore.roboticsVerifyWearAttestation(
            credentialJson: credentialJson,
            publicKey: publicKey
        )
    }

    /// Derive a physical capability scope narrowed for a wear level. `paramsJson`
    /// carries `{scope, wearLevel}`. Returns the narrowed scope JSON.
    public static func attenuateForWear(paramsJson: String) throws -> String {
        try VouchCore.roboticsAttenuateForWear(paramsJson: paramsJson)
    }

    // MARK: Bystander-consent evidence

    /// Verify bystander-consent evidence. `paramsJson` carries `{evidence,
    /// captureMb?, consentTokens?, bystanderKeys?, now?}`. Pass the robot public
    /// key. Returns the credentialSubject JSON, or the JSON literal `null` if
    /// invalid.
    public static func verifyConsentEvidence(
        paramsJson: String,
        robotPublicKey: Data
    ) throws -> String {
        try VouchCore.roboticsVerifyConsentEvidence(
            paramsJson: paramsJson,
            robotPublicKey: robotPublicKey
        )
    }

    // MARK: Cross-embodiment continuity

    /// Verify a cross-embodiment continuity chain. `paramsJson` carries the chain
    /// (`{embodiments, originBody?}`). Pass the agent public key. Returns the
    /// result JSON `{ok, currentBody}`.
    public static func verifyContinuityChain(
        paramsJson: String,
        agentPublicKey: Data
    ) throws -> String {
        try VouchCore.roboticsVerifyContinuityChain(
            paramsJson: paramsJson,
            agentPublicKey: agentPublicKey
        )
    }

    // MARK: Physical custody handoff

    /// Verify a physical custody handoff chain. `paramsJson` carries the chain,
    /// the actor keys, and options (`{handoffs, publicKeys, originActor?}`).
    /// Returns the result JSON `{ok, currentHolder}`.
    public static func verifyHandoffChain(paramsJson: String) throws -> String {
        try VouchCore.roboticsVerifyHandoffChain(paramsJson: paramsJson)
    }
}
