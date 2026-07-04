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
}
