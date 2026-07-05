import Foundation

/// Idiomatic entry point for the Vouch Protocol core on Apple platforms.
///
/// The `VouchCore` module also exports the lower-level UniFFI functions directly
/// (`canonicalize(json:)`, `generateEd25519()`, ...). This `Vouch` namespace
/// gathers them behind a discoverable surface and adds small conveniences. Every
/// call delegates to the canonical Rust core, so output is byte-identical to the
/// TypeScript, Python, Go, JVM, and .NET SDKs.
public enum Vouch {
    /// Library version of the underlying core.
    public static func version() -> String { VouchCore.version() }

    // MARK: JCS

    /// RFC 8785 canonicalization of a JSON string.
    public static func canonicalize(_ json: String) throws -> String {
        try VouchCore.canonicalize(json: json)
    }

    // MARK: Ed25519 / did:key

    public static func generateEd25519() throws -> Ed25519KeyPair {
        try VouchCore.generateEd25519()
    }
    public static func sign(seed: Data, message: Data) throws -> Data {
        try VouchCore.ed25519Sign(seed: seed, message: message)
    }
    public static func verify(publicKey: Data, message: Data, signature: Data) throws -> Bool {
        try VouchCore.ed25519Verify(publicKey: publicKey, message: message, signature: signature)
    }
    public static func didKey(fromEd25519 publicKey: Data) throws -> String {
        try VouchCore.didKeyFromEd25519(publicKey: publicKey)
    }
    public static func ed25519(fromDidKey did: String) throws -> Data {
        try VouchCore.ed25519FromDidKey(did: did)
    }

    // MARK: Data Integrity (eddsa-jcs-2022)

    /// Sign a credential, returning the credential JSON with a `proof` attached.
    public static func sign(
        _ credentialJson: String,
        seed: Data,
        verificationMethod: String,
        created: String
    ) throws -> String {
        try VouchCore.sign(
            credentialJson: credentialJson,
            seed: seed,
            verificationMethod: verificationMethod,
            created: created
        )
    }

    public static func verifyProof(_ credentialJson: String, publicKey: Data) throws -> Bool {
        try VouchCore.verifyProof(credentialJson: credentialJson, publicKey: publicKey)
    }

    /// Verify the proof and the validity window. `clockSkewSeconds` tolerates drift.
    public static func verify(
        _ credentialJson: String,
        publicKey: Data,
        now: String,
        clockSkewSeconds: Int64 = 30
    ) throws -> VerifyResult {
        try VouchCore.verify(
            credentialJson: credentialJson,
            publicKey: publicKey,
            nowIso: now,
            clockSkewSeconds: clockSkewSeconds
        )
    }

    // MARK: Post-quantum

    public static func generateMldsa44() throws -> MlDsaKeyPair { try VouchCore.generateMldsa44() }

    public static func verifyDual(_ credentialJson: String, ed25519PublicKey: Data, mldsaPublicKey: Data) throws -> Bool {
        try VouchCore.verifyDual(credentialJson: credentialJson, ed25519Public: ed25519PublicKey, mldsaPublic: mldsaPublicKey)
    }
    public static func verifyComposite(_ credentialJson: String, ed25519PublicKey: Data, mldsaPublicKey: Data) throws -> Bool {
        try VouchCore.verifyComposite(credentialJson: credentialJson, ed25519Public: ed25519PublicKey, mldsaPublic: mldsaPublicKey)
    }

    // MARK: Revocation

    public static func verifyStatus(_ credentialStatusJson: String, statusListCredentialJson: String) throws -> Bool {
        try VouchCore.verifyStatus(
            credentialStatusJson: credentialStatusJson,
            statusListCredentialJson: statusListCredentialJson
        )
    }

    // MARK: Delegation

    /// Build a delegation link. `validFrom`, `validUntil`, and
    /// `parentProofValue` are optional. Returns the link as JSON.
    public static func buildDelegationLink(
        issuer: String,
        subject: String,
        intentJson: String,
        validFrom: String? = nil,
        validUntil: String? = nil,
        parentProofValue: String? = nil
    ) throws -> String {
        try VouchCore.buildDelegationLink(
            issuer: issuer,
            subject: subject,
            intentJson: intentJson,
            validFrom: validFrom,
            validUntil: validUntil,
            parentProofValue: parentProofValue
        )
    }

    /// Validate the time-bound rule over a delegation chain (a JSON array of links).
    public static func verifyChainTimeBound(
        _ chainJson: String,
        now: String,
        clockSkewSeconds: Int64 = 30
    ) throws -> Bool {
        try VouchCore.verifyChainTimeBound(
            chainJson: chainJson, nowIso: now, clockSkewSeconds: clockSkewSeconds
        )
    }

    // MARK: FROST(Ed25519) threshold signing (RFC 9591)
    //
    // The aggregated signature is a standard Ed25519 signature, verifiable
    // with verify(_:publicKey:message:signature:) like any other; no new
    // proof type. See vouch_core::threshold for the ceremony and why the full
    // private key is never reconstructed.

    public static func thresholdGenerateKey(minSigners: UInt16, maxSigners: UInt16) throws -> String {
        try VouchCore.thresholdGenerateKey(minSigners: minSigners, maxSigners: maxSigners)
    }
    public static func thresholdCommit(_ keyShareJson: String) throws -> String {
        try VouchCore.thresholdCommit(keyShareJson: keyShareJson)
    }
    public static func thresholdSignShare(
        message: Data, keyShareJson: String, noncesB64: String, commitmentsJson: String
    ) throws -> String {
        try VouchCore.thresholdSignShare(
            message: message, keyShareJson: keyShareJson, noncesB64: noncesB64, commitmentsJson: commitmentsJson
        )
    }
    public static func thresholdAggregate(
        message: Data, commitmentsJson: String, sharesJson: String, groupPublicKeyJson: String
    ) throws -> Data {
        try VouchCore.thresholdAggregate(
            message: message, commitmentsJson: commitmentsJson, sharesJson: sharesJson,
            groupPublicKeyJson: groupPublicKeyJson
        )
    }

    // MARK: Root-identity recovery by Shamir secret sharing
    //
    // Distinct from FROST above: the seed IS reconstructed here, deliberately,
    // for cold recovery of a root identity, not for hot signing. See
    // vouch_core::recovery.

    public static func recoverySplitSecret(_ secretB64: String, threshold: UInt16, shares: UInt16) throws -> String {
        try VouchCore.recoverySplitSecret(secretB64: secretB64, threshold: threshold, shares: shares)
    }
    public static func recoveryCombineShares(_ sharesJson: String) throws -> String {
        try VouchCore.recoveryCombineShares(sharesJson: sharesJson)
    }
    public static func recoverySplitIdentity(_ seedB64: String, threshold: UInt16, shares: UInt16) throws -> String {
        try VouchCore.recoverySplitIdentity(seedB64: seedB64, threshold: threshold, shares: shares)
    }
    public static func recoveryRecoverIdentity(_ sharesJson: String, did: String) throws -> String {
        try VouchCore.recoveryRecoverIdentity(sharesJson: sharesJson, did: did)
    }
}
