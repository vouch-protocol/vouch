using System;
using System.Runtime.InteropServices;

namespace VouchProtocol.Core;

/// <summary>Thrown when the Vouch core reports an error.</summary>
public sealed class VouchException : Exception
{
    public VouchException(string message) : base(message) { }
}

/// <summary>
/// .NET SDK for the Vouch Protocol core (#34). Calls the canonical Rust core
/// (<c>vouch-core</c>) through its cbindgen C ABI via P/Invoke, so .NET apps
/// verify credentials with the exact same bytes as every other Vouch SDK.
/// Binary values are base64 strings; credentials and proofs are JSON strings.
/// </summary>
public static class Vouch
{
    private const string Lib = "vouch_core_uniffi";

    [DllImport(Lib)] private static extern void vouch_string_free(IntPtr s);
    [DllImport(Lib)] private static extern IntPtr vouch_version();
    [DllImport(Lib)] private static extern IntPtr vouch_canonicalize([MarshalAs(UnmanagedType.LPUTF8Str)] string json, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_generate_ed25519(out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_sign([MarshalAs(UnmanagedType.LPUTF8Str)] string cred, [MarshalAs(UnmanagedType.LPUTF8Str)] string seedB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string vm, [MarshalAs(UnmanagedType.LPUTF8Str)] string created, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_build_proof([MarshalAs(UnmanagedType.LPUTF8Str)] string cred, [MarshalAs(UnmanagedType.LPUTF8Str)] string seedB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string vm, [MarshalAs(UnmanagedType.LPUTF8Str)] string created, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_verify_proof([MarshalAs(UnmanagedType.LPUTF8Str)] string cred, [MarshalAs(UnmanagedType.LPUTF8Str)] string pubB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_verify([MarshalAs(UnmanagedType.LPUTF8Str)] string cred, [MarshalAs(UnmanagedType.LPUTF8Str)] string pubB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string nowIso, long skew, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_verify_dual([MarshalAs(UnmanagedType.LPUTF8Str)] string cred, [MarshalAs(UnmanagedType.LPUTF8Str)] string edPubB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string mldsaPubB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_verify_composite([MarshalAs(UnmanagedType.LPUTF8Str)] string cred, [MarshalAs(UnmanagedType.LPUTF8Str)] string edPubB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string mldsaPubB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_verify_status([MarshalAs(UnmanagedType.LPUTF8Str)] string csJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string slJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_build_delegation_link([MarshalAs(UnmanagedType.LPUTF8Str)] string issuer, [MarshalAs(UnmanagedType.LPUTF8Str)] string subject, [MarshalAs(UnmanagedType.LPUTF8Str)] string intentJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string? validFrom, [MarshalAs(UnmanagedType.LPUTF8Str)] string? validUntil, [MarshalAs(UnmanagedType.LPUTF8Str)] string? parentProofValue, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_verify_chain_time_bound([MarshalAs(UnmanagedType.LPUTF8Str)] string chainJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string nowIso, long skew, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_threshold_generate_key(ushort minSigners, ushort maxSigners, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_threshold_commit([MarshalAs(UnmanagedType.LPUTF8Str)] string keyShareJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_threshold_sign_share([MarshalAs(UnmanagedType.LPUTF8Str)] string messageB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string keyShareJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string noncesB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string commitmentsJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_threshold_aggregate([MarshalAs(UnmanagedType.LPUTF8Str)] string messageB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string commitmentsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string sharesJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string groupPublicKeyJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_recovery_split_secret([MarshalAs(UnmanagedType.LPUTF8Str)] string secretB64, ushort threshold, ushort shares, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_recovery_combine_shares([MarshalAs(UnmanagedType.LPUTF8Str)] string sharesJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_recovery_split_identity([MarshalAs(UnmanagedType.LPUTF8Str)] string seedB64, ushort threshold, ushort shares, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_recovery_recover_identity([MarshalAs(UnmanagedType.LPUTF8Str)] string sharesJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string did, out IntPtr err);

    private static string Take(IntPtr result, IntPtr err)
    {
        if (result == IntPtr.Zero)
        {
            string msg = err == IntPtr.Zero ? "unknown error" : (Marshal.PtrToStringUTF8(err) ?? "error");
            if (err != IntPtr.Zero) vouch_string_free(err);
            throw new VouchException(msg);
        }
        string s = Marshal.PtrToStringUTF8(result) ?? string.Empty;
        vouch_string_free(result);
        return s;
    }

    private static bool AsBool(string s) => s == "true";

    /// <summary>Version of the underlying core.</summary>
    public static string Version()
    {
        var p = vouch_version();
        var s = Marshal.PtrToStringUTF8(p) ?? string.Empty;
        vouch_string_free(p);
        return s;
    }

    /// <summary>RFC 8785 canonicalization of a JSON string.</summary>
    public static string Canonicalize(string json)
        => Take(vouch_canonicalize(json, out var err), err);

    /// <summary>Generate an Ed25519 key pair as JSON {seed_b64, public_b64, multikey, did_key}.</summary>
    public static string GenerateEd25519()
        => Take(vouch_generate_ed25519(out var err), err);

    /// <summary>Sign a credential (eddsa-jcs-2022), returning the credential with a proof attached.</summary>
    public static string Sign(string credentialJson, string seedB64, string verificationMethod, string created)
        => Take(vouch_sign(credentialJson, seedB64, verificationMethod, created, out var err), err);

    /// <summary>Build a detached eddsa-jcs-2022 proof object (JSON).</summary>
    public static string BuildProof(string credentialJson, string seedB64, string verificationMethod, string created)
        => Take(vouch_build_proof(credentialJson, seedB64, verificationMethod, created, out var err), err);

    /// <summary>Verify an eddsa-jcs-2022 proof.</summary>
    public static bool VerifyProof(string credentialJson, string publicB64)
        => AsBool(Take(vouch_verify_proof(credentialJson, publicB64, out var err), err));

    /// <summary>Verify proof + validity window, as JSON {proofValid, timeValid, valid}.</summary>
    public static string Verify(string credentialJson, string publicB64, string nowIso, long clockSkewSeconds = 30)
        => Take(vouch_verify(credentialJson, publicB64, nowIso, clockSkewSeconds, out var err), err);

    /// <summary>Verify a dual proof (Ed25519 + ML-DSA-44).</summary>
    public static bool VerifyDual(string credentialJson, string ed25519PublicB64, string mldsaPublicB64)
        => AsBool(Take(vouch_verify_dual(credentialJson, ed25519PublicB64, mldsaPublicB64, out var err), err));

    /// <summary>Verify a v1.6.x composite hybrid proof.</summary>
    public static bool VerifyComposite(string credentialJson, string ed25519PublicB64, string mldsaPublicB64)
        => AsBool(Take(vouch_verify_composite(credentialJson, ed25519PublicB64, mldsaPublicB64, out var err), err));

    /// <summary>Verify a credential's revocation status against a BitstringStatusList credential.</summary>
    public static bool VerifyStatus(string credentialStatusJson, string statusListCredentialJson)
        => AsBool(Take(vouch_verify_status(credentialStatusJson, statusListCredentialJson, out var err), err));

    /// <summary>Build a delegation link. Pass null for optional validFrom/validUntil/parentProofValue. Returns the link as JSON.</summary>
    public static string BuildDelegationLink(string issuer, string subject, string intentJson,
        string? validFrom = null, string? validUntil = null, string? parentProofValue = null)
        => Take(vouch_build_delegation_link(issuer, subject, intentJson, validFrom, validUntil, parentProofValue, out var err), err);

    /// <summary>Validate the time-bound rule over a delegation chain (a JSON array of links).</summary>
    public static bool VerifyChainTimeBound(string chainJson, string nowIso, long clockSkewSeconds)
        => AsBool(Take(vouch_verify_chain_time_bound(chainJson, nowIso, clockSkewSeconds, out var err), err));

    // -- FROST(Ed25519) threshold signing (RFC 9591) --------------------------
    // The aggregated signature is a standard Ed25519 signature, verifiable with
    // Verify()/VerifyProof() like any other; no new proof type. See
    // vouch_core::threshold for the ceremony and why the full private key is
    // never reconstructed.

    public static string ThresholdGenerateKey(int minSigners, int maxSigners)
        => Take(vouch_threshold_generate_key((ushort)minSigners, (ushort)maxSigners, out var err), err);

    public static string ThresholdCommit(string keyShareJson)
        => Take(vouch_threshold_commit(keyShareJson, out var err), err);

    public static string ThresholdSignShare(string messageB64, string keyShareJson, string noncesB64, string commitmentsJson)
        => Take(vouch_threshold_sign_share(messageB64, keyShareJson, noncesB64, commitmentsJson, out var err), err);

    public static string ThresholdAggregate(string messageB64, string commitmentsJson, string sharesJson, string groupPublicKeyJson)
        => Take(vouch_threshold_aggregate(messageB64, commitmentsJson, sharesJson, groupPublicKeyJson, out var err), err);

    // -- Root-identity recovery by Shamir secret sharing -----------------------
    // Distinct from FROST above: the seed IS reconstructed here, deliberately,
    // for cold recovery of a root identity, not for hot signing. See
    // vouch_core::recovery.

    public static string RecoverySplitSecret(string secretB64, int threshold, int shares)
        => Take(vouch_recovery_split_secret(secretB64, (ushort)threshold, (ushort)shares, out var err), err);

    public static string RecoveryCombineShares(string sharesJson)
        => Take(vouch_recovery_combine_shares(sharesJson, out var err), err);

    public static string RecoverySplitIdentity(string seedB64, int threshold, int shares)
        => Take(vouch_recovery_split_identity(seedB64, (ushort)threshold, (ushort)shares, out var err), err);

    public static string RecoveryRecoverIdentity(string sharesJson, string did)
        => Take(vouch_recovery_recover_identity(sharesJson, did, out var err), err);
}
