using System;
using System.Runtime.InteropServices;

namespace VouchProtocol.Core;

/// <summary>
/// .NET SDK for the Vouch Protocol robotics surface. Wraps the robotics C ABI
/// exposed by the canonical Rust core (<c>vouch-core</c>) through its cbindgen
/// C ABI via P/Invoke, so .NET robot fleets mint, verify, and check credentials
/// with the exact same bytes as every other Vouch SDK. Binary key values are
/// base64 strings; credentials, scopes, actions, and reports are JSON strings.
/// </summary>
public static class VouchRobotics
{
    private const string Lib = "vouch_core_uniffi";

    [DllImport(Lib)] private static extern void vouch_string_free(IntPtr s);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_mint_identity([MarshalAs(UnmanagedType.LPUTF8Str)] string robotSeedB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string paramsJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_identity([MarshalAs(UnmanagedType.LPUTF8Str)] string credentialJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string publicB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_check_action([MarshalAs(UnmanagedType.LPUTF8Str)] string scopeJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string actionJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_passport([MarshalAs(UnmanagedType.LPUTF8Str)] string uri, [MarshalAs(UnmanagedType.LPUTF8Str)] string publicB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string nowIso, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_check_conformance([MarshalAs(UnmanagedType.LPUTF8Str)] string credentialsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string profileId, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_build_conformance_attestation([MarshalAs(UnmanagedType.LPUTF8Str)] string signerSeedB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string paramsJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_conformance_attestation([MarshalAs(UnmanagedType.LPUTF8Str)] string credentialJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string publicB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_sign_pq([MarshalAs(UnmanagedType.LPUTF8Str)] string credentialJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string ed25519SeedB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string mldsaSecretB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string mldsaPublicB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string createdIso, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_robot_credential([MarshalAs(UnmanagedType.LPUTF8Str)] string credentialJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string ed25519PublicB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string? mldsa44PublicB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_authorize_access([MarshalAs(UnmanagedType.LPUTF8Str)] string paramsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string operatorPublicB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string robotPublicB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_fused_attestation([MarshalAs(UnmanagedType.LPUTF8Str)] string credentialJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string publicB64, [MarshalAs(UnmanagedType.LPUTF8Str)] string? fusedOutputMb, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_wear_attestation([MarshalAs(UnmanagedType.LPUTF8Str)] string credentialJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string publicB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_attenuate_for_wear([MarshalAs(UnmanagedType.LPUTF8Str)] string paramsJson, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_consent_evidence([MarshalAs(UnmanagedType.LPUTF8Str)] string paramsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string robotPublicB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_continuity_chain([MarshalAs(UnmanagedType.LPUTF8Str)] string paramsJson, [MarshalAs(UnmanagedType.LPUTF8Str)] string agentPublicB64, out IntPtr err);
    [DllImport(Lib)] private static extern IntPtr vouch_robotics_verify_handoff_chain([MarshalAs(UnmanagedType.LPUTF8Str)] string paramsJson, out IntPtr err);

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

    /// <summary>Mint a RobotIdentityCredential (make/model/serial + hardware root). Returns the signed credential JSON.</summary>
    public static string MintIdentity(string robotSeedB64, string paramsJson)
        => Take(vouch_robotics_mint_identity(robotSeedB64, paramsJson, out var err), err);

    /// <summary>Verify a RobotIdentityCredential. Returns the credentialSubject JSON.</summary>
    public static string VerifyIdentity(string credentialJson, string publicB64)
        => Take(vouch_robotics_verify_identity(credentialJson, publicB64, out var err), err);

    /// <summary>Check a physical action against a physical capability scope. Returns JSON {ok, reasons}.</summary>
    public static string CheckAction(string scopeJson, string actionJson)
        => Take(vouch_robotics_check_action(scopeJson, actionJson, out var err), err);

    /// <summary>Verify a scannable robot passport URI. Returns the passport summary JSON.</summary>
    public static string VerifyPassport(string uri, string publicB64, string nowIso)
        => Take(vouch_robotics_verify_passport(uri, publicB64, nowIso, out var err), err);

    /// <summary>Check a set of robot credentials (JSON array) against a named regulatory profile. Returns the report JSON {profileId, regime, conforms, satisfiedCount, totalCount, requirements}.</summary>
    public static string CheckConformance(string credentialsJson, string profileId)
        => Take(vouch_robotics_check_conformance(credentialsJson, profileId, out var err), err);

    /// <summary>Sign a point-in-time conformance attestation over a report. Returns the signed credential JSON.</summary>
    public static string BuildConformanceAttestation(string signerSeedB64, string paramsJson)
        => Take(vouch_robotics_build_conformance_attestation(signerSeedB64, paramsJson, out var err), err);

    /// <summary>Verify a conformance attestation and its bound report digest. Returns the credentialSubject JSON.</summary>
    public static string VerifyConformanceAttestation(string credentialJson, string publicB64)
        => Take(vouch_robotics_verify_conformance_attestation(credentialJson, publicB64, out var err), err);

    /// <summary>Attach a hybrid post-quantum proof (Ed25519 + ML-DSA-44) to a robot credential. Returns the re-signed credential JSON.</summary>
    public static string SignPq(string credentialJson, string ed25519SeedB64, string mldsaSecretB64, string mldsaPublicB64, string createdIso)
        => Take(vouch_robotics_sign_pq(credentialJson, ed25519SeedB64, mldsaSecretB64, mldsaPublicB64, createdIso, out var err), err);

    /// <summary>Verify a robot credential carrying a classical or a hybrid proof, auto-detected. Pass the ML-DSA-44 public key (base64) for a hybrid credential, or null for a classical one.</summary>
    public static bool VerifyRobotCredential(string credentialJson, string ed25519PublicB64, string? mldsa44PublicB64 = null)
        => AsBool(Take(vouch_robotics_verify_robot_credential(credentialJson, ed25519PublicB64, mldsa44PublicB64, out var err), err));

    /// <summary>Authorize an infrastructure access request offline against an operator grant. paramsJson carries {grant, request, now?}. Pass the operator and robot public keys (base64). Returns JSON {ok, reasons}.</summary>
    public static string AuthorizeAccess(string paramsJson, string operatorPublicB64, string robotPublicB64)
        => Take(vouch_robotics_authorize_access(paramsJson, operatorPublicB64, robotPublicB64, out var err), err);

    /// <summary>Verify a fused-sensor provenance attestation. Pass the robot public key (base64) and, optionally, the raw fused output as multibase (or null) to reproduce its hash. Returns the credentialSubject JSON or "null".</summary>
    public static string VerifyFusedAttestation(string credentialJson, string publicB64, string? fusedOutputMb = null)
        => Take(vouch_robotics_verify_fused_attestation(credentialJson, publicB64, fusedOutputMb, out var err), err);

    /// <summary>Verify a robot wear attestation. Pass the robot public key (base64). Returns the credentialSubject JSON or "null".</summary>
    public static string VerifyWearAttestation(string credentialJson, string publicB64)
        => Take(vouch_robotics_verify_wear_attestation(credentialJson, publicB64, out var err), err);

    /// <summary>Derive a physical capability scope narrowed for a wear level. paramsJson carries {scope, wearLevel}. Returns the narrowed scope JSON.</summary>
    public static string AttenuateForWear(string paramsJson)
        => Take(vouch_robotics_attenuate_for_wear(paramsJson, out var err), err);

    /// <summary>Verify bystander-consent evidence. paramsJson carries {evidence, captureMb?, consentTokens?, bystanderKeys?, now?}. Pass the robot public key (base64). Returns the credentialSubject JSON or "null".</summary>
    public static string VerifyConsentEvidence(string paramsJson, string robotPublicB64)
        => Take(vouch_robotics_verify_consent_evidence(paramsJson, robotPublicB64, out var err), err);

    /// <summary>Verify a cross-embodiment continuity chain. paramsJson carries {embodiments, originBody?}. Pass the agent public key (base64). Returns JSON {ok, currentBody}.</summary>
    public static string VerifyContinuityChain(string paramsJson, string agentPublicB64)
        => Take(vouch_robotics_verify_continuity_chain(paramsJson, agentPublicB64, out var err), err);

    /// <summary>Verify a physical custody handoff chain. paramsJson carries {handoffs, publicKeys, originActor?} where publicKeys maps a receiver DID to its base64url-no-pad Ed25519 public key. Returns JSON {ok, currentHolder}.</summary>
    public static string VerifyHandoffChain(string paramsJson)
        => Take(vouch_robotics_verify_handoff_chain(paramsJson, out var err), err);
}
