using System;
using System.Collections.Generic;
using System.Linq;

namespace VouchProtocol.Core;

/// <summary>
/// Cross-device identity by per-device keys and delegation (the OSS path).
///
/// The private key never travels. Each device mints its OWN key locally (see
/// <see cref="VouchAgent.Create"/>), and the user's root identity delegates
/// scoped, time-bound, revocable authority to that device's DID via
/// <see cref="EnrollDevice"/>. A device signs its own actions with its own
/// key, chained under the root grant, and <see cref="VerifyDelegatedChain"/>
/// checks the whole chain. Losing a device means revoking one delegation, not
/// rotating the whole identity, and no key is ever copied between devices.
///
/// Mirrors <c>vouch.fleet</c> (Python), <c>fleet.ts</c> (TypeScript), and
/// <c>go-sidecar/signer/fleet.go</c> (Go).
/// </summary>
public static class VouchFleet
{
    private const int DefaultValidSeconds = 86400;
    private const long DefaultClockSkewSeconds = 30;

    /// <summary>
    /// Issues a delegation grant from the root agent to a device's DID. The
    /// returned grant authorizes deviceDid to act within the given scope; the
    /// device, holding its own key, signs its actions with this grant as the
    /// parent of its own credential, chaining back to the root. The root
    /// never sees or holds the device's key.
    /// </summary>
    public static string EnrollDevice(
        VouchAgent root, string deviceDid, string action, string target, string resource,
        int validSeconds = DefaultValidSeconds)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string validFrom = VouchAgent.Iso(now);
        string validUntil = VouchAgent.Iso(now.AddSeconds(validSeconds));
        string credentialId = "urn:uuid:" + Guid.NewGuid();
        string unsigned = VouchCredentials.Build(
            root.Did, action, target, resource, deviceDid, validFrom, validUntil, credentialId);
        return Vouch.Sign(unsigned, root.SeedB64, root.Did + "#key-1", validFrom);
    }

    /// <summary>Reports whether an identifier (a device DID or a credential id) has been revoked.</summary>
    public delegate bool RevocationCheck(string identifier);

    /// <summary>The outcome of verifying a delegated device chain.</summary>
    public sealed class ChainResult
    {
        public bool Ok { get; }
        public string? Reason { get; }
        public VouchCredentials.Credential? Leaf { get; }
        public string? RootDid { get; }

        private ChainResult(bool ok, string? reason, VouchCredentials.Credential? leaf, string? rootDid)
        {
            Ok = ok;
            Reason = reason;
            Leaf = leaf;
            RootDid = rootDid;
        }

        internal static ChainResult Fail(string reason, VouchCredentials.Credential? leaf = null) => new(false, reason, leaf, null);
        internal static ChainResult Success(VouchCredentials.Credential leaf, string rootDid) => new(true, null, leaf, rootDid);
    }

    /// <summary>
    /// Verifies a delegation chain from a trusted root down to a leaf action.
    /// credentials is ordered root-first: [rootGrant, ...intermediateGrants,
    /// leafAction]. Every credential's Data Integrity proof and validity
    /// window are checked, each step must be authorized by the step before it
    /// (the child's issuer is the parent's delegatee), the resource may only
    /// narrow, and the validity windows must nest. trustedRoots maps an
    /// accepted root issuer DID to its base64 public key; the first
    /// credential's issuer MUST appear there.
    /// </summary>
    public static ChainResult VerifyDelegatedChain(
        IReadOnlyList<string> credentials,
        IReadOnlyDictionary<string, string> trustedRoots,
        RevocationCheck? revoked = null,
        long clockSkewSeconds = DefaultClockSkewSeconds,
        string? requireAction = null,
        string? requireTarget = null,
        string? requireResource = null)
    {
        if (credentials.Count == 0)
        {
            return ChainResult.Fail("empty chain");
        }
        RevocationCheck isRevoked = revoked ?? (_ => false);

        var passports = new List<VouchCredentials.Credential>(credentials.Count);
        for (int index = 0; index < credentials.Count; index++)
        {
            string credentialJson = credentials[index];
            var passport = new VouchCredentials.Credential(credentialJson);
            string? issuer = passport.Issuer;
            if (string.IsNullOrEmpty(issuer))
            {
                return ChainResult.Fail($"credential {index} has no issuer");
            }

            string? key = trustedRoots.TryGetValue(issuer, out string? rk) ? rk : null;
            if (index == 0 && key is null)
            {
                return ChainResult.Fail($"root issuer \"{issuer}\" is not in trusted roots");
            }
            key ??= VouchAgent.PublicKeyForIssuer(issuer);
            if (key is null)
            {
                return ChainResult.Fail($"credential {index} issuer \"{issuer}\" key could not be resolved");
            }

            string result = Vouch.Verify(credentialJson, key, VouchAgent.Iso(DateTimeOffset.UtcNow), clockSkewSeconds);
            if (!result.Contains("\"valid\":true"))
            {
                return ChainResult.Fail($"credential {index} failed verification");
            }

            if (isRevoked(issuer))
            {
                return ChainResult.Fail($"credential {index} issuer \"{issuer}\" is revoked");
            }
            if (!string.IsNullOrEmpty(passport.Id) && isRevoked(passport.Id))
            {
                return ChainResult.Fail($"credential {index} ({passport.Id}) is revoked");
            }
            passports.Add(passport);
        }

        for (int i = 0; i < passports.Count - 1; i++)
        {
            VouchCredentials.Credential parent = passports[i];
            VouchCredentials.Credential child = passports[i + 1];

            string? delegatee = parent.Delegatee;
            if (string.IsNullOrEmpty(delegatee))
            {
                return ChainResult.Fail($"link {i} (grant by \"{parent.Issuer}\") names no delegatee");
            }
            if (isRevoked(delegatee))
            {
                return ChainResult.Fail($"link {i}: delegatee \"{delegatee}\" is revoked");
            }
            if (delegatee != child.Issuer)
            {
                return ChainResult.Fail($"link {i}: child issuer \"{child.Issuer}\" is not the delegatee \"{delegatee}\" the parent authorized");
            }

            string? parentResource = parent.Resource;
            string? childResource = child.Resource;
            if (parentResource is not null && childResource is not null && !IsSubResource(childResource, parentResource))
            {
                return ChainResult.Fail($"link {i}: resource \"{childResource}\" is not within the granted \"{parentResource}\"");
            }

            if (!WindowWithin(child, parent))
            {
                return ChainResult.Fail($"link {i}: child validity is outside the grant window");
            }
        }

        VouchCredentials.Credential leaf = passports[^1];
        if (requireAction is not null && requireAction != leaf.Action)
        {
            return ChainResult.Fail($"leaf intent.action != \"{requireAction}\"", leaf);
        }
        if (requireTarget is not null && requireTarget != leaf.Target)
        {
            return ChainResult.Fail($"leaf intent.target != \"{requireTarget}\"", leaf);
        }
        if (requireResource is not null && requireResource != leaf.Resource)
        {
            return ChainResult.Fail($"leaf intent.resource != \"{requireResource}\"", leaf);
        }

        return ChainResult.Success(leaf, passports[0].Issuer!);
    }

    private static bool IsSubResource(string child, string parent)
    {
        if (child == parent)
        {
            return true;
        }
        string trimmed = parent.EndsWith('/') ? parent[..^1] : parent;
        return child.StartsWith(trimmed + "/", StringComparison.Ordinal);
    }

    private static bool WindowWithin(VouchCredentials.Credential child, VouchCredentials.Credential parent)
    {
        if (child.ValidFrom is null || child.ValidUntil is null || parent.ValidFrom is null || parent.ValidUntil is null)
        {
            return false;
        }
        if (!DateTimeOffset.TryParse(child.ValidFrom, out var cFrom) || !DateTimeOffset.TryParse(child.ValidUntil, out var cUntil)
            || !DateTimeOffset.TryParse(parent.ValidFrom, out var pFrom) || !DateTimeOffset.TryParse(parent.ValidUntil, out var pUntil))
        {
            return false;
        }
        return cFrom >= pFrom && cUntil <= pUntil;
    }

    /// <summary>
    /// A small in-memory record of a root's enrolled and revoked devices. Pass
    /// <see cref="IsRevoked"/> straight to <see cref="VerifyDelegatedChain"/>,
    /// or back this with your own store (a database, a BitstringStatusList)
    /// by implementing <see cref="RevocationCheck"/> yourself; this is only
    /// the simplest default.
    /// </summary>
    public sealed class DeviceRegistry
    {
        private readonly HashSet<string> _enrolled = new();
        private readonly HashSet<string> _revoked = new();

        /// <summary>Records a device as enrolled (the grant is not retained).</summary>
        public void Enroll(string deviceDid, string grant)
        {
            _enrolled.Add(deviceDid);
            _revoked.Remove(deviceDid);
        }

        /// <summary>Revokes a device. Chains issued by or delegated to it stop verifying.</summary>
        public void Revoke(string deviceDid) => _revoked.Add(deviceDid);

        public bool IsRevoked(string identifier) => _revoked.Contains(identifier);

        /// <summary>Enrolled devices that have not been revoked.</summary>
        public IReadOnlyList<string> ActiveDevices() => _enrolled.Where(did => !_revoked.Contains(did)).ToList();
    }
}
