using System;
using System.Numerics;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VouchProtocol.Core;

/// <summary>
/// Ergonomic developer-experience layer over <see cref="Vouch"/>.
///
/// Mirrors the Agent helper in the Python and TypeScript SDKs: one object that
/// holds an identity and signs and verifies, so callers do not build credential
/// JSON or pass seeds and public keys around by hand. The credential body is
/// built in-language, the same way the Python, TypeScript, and Go SDKs build it,
/// and the crypto goes through the core. The wire format is unchanged.
/// </summary>
public sealed class VouchAgent
{
    private const int DefaultExpirySeconds = 300;

    private readonly string _did;
    private readonly string _seedB64;
    private readonly string _publicB64;
    private readonly int _defaultExpiry;

    private VouchAgent(string did, string seedB64, string publicB64, int defaultExpiry)
    {
        _did = did;
        _seedB64 = seedB64;
        _publicB64 = publicB64;
        _defaultExpiry = defaultExpiry;
    }

    /// <summary>Mint a fresh identity. With a domain it is did:web, without one did:key.</summary>
    public static VouchAgent Create(string? domain = null, int defaultExpirySeconds = DefaultExpirySeconds)
    {
        using JsonDocument kp = JsonDocument.Parse(Vouch.GenerateEd25519());
        JsonElement root = kp.RootElement;
        string seed = root.GetProperty("seed_b64").GetString()!;
        string pub = root.GetProperty("public_b64").GetString()!;
        string did = !string.IsNullOrEmpty(domain)
            ? $"did:web:{domain}"
            : root.GetProperty("did_key").GetString()!;
        return new VouchAgent(did, seed, pub, defaultExpirySeconds);
    }

    /// <summary>Rehydrate an agent from stored key material (no new identity is minted).</summary>
    public static VouchAgent Load(string did, string seedB64, string publicB64)
        => new(did, seedB64, publicB64, DefaultExpirySeconds);

    public string Did => _did;

    public string PublicKeyB64 => _publicB64;

    /// <summary>Sign an intent as a Vouch Credential, returning the signed credential JSON.</summary>
    public string Sign(string action, string target, string resource, int? validSeconds = null)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string validFrom = Iso(now);
        string validUntil = Iso(now.AddSeconds(validSeconds ?? _defaultExpiry));
        string credentialId = "urn:uuid:" + Guid.NewGuid();
        string unsigned = VouchCredentials.Build(
            _did, action, target, resource, validFrom, validUntil, credentialId);
        return Vouch.SignCredential(unsigned, _seedB64, _did + "#key-1", validFrom);
    }

    /// <summary>
    /// Verify a credential. If it was issued by this agent, it is checked against
    /// this agent's own key; otherwise the issuer key is resolved from a did:key
    /// issuer. Returns true only when the proof and the validity window are valid.
    /// </summary>
    public bool Verify(string credentialJson)
    {
        string? issuer = IssuerOf(credentialJson);
        string? pub = _did == issuer ? _publicB64 : PublicKeyForIssuer(issuer);
        return pub is not null && VerifyWith(credentialJson, pub);
    }

    /// <summary>Verify a credential against an explicit public key (base64).</summary>
    public static bool VerifyWith(string credentialJson, string publicB64)
    {
        string result = Vouch.VerifyCredential(credentialJson, publicB64, Iso(DateTimeOffset.UtcNow), 30);
        return result.Contains("\"valid\":true");
    }

    /// <summary>
    /// Resolve the Ed25519 public key (base64) for a did:key issuer. Returns null
    /// for non-did:key issuers, which need an explicit key or a DID-document lookup.
    /// </summary>
    public static string? PublicKeyForIssuer(string? issuer)
    {
        if (issuer is null || !issuer.StartsWith("did:key:", StringComparison.Ordinal))
        {
            return null;
        }
        try
        {
            return Convert.ToBase64String(Multibase.DecodeEd25519DidKey(issuer));
        }
        catch (Exception)
        {
            return null;
        }
    }

    internal static string Iso(DateTimeOffset t)
        => t.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ");

    private static string? IssuerOf(string credentialJson)
    {
        try
        {
            using JsonDocument doc = JsonDocument.Parse(credentialJson);
            if (doc.RootElement.TryGetProperty("issuer", out JsonElement issuer))
            {
                return issuer.ValueKind == JsonValueKind.Array
                    ? issuer[0].GetString()
                    : issuer.GetString();
            }
        }
        catch (JsonException)
        {
            // fall through
        }
        return null;
    }
}

/// <summary>
/// Builds the unsigned Vouch Credential body in-language and reads it back. The
/// shape matches the Rust core and the Python/TypeScript/Go SDKs; only the crypto
/// goes through the core, so credentials verify identically across SDKs.
/// </summary>
public static class VouchCredentials
{
    public const string VcContextV2 = "https://www.w3.org/ns/credentials/v2";
    public const string VouchContextV1 = "https://vouch-protocol.com/contexts/v1";
    public const string ProtocolVersion = "1.0";

    /// <summary>Construct the unsigned credential JSON. Intent fields are required.</summary>
    public static string Build(
        string issuerDid,
        string action,
        string target,
        string resource,
        string validFrom,
        string validUntil,
        string credentialId)
    {
        RequireNonEmpty(nameof(action), action);
        RequireNonEmpty(nameof(target), target);
        RequireNonEmpty(nameof(resource), resource);

        var intent = new JsonObject
        {
            ["action"] = action,
            ["target"] = target,
            ["resource"] = resource,
        };
        var subject = new JsonObject
        {
            ["id"] = issuerDid,
            ["vouchVersion"] = ProtocolVersion,
            ["intent"] = intent,
        };
        var vc = new JsonObject
        {
            ["@context"] = new JsonArray(VcContextV2, VouchContextV1),
            ["id"] = credentialId,
            ["type"] = new JsonArray("VerifiableCredential", "VouchCredential"),
            ["issuer"] = issuerDid,
            ["validFrom"] = validFrom,
            ["validUntil"] = validUntil,
            ["credentialSubject"] = subject,
        };
        return vc.ToJsonString();
    }

    private static void RequireNonEmpty(string name, string value)
    {
        if (string.IsNullOrEmpty(value))
        {
            throw new VouchException($"intent.{name} is required and must be a non-empty string");
        }
    }

    /// <summary>A read-friendly view over a credential JSON.</summary>
    public sealed class Credential
    {
        private readonly JsonElement _root;

        public Credential(string credentialJson)
        {
            if (string.IsNullOrEmpty(credentialJson))
            {
                throw new VouchException("credential JSON is empty");
            }
            _root = JsonDocument.Parse(credentialJson).RootElement.Clone();
        }

        public string? Action => IntentField("action");

        public string? Target => IntentField("target");

        public string? Resource => IntentField("resource");

        public string? Issuer
        {
            get
            {
                if (!_root.TryGetProperty("issuer", out JsonElement issuer))
                {
                    return null;
                }
                return issuer.ValueKind == JsonValueKind.Array ? issuer[0].GetString() : issuer.GetString();
            }
        }

        public string? ValidUntil =>
            _root.TryGetProperty("validUntil", out JsonElement v) ? v.GetString() : null;

        private string? IntentField(string key)
        {
            if (_root.TryGetProperty("credentialSubject", out JsonElement subject)
                && subject.TryGetProperty("intent", out JsonElement intent)
                && intent.TryGetProperty(key, out JsonElement value))
            {
                return value.GetString();
            }
            return null;
        }
    }
}

/// <summary>
/// Minimal base58btc / Multikey decoding for did:key issuers. A did:key encodes
/// the public key in the identifier: did:key:z(base58btc(0xed 0x01 || key)).
/// Encoding stays in the Rust core; this is only the read path needed to resolve
/// a did:key offline.
/// </summary>
internal static class Multibase
{
    private const string Alphabet =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const int Ed25519PublicKeyLen = 32;

    internal static byte[] DecodeEd25519DidKey(string didKey)
    {
        if (didKey is null || !didKey.StartsWith("did:key:", StringComparison.Ordinal))
        {
            throw new VouchException("not a did:key");
        }
        string multikey = didKey["did:key:".Length..];
        if (multikey.Length == 0 || multikey[0] != 'z')
        {
            throw new VouchException("did:key must use base58btc (z) multibase");
        }
        byte[] decoded = Base58Decode(multikey[1..]);
        if (decoded.Length != 2 + Ed25519PublicKeyLen
            || decoded[0] != 0xed || decoded[1] != 0x01)
        {
            throw new VouchException("did:key is not an Ed25519 key");
        }
        var pub = new byte[Ed25519PublicKeyLen];
        Array.Copy(decoded, 2, pub, 0, Ed25519PublicKeyLen);
        return pub;
    }

    private static byte[] Base58Decode(string s)
    {
        BigInteger num = BigInteger.Zero;
        foreach (char c in s)
        {
            int digit = Alphabet.IndexOf(c);
            if (digit < 0)
            {
                throw new VouchException($"invalid base58 character: {c}");
            }
            num = num * 58 + digit;
        }

        // BigInteger -> big-endian bytes, dropping any sign byte.
        byte[] be = num.ToByteArray(isUnsigned: true, isBigEndian: true);

        int leadingZeros = 0;
        while (leadingZeros < s.Length && s[leadingZeros] == '1')
        {
            leadingZeros++;
        }

        var outBytes = new byte[leadingZeros + be.Length];
        Array.Copy(be, 0, outBytes, leadingZeros, be.Length);
        return outBytes;
    }
}
