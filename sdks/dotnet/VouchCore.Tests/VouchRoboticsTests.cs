using System;
using System.IO;
using System.Text.Json;
using VouchProtocol.Core;
using Xunit;

namespace VouchProtocol.Core.Tests;

/// <summary>
/// Keyless, deterministic tests for the robotics surface (VouchRobotics).
/// These exercise the pure policy paths (physical action check and conformance
/// report), which need no key material and produce the same result on every run.
/// </summary>
public class VouchRoboticsTests
{
    private const string Scope =
        "{\"maxForceN\":80.0,\"maxSpeedMps\":1.5,\"maxSpeedNearHumansMps\":0.25,\"allowedZones\":[\"cell-3\"]}";

    [Fact]
    public void CheckActionAllowsWithinScope()
    {
        const string action = "{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}";
        using var report = JsonDocument.Parse(VouchRobotics.CheckAction(Scope, action));
        Assert.True(report.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public void CheckActionRejectsOverSpeedNearHumans()
    {
        const string action = "{\"speedMps\":1.2,\"nearHumans\":true,\"zone\":\"cell-3\"}";
        using var report = JsonDocument.Parse(VouchRobotics.CheckAction(Scope, action));
        Assert.False(report.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public void CheckConformanceReportsFullCoverage()
    {
        const string credentials =
            "[" +
            "{\"type\":[\"VerifiableCredential\",\"RobotIdentityCredential\"]," +
            "\"credentialSubject\":{\"id\":\"did:web:r\",\"make\":\"Acme\",\"model\":\"AR-7\"," +
            "\"serial\":\"SN-1\",\"hardwareRoot\":{\"kind\":\"TPM\"}}}," +
            "{\"type\":[\"VerifiableCredential\",\"ModelProvenanceAttestation\"]," +
            "\"credentialSubject\":{\"id\":\"did:web:r\",\"vla\":{\"modelName\":\"M\"," +
            "\"weightsHash\":\"uW\",\"safetyPolicy\":\"uP\",\"configHash\":\"uC\"}}}," +
            "{\"type\":[\"VerifiableCredential\",\"PhysicalCapabilityScope\"]," +
            "\"credentialSubject\":{\"id\":\"did:web:r\",\"physicalScope\":{\"maxForceN\":80.0," +
            "\"maxSpeedMps\":1.5,\"maxSpeedNearHumansMps\":0.25,\"allowedZones\":[\"cell-3\"]}}}," +
            "{\"type\":[\"VerifiableCredential\",\"RobotSafetyRecordCredential\"]," +
            "\"credentialSubject\":{\"id\":\"did:web:r\",\"totalEvents\":2,\"logHead\":\"uHEAD\"}}" +
            "]";

        using var report = JsonDocument.Parse(
            VouchRobotics.CheckConformance(credentials, "eu-ai-act-high-risk"));
        Assert.True(report.RootElement.GetProperty("conforms").GetBoolean());
        Assert.Equal(4, report.RootElement.GetProperty("totalCount").GetInt32());
    }
}

/// <summary>
/// Cross-language interop tests for the curated robotics C ABI functions that
/// take key material. These verify the Python-signed credentials and chains
/// pinned in the shared interop vector: the .NET wrapper accepts, byte for byte,
/// what the Python module produced, over the exact same Rust core.
/// </summary>
public class VouchRoboticsInteropTests
{
    private static readonly JsonElement Vector = LoadVector();

    private static JsonElement LoadVector()
        => JsonDocument.Parse(File.ReadAllText("robotics-vector.json")).RootElement;

    // The interop vector carries public keys as Ed25519 JWKs. The C ABI expects
    // the raw public key as standard base64, so decode the JWK "x" (base64url,
    // no padding) to bytes and re-encode as standard base64.
    private static string KeyB64(JsonElement jwk)
    {
        string x = jwk.GetProperty("x").GetString()!;
        return Convert.ToBase64String(FromBase64Url(x));
    }

    private static byte[] FromBase64Url(string s)
    {
        string b = s.Replace('-', '+').Replace('_', '/');
        switch (b.Length % 4)
        {
            case 2: b += "=="; break;
            case 3: b += "="; break;
        }
        return Convert.FromBase64String(b);
    }

    [Fact]
    public void AuthorizesPythonSignedGrantAndRequest()
    {
        string paramsJson = JsonSerializer.Serialize(new
        {
            grant = Vector.GetProperty("access_grant_credential"),
            request = Vector.GetProperty("access_request_credential"),
        });
        string operatorB64 = KeyB64(Vector.GetProperty("access_operator_key"));
        string robotB64 = KeyB64(Vector.GetProperty("access_robot_key"));

        using var res = JsonDocument.Parse(
            VouchRobotics.AuthorizeAccess(paramsJson, operatorB64, robotB64));
        Assert.True(res.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public void VerifiesPythonSignedFusedAttestation()
    {
        string credential = Vector.GetProperty("fused_perception_attestation").GetRawText();
        string robotB64 = KeyB64(Vector.GetProperty("robot_public_key_jwk"));

        string subject = VouchRobotics.VerifyFusedAttestation(credential, robotB64);
        Assert.NotEqual("null", subject);
        using var doc = JsonDocument.Parse(subject);
        Assert.Equal("occupancy-grid-v1", doc.RootElement.GetProperty("fusionMethod").GetString());
    }

    [Fact]
    public void ReproducesExpectedAttenuatedScope()
    {
        string paramsJson = JsonSerializer.Serialize(new
        {
            scope = Vector.GetProperty("wear_input_scope"),
            wearLevel = Vector.GetProperty("wear_attenuation_level").GetDouble(),
        });

        string narrowed = VouchRobotics.AttenuateForWear(paramsJson);

        // Compare canonically so key order does not matter.
        string got = Vouch.Canonicalize(narrowed);
        string expected = Vouch.Canonicalize(
            Vector.GetProperty("expected_attenuated_scope").GetRawText());
        Assert.Equal(expected, got);
    }

    [Fact]
    public void VerifiesPythonSignedConsentEvidence()
    {
        string paramsJson = JsonSerializer.Serialize(new
        {
            evidence = Vector.GetProperty("consent_evidence_credential"),
        });
        string robotB64 = KeyB64(Vector.GetProperty("robot_public_key_jwk"));

        string subject = VouchRobotics.VerifyConsentEvidence(paramsJson, robotB64);
        Assert.NotEqual("null", subject);
        using var doc = JsonDocument.Parse(subject);
        Assert.Equal("explicit-consent", doc.RootElement.GetProperty("basis").GetString());
    }

    [Fact]
    public void VerifiesPythonSignedContinuityChain()
    {
        string paramsJson = JsonSerializer.Serialize(new
        {
            embodiments = Vector.GetProperty("embodiment_chain"),
        });
        string agentB64 = KeyB64(Vector.GetProperty("embodiment_agent_key"));

        using var res = JsonDocument.Parse(
            VouchRobotics.VerifyContinuityChain(paramsJson, agentB64));
        Assert.True(res.RootElement.GetProperty("ok").GetBoolean());
    }

    [Fact]
    public void VerifiesPythonSignedHandoffChain()
    {
        // The handoff chain names each receiver's public key as a base64url-no-pad
        // string keyed by DID, the shape the C ABI decodes.
        var publicKeys = new System.Collections.Generic.Dictionary<string, string>();
        foreach (var actor in Vector.GetProperty("custody_actor_keys").EnumerateObject())
        {
            string x = actor.Value.GetProperty("x").GetString()!;
            publicKeys[actor.Name] = x;
        }

        string paramsJson = JsonSerializer.Serialize(new
        {
            handoffs = Vector.GetProperty("custody_chain"),
            publicKeys,
            originActor = Vector.GetProperty("custody_origin_actor").GetString(),
        });

        using var res = JsonDocument.Parse(VouchRobotics.VerifyHandoffChain(paramsJson));
        Assert.True(res.RootElement.GetProperty("ok").GetBoolean());
    }
}
