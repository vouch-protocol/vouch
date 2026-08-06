using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using VouchProtocol.Core;
using Xunit;

namespace VouchProtocol.Core.Tests;

/// <summary>
/// Verify-side example for the two robotics accountability flows, using only
/// the curated wrapper surface. Mirrors the producer-side
/// Python/TypeScript/Go/Rust examples (examples/robotics_ai_act_evidence_pack.py
/// and examples/robotics_vla_accountability_loop.py) from the consuming side:
///
/// Regulatory evidence pack: CheckConformance maps the shared interop vector's
/// Python-signed credential set onto all five built-in profiles, reporting
/// CONFORMS for the EU AI Act, ISO 10218, and the EU Machinery Regulation and
/// the exact open clause for the two profiles the set leaves gaps in;
/// BuildConformanceAttestation then signs a point-in-time attestation per
/// profile and VerifyConformanceAttestation checks it offline.
///
/// VLA accountability loop: VerifyIdentity / VerifyRobotCredential
/// authenticate the robot before trusting it (the wrapper-side analogue of
/// provenance-on-load), and CheckAction reproduces the pre-actuation scope
/// gate, denying the over-speed and out-of-zone actions and allowing the safe
/// ones.
/// </summary>
public class RoboticsVerifyExampleTests
{
    private static readonly string[] AllProfileIds =
    {
        "eu-ai-act-high-risk",
        "iso-10218",
        "iso-ts-15066",
        "eu-machinery-2023-1230",
        "ul-3300",
    };

    // A fixed assessor signing seed (0x03 x 32) and its Ed25519 public key, so
    // the attestation round-trip is deterministic like the Rust core tests.
    private const string AssessorSeedB64 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    private const string AssessorPubB64 = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";

    private const string Scope =
        "{\"maxForceN\":80.0,\"maxSpeedMps\":1.5,\"maxSpeedNearHumansMps\":0.5,\"allowedZones\":[\"cell-3\"]}";

    private static readonly JsonElement Vector = LoadVector();

    private static JsonElement LoadVector()
        => JsonDocument.Parse(File.ReadAllText("robotics-vector.json")).RootElement;

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

    private static string RobotPublicB64()
        => KeyB64(Vector.GetProperty("robot_public_key_jwk"));

    private static string CredentialsJson()
        => Vector.GetProperty("conformance_credentials").GetRawText();

    [Fact]
    public void VerifiesTheRobotBeforeTrustingIt()
    {
        string credential = Vector.GetProperty("robot_identity_credential").GetRawText();

        string subject = VouchRobotics.VerifyIdentity(credential, RobotPublicB64());
        Assert.NotEqual("null", subject);
        using var doc = JsonDocument.Parse(subject);
        Assert.Equal("Acme Robotics", doc.RootElement.GetProperty("make").GetString());

        Assert.True(VouchRobotics.VerifyRobotCredential(credential, RobotPublicB64()));
    }

    [Fact]
    public void ReportsConformanceAndGapsAcrossAllFiveProfiles()
    {
        foreach (string pid in AllProfileIds)
        {
            using var report = JsonDocument.Parse(
                VouchRobotics.CheckConformance(CredentialsJson(), pid));
            Assert.Equal(pid, report.RootElement.GetProperty("profileId").GetString());

            bool conforms = report.RootElement.GetProperty("conforms").GetBoolean();
            if (pid == "iso-ts-15066" || pid == "ul-3300")
            {
                // The vector's four-credential set carries no heartbeat motion
                // digest and no perception provenance, so exactly these two
                // profiles must report the open clause.
                Assert.False(conforms);
            }
            else
            {
                Assert.True(conforms);
            }
        }
    }

    [Fact]
    public void SignsAndVerifiesOneAttestationPerProfile()
    {
        foreach (string pid in AllProfileIds)
        {
            string report = VouchRobotics.CheckConformance(CredentialsJson(), pid);
            string paramsJson =
                "{\"issuerDid\":\"did:web:assessor.example.com\"," +
                "\"robotDid\":\"did:web:robot.example.com\"," +
                "\"report\":" + report + "," +
                "\"validFrom\":\"2026-01-01T00:00:00Z\"}";
            string attestation = VouchRobotics.BuildConformanceAttestation(AssessorSeedB64, paramsJson);

            string subject = VouchRobotics.VerifyConformanceAttestation(attestation, AssessorPubB64);
            Assert.NotEqual("null", subject);
            using var doc = JsonDocument.Parse(subject);
            Assert.Equal(pid, doc.RootElement.GetProperty("profileId").GetString());

            // A wrong key must not verify the attestation.
            Assert.Equal("null",
                VouchRobotics.VerifyConformanceAttestation(attestation, RobotPublicB64()));
        }
    }

    [Theory]
    [InlineData("{\"forceN\":20.0,\"speedMps\":0.3,\"nearHumans\":true,\"zone\":\"cell-3\"}", true, null)]
    [InlineData("{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}", true, null)]
    [InlineData("{\"speedMps\":2.5,\"nearHumans\":true,\"zone\":\"cell-3\"}", false, "speed_exceeded")]
    [InlineData("{\"forceN\":15.0,\"speedMps\":0.5,\"zone\":\"loading-bay\"}", false, "zone_not_allowed")]
    public void VlaGateAllowsSafeAndDeniesUnsafeActions(string action, bool wantOk, string? wantReason)
    {
        string result = VouchRobotics.CheckAction(Scope, action);
        using var doc = JsonDocument.Parse(result);
        Assert.Equal(wantOk, doc.RootElement.GetProperty("ok").GetBoolean());
        if (wantReason != null)
        {
            Assert.Contains(wantReason, result);
        }
    }
}
