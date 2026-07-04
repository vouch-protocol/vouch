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
