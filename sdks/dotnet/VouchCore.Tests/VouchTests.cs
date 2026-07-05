using System.IO;
using System.Text.Json;
using VouchProtocol.Core;
using Xunit;

namespace VouchProtocol.Core.Tests;

public class VouchTests
{
    private const string Cred =
        "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\"]," +
        "\"type\":[\"VerifiableCredential\",\"VouchCredential\"]," +
        "\"issuer\":\"did:web:a\",\"validFrom\":\"2026-04-26T10:00:00Z\"," +
        "\"validUntil\":\"2026-04-26T10:05:00Z\",\"credentialSubject\":{\"id\":\"did:web:a\"," +
        "\"vouchVersion\":\"1.0\",\"intent\":{\"action\":\"read\",\"target\":\"t\",\"resource\":\"https://x/y\"}}}";

    [Fact]
    public void CanonicalizeSortsKeys()
    {
        Assert.Equal("{\"a\":2,\"b\":1}", Vouch.Canonicalize("{\"b\":1,\"a\":2}"));
    }

    [Fact]
    public void SignAndVerify()
    {
        using var kp = JsonDocument.Parse(Vouch.GenerateEd25519());
        var seed = kp.RootElement.GetProperty("seed_b64").GetString()!;
        var pub = kp.RootElement.GetProperty("public_b64").GetString()!;
        Assert.StartsWith("did:key:z6Mk", kp.RootElement.GetProperty("did_key").GetString());

        var signed = Vouch.Sign(Cred, seed, "did:web:a#key-1", "2026-04-26T10:00:00Z");
        Assert.True(Vouch.VerifyProof(signed, pub));

        using var ok = JsonDocument.Parse(Vouch.Verify(signed, pub, "2026-04-26T10:02:00Z"));
        Assert.True(ok.RootElement.GetProperty("valid").GetBoolean());

        using var expired = JsonDocument.Parse(Vouch.Verify(signed, pub, "2026-04-26T11:00:00Z"));
        Assert.False(expired.RootElement.GetProperty("valid").GetBoolean());
    }

    [Fact]
    public void CrossImplementationInterop()
    {
        var vec = JsonDocument.Parse(File.ReadAllText("vector.json")).RootElement;
        var pub = vec.GetProperty("ed25519").GetProperty("public_key_b64").GetString()!;
        var seed = vec.GetProperty("ed25519").GetProperty("seed_b64").GetString()!;
        var vm = vec.GetProperty("verificationMethod").GetString()!;
        var created = vec.GetProperty("created").GetString()!;
        var expectedProofValue = vec.GetProperty("proofValue").GetString()!;
        var signedCred = vec.GetProperty("signed_credential").GetRawText();
        var unsignedCred = vec.GetProperty("unsigned_credential").GetRawText();

        Assert.True(Vouch.VerifyProof(signedCred, pub));

        using var proof = JsonDocument.Parse(Vouch.BuildProof(unsignedCred, seed, vm, created));
        Assert.Equal(expectedProofValue, proof.RootElement.GetProperty("proofValue").GetString());
    }

    [Fact]
    public void DelegationTimeBound()
    {
        const string intent = "{\"action\":\"read\",\"target\":\"t\",\"resource\":\"https://api/x\"}";
        var l1 = Vouch.BuildDelegationLink("did:web:a", "did:web:b", intent, "2026-04-26T09:00:00Z", "2026-04-26T12:00:00Z");
        var l2 = Vouch.BuildDelegationLink("did:web:b", "did:web:c", intent, "2026-04-26T10:00:00Z", "2026-04-26T11:00:00Z");
        var chain = "[" + l1 + "," + l2 + "]";
        Assert.True(Vouch.VerifyChainTimeBound(chain, "2026-04-26T10:30:00Z", 30));
        Assert.False(Vouch.VerifyChainTimeBound(chain, "2026-04-26T13:00:00Z", 30));
    }
}
