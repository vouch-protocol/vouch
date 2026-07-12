using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
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

    [Fact]
    public void ThresholdFrostCeremonyProducesValidSignature()
    {
        // Rust's aggregate() self-verifies before returning (see
        // vouch_core::threshold), so a completed, non-throwing ceremony is
        // itself the proof that the resulting signature is a valid, standard
        // Ed25519 signature over the message.
        using var generated = JsonDocument.Parse(Vouch.ThresholdGenerateKey(2, 3));
        var shares = generated.RootElement.GetProperty("shares");
        Assert.Equal(3, shares.GetArrayLength());

        string share0 = shares[0].GetRawText();
        string share1 = shares[1].GetRawText();
        string id0 = shares[0].GetProperty("identifier").GetString()!;
        string id1 = shares[1].GetProperty("identifier").GetString()!;

        using var round1A = JsonDocument.Parse(Vouch.ThresholdCommit(share0));
        using var round1B = JsonDocument.Parse(Vouch.ThresholdCommit(share1));

        string commitmentsJson = JsonSerializer.Serialize(new Dictionary<string, string>
        {
            [id0] = round1A.RootElement.GetProperty("commitments").GetString()!,
            [id1] = round1B.RootElement.GetProperty("commitments").GetString()!,
        });

        string message = Convert.ToBase64String(Encoding.UTF8.GetBytes("charge api.bank invoices/42"));

        string sigShare0 = Vouch.ThresholdSignShare(message, share0, round1A.RootElement.GetProperty("nonces").GetString()!, commitmentsJson);
        string sigShare1 = Vouch.ThresholdSignShare(message, share1, round1B.RootElement.GetProperty("nonces").GetString()!, commitmentsJson);

        string sharesJson = JsonSerializer.Serialize(new Dictionary<string, string> { [id0] = sigShare0, [id1] = sigShare1 });
        string groupPublicKeyJson = generated.RootElement.GetProperty("group_public_key").GetRawText();

        string signatureB64 = Vouch.ThresholdAggregate(message, commitmentsJson, sharesJson, groupPublicKeyJson);
        Assert.Equal(64, Convert.FromBase64String(signatureB64).Length);
    }

    [Fact]
    public void ThresholdRejectsBadThreshold()
    {
        Assert.Throws<VouchException>(() => Vouch.ThresholdGenerateKey(1, 3));
    }

    [Fact]
    public void RecoverySplitAndCombineRoundtrips()
    {
        string secretB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("a 32 byte secret for shamir!!!!!"));
        using var sharesDoc = JsonDocument.Parse(Vouch.RecoverySplitSecret(secretB64, 3, 5));
        var shares = sharesDoc.RootElement.EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal(5, shares.Count);

        string combined = Vouch.RecoveryCombineShares(JsonSerializer.Serialize(shares.Take(3)));
        Assert.Equal(secretB64, combined);

        string combinedAlt = Vouch.RecoveryCombineShares(JsonSerializer.Serialize(new[] { shares[0], shares[2], shares[4] }));
        Assert.Equal(secretB64, combinedAlt);
    }

    [Fact]
    public void RecoveryBelowThresholdDoesNotRevealSecret()
    {
        string secretB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("another shamir secret!!"));
        using var sharesDoc = JsonDocument.Parse(Vouch.RecoverySplitSecret(secretB64, 3, 5));
        var shares = sharesDoc.RootElement.EnumerateArray().Select(e => e.GetString()!).ToList();
        string combined = Vouch.RecoveryCombineShares(JsonSerializer.Serialize(shares.Take(2)));
        Assert.NotEqual(secretB64, combined);
    }

    [Fact]
    public void RecoverySplitAndRecoverIdentitySignsIdentically()
    {
        using var kp = JsonDocument.Parse(Vouch.GenerateEd25519());
        string seedB64 = kp.RootElement.GetProperty("seed_b64").GetString()!;
        string didKey = kp.RootElement.GetProperty("did_key").GetString()!;
        string pub = kp.RootElement.GetProperty("public_b64").GetString()!;

        using var sharesDoc = JsonDocument.Parse(Vouch.RecoverySplitIdentity(seedB64, 2, 3));
        var shares = sharesDoc.RootElement.EnumerateArray().Select(e => e.GetString()!).ToList();
        Assert.Equal(3, shares.Count);

        using var recovered = JsonDocument.Parse(Vouch.RecoveryRecoverIdentity(JsonSerializer.Serialize(shares.Take(2)), didKey));
        Assert.Equal(didKey, recovered.RootElement.GetProperty("did").GetString());
        string recoveredSeed = recovered.RootElement.GetProperty("seed").GetString()!;
        Assert.Equal(seedB64, recoveredSeed);

        // The recovered seed is the original: sign with it and verify against
        // the original public key.
        string signed = Vouch.Sign(Cred, recoveredSeed, didKey + "#key-1", "2026-04-26T10:00:00Z");
        Assert.True(Vouch.VerifyProof(signed, pub));
    }

    [Fact]
    public void RecoveryTooFewSharesGivesWrongResultNotError()
    {
        using var kp = JsonDocument.Parse(Vouch.GenerateEd25519());
        string seedB64 = kp.RootElement.GetProperty("seed_b64").GetString()!;
        using var sharesDoc = JsonDocument.Parse(Vouch.RecoverySplitIdentity(seedB64, 3, 5));
        var shares = sharesDoc.RootElement.EnumerateArray().Select(e => e.GetString()!).ToList();
        using var recovered = JsonDocument.Parse(Vouch.RecoveryRecoverIdentity(JsonSerializer.Serialize(shares.Take(2)), ""));
        Assert.NotEqual(seedB64, recovered.RootElement.GetProperty("seed").GetString());
    }
}
