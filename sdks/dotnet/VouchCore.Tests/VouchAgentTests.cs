using VouchProtocol.Core;
using Xunit;

namespace VouchCore.Tests;

/// <summary>Tests for the ergonomic DX layer (VouchAgent, VouchCredentials).</summary>
public class VouchAgentTests
{
    [Fact]
    public void DidWebMintSignVerify()
    {
        VouchAgent agent = VouchAgent.Create("agent.example");
        Assert.Equal("did:web:agent.example", agent.Did);
        string signed = agent.Sign("read", "did:web:files", "https://files/x");
        Assert.True(agent.Verify(signed));

        var c = new VouchCredentials.Credential(signed);
        Assert.Equal("read", c.Action);
        Assert.Equal("did:web:files", c.Target);
        Assert.Equal("https://files/x", c.Resource);
        Assert.Equal("did:web:agent.example", c.Issuer);
    }

    [Fact]
    public void DidKeyWhenNoDomain()
    {
        VouchAgent agent = VouchAgent.Create();
        Assert.StartsWith("did:key:", agent.Did);
        string signed = agent.Sign("write", "t", "r");
        Assert.True(agent.Verify(signed));
    }

    [Fact]
    public void DidKeyResolutionAcrossIssuers()
    {
        VouchAgent a = VouchAgent.Create();
        VouchAgent b = VouchAgent.Create();
        string signedByB = b.Sign("read", "t", "https://x/y");
        Assert.True(a.Verify(signedByB));
    }

    [Fact]
    public void WrongKeyFails()
    {
        VouchAgent a = VouchAgent.Create("a.example");
        VouchAgent b = VouchAgent.Create("b.example");
        string signed = a.Sign("read", "t", "https://x/y");
        Assert.False(VouchAgent.VerifyWith(signed, b.PublicKeyB64));
    }

    [Fact]
    public void VerifyWithOwnKey()
    {
        VouchAgent agent = VouchAgent.Create("agent.example");
        string signed = agent.Sign("read", "t", "https://x/y");
        Assert.True(VouchAgent.VerifyWith(signed, agent.PublicKeyB64));
    }

    [Fact]
    public void MissingIntentFieldThrows()
    {
        Assert.Throws<VouchException>(() => VouchCredentials.Build(
            "did:web:a", "", "t", "https://x/y",
            "2026-01-01T00:00:00Z", "2026-01-01T00:05:00Z", "urn:uuid:1"));
    }

    [Fact]
    public void PublicKeyForIssuerNullForNonDidKey()
    {
        Assert.Null(VouchAgent.PublicKeyForIssuer("did:web:agent.example"));
    }
}
