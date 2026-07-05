using System.Collections.Generic;
using VouchProtocol.Core;
using Xunit;

namespace VouchCore.Tests;

/// <summary>Tests for VouchFleet (cross-device identity and delegation).</summary>
public class VouchFleetTests
{
    private static Dictionary<string, string> TrustedRoot(VouchAgent root)
        => new() { [root.Did] = root.PublicKeyB64 };

    private static string SignDeviceAction(VouchAgent device, string grant, string resource)
    {
        var grantView = new VouchCredentials.Credential(grant);
        return device.Sign(grantView.Action!, grantView.Target!, resource);
    }

    [Fact]
    public void EnrollAndVerifyChain()
    {
        VouchAgent root = VouchAgent.Create("root.example");
        VouchAgent device = VouchAgent.Create(); // did:key

        string grant = VouchFleet.EnrollDevice(root, device.Did, "charge", "api.bank", "https://api.bank/invoices");
        string action = SignDeviceAction(device, grant, "https://api.bank/invoices/42");

        var result = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, TrustedRoot(root));
        Assert.True(result.Ok, result.Reason);
        Assert.Equal(root.Did, result.RootDid);
        Assert.Equal(device.Did, result.Leaf!.Issuer);
        Assert.Equal("https://api.bank/invoices/42", result.Leaf!.Resource);
    }

    [Fact]
    public void UntrustedRootRejected()
    {
        VouchAgent root = VouchAgent.Create("root.example");
        VouchAgent device = VouchAgent.Create();
        string grant = VouchFleet.EnrollDevice(root, device.Did, "charge", "api.bank", "https://api.bank/invoices");
        string action = SignDeviceAction(device, grant, "https://api.bank/invoices/42");

        var result = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, new Dictionary<string, string>());
        Assert.False(result.Ok);
    }

    [Fact]
    public void WrongDeviceIssuerRejected()
    {
        VouchAgent root = VouchAgent.Create("root.example");
        VouchAgent device = VouchAgent.Create();
        VouchAgent impostor = VouchAgent.Create();
        string grant = VouchFleet.EnrollDevice(root, device.Did, "charge", "api.bank", "https://api.bank/invoices");
        string action = SignDeviceAction(impostor, grant, "https://api.bank/invoices/42");

        var result = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, TrustedRoot(root));
        Assert.False(result.Ok);
    }

    [Fact]
    public void TamperedActionRejected()
    {
        VouchAgent root = VouchAgent.Create("root.example");
        VouchAgent device = VouchAgent.Create();
        string grant = VouchFleet.EnrollDevice(root, device.Did, "charge", "api.bank", "https://api.bank/invoices");
        string action = SignDeviceAction(device, grant, "https://api.bank/invoices/42")
            .Replace("invoices/42", "invoices/evil");

        var result = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, TrustedRoot(root));
        Assert.False(result.Ok);
    }

    [Fact]
    public void LeafIntentPolicy()
    {
        VouchAgent root = VouchAgent.Create("root.example");
        VouchAgent device = VouchAgent.Create();
        string grant = VouchFleet.EnrollDevice(root, device.Did, "charge", "api.bank", "https://api.bank/invoices");
        string action = SignDeviceAction(device, grant, "https://api.bank/invoices/42");
        var roots = TrustedRoot(root);

        var ok = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, roots, requireAction: "charge");
        Assert.True(ok.Ok, ok.Reason);

        var bad = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, roots, requireAction: "refund");
        Assert.False(bad.Ok);
    }

    [Fact]
    public void RevokedDeviceRejected()
    {
        VouchAgent root = VouchAgent.Create("root.example");
        VouchAgent device = VouchAgent.Create();
        string grant = VouchFleet.EnrollDevice(root, device.Did, "charge", "api.bank", "https://api.bank/invoices");
        string action = SignDeviceAction(device, grant, "https://api.bank/invoices/42");
        var roots = TrustedRoot(root);

        var before = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, roots);
        Assert.True(before.Ok, before.Reason);

        var after = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, roots, revoked: id => id == device.Did);
        Assert.False(after.Ok);
    }

    [Fact]
    public void DeviceRegistryTracksRevocation()
    {
        VouchAgent root = VouchAgent.Create("root.example");
        VouchAgent device = VouchAgent.Create();
        string grant = VouchFleet.EnrollDevice(root, device.Did, "charge", "api.bank", "https://api.bank/invoices");
        string action = SignDeviceAction(device, grant, "https://api.bank/invoices/42");
        var roots = TrustedRoot(root);

        var registry = new VouchFleet.DeviceRegistry();
        registry.Enroll(device.Did, grant);
        Assert.Single(registry.ActiveDevices());

        var before = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, roots, revoked: registry.IsRevoked);
        Assert.True(before.Ok, before.Reason);

        registry.Revoke(device.Did);
        Assert.Empty(registry.ActiveDevices());
        var after = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, roots, revoked: registry.IsRevoked);
        Assert.False(after.Ok);
    }

    [Fact]
    public void DidKeyLinkResolvesWithoutTrustMap()
    {
        VouchAgent root = VouchAgent.Create("root.example");
        VouchAgent device = VouchAgent.Create();
        string grant = VouchFleet.EnrollDevice(root, device.Did, "read", "t", "https://x/y");
        string action = SignDeviceAction(device, grant, "https://x/y/z");

        var result = VouchFleet.VerifyDelegatedChain(new[] { grant, action }, TrustedRoot(root));
        Assert.True(result.Ok, result.Reason);
    }
}
