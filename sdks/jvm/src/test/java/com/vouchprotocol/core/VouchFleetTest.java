package com.vouchprotocol.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

/** JUnit suite for {@link VouchFleet} (cross-device identity and delegation). */
class VouchFleetTest {

    private static Map<String, String> trustedRoot(VouchAgent root) {
        Map<String, String> roots = new HashMap<>();
        roots.put(root.did(), root.publicKeyB64());
        return roots;
    }

    @Test
    void enrollAndVerifyChain() {
        VouchAgent root = VouchAgent.create("root.example");
        VouchAgent device = VouchAgent.create(null); // did:key

        String grant = VouchFleet.enrollDevice(root, device.did(), "charge", "api.bank", "https://api.bank/invoices");
        String action = signDeviceAction(device, grant, "https://api.bank/invoices/42");

        VouchFleet.ChainResult result = VouchFleet.verifyDelegatedChain(List.of(grant, action), trustedRoot(root));
        assertTrue(result.ok, result.reason);
        assertEquals(root.did(), result.rootDid);
        assertEquals(device.did(), result.leaf.issuer());
        assertEquals("https://api.bank/invoices/42", result.leaf.resource());
    }

    @Test
    void untrustedRootRejected() {
        VouchAgent root = VouchAgent.create("root.example");
        VouchAgent device = VouchAgent.create(null);
        String grant = VouchFleet.enrollDevice(root, device.did(), "charge", "api.bank", "https://api.bank/invoices");
        String action = signDeviceAction(device, grant, "https://api.bank/invoices/42");

        VouchFleet.ChainResult result = VouchFleet.verifyDelegatedChain(List.of(grant, action), new HashMap<>());
        assertFalse(result.ok);
    }

    @Test
    void wrongDeviceIssuerRejected() {
        VouchAgent root = VouchAgent.create("root.example");
        VouchAgent device = VouchAgent.create(null);
        VouchAgent impostor = VouchAgent.create(null);
        String grant = VouchFleet.enrollDevice(root, device.did(), "charge", "api.bank", "https://api.bank/invoices");
        String action = signDeviceAction(impostor, grant, "https://api.bank/invoices/42");

        VouchFleet.ChainResult result = VouchFleet.verifyDelegatedChain(List.of(grant, action), trustedRoot(root));
        assertFalse(result.ok);
    }

    @Test
    void tamperedActionRejected() {
        VouchAgent root = VouchAgent.create("root.example");
        VouchAgent device = VouchAgent.create(null);
        String grant = VouchFleet.enrollDevice(root, device.did(), "charge", "api.bank", "https://api.bank/invoices");
        String action = signDeviceAction(device, grant, "https://api.bank/invoices/42")
                .replace("invoices/42", "invoices/evil");

        VouchFleet.ChainResult result = VouchFleet.verifyDelegatedChain(List.of(grant, action), trustedRoot(root));
        assertFalse(result.ok);
    }

    @Test
    void leafIntentPolicy() {
        VouchAgent root = VouchAgent.create("root.example");
        VouchAgent device = VouchAgent.create(null);
        String grant = VouchFleet.enrollDevice(root, device.did(), "charge", "api.bank", "https://api.bank/invoices");
        String action = signDeviceAction(device, grant, "https://api.bank/invoices/42");
        Map<String, String> roots = trustedRoot(root);

        VouchFleet.ChainResult ok = VouchFleet.verifyDelegatedChain(
                List.of(grant, action), roots, null, 30, "charge", null, null);
        assertTrue(ok.ok, ok.reason);

        VouchFleet.ChainResult bad = VouchFleet.verifyDelegatedChain(
                List.of(grant, action), roots, null, 30, "refund", null, null);
        assertFalse(bad.ok);
    }

    @Test
    void revokedDeviceRejected() {
        VouchAgent root = VouchAgent.create("root.example");
        VouchAgent device = VouchAgent.create(null);
        String grant = VouchFleet.enrollDevice(root, device.did(), "charge", "api.bank", "https://api.bank/invoices");
        String action = signDeviceAction(device, grant, "https://api.bank/invoices/42");
        Map<String, String> roots = trustedRoot(root);

        VouchFleet.ChainResult before = VouchFleet.verifyDelegatedChain(List.of(grant, action), roots);
        assertTrue(before.ok, before.reason);

        VouchFleet.ChainResult after = VouchFleet.verifyDelegatedChain(
                List.of(grant, action), roots, id -> id.equals(device.did()), 30, null, null, null);
        assertFalse(after.ok);
    }

    @Test
    void deviceRegistryTracksRevocation() {
        VouchAgent root = VouchAgent.create("root.example");
        VouchAgent device = VouchAgent.create(null);
        String grant = VouchFleet.enrollDevice(root, device.did(), "charge", "api.bank", "https://api.bank/invoices");
        String action = signDeviceAction(device, grant, "https://api.bank/invoices/42");
        Map<String, String> roots = trustedRoot(root);

        VouchFleet.DeviceRegistry registry = new VouchFleet.DeviceRegistry();
        registry.enroll(device.did(), grant);
        assertEquals(1, registry.activeDevices().size());

        VouchFleet.ChainResult before = VouchFleet.verifyDelegatedChain(
                List.of(grant, action), roots, registry::isRevoked, 30, null, null, null);
        assertTrue(before.ok, before.reason);

        registry.revoke(device.did());
        assertEquals(0, registry.activeDevices().size());
        VouchFleet.ChainResult after = VouchFleet.verifyDelegatedChain(
                List.of(grant, action), roots, registry::isRevoked, 30, null, null, null);
        assertFalse(after.ok);
    }

    @Test
    void didKeyLinkResolvesWithoutTrustMap() {
        VouchAgent root = VouchAgent.create("root.example");
        VouchAgent device = VouchAgent.create(null);
        String grant = VouchFleet.enrollDevice(root, device.did(), "read", "t", "https://x/y");
        String action = signDeviceAction(device, grant, "https://x/y/z");

        // Only the root key is supplied; the device link (did:key) resolves offline.
        VouchFleet.ChainResult result = VouchFleet.verifyDelegatedChain(List.of(grant, action), trustedRoot(root));
        assertTrue(result.ok, result.reason);
    }

    /** Signs a device action credential chained under grant, mirroring EnrollDevice's grant shape. */
    private static String signDeviceAction(VouchAgent device, String grant, String resource) {
        VouchCredentials.Credential grantView = new VouchCredentials.Credential(grant);
        String action = grantView.action();
        String target = grantView.target();
        return device.sign(action, target, resource);
    }
}
