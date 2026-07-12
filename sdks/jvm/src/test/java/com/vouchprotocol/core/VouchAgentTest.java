package com.vouchprotocol.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Tests for the ergonomic DX layer (VouchAgent, VouchCredentials). */
class VouchAgentTest {

    @Test
    void didWebMintSignVerify() {
        VouchAgent agent = VouchAgent.create("agent.example");
        assertEquals("did:web:agent.example", agent.did());
        String signed = agent.sign("read", "did:web:files", "https://files/x");
        assertTrue(agent.verify(signed), "agent should verify its own credential");

        VouchCredentials.Credential c = new VouchCredentials.Credential(signed);
        assertEquals("read", c.action());
        assertEquals("did:web:files", c.target());
        assertEquals("https://files/x", c.resource());
        assertEquals("did:web:agent.example", c.issuer());
    }

    @Test
    void didKeyWhenNoDomain() {
        VouchAgent agent = VouchAgent.create(null);
        assertTrue(agent.did().startsWith("did:key:"), "no domain should yield a did:key");
        String signed = agent.sign("write", "t", "r");
        assertTrue(agent.verify(signed));
    }

    @Test
    void didKeyResolutionAcrossIssuers() {
        VouchAgent a = VouchAgent.create(null); // did:key
        VouchAgent b = VouchAgent.create(null); // did:key
        String signedByB = b.sign("read", "t", "https://x/y");
        // a does not know b; it resolves b's key from b's did:key issuer.
        assertTrue(a.verify(signedByB), "did:key issuer should resolve offline");
    }

    @Test
    void wrongKeyFails() {
        VouchAgent a = VouchAgent.create("a.example");
        VouchAgent b = VouchAgent.create("b.example");
        String signed = a.sign("read", "t", "https://x/y");
        // b is did:web (no resolution here); verifying a's credential with b's key fails.
        assertFalse(VouchAgent.verifyWith(signed, b.publicKeyB64()));
    }

    @Test
    void loadRoundTrip() {
        VouchAgent agent = VouchAgent.create("agent.example");
        String signed = agent.sign("read", "t", "https://x/y");
        // Verifying with the agent's own public key (offline) still works.
        assertTrue(VouchAgent.verifyWith(signed, agent.publicKeyB64()));
    }

    @Test
    void missingIntentFieldThrows() {
        assertThrows(
                VouchAgent.VouchAgentException.class,
                () -> VouchCredentials.build(
                        "did:web:a", "", "t", "https://x/y", "2026-01-01T00:00:00Z",
                        "2026-01-01T00:05:00Z", "urn:uuid:1"));
    }

    @Test
    void publicKeyForIssuerNullForNonDidKey() {
        assertEquals(null, VouchAgent.publicKeyForIssuer("did:web:agent.example"));
    }
}
