package com.vouchprotocol.core;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

/**
 * Robotics helpers for the Vouch Protocol core.
 *
 * A thin JNA layer over the canonical Rust core's robotics C ABI (the
 * cbindgen-generated {@code vouch_core.h}), matching {@link Vouch}. It mints and
 * verifies robot identity credentials, checks physical actions against a
 * capability scope, verifies scannable robot passports, evaluates regulatory
 * conformance, and signs and verifies post-quantum robot credentials. As with
 * {@link Vouch}, binary values (keys, seeds) are base64 strings and credentials,
 * scopes, actions, and reports are JSON strings; the JVM operates on exactly the
 * same bytes as every other Vouch SDK.
 */
public final class VouchRobotics {

    /** Direct mapping of the robotics C ABI. Functions return a heap C string (freed here). */
    interface Lib extends Library {
        Pointer vouch_robotics_mint_identity(String robotSeedB64, String paramsJson, PointerByReference err);
        Pointer vouch_robotics_verify_identity(String credentialJson, String publicB64, PointerByReference err);
        Pointer vouch_robotics_check_action(String scopeJson, String actionJson, PointerByReference err);
        Pointer vouch_robotics_verify_passport(String uri, String publicB64, String nowIso, PointerByReference err);
        Pointer vouch_robotics_check_conformance(String credentialsJson, String profileId, PointerByReference err);
        Pointer vouch_robotics_build_conformance_attestation(String signerSeedB64, String paramsJson, PointerByReference err);
        Pointer vouch_robotics_verify_conformance_attestation(String credentialJson, String publicB64, PointerByReference err);
        Pointer vouch_robotics_sign_pq(String credentialJson, String ed25519SeedB64, String mldsaSecretB64, String mldsaPublicB64, String createdIso, PointerByReference err);
        Pointer vouch_robotics_verify_robot_credential(String credentialJson, String ed25519PublicB64, String mldsa44PublicB64, PointerByReference err);
        Pointer vouch_robotics_authorize_access(String paramsJson, String operatorPublicB64, String robotPublicB64, PointerByReference err);
        Pointer vouch_robotics_verify_fused_attestation(String credentialJson, String publicB64, String fusedOutputMb, PointerByReference err);
        Pointer vouch_robotics_verify_wear_attestation(String credentialJson, String publicB64, PointerByReference err);
        Pointer vouch_robotics_attenuate_for_wear(String paramsJson, PointerByReference err);
        Pointer vouch_robotics_verify_consent_evidence(String paramsJson, String robotPublicB64, PointerByReference err);
        Pointer vouch_robotics_verify_continuity_chain(String paramsJson, String agentPublicB64, PointerByReference err);
        Pointer vouch_robotics_verify_handoff_chain(String paramsJson, PointerByReference err);
        void vouch_string_free(Pointer s);
    }

    private static final Lib LIB = Native.load("vouch_core_uniffi", Lib.class);

    private VouchRobotics() {}

    private static String take(Pointer result, PointerByReference err) {
        if (result == null) {
            Pointer e = err.getValue();
            String msg = (e == null) ? "unknown error" : e.getString(0);
            if (e != null) LIB.vouch_string_free(e);
            throw new Vouch.VouchException(msg);
        }
        String s = result.getString(0);
        LIB.vouch_string_free(result);
        return s;
    }

    private static boolean asBool(String s) { return "true".equals(s); }

    /** Mint a RobotIdentityCredential (make/model/serial + hardware root); returns the signed credential JSON. */
    public static String mintIdentity(String robotSeedB64, String paramsJson) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_mint_identity(robotSeedB64, paramsJson, err), err);
    }

    /** Verify a RobotIdentityCredential. Returns the credentialSubject JSON. */
    public static String verifyIdentity(String credentialJson, String publicB64) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_verify_identity(credentialJson, publicB64, err), err);
    }

    /** Check a physical action against a physical capability scope. Returns JSON {ok, reasons}. */
    public static String checkAction(String scopeJson, String actionJson) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_check_action(scopeJson, actionJson, err), err);
    }

    /** Verify a scannable robot passport URI. Returns the passport summary JSON. */
    public static String verifyPassport(String uri, String publicB64, String nowIso) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_verify_passport(uri, publicB64, nowIso, err), err);
    }

    /** Check a set of robot credentials (a JSON array) against a named regulatory profile. Returns the report JSON. */
    public static String checkConformance(String credentialsJson, String profileId) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_check_conformance(credentialsJson, profileId, err), err);
    }

    /** Sign a point-in-time conformance attestation over a report. Returns the signed credential JSON. */
    public static String buildConformanceAttestation(String signerSeedB64, String paramsJson) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_build_conformance_attestation(signerSeedB64, paramsJson, err), err);
    }

    /** Verify a conformance attestation and its bound report digest. Returns the credentialSubject JSON. */
    public static String verifyConformanceAttestation(String credentialJson, String publicB64) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_verify_conformance_attestation(credentialJson, publicB64, err), err);
    }

    /** Attach a hybrid post-quantum proof (Ed25519 + ML-DSA-44) to a robot credential. Returns the re-signed credential JSON. */
    public static String signPq(String credentialJson, String ed25519SeedB64, String mldsaSecretB64,
            String mldsaPublicB64, String createdIso) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_sign_pq(credentialJson, ed25519SeedB64, mldsaSecretB64, mldsaPublicB64, createdIso, err), err);
    }

    /**
     * Verify a robot credential carrying a classical Ed25519 proof. Convenience
     * overload for credentials without a post-quantum proof.
     */
    public static boolean verifyRobotCredential(String credentialJson, String ed25519PublicB64) {
        return verifyRobotCredential(credentialJson, ed25519PublicB64, null);
    }

    /**
     * Verify a robot credential whether it carries a classical or a hybrid proof,
     * auto-detected from the proof. Pass the ML-DSA-44 public key (base64) for a
     * hybrid credential, or {@code null} for a classical one.
     */
    public static boolean verifyRobotCredential(String credentialJson, String ed25519PublicB64, String mldsa44PublicB64) {
        PointerByReference err = new PointerByReference();
        return asBool(take(LIB.vouch_robotics_verify_robot_credential(credentialJson, ed25519PublicB64, mldsa44PublicB64, err), err));
    }

    /**
     * Authorize an infrastructure access request offline against an operator grant.
     * {@code paramsJson} carries {@code {grant, request, now?}}. Pass the operator
     * and robot public keys (base64). Returns the authorize result JSON {@code {ok,
     * reasons}}.
     */
    public static String authorizeAccess(String paramsJson, String operatorPublicB64, String robotPublicB64) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_authorize_access(paramsJson, operatorPublicB64, robotPublicB64, err), err);
    }

    /**
     * Verify a fused-sensor provenance attestation carrying the classical proof.
     * Convenience overload for a credential verified without reproducing the fused
     * output hash.
     */
    public static String verifyFusedAttestation(String credentialJson, String publicB64) {
        return verifyFusedAttestation(credentialJson, publicB64, null);
    }

    /**
     * Verify a fused-sensor provenance attestation. Pass the robot public key
     * (base64) and, optionally, the raw fused output as multibase (or {@code null})
     * to reproduce its hash. Returns the credentialSubject JSON or {@code "null"}.
     */
    public static String verifyFusedAttestation(String credentialJson, String publicB64, String fusedOutputMb) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_verify_fused_attestation(credentialJson, publicB64, fusedOutputMb, err), err);
    }

    /** Verify a robot wear attestation. Pass the robot public key (base64). Returns the credentialSubject JSON or {@code "null"}. */
    public static String verifyWearAttestation(String credentialJson, String publicB64) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_verify_wear_attestation(credentialJson, publicB64, err), err);
    }

    /**
     * Derive a physical capability scope narrowed for a wear level. {@code
     * paramsJson} carries {@code {scope, wearLevel}}. Returns the narrowed scope JSON.
     */
    public static String attenuateForWear(String paramsJson) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_attenuate_for_wear(paramsJson, err), err);
    }

    /**
     * Verify bystander-consent evidence. {@code paramsJson} carries {@code {evidence,
     * captureMb?, consentTokens?, bystanderKeys?, now?}}. Pass the robot public key
     * (base64). Returns the credentialSubject JSON or {@code "null"}.
     */
    public static String verifyConsentEvidence(String paramsJson, String robotPublicB64) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_verify_consent_evidence(paramsJson, robotPublicB64, err), err);
    }

    /**
     * Verify a cross-embodiment continuity chain. {@code paramsJson} carries {@code
     * {embodiments, originBody?}}. Pass the agent public key (base64). Returns the
     * result JSON {@code {ok, currentBody}}.
     */
    public static String verifyContinuityChain(String paramsJson, String agentPublicB64) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_verify_continuity_chain(paramsJson, agentPublicB64, err), err);
    }

    /**
     * Verify a physical custody handoff chain. {@code paramsJson} carries {@code
     * {handoffs, publicKeys, originActor?}} where each {@code publicKeys} value is the
     * receiver's Ed25519 public key as a base64url-no-pad string. Returns the result
     * JSON {@code {ok, currentHolder}}.
     */
    public static String verifyHandoffChain(String paramsJson) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_robotics_verify_handoff_chain(paramsJson, err), err);
    }
}
