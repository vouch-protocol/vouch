package com.vouchprotocol.core;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.PointerByReference;

/**
 * Java SDK for the Vouch Protocol core (#33).
 *
 * A thin JNA layer over the canonical Rust core's C ABI (the cbindgen-generated
 * {@code vouch_core.h}), so the JVM verifies credentials with the exact same
 * bytes as every other Vouch SDK. Binary values are base64 strings; credentials
 * and proofs are JSON strings.
 *
 * Kotlin users may prefer the generated UniFFI binding (vouch_core.kt) bundled
 * in this module; this Java class needs no Kotlin runtime.
 */
public final class Vouch {

    /** Direct mapping of the C ABI. Functions return a heap C string (freed here). */
    interface Lib extends Library {
        Pointer vouch_version();
        Pointer vouch_canonicalize(String json, PointerByReference err);
        Pointer vouch_generate_ed25519(PointerByReference err);
        Pointer vouch_sign(String cred, String seedB64, String vm, String created, PointerByReference err);
        Pointer vouch_build_proof(String cred, String seedB64, String vm, String created, PointerByReference err);
        Pointer vouch_verify_proof(String cred, String pubB64, PointerByReference err);
        Pointer vouch_verify(String cred, String pubB64, String nowIso, long skew, PointerByReference err);
        Pointer vouch_verify_dual(String cred, String edPubB64, String mldsaPubB64, PointerByReference err);
        Pointer vouch_verify_composite(String cred, String edPubB64, String mldsaPubB64, PointerByReference err);
        Pointer vouch_verify_status(String csJson, String slJson, PointerByReference err);
        Pointer vouch_build_delegation_link(String issuer, String subject, String intentJson, String validFrom, String validUntil, String parentProofValue, PointerByReference err);
        Pointer vouch_verify_chain_time_bound(String chainJson, String nowIso, long skew, PointerByReference err);
        void vouch_string_free(Pointer s);
    }

    private static final Lib LIB = Native.load("vouch_core_uniffi", Lib.class);

    /** Thrown when the core reports an error. */
    public static final class VouchException extends RuntimeException {
        public VouchException(String message) { super(message); }
    }

    private Vouch() {}

    private static String take(Pointer result, PointerByReference err) {
        if (result == null) {
            Pointer e = err.getValue();
            String msg = (e == null) ? "unknown error" : e.getString(0);
            if (e != null) LIB.vouch_string_free(e);
            throw new VouchException(msg);
        }
        String s = result.getString(0);
        LIB.vouch_string_free(result);
        return s;
    }

    private static boolean asBool(String s) { return "true".equals(s); }

    /** Version of the underlying core. */
    public static String version() {
        Pointer p = LIB.vouch_version();
        String s = p.getString(0);
        LIB.vouch_string_free(p);
        return s;
    }

    /** RFC 8785 canonicalization of a JSON string. */
    public static String canonicalize(String json) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_canonicalize(json, err), err);
    }

    /** Generate an Ed25519 key pair as JSON {seed_b64, public_b64, multikey, did_key}. */
    public static String generateEd25519() {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_generate_ed25519(err), err);
    }

    /** Sign a credential (eddsa-jcs-2022), returning the credential with a proof attached. */
    public static String sign(String credentialJson, String seedB64, String verificationMethod, String created) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_sign(credentialJson, seedB64, verificationMethod, created, err), err);
    }

    /** Build a detached eddsa-jcs-2022 proof object (JSON). */
    public static String buildProof(String credentialJson, String seedB64, String verificationMethod, String created) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_build_proof(credentialJson, seedB64, verificationMethod, created, err), err);
    }

    /** Verify an eddsa-jcs-2022 proof. */
    public static boolean verifyProof(String credentialJson, String publicB64) {
        PointerByReference err = new PointerByReference();
        return asBool(take(LIB.vouch_verify_proof(credentialJson, publicB64, err), err));
    }

    /** Verify proof + validity window, as JSON {proofValid, timeValid, valid}. */
    public static String verify(String credentialJson, String publicB64, String nowIso, long clockSkewSeconds) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_verify(credentialJson, publicB64, nowIso, clockSkewSeconds, err), err);
    }

    /** Verify a dual proof (Ed25519 + ML-DSA-44). */
    public static boolean verifyDual(String credentialJson, String ed25519PublicB64, String mldsaPublicB64) {
        PointerByReference err = new PointerByReference();
        return asBool(take(LIB.vouch_verify_dual(credentialJson, ed25519PublicB64, mldsaPublicB64, err), err));
    }

    /** Verify a v1.6.x composite hybrid proof. */
    public static boolean verifyComposite(String credentialJson, String ed25519PublicB64, String mldsaPublicB64) {
        PointerByReference err = new PointerByReference();
        return asBool(take(LIB.vouch_verify_composite(credentialJson, ed25519PublicB64, mldsaPublicB64, err), err));
    }

    /** Verify a credential's revocation status against a BitstringStatusList credential. */
    public static boolean verifyStatus(String credentialStatusJson, String statusListCredentialJson) {
        PointerByReference err = new PointerByReference();
        return asBool(take(LIB.vouch_verify_status(credentialStatusJson, statusListCredentialJson, err), err));
    }

    /**
     * Build a delegation link. Pass null for any of validFrom, validUntil,
     * parentProofValue to omit it. Returns the link as JSON.
     */
    public static String buildDelegationLink(String issuer, String subject, String intentJson,
            String validFrom, String validUntil, String parentProofValue) {
        PointerByReference err = new PointerByReference();
        return take(LIB.vouch_build_delegation_link(issuer, subject, intentJson, validFrom, validUntil, parentProofValue, err), err);
    }

    /** Validate the time-bound rule over a delegation chain (a JSON array of links). */
    public static boolean verifyChainTimeBound(String chainJson, String nowIso, long clockSkewSeconds) {
        PointerByReference err = new PointerByReference();
        return asBool(take(LIB.vouch_verify_chain_time_bound(chainJson, nowIso, clockSkewSeconds, err), err));
    }
}
