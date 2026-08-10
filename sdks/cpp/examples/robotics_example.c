/*
 * Vouch Protocol robotics C example.
 *
 * The C ABI (vouch_core.h) exposes a narrower robotics surface than the
 * reference SDKs: 18 vouch_robotics_* entry points, verify-side plus identity
 * minting and conformance attestation. This example exercises that surface as
 * a trimmed version of the two accountability flows the Python, TypeScript, Go
 * and Rust examples run in full (examples/robotics_ai_act_evidence_pack.py and
 * examples/robotics_vla_accountability_loop.py):
 *
 *   1. Identity: verify the Python-minted RobotIdentityCredential from the
 *      shared interop vector (cross-language proof), then mint one from C.
 *   2. Action gate: check a safe and two unsafe actions against a physical
 *      capability scope, the pre-actuation gate of the VLA loop.
 *   3. Evidence pack: run check_conformance over the vector's credential set,
 *      then sign a point-in-time conformance attestation and verify it, and
 *      confirm a wrong key is rejected.
 *
 * A note on minting, and a real limit of the C ABI: a RobotIdentityCredential
 * embeds a hardware-root attestation, the secure element's signature over the
 * binding of the robot DID to the robot key. The C ABI deliberately exposes no
 * raw-signature primitive (vouch_sign signs a credential, not arbitrary bytes),
 * so that signature must come from the TPM or secure element itself, or from a
 * reference SDK. Step 1b below mints with a placeholder attestation to show the
 * mint path and the credential shape, and then shows verify_identity REJECTING
 * it: the hardware root is enforced, not decorative.
 *
 * Every returned string is freed with vouch_string_free (see example.c).
 *
 * Build + run:  make robotics_example run-robotics   (see ../Makefile)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vouch_core.h"

/* A fixed assessor signing seed (0x03 x 32) and its Ed25519 public key, both
 * standard base64, so the attestation round-trip is deterministic. Shared with
 * robotics_verify_example.cpp. */
static const char *kAssessorSeedB64 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
static const char *kAssessorPubB64 = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";

/* A different key (0x04 x 32) used only to prove a wrong key is rejected. */
static const char *kOtherPubB64 = "T7LUicUOAmZaTdRW8bYFPLoLNRUeDVaJRq1cyfw8jSU=";

static const char *kScopeJson =
    "{\"maxForceN\":80.0,\"maxSpeedMps\":1.5,"
    "\"maxSpeedNearHumansMps\":0.5,\"allowedZones\":[\"cell-3\"]}";

/* ---- small helpers -------------------------------------------------------- */

/* The verify entry points signal "invalid" by returning the JSON literal
 * "null" rather than a NULL pointer (a NULL pointer means a hard error, with a
 * message in err_out). Both count as a rejection. */
static int rejected(const char *out) {
    return out == NULL || strcmp(out, "null") == 0;
}

/* Take ownership of a C ABI return value, aborting with the error it set. */
static char *take(char *out, char *err, const char *what) {
    if (!out) {
        fprintf(stderr, "%s failed: %s\n", what, err ? err : "(no message)");
        if (err) vouch_string_free(err);
        exit(2);
    }
    return out;
}

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return NULL;
    }
    buf[n] = 0;
    fclose(f);
    return buf;
}

/* Return the raw JSON text of the value for a key (caller frees). Handles
 * nested braces/brackets and skips string contents, the same controlled
 * extraction the C++ robotics example uses; the vector is well-formed by
 * construction, so this is not a general-purpose JSON parser. */
static char *json_value(const char *doc, const char *key) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *k = strstr(doc, pat);
    if (!k) {
        fprintf(stderr, "interop vector missing field %s\n", key);
        exit(2);
    }
    const char *p = strchr(k + strlen(pat), ':');
    if (!p) exit(2);
    p++;
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
    const char *start = p;
    char open = *p;
    if (open == '{' || open == '[') {
        char close = (open == '{') ? '}' : ']';
        int depth = 0;
        int in_str = 0;
        for (; *p; p++) {
            if (in_str) {
                if (*p == '\\') {
                    p++;
                } else if (*p == '"') {
                    in_str = 0;
                }
                continue;
            }
            if (*p == '"') {
                in_str = 1;
            } else if (*p == open) {
                depth++;
            } else if (*p == close) {
                if (--depth == 0) {
                    p++;
                    break;
                }
            }
        }
    } else if (open == '"') {
        p++;
        for (; *p; p++) {
            if (*p == '\\') {
                p++;
            } else if (*p == '"') {
                p++;
                break;
            }
        }
    } else {
        while (*p && *p != ',' && *p != '}' && *p != '\n') p++;
    }
    size_t len = (size_t)(p - start);
    char *out = malloc(len + 1);
    memcpy(out, start, len);
    out[len] = 0;
    return out;
}

/* Strip surrounding quotes from a JSON string value, in place. */
static char *unquote(char *s) {
    size_t n = strlen(s);
    if (n >= 2 && s[0] == '"' && s[n - 1] == '"') {
        memmove(s, s + 1, n - 2);
        s[n - 2] = 0;
    }
    return s;
}

/* base64url (no padding) -> standard base64, which the C ABI expects for keys. */
static char *b64url_to_b64(const char *in) {
    size_t n = strlen(in);
    size_t pad = (4 - (n % 4)) % 4;
    char *out = malloc(n + pad + 1);
    for (size_t i = 0; i < n; i++) {
        out[i] = in[i] == '-' ? '+' : (in[i] == '_' ? '/' : in[i]);
    }
    for (size_t i = 0; i < pad; i++) out[n + i] = '=';
    out[n + pad] = 0;
    return out;
}

/* Report a check_action verdict: the result JSON is {"ok":bool,"reasons":[..]}. */
static void report_action(const char *label, const char *scope, const char *action) {
    char *err = NULL;
    char *res = take(vouch_robotics_check_action(scope, action, &err), err, "check_action");
    int allowed = strstr(res, "\"ok\":true") != NULL;
    char *reasons = json_value(res, "reasons");
    if (allowed) {
        printf("  [ALLOW] %s\n", label);
    } else {
        printf("  [DENY ] %-24s %s\n", label, reasons);
    }
    free(reasons);
    vouch_string_free(res);
}

int main(int argc, char **argv) {
    const char *vector_path =
        argc > 1 ? argv[1] : "../../../test-vectors/robotics/vector.json";
    char *doc = read_file(vector_path);
    if (!doc) {
        fprintf(stderr, "cannot open interop vector at %s\n", vector_path);
        return 2;
    }

    char *err = NULL;
    char *version = vouch_version();
    printf("vouch core %s, robotics over the C ABI\n\n", version ? version : "?");
    if (version) vouch_string_free(version);

    /* ---- 1a. verify the Python-minted identity (cross-language interop) ---- */
    char *jwk = json_value(doc, "robot_public_key_jwk");
    char *x_q = json_value(jwk, "x");
    char *robot_pub = b64url_to_b64(unquote(x_q));
    char *identity = json_value(doc, "robot_identity_credential");

    err = NULL;
    char *subject =
        take(vouch_robotics_verify_identity(identity, robot_pub, &err), err, "verify_identity");
    char *make = json_value(subject, "make");
    char *model = json_value(subject, "model");
    printf("identity verifies (minted in Python): %s %s\n", unquote(make), unquote(model));
    free(make);
    free(model);
    vouch_string_free(subject);

    /* ---- 1b. mint from C, and show the hardware root is enforced ---------- */
    err = NULL;
    char *keys = take(vouch_generate_ed25519(&err), err, "generate_ed25519");
    char *seed_q = json_value(keys, "seed_b64");
    char *pub_q = json_value(keys, "public_b64");
    char *mk_q = json_value(keys, "multikey");
    char *seed = unquote(seed_q);
    char *fresh_pub = unquote(pub_q);
    char *root_mk = unquote(mk_q);

    /* A syntactically valid but cryptographically fabricated attestation: the
     * C ABI cannot produce the real one (no raw-signature primitive). */
    char params[1024];
    snprintf(params, sizeof params,
             "{\"robotDid\":\"did:web:ar7.example.com\",\"make\":\"Acme Robotics\","
             "\"model\":\"AR-7\",\"serial\":\"SN-000123\",\"rootKind\":\"TPM\","
             "\"rootPublicMultibase\":\"%s\","
             "\"attestation\":\"uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
             "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\","
             "\"validFrom\":\"2026-01-01T00:00:00Z\"}",
             root_mk);

    err = NULL;
    char *minted = take(vouch_robotics_mint_identity(seed, params, &err), err, "mint_identity");
    char *minted_type = json_value(minted, "type");
    printf("minted from C: type=%s\n", minted_type);
    free(minted_type);

    err = NULL;
    char *minted_subject = vouch_robotics_verify_identity(minted, fresh_pub, &err);
    printf("  hardware root enforced: locally minted credential %s\n",
           rejected(minted_subject) ? "REJECTED (expected: fabricated attestation)"
                                    : "ACCEPTED (unexpected)");
    if (minted_subject) vouch_string_free(minted_subject);
    if (err) vouch_string_free(err);
    vouch_string_free(minted);
    free(seed_q);
    free(pub_q);
    free(mk_q);
    vouch_string_free(keys);

    /* ---- 2. the pre-actuation scope gate --------------------------------- */
    printf("\npre-actuation scope gate:\n");
    report_action("pick up the cup", kScopeJson,
                  "{\"forceN\":20.0,\"speedMps\":0.3,\"nearHumans\":true,\"zone\":\"cell-3\"}");
    report_action("sprint to the dock", kScopeJson,
                  "{\"speedMps\":2.5,\"nearHumans\":true,\"zone\":\"cell-3\"}");
    report_action("fetch from loading bay", kScopeJson,
                  "{\"forceN\":15.0,\"speedMps\":0.5,\"zone\":\"loading-bay\"}");

    /* ---- 3. the evidence pack: conformance + signed attestation ----------- */
    char *creds = json_value(doc, "conformance_credentials");
    char *profile_q = json_value(doc, "conformance_profile_id");
    char *profile = unquote(profile_q);

    err = NULL;
    char *report =
        take(vouch_robotics_check_conformance(creds, profile, &err), err, "check_conformance");
    int conforms = strstr(report, "\"conforms\":true") != NULL;
    char *satisfied = json_value(report, "satisfiedCount");
    char *total = json_value(report, "totalCount");
    printf("\nconformance (%s): %s %s/%s\n", profile, conforms ? "CONFORMS" : "GAPS", satisfied,
           total);
    free(satisfied);
    free(total);

    /* CONFORMS says the evidence covers the clauses this profile maps, which is
     * a weaker claim than compliance with the regulation. Every report carries
     * how well-sourced its clause numbers are, so the two never get conflated. */
    char *citations = json_value(report, "citations");
    printf("  citations: %s\n", citations);
    free(citations);

    /* Sign a point-in-time attestation over that report, then verify it. */
    size_t att_len = strlen(report) + 512;
    char *att_params = malloc(att_len);
    snprintf(att_params, att_len,
             "{\"issuerDid\":\"did:web:assessor.example.com\","
             "\"robotDid\":\"did:web:ar7.example.com\",\"report\":%s,"
             "\"validFrom\":\"2026-01-01T00:00:00Z\"}",
             report);

    err = NULL;
    char *attestation =
        take(vouch_robotics_build_conformance_attestation(kAssessorSeedB64, att_params, &err), err,
             "build_conformance_attestation");

    err = NULL;
    char *att_subject =
        take(vouch_robotics_verify_conformance_attestation(attestation, kAssessorPubB64, &err), err,
             "verify_conformance_attestation");
    char *digest = json_value(att_subject, "reportDigest");
    printf("attestation verifies: true  reportDigest=%.18s...\n", unquote(digest));
    free(digest);
    vouch_string_free(att_subject);

    err = NULL;
    char *wrong = vouch_robotics_verify_conformance_attestation(attestation, kOtherPubB64, &err);
    printf("wrong key rejected: %s\n", rejected(wrong) ? "yes" : "no (unexpected)");
    if (wrong) vouch_string_free(wrong);
    if (err) vouch_string_free(err);

    free(att_params);
    vouch_string_free(attestation);
    vouch_string_free(report);
    free(profile_q);
    free(creds);
    free(identity);
    free(robot_pub);
    free(x_q);
    free(jwk);
    free(doc);

    printf("\nall robotics C ABI checks completed\n");
    return 0;
}
