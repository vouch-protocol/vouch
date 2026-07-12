/*
 * Vouch Protocol C bindings example.
 *
 * Links the prebuilt core library and exercises the C ABI: canonicalization,
 * verifying the shared eddsa-jcs-2022 vector, reproducing its proofValue
 * (cross-implementation interop), and delegation. Every returned string is freed
 * with vouch_string_free.
 *
 * Build + run:  make run   (see ../Makefile and the README).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vouch_core.h"

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

/* Extract the string value of "key":"value" (caller frees). */
static char *find_field(const char *json, const char *key) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), ':');
    if (!p) return NULL;
    p++;
    while (*p == ' ') p++;
    if (*p != '"') return NULL;
    p++;
    const char *start = p;
    while (*p && !(*p == '"' && p[-1] != '\\')) p++;
    size_t len = (size_t)(p - start);
    char *out = malloc(len + 1);
    memcpy(out, start, len);
    out[len] = 0;
    return out;
}

/* Extract the "key": { ... } object substring, brace matched (caller frees). */
static char *find_object(const char *json, const char *key) {
    char pat[128];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(json, pat);
    if (!p) return NULL;
    p = strchr(p, '{');
    if (!p) return NULL;
    const char *start = p;
    int depth = 0, in_str = 0, esc = 0;
    for (; *p; p++) {
        char c = *p;
        if (in_str) {
            if (esc) esc = 0;
            else if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
        } else if (c == '"') in_str = 1;
        else if (c == '{') depth++;
        else if (c == '}') {
            depth--;
            if (depth == 0) { p++; break; }
        }
    }
    size_t len = (size_t)(p - start);
    char *out = malloc(len + 1);
    memcpy(out, start, len);
    out[len] = 0;
    return out;
}

static int pass = 0, fail = 0;
static void ok(const char *name, int cond) {
    printf("  %s  %s\n", cond ? "PASS" : "FAIL", name);
    if (cond) pass++; else fail++;
}

int main(int argc, char **argv) {
    const char *vec_path =
        argc > 1 ? argv[1] : "../../../test-vectors/data-integrity-eddsa-jcs-2022/vector.json";
    char *err = NULL;

    char *ver = vouch_version();
    printf("vouch core version: %s\n", ver);
    vouch_string_free(ver);

    char *canon = vouch_canonicalize("{\"b\":1,\"a\":2}", &err);
    ok("canonicalize sorts keys", canon && strcmp(canon, "{\"a\":2,\"b\":1}") == 0);
    vouch_string_free(canon);
    vouch_string_free(err);
    err = NULL;

    char *vec = read_file(vec_path);
    if (!vec) {
        fprintf(stderr, "cannot read vector %s\n", vec_path);
        return 2;
    }
    char *pub = find_field(vec, "public_key_b64");
    char *seed = find_field(vec, "seed_b64");
    char *vm = find_field(vec, "verificationMethod");
    char *created = find_field(vec, "created");
    char *expected_pv = find_field(vec, "proofValue");
    char *signed_cred = find_object(vec, "signed_credential");
    char *unsigned_cred = find_object(vec, "unsigned_credential");

    char *vres = vouch_verify_proof(signed_cred, pub, &err);
    ok("verifies shared signed credential (cross-impl)", vres && strcmp(vres, "true") == 0);
    vouch_string_free(vres);
    vouch_string_free(err);
    err = NULL;

    char *proof = vouch_build_proof(unsigned_cred, seed, vm, created, &err);
    char *got_pv = proof ? find_field(proof, "proofValue") : NULL;
    ok("reproduces shared proofValue (cross-impl)",
       got_pv && expected_pv && strcmp(got_pv, expected_pv) == 0);
    vouch_string_free(proof);
    free(got_pv);
    vouch_string_free(err);
    err = NULL;

    const char *intent = "{\"action\":\"read\",\"target\":\"t\",\"resource\":\"https://api/x\"}";
    char *l1 = vouch_build_delegation_link("did:web:a", "did:web:b", intent,
                                           "2026-04-26T09:00:00Z", "2026-04-26T12:00:00Z", NULL, &err);
    char *l2 = vouch_build_delegation_link("did:web:b", "did:web:c", intent,
                                           "2026-04-26T10:00:00Z", "2026-04-26T11:00:00Z", NULL, &err);
    char chain[4096];
    snprintf(chain, sizeof chain, "[%s,%s]", l1 ? l1 : "", l2 ? l2 : "");
    char *t1 = vouch_verify_chain_time_bound(chain, "2026-04-26T10:30:00Z", 30, &err);
    char *t2 = vouch_verify_chain_time_bound(chain, "2026-04-26T13:00:00Z", 30, &err);
    ok("delegation chain time-bound valid", t1 && strcmp(t1, "true") == 0);
    ok("delegation chain outside window rejected", t2 && strcmp(t2, "false") == 0);
    vouch_string_free(l1);
    vouch_string_free(l2);
    vouch_string_free(t1);
    vouch_string_free(t2);
    vouch_string_free(err);

    /* FROST(Ed25519) threshold signing: 2-of-3 signs, and the aggregate
     * self-verifies inside the core before it is returned, so a successful,
     * non-NULL result already proves the signature is valid. */
    char *generated = vouch_threshold_generate_key(2, 3, &err);
    ok("threshold_generate_key succeeds", generated != NULL);
    vouch_string_free(err);
    err = NULL;

    char *share0 = NULL, *share1 = NULL, *id0 = NULL, *id1 = NULL;
    if (generated) {
        const char *p = strstr(generated, "\"shares\"");
        p = strchr(p, '[');
        p++; /* first '{' of shares[0] */
        const char *start0 = p;
        int depth = 0;
        for (; *p; p++) {
            if (*p == '{') depth++;
            else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
        }
        share0 = malloc((size_t)(p - start0) + 1);
        memcpy(share0, start0, (size_t)(p - start0));
        share0[p - start0] = 0;
        while (*p == ',' || *p == ' ') p++;
        const char *start1 = p;
        depth = 0;
        for (; *p; p++) {
            if (*p == '{') depth++;
            else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
        }
        share1 = malloc((size_t)(p - start1) + 1);
        memcpy(share1, start1, (size_t)(p - start1));
        share1[p - start1] = 0;
        id0 = find_field(share0, "identifier");
        id1 = find_field(share1, "identifier");
    }

    char *round1_0 = share0 ? vouch_threshold_commit(share0, &err) : NULL;
    vouch_string_free(err);
    err = NULL;
    char *round1_1 = share1 ? vouch_threshold_commit(share1, &err) : NULL;
    vouch_string_free(err);
    err = NULL;

    char *commitments_json = NULL;
    char *sig_share0 = NULL, *sig_share1 = NULL;
    const char *message_b64 = "Y2hhcmdlIGFwaS5iYW5rIGludm9pY2VzLzQy"; /* base64("charge api.bank invoices/42") */
    if (round1_0 && round1_1 && id0 && id1) {
        char *nonces0 = find_field(round1_0, "nonces");
        char *nonces1 = find_field(round1_1, "nonces");
        char *commitments0 = find_field(round1_0, "commitments");
        char *commitments1 = find_field(round1_1, "commitments");
        char buf[4096];
        snprintf(buf, sizeof buf, "{\"%s\":\"%s\",\"%s\":\"%s\"}", id0, commitments0, id1, commitments1);
        commitments_json = malloc(strlen(buf) + 1);
        strcpy(commitments_json, buf);

        sig_share0 = vouch_threshold_sign_share(message_b64, share0, nonces0, commitments_json, &err);
        vouch_string_free(err);
        err = NULL;
        sig_share1 = vouch_threshold_sign_share(message_b64, share1, nonces1, commitments_json, &err);
        vouch_string_free(err);
        err = NULL;

        free(nonces0);
        free(nonces1);
        free(commitments0);
        free(commitments1);
    }
    ok("threshold_sign_share succeeds for both signers", sig_share0 != NULL && sig_share1 != NULL);

    char *group_public_key_json = generated ? find_object(generated, "group_public_key") : NULL;
    char *signature = NULL;
    if (commitments_json && sig_share0 && sig_share1 && group_public_key_json) {
        char shares_json[4096];
        snprintf(shares_json, sizeof shares_json, "{\"%s\":\"%s\",\"%s\":\"%s\"}", id0, sig_share0, id1, sig_share1);
        signature = vouch_threshold_aggregate(message_b64, commitments_json, shares_json, group_public_key_json, &err);
    }
    ok("threshold_aggregate produces a self-verified signature", signature != NULL);
    vouch_string_free(err);
    err = NULL;

    vouch_string_free(generated);
    vouch_string_free(round1_0);
    vouch_string_free(round1_1);
    vouch_string_free(sig_share0);
    vouch_string_free(sig_share1);
    vouch_string_free(signature);
    free(share0);
    free(share1);
    free(id0);
    free(id1);
    free(commitments_json);
    free(group_public_key_json);

    /* Root-identity recovery by Shamir secret sharing: split a fresh
     * identity's seed into 3 shares (any 2 rebuild it), recover from 2 of
     * them, and confirm the recovered seed signs identically to the
     * original. */
    char *kp = vouch_generate_ed25519(&err);
    vouch_string_free(err);
    err = NULL;
    char *seed_b64 = kp ? find_field(kp, "seed_b64") : NULL;
    char *did_key = kp ? find_field(kp, "did_key") : NULL;

    char *rec_shares_json = seed_b64 ? vouch_recovery_split_identity(seed_b64, 2, 3, &err) : NULL;
    vouch_string_free(err);
    err = NULL;

    char *rshare0 = NULL, *rshare1 = NULL;
    if (rec_shares_json) {
        const char *p = strchr(rec_shares_json, '[') + 1;
        while (*p == ' ') p++;
        const char *s0 = p + 1; /* skip opening quote */
        const char *e0 = strchr(s0, '"');
        rshare0 = malloc((size_t)(e0 - s0) + 1);
        memcpy(rshare0, s0, (size_t)(e0 - s0));
        rshare0[e0 - s0] = 0;
        p = e0 + 1;
        while (*p == ',' || *p == ' ') p++;
        const char *s1 = p + 1;
        const char *e1 = strchr(s1, '"');
        rshare1 = malloc((size_t)(e1 - s1) + 1);
        memcpy(rshare1, s1, (size_t)(e1 - s1));
        rshare1[e1 - s1] = 0;
    }

    char *recovered = NULL;
    if (rshare0 && rshare1) {
        char subset[2048];
        snprintf(subset, sizeof subset, "[\"%s\",\"%s\"]", rshare0, rshare1);
        recovered = vouch_recovery_recover_identity(subset, did_key ? did_key : "", &err);
    }
    char *recovered_seed = recovered ? find_field(recovered, "seed") : NULL;
    ok("recovered identity seed matches the original",
       recovered_seed && seed_b64 && strcmp(recovered_seed, seed_b64) == 0);
    vouch_string_free(err);
    err = NULL;

    vouch_string_free(kp);
    vouch_string_free(rec_shares_json);
    vouch_string_free(recovered);
    free(seed_b64);
    free(did_key);
    free(rshare0);
    free(rshare1);
    free(recovered_seed);

    free(pub);
    free(seed);
    free(vm);
    free(created);
    free(expected_pv);
    free(signed_cred);
    free(unsigned_cred);
    free(vec);

    printf("\nTOTAL: %d pass, %d fail\n", pass, fail);
    return fail ? 1 : 0;
}
