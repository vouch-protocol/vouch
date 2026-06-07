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
