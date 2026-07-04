# Vouch Protocol C bindings

These are the **C bindings shipped with the core**, not a separate code SDK. The
canonical Rust core (`vouch-core`) exposes a plain C ABI through a
cbindgen-generated header, and this directory packages that header plus a
prebuilt shared library and a working example. C and C++ programs (and anything
that can call C, including .NET P/Invoke) link against it. Apache-2.0.

```
sdks/cpp/
  include/vouch_core.h     the C header (cbindgen-generated)
  lib/libvouch_core_uniffi.so   prebuilt shared library (linux-x64)
  examples/example.c       a working example + Makefile
  CMakeLists.txt           CMake build of the example
  build-native.sh          rebuild the library + header from the core
```

## What it gives you

JCS canonicalization, Ed25519, did:key/multikey, Data Integrity proofs
(eddsa-jcs-2022), credential verify, delegation (build a link, validate a chain's
time-bound rule), dual-proof ML-DSA-44 and composite verify, and
BitstringStatusList revocation. A curated robotics surface in the
`vouch::robotics` namespace verifies a robot credential (classical or hybrid
post-quantum), mints and verifies identity, checks regulatory conformance, verifies
a passport, and checks a physical action. Every value crossing the ABI is a NUL-terminated
UTF-8 C string: JSON for credentials and proofs, base64 for binary. Returned
strings are heap allocated and must be freed with `vouch_string_free`. On error a
function returns NULL and writes a message to the `err_out` argument (also freed
with `vouch_string_free`).

## Quickstart

```c
#include "vouch_core.h"
#include <stdio.h>

int main(void) {
    char *err = NULL;
    char *canon = vouch_canonicalize("{\"b\":1,\"a\":2}", &err);
    printf("%s\n", canon);          // {"a":1,"b":2} sorted: {"a":2,"b":1}
    vouch_string_free(canon);

    char *ok = vouch_verify_proof(signed_credential_json, public_key_base64, &err);
    // ok is "true" or "false"; on error ok is NULL and err holds the message.
    vouch_string_free(ok);
    return 0;
}
```

## Build the example

With the Makefile (gcc or clang):

```
cd examples
make run
```

With CMake:

```
cmake -S . -B build
cmake --build build
./build/example
```

## Linking your own program

```
cc -I/path/to/sdks/cpp/include myprog.c -L/path/to/sdks/cpp/lib -lvouch_core_uniffi -o myprog
LD_LIBRARY_PATH=/path/to/sdks/cpp/lib ./myprog
```

For static linking, run `./build-native.sh` to produce `lib/libvouch_core_uniffi.a`
(around 50 MB) and link that instead. The prebuilt shared library here is
linux-x64; run `build-native.sh` on macOS or Windows to produce the `.dylib` or
`.dll`.

## Interop

The example reads the shared vector at `test-vectors/` and confirms it verifies
the shared signed credential and reproduces the identical proofValue, so a proof
built here matches every other Vouch SDK.
