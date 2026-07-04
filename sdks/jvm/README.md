# Vouch Protocol JVM SDK (Kotlin + Java)

The JVM SDK for the Vouch Protocol (#33). It calls the canonical Rust core
(`vouch-core`) through JNA, so Android, Kotlin, and Java apps verify credentials
with the exact same bytes as every other Vouch SDK. Apache-2.0.

Two entry points over the same native core:

- **Java**: `com.vouchprotocol.core.Vouch` (a thin JNA wrapper over the cbindgen
  C ABI, no Kotlin runtime required).
- **Kotlin**: the generated UniFFI binding `vouch_core.kt` (bundled), for Kotlin
  callers who want native types.

## What you get

- JCS canonicalization, Ed25519, did:key/multikey
- Data Integrity proofs (`eddsa-jcs-2022`): sign + verify, with validity-window checks
- Post-quantum dual-proof and composite verification
- BitstringStatusList revocation checks
- Robotics (`VouchRobotics`): verify a robot credential (classical or hybrid post-quantum, auto-detected), mint and verify identity, regulatory conformance, passport, and physical action checks

## Build

```
./build-native.sh     # builds the host native lib + refreshes the Kotlin binding
gradle test           # runs the JUnit suite against the native core
```

`build-native.sh` also prints the cargo-ndk commands to cross-compile the
per-ABI Android `.so` files into `src/main/jniLibs/`.

The host native library is bundled under `src/main/resources/<jna-platform>/`
(e.g. `linux-x86-64/`), so JNA loads it from the jar with no extra setup.

## Use (Java)

```java
import com.vouchprotocol.core.Vouch;

String kp = Vouch.generateEd25519();           // JSON {seed_b64, public_b64, multikey, did_key}
String signed = Vouch.signCredential(credentialJson, seedB64, didKey + "#key-1", "2026-04-26T10:00:00Z");
boolean ok = Vouch.verifyProof(signed, publicB64);
String result = Vouch.verifyCredential(signed, publicB64, nowIso, 30);  // JSON {proofValid, timeValid, valid}
```

Binary values are base64 strings; credentials and proofs are JSON strings.

## Use (Kotlin / UniFFI)

```kotlin
import uniffi.vouch_core.*

val kp = generateEd25519()
val signed = signCredential(credentialJson, kp.seed, "${kp.didKey}#key-1", "2026-04-26T10:00:00Z")
val ok = verifyProof(signed, kp.publicKey)     // ByteArray keys, native types
```

## Verified

A standalone smoke test (`VouchSmoke`) and the JUnit suite confirm cross-impl
interop: the JVM verifies the shared `eddsa-jcs-2022` vector and reproduces its
exact `proofValue` through the native core. To run the smoke directly:

```
javac -cp lib/jna-5.14.0.jar -d build/classes src/main/java/com/vouchprotocol/core/Vouch.java src/test/java/com/vouchprotocol/core/VouchSmoke.java
java -cp build/classes:lib/jna-5.14.0.jar -Djna.library.path=$(pwd)/lib com.vouchprotocol.core.VouchSmoke
```
