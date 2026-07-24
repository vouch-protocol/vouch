# VouchProtocol.Core (.NET SDK)

The .NET SDK for the Vouch Protocol (#34). It P/Invokes the canonical Rust core
(`vouch-core`) through its cbindgen C ABI, so .NET apps verify credentials with
the exact same bytes as every other Vouch SDK. Apache-2.0.

## What you get

- JCS canonicalization, Ed25519, did:key/multikey
- Data Integrity proofs (`eddsa-jcs-2022`): sign + verify, with validity-window checks
- Post-quantum dual-proof and composite verification
- BitstringStatusList revocation checks
- Robotics (`VouchRobotics`): verify a robot credential (classical or post-quantum, auto-detected), mint and verify identity, regulatory conformance, passport, and physical action checks

## Build

```
./build-native.sh     # builds the host native lib into runtimes/<rid>/native
dotnet test           # builds the library and runs the xUnit suite
```

Run `build-native.sh` on each platform you target (Linux, macOS, Windows) so all
runtime identifiers are populated. The native library is bundled in the NuGet
package under `runtimes/<rid>/native`, so consumers need no extra setup.

## Use

```csharp
using VouchProtocol.Core;
using System.Text.Json;

using var kp = JsonDocument.Parse(Vouch.GenerateEd25519());
var seed = kp.RootElement.GetProperty("seed_b64").GetString()!;
var pub  = kp.RootElement.GetProperty("public_b64").GetString()!;
var did  = kp.RootElement.GetProperty("did_key").GetString()!;

var signed = Vouch.Sign(credentialJson, seed, did + "#key-1", "2026-04-26T10:00:00Z");
bool ok = Vouch.VerifyProof(signed, pub);
var result = Vouch.Verify(signed, pub, nowIso);  // JSON {proofValid, timeValid, valid}
```

Binary values are base64 strings; credentials and proofs are JSON strings.
Methods throw `VouchException` on error.

## Interop

The xUnit suite includes a cross-implementation test: .NET verifies the shared
`eddsa-jcs-2022` vector and reproduces its exact `proofValue` through the native
core. A proof built here verifies in every other Vouch SDK.
