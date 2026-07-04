//! Clean C ABI for the Vouch Protocol core (for .NET P/Invoke and C/C++).
//!
//! All arguments and return values are NUL-terminated UTF-8 C strings: JSON for
//! credentials/proofs, base64 for binary (keys, signatures). Returned strings
//! are heap allocated by Rust and MUST be freed with `vouch_string_free`. A
//! function returns NULL on error and writes the message to `*err_out` (also
//! freed with `vouch_string_free`); on success `*err_out` is set to NULL.
//! cbindgen generates `vouch_core.h` from this.
//!
//! Safety: every fallible function runs its body inside `catch_unwind`, so a
//! Rust panic can never unwind across the C boundary (which would be undefined
//! behavior for the C/.NET caller). Functions are written explicitly (no macro)
//! so cbindgen, which does not expand macros, emits a declaration for each.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, UnwindSafe};
use std::ptr;

use crate as core;

/// Copy a C string argument into an owned `String` (sound: no borrow escapes).
fn cstr_in(p: *const c_char) -> Result<String, String> {
    if p.is_null() {
        return Err("null argument".into());
    }
    unsafe { CStr::from_ptr(p) }
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|e| format!("invalid utf-8: {e}"))
}

/// Like `cstr_in`, but a NULL pointer maps to None (an optional argument).
fn cstr_in_opt(p: *const c_char) -> Result<Option<String>, String> {
    if p.is_null() {
        Ok(None)
    } else {
        cstr_in(p).map(Some)
    }
}

fn cstr_out(s: String) -> *mut c_char {
    CString::new(s).map(|c| c.into_raw()).unwrap_or(ptr::null_mut())
}

fn set_err(err_out: *mut *mut c_char, msg: String) {
    if !err_out.is_null() {
        unsafe { *err_out = cstr_out(msg) };
    }
}

fn b64(b: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(b)
}
fn unb64(s: &str) -> Result<Vec<u8>, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s).map_err(|e| format!("base64: {e}"))
}
fn bool_str(b: bool) -> String {
    if b { "true".into() } else { "false".into() }
}

/// Run `body`, catching any panic, and marshal the result to a C string. Always
/// initializes `*err_out` to NULL first so a caller never reads stale memory.
fn guard<F>(err_out: *mut *mut c_char, body: F) -> *mut c_char
where
    F: FnOnce() -> Result<String, String> + UnwindSafe,
{
    if !err_out.is_null() {
        unsafe { *err_out = ptr::null_mut() };
    }
    match catch_unwind(body) {
        Ok(Ok(s)) => cstr_out(s),
        Ok(Err(e)) => {
            set_err(err_out, e);
            ptr::null_mut()
        }
        Err(_) => {
            set_err(err_out, "internal error".into());
            ptr::null_mut()
        }
    }
}

/// Free a string returned by this library.
#[no_mangle]
pub extern "C" fn vouch_string_free(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}

/// Library version (caller frees).
#[no_mangle]
pub extern "C" fn vouch_version() -> *mut c_char {
    cstr_out(core::version())
}

/// RFC 8785 canonicalization of a JSON string. NULL on error.
#[no_mangle]
pub extern "C" fn vouch_canonicalize(json: *const c_char, err_out: *mut *mut c_char) -> *mut c_char {
    guard(err_out, move || {
        let json = cstr_in(json)?;
        core::canonicalize(json).map_err(|e| e.to_string())
    })
}

/// Generate an Ed25519 key pair. Returns JSON {seed_b64, public_b64, multikey, did_key}.
#[no_mangle]
pub extern "C" fn vouch_generate_ed25519(err_out: *mut *mut c_char) -> *mut c_char {
    guard(err_out, move || {
        let kp = core::generate_ed25519().map_err(|e| e.to_string())?;
        Ok(serde_json::json!({
            "seed_b64": b64(&kp.seed), "public_b64": b64(&kp.public_key),
            "multikey": kp.multikey, "did_key": kp.did_key
        })
        .to_string())
    })
}

/// Sign a credential (eddsa-jcs-2022). seed_b64 is the 32-byte Ed25519 seed.
#[no_mangle]
pub extern "C" fn vouch_sign_credential(
    credential_json: *const c_char,
    seed_b64: *const c_char,
    verification_method: *const c_char,
    created: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let seed = unb64(&cstr_in(seed_b64)?)?;
        let vm = cstr_in(verification_method)?;
        let created = cstr_in(created)?;
        core::sign_credential(cred, seed, vm, created).map_err(|e| e.to_string())
    })
}

/// Build a detached eddsa-jcs-2022 proof object (JSON).
#[no_mangle]
pub extern "C" fn vouch_build_proof(
    credential_json: *const c_char,
    seed_b64: *const c_char,
    verification_method: *const c_char,
    created: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let seed = unb64(&cstr_in(seed_b64)?)?;
        let vm = cstr_in(verification_method)?;
        let created = cstr_in(created)?;
        core::build_proof(cred, seed, vm, created).map_err(|e| e.to_string())
    })
}

/// Verify an eddsa-jcs-2022 proof. Returns "true"/"false".
#[no_mangle]
pub extern "C" fn vouch_verify_proof(
    credential_json: *const c_char,
    public_b64: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let pk = unb64(&cstr_in(public_b64)?)?;
        Ok(bool_str(core::verify_proof(cred, pk).map_err(|e| e.to_string())?))
    })
}

/// Verify a credential's proof and validity window. Returns JSON
/// {proofValid, timeValid, valid}.
#[no_mangle]
pub extern "C" fn vouch_verify_credential(
    credential_json: *const c_char,
    public_b64: *const c_char,
    now_iso: *const c_char,
    clock_skew_seconds: i64,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let pk = unb64(&cstr_in(public_b64)?)?;
        let now = cstr_in(now_iso)?;
        let r = core::verify_credential(cred, pk, now, clock_skew_seconds).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({"proofValid": r.proof_valid, "timeValid": r.time_valid, "valid": r.valid}).to_string())
    })
}

/// Verify a dual proof (Ed25519 + ML-DSA-44). Returns "true"/"false".
#[no_mangle]
pub extern "C" fn vouch_verify_dual(
    credential_json: *const c_char,
    ed25519_public_b64: *const c_char,
    mldsa_public_b64: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let ed = unb64(&cstr_in(ed25519_public_b64)?)?;
        let ml = unb64(&cstr_in(mldsa_public_b64)?)?;
        Ok(bool_str(core::verify_dual(cred, ed, ml).map_err(|e| e.to_string())?))
    })
}

/// Verify a v1.6.x composite hybrid proof. Returns "true"/"false".
#[no_mangle]
pub extern "C" fn vouch_verify_composite(
    credential_json: *const c_char,
    ed25519_public_b64: *const c_char,
    mldsa_public_b64: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let ed = unb64(&cstr_in(ed25519_public_b64)?)?;
        let ml = unb64(&cstr_in(mldsa_public_b64)?)?;
        Ok(bool_str(core::verify_composite(cred, ed, ml).map_err(|e| e.to_string())?))
    })
}

/// Verify a credential's revocation status against a BitstringStatusList
/// credential. Returns "true" (set/revoked) or "false".
#[no_mangle]
pub extern "C" fn vouch_verify_status(
    credential_status_json: *const c_char,
    status_list_credential_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cs = cstr_in(credential_status_json)?;
        let sl = cstr_in(status_list_credential_json)?;
        Ok(bool_str(core::verify_status(cs, sl).map_err(|e| e.to_string())?))
    })
}

/// Build a delegation link. The valid_from / valid_until / parent_proof_value
/// arguments are optional: pass NULL to omit them. Returns the link as JSON.
#[no_mangle]
pub extern "C" fn vouch_build_delegation_link(
    issuer: *const c_char,
    subject: *const c_char,
    intent_json: *const c_char,
    valid_from: *const c_char,
    valid_until: *const c_char,
    parent_proof_value: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let issuer = cstr_in(issuer)?;
        let subject = cstr_in(subject)?;
        let intent = cstr_in(intent_json)?;
        let vf = cstr_in_opt(valid_from)?;
        let vu = cstr_in_opt(valid_until)?;
        let ppv = cstr_in_opt(parent_proof_value)?;
        core::build_delegation_link(issuer, subject, intent, vf, vu, ppv).map_err(|e| e.to_string())
    })
}

/// Validate the time-bound rule over a delegation chain (a JSON array of links).
/// Returns "true"/"false".
#[no_mangle]
pub extern "C" fn vouch_verify_chain_time_bound(
    chain_json: *const c_char,
    now_iso: *const c_char,
    clock_skew_seconds: i64,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let chain = cstr_in(chain_json)?;
        let now = cstr_in(now_iso)?;
        Ok(bool_str(
            core::verify_chain_time_bound(chain, now, clock_skew_seconds).map_err(|e| e.to_string())?,
        ))
    })
}

// ---------------------------------------------------------------------------
// Robotics: a curated set of the robot-credential operations, for C/C++/.NET/JVM/Swift.
// JSON in, JSON out; keys are base64. Same shapes as the Python, TypeScript, Go,
// and Rust reference implementations.
// ---------------------------------------------------------------------------

/// Mint a RobotIdentityCredential.  carries make/model/serial and
/// the hardware root; returns the signed credential JSON.
#[no_mangle]
pub extern "C" fn vouch_robotics_mint_identity(
    robot_seed_b64: *const c_char,
    params_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let seed = unb64(&cstr_in(robot_seed_b64)?)?;
        let params = cstr_in(params_json)?;
        vouch_core::robotics_json::mint_robot_identity(&seed, &params).map_err(|e| e.to_string())
    })
}

/// Verify a RobotIdentityCredential. Returns the credentialSubject JSON.
#[no_mangle]
pub extern "C" fn vouch_robotics_verify_identity(
    credential_json: *const c_char,
    public_b64: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let pk = unb64(&cstr_in(public_b64)?)?;
        vouch_core::robotics_json::verify_robot_identity(&cred, &pk).map_err(|e| e.to_string())
    })
}

/// Check a physical action against a physical capability scope. Returns JSON
/// {ok, reasons}.
#[no_mangle]
pub extern "C" fn vouch_robotics_check_action(
    scope_json: *const c_char,
    action_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let scope = cstr_in(scope_json)?;
        let action = cstr_in(action_json)?;
        vouch_core::robotics_json::check_physical_action(&scope, &action).map_err(|e| e.to_string())
    })
}

/// Verify a scannable robot passport URI. Returns the passport summary JSON.
#[no_mangle]
pub extern "C" fn vouch_robotics_verify_passport(
    uri: *const c_char,
    public_b64: *const c_char,
    now_iso: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let uri = cstr_in(uri)?;
        let pk = unb64(&cstr_in(public_b64)?)?;
        let now = cstr_in(now_iso)?;
        vouch_core::robotics_json::verify_passport_uri(&uri, &pk, &now).map_err(|e| e.to_string())
    })
}

/// Check a set of robot credentials against a named regulatory profile.
///  is a JSON array; returns the deterministic report JSON.
#[no_mangle]
pub extern "C" fn vouch_robotics_check_conformance(
    credentials_json: *const c_char,
    profile_id: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let creds = cstr_in(credentials_json)?;
        let profile = cstr_in(profile_id)?;
        vouch_core::robotics_json::check_conformance(&creds, &profile).map_err(|e| e.to_string())
    })
}

/// Sign a point-in-time conformance attestation over a report. 
/// carries issuerDid/robotDid/report; returns the signed credential JSON.
#[no_mangle]
pub extern "C" fn vouch_robotics_build_conformance_attestation(
    signer_seed_b64: *const c_char,
    params_json: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let seed = unb64(&cstr_in(signer_seed_b64)?)?;
        let params = cstr_in(params_json)?;
        vouch_core::robotics_json::build_conformance_attestation(&seed, &params).map_err(|e| e.to_string())
    })
}

/// Verify a conformance attestation and its bound report digest. Returns the
/// credentialSubject JSON.
#[no_mangle]
pub extern "C" fn vouch_robotics_verify_conformance_attestation(
    credential_json: *const c_char,
    public_b64: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let pk = unb64(&cstr_in(public_b64)?)?;
        vouch_core::robotics_json::verify_conformance_attestation(&cred, &pk).map_err(|e| e.to_string())
    })
}

/// Attach a hybrid post-quantum proof (Ed25519 + ML-DSA-44) to a robot
/// credential. Returns the re-signed credential JSON.
#[no_mangle]
pub extern "C" fn vouch_robotics_sign_pq(
    credential_json: *const c_char,
    ed25519_seed_b64: *const c_char,
    mldsa_secret_b64: *const c_char,
    mldsa_public_b64: *const c_char,
    created_iso: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let ed_seed = unb64(&cstr_in(ed25519_seed_b64)?)?;
        let ml_sec = unb64(&cstr_in(mldsa_secret_b64)?)?;
        let ml_pub = unb64(&cstr_in(mldsa_public_b64)?)?;
        let created = cstr_in(created_iso)?;
        vouch_core::robotics_json::sign_pq(&cred, &ed_seed, &ml_sec, &ml_pub, &created)
            .map_err(|e| e.to_string())
    })
}

/// Verify a robot credential whether it carries a classical or a hybrid proof,
/// auto-detected from the proof. Pass the ML-DSA-44 public key (base64) for a
/// hybrid credential, or NULL for a classical one. Returns "true"/"false".
#[no_mangle]
pub extern "C" fn vouch_robotics_verify_robot_credential(
    credential_json: *const c_char,
    ed25519_public_b64: *const c_char,
    mldsa44_public_b64: *const c_char,
    err_out: *mut *mut c_char,
) -> *mut c_char {
    guard(err_out, move || {
        let cred = cstr_in(credential_json)?;
        let ed_pub = unb64(&cstr_in(ed25519_public_b64)?)?;
        let ml_pub = match cstr_in_opt(mldsa44_public_b64)? {
            Some(s) => Some(unb64(&s)?),
            None => None,
        };
        Ok(bool_str(
            vouch_core::robotics_json::verify_robot_credential(&cred, &ed_pub, ml_pub.as_deref())
                .map_err(|e| e.to_string())?,
        ))
    })
}
