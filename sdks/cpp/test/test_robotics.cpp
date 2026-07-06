// Tests for the robotics wrappers in the C++ ergonomic layer (vouch.hpp).
// Build and run:
//   g++ -std=c++17 -I../include test_robotics.cpp -o test_robotics -L../lib -lvouch_core_uniffi
//   LD_LIBRARY_PATH=../lib ./test_robotics
//
// The first two checks are keyless and deterministic: they exercise the physical
// action gate and the conformance report, neither of which needs a signer. The
// remaining checks drive the curated robotics C ABI against the shared
// cross-language interop vector (test-vectors/robotics/vector.json), verifying
// credentials and chains minted by the Python reference the same way the Go
// sidecar interop tests do.

#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "vouch.hpp"

static int failures = 0;

static void check(bool cond, const char* name) {
  if (cond) {
    std::printf("  ok   %s\n", name);
  } else {
    std::printf("  FAIL %s\n", name);
    failures++;
  }
}

// ---- interop-vector helpers -----------------------------------------------
//
// The vector is a controlled, well-formed JSON document, so a small balanced
// extractor is enough to pull a top-level value out as raw JSON text and splice
// it into the params objects the curated C ABI expects. No general JSON parser
// is pulled in; this mirrors the "controlled inputs from the core" scanning the
// vouch.hpp detail layer already relies on.

// Read the whole interop vector file.
static std::string load_vector() {
  const char* path = "../../../test-vectors/robotics/vector.json";
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    std::fprintf(stderr, "cannot open interop vector at %s\n", path);
    std::exit(2);
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// Return the raw JSON text of the value for a top-level key, e.g. the object,
// array, string, or number that follows "key":. Handles nested braces and
// brackets and skips over string contents (including escaped quotes).
static std::string field(const std::string& doc, const std::string& key) {
  std::string pat = "\"" + key + "\"";
  size_t k = doc.find(pat);
  if (k == std::string::npos) {
    std::fprintf(stderr, "interop vector missing field %s\n", key.c_str());
    std::exit(2);
  }
  size_t colon = doc.find(':', k + pat.size());
  size_t i = colon + 1;
  while (i < doc.size() && (doc[i] == ' ' || doc[i] == '\n' || doc[i] == '\r' ||
                            doc[i] == '\t')) {
    i++;
  }
  size_t start = i;
  char open = doc[i];
  if (open == '{' || open == '[') {
    char close = (open == '{') ? '}' : ']';
    int depth = 0;
    bool in_str = false;
    for (; i < doc.size(); i++) {
      char c = doc[i];
      if (in_str) {
        if (c == '\\') {
          i++;
        } else if (c == '"') {
          in_str = false;
        }
        continue;
      }
      if (c == '"') {
        in_str = true;
      } else if (c == open) {
        depth++;
      } else if (c == close) {
        depth--;
        if (depth == 0) return doc.substr(start, i - start + 1);
      }
    }
  } else if (open == '"') {
    for (i++; i < doc.size(); i++) {
      if (doc[i] == '\\') {
        i++;
      } else if (doc[i] == '"') {
        return doc.substr(start, i - start + 1);
      }
    }
  } else {
    // A bare scalar (number, true, false, null): read to the next delimiter.
    for (; i < doc.size(); i++) {
      char c = doc[i];
      if (c == ',' || c == '}' || c == ']' || c == '\n' || c == '\r') {
        return doc.substr(start, i - start);
      }
    }
  }
  std::fprintf(stderr, "interop vector field %s is malformed\n", key.c_str());
  std::exit(2);
}

// Return the final top-level element of a JSON array's text, e.g. the last link
// of a chain. Scans balanced objects and skips string contents.
static std::string last_array_element(const std::string& arr) {
  // Find the opening '[' and walk elements at depth 1.
  size_t i = arr.find('[');
  size_t elem_start = std::string::npos;
  int depth = 0;
  bool in_str = false;
  std::string last;
  for (; i < arr.size(); i++) {
    char c = arr[i];
    if (in_str) {
      if (c == '\\') {
        i++;
      } else if (c == '"') {
        in_str = false;
      }
      continue;
    }
    if (c == '"') {
      in_str = true;
    } else if (c == '[' || c == '{') {
      if (depth == 1 && elem_start == std::string::npos) elem_start = i;
      depth++;
    } else if (c == ']' || c == '}') {
      depth--;
      if (depth == 1 && elem_start != std::string::npos) {
        last = arr.substr(elem_start, i - elem_start + 1);
        elem_start = std::string::npos;
      }
    }
  }
  return last;
}

// Read the string value of a JWK member (e.g. its base64url "x" coordinate).
static std::string jwk_member(const std::string& jwk, const std::string& member) {
  return vouch::detail::json_string(jwk, member);
}

// Convert a base64url-no-pad string (as carried in a JWK "x") to the standard
// base64 the curated C ABI decodes with STANDARD. This is how the raw Ed25519
// public key reaches the header, matching the Go interop tests that base64url
// -decode the same "x" into the 32 raw bytes.
static std::string b64url_to_std(const std::string& b64url) {
  std::string s = b64url;
  for (char& c : s) {
    if (c == '-') c = '+';
    else if (c == '_') c = '/';
  }
  while (s.size() % 4 != 0) s.push_back('=');
  return s;
}

// The standard-base64 raw public key extracted from a JWK object.
static std::string pub_b64_from_jwk(const std::string& jwk) {
  return b64url_to_std(jwk_member(jwk, "x"));
}

int main() {
  // check_action: an in-scope action passes, an over-speed action fails.
  {
    std::string scope =
        "{\"maxForceN\":80.0,\"maxSpeedMps\":1.5,"
        "\"maxSpeedNearHumansMps\":0.25,\"allowedZones\":[\"cell-3\"]}";

    std::string ok_action =
        "{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}";
    std::string ok_result = vouch::robotics::check_action(scope, ok_action);
    check(ok_result.find("\"ok\":true") != std::string::npos, "action within scope allowed");

    std::string bad_action =
        "{\"speedMps\":1.2,\"nearHumans\":true,\"zone\":\"cell-3\"}";
    std::string bad_result = vouch::robotics::check_action(scope, bad_action);
    check(bad_result.find("\"ok\":false") != std::string::npos, "over-speed action denied");
  }

  // check_conformance: a full set of four credentials conforms to the EU AI Act
  // high-risk profile.
  {
    std::string credentials =
        "["
        "{\"type\":[\"VerifiableCredential\",\"RobotIdentityCredential\"],"
        "\"credentialSubject\":{\"id\":\"did:web:r\",\"make\":\"Acme\",\"model\":\"AR-7\","
        "\"serial\":\"SN-1\",\"hardwareRoot\":{\"kind\":\"TPM\"}}},"
        "{\"type\":[\"VerifiableCredential\",\"ModelProvenanceAttestation\"],"
        "\"credentialSubject\":{\"id\":\"did:web:r\",\"vla\":{\"modelName\":\"M\","
        "\"weightsHash\":\"uW\",\"safetyPolicy\":\"uP\",\"configHash\":\"uC\"}}},"
        "{\"type\":[\"VerifiableCredential\",\"PhysicalCapabilityScope\"],"
        "\"credentialSubject\":{\"id\":\"did:web:r\",\"physicalScope\":{\"maxForceN\":80.0,"
        "\"maxSpeedMps\":1.5,\"maxSpeedNearHumansMps\":0.25,\"allowedZones\":[\"cell-3\"]}}},"
        "{\"type\":[\"VerifiableCredential\",\"RobotSafetyRecordCredential\"],"
        "\"credentialSubject\":{\"id\":\"did:web:r\",\"totalEvents\":2,\"logHead\":\"uHEAD\"}}"
        "]";

    std::string report = vouch::robotics::check_conformance(credentials, "eu-ai-act-high-risk");
    check(report.find("\"conforms\":true") != std::string::npos, "profile conforms");
    check(report.find("\"totalCount\":4") != std::string::npos, "four requirements counted");
  }

  // The remaining checks drive the curated robotics C ABI against the shared
  // interop vector, verifying Python-minted credentials and chains.
  std::string v = load_vector();
  // A time inside every window the vector's grant, request, evidence, and
  // consent token share.
  const std::string now = "2026-01-01T00:05:00Z";

  // authorize_access: an operator grant plus a matching robot request authorizes
  // the door-open, checked offline under the operator and robot public keys.
  {
    std::string grant = field(v, "access_grant_credential");
    std::string request = field(v, "access_request_credential");
    std::string operator_pub = pub_b64_from_jwk(field(v, "access_operator_key"));
    std::string robot_pub = pub_b64_from_jwk(field(v, "access_robot_key"));

    std::string params =
        "{\"grant\":" + grant + ",\"request\":" + request + ",\"now\":\"" + now + "\"}";
    std::string result = vouch::robotics::authorize_access(params, operator_pub, robot_pub);
    check(result.find("\"ok\":true") != std::string::npos, "access request authorized");
  }

  // verify_fused_attestation: the fused-perception attestation verifies under the
  // robot key and yields a non-null subject.
  {
    std::string cred = field(v, "fused_perception_attestation");
    std::string robot_pub = pub_b64_from_jwk(field(v, "robot_public_key_jwk"));
    std::string subject = vouch::robotics::verify_fused_attestation(cred, robot_pub);
    check(subject != "null" && subject.find("\"fusionMethod\"") != std::string::npos,
          "fused attestation verified (subject non-null)");
  }

  // verify_wear_attestation: the latest link of the wear chain verifies under the
  // robot key and yields a non-null subject.
  {
    std::string chain = field(v, "wear_chain");
    // The wear chain is a JSON array; take its last link for a single-attestation
    // verify. The last element is the most-worn attestation.
    std::string latest = last_array_element(chain);
    std::string robot_pub = pub_b64_from_jwk(field(v, "robot_public_key_jwk"));
    std::string subject = vouch::robotics::verify_wear_attestation(latest, robot_pub);
    check(subject != "null" && subject.find("\"wearLevel\"") != std::string::npos,
          "wear attestation verified (subject non-null)");
  }

  // attenuate_for_wear: narrowing the input scope for the wear level reproduces
  // the pinned expected scope exactly.
  {
    std::string scope = field(v, "wear_input_scope");
    std::string level = field(v, "wear_attenuation_level");
    std::string expected = field(v, "expected_attenuated_scope");
    std::string params = "{\"scope\":" + scope + ",\"wearLevel\":" + level + "}";
    std::string narrowed = vouch::robotics::attenuate_for_wear(params);

    // Compare on the numeric fields the core narrows; formatting of the objects
    // is otherwise identical (same key order, same passthrough fields).
    check(narrowed.find("\"maxForceN\":60.0") != std::string::npos &&
              narrowed.find("\"maxSpeedMps\":1.125") != std::string::npos &&
              narrowed.find("\"maxSpeedNearHumansMps\":0.1875") != std::string::npos,
          "attenuated scope reproduces expected narrowed limits");
    check(expected.find("\"maxForceN\": 60.0") != std::string::npos,
          "vector pins the expected narrowed force (sanity)");
  }

  // verify_consent_evidence: the robot-signed evidence verifies under the robot
  // key, with the bystander-signed token checked under the bystander key
  // (multibase) that the evidence commits to.
  {
    std::string evidence = field(v, "consent_evidence_credential");
    std::string token = field(v, "consent_token_credential");
    std::string robot_pub = pub_b64_from_jwk(field(v, "robot_public_key_jwk"));
    // bystanderKeys maps the token issuer DID to its multibase ('u') public key.
    std::string bystander_x = jwk_member(field(v, "consent_bystander_key"), "x");
    std::string bystander_did = vouch::detail::json_string(token, "issuer");

    std::string params = "{\"evidence\":" + evidence + ",\"consentTokens\":[" + token +
                         "],\"bystanderKeys\":{\"" + bystander_did + "\":\"u" + bystander_x +
                         "\"},\"now\":\"" + now + "\"}";
    std::string subject = vouch::robotics::verify_consent_evidence(params, robot_pub);
    check(subject != "null" && subject.find("\"basis\":\"explicit-consent\"") != std::string::npos,
          "consent evidence verified (subject non-null)");
  }

  // verify_continuity_chain: the cross-embodiment chain verifies under the single
  // agent key and ends on body-b.
  {
    std::string chain = field(v, "embodiment_chain");
    std::string agent_pub = pub_b64_from_jwk(field(v, "embodiment_agent_key"));
    std::string params = "{\"embodiments\":" + chain + "}";
    std::string result = vouch::robotics::verify_continuity_chain(params, agent_pub);
    check(result.find("\"ok\":true") != std::string::npos, "continuity chain verified");
    check(result.find("did:web:body-b.example.com") != std::string::npos,
          "continuity chain ends on body-b");
  }

  // verify_handoff_chain: the custody chain verifies under the per-actor keys
  // (base64url) and ends on robot-b, starting from the pinned origin actor.
  {
    std::string chain = field(v, "custody_chain");
    std::string actor_keys = field(v, "custody_actor_keys");  // {did: {kty,crv,x}, ...}
    std::string origin = field(v, "custody_origin_actor");    // quoted DID string

    // Build publicKeys as {did: "base64url-x"}. The vector carries each actor key
    // as a JWK; the C ABI's handoff path wants the raw base64url ('x') per DID.
    std::string did_a = "did:web:robot-a.example.com";
    std::string did_b = "did:web:robot-b.example.com";
    // Each per-DID JWK object is nested; pull its "x" by scanning from the DID.
    auto jwk_x_for = [&](const std::string& did) {
      size_t d = actor_keys.find("\"" + did + "\"");
      std::string tail = actor_keys.substr(d);
      return jwk_member(tail, "x");
    };
    std::string public_keys = "{\"" + did_a + "\":\"" + jwk_x_for(did_a) + "\",\"" + did_b +
                              "\":\"" + jwk_x_for(did_b) + "\"}";

    std::string params = "{\"handoffs\":" + chain + ",\"publicKeys\":" + public_keys +
                         ",\"originActor\":" + origin + "}";
    std::string result = vouch::robotics::verify_handoff_chain(params);
    check(result.find("\"ok\":true") != std::string::npos, "custody handoff chain verified");
    check(result.find(did_b) != std::string::npos, "custody chain ends on robot-b");
  }

  if (failures == 0) {
    std::printf("ALL C++ ROBOTICS TESTS PASSED\n");
    return 0;
  }
  std::printf("%d FAILURE(S)\n", failures);
  return 1;
}
