// Verify-side example for the two robotics accountability flows, using only
// the curated vouch::robotics surface (vouch.hpp). Mirrors the producer-side
// Python/TypeScript/Go/Rust examples (examples/robotics_ai_act_evidence_pack.py
// and examples/robotics_vla_accountability_loop.py) from the consuming side:
//
//   1. Regulatory evidence pack: check_conformance maps the shared interop
//      vector's Python-signed credential set onto all five built-in profiles,
//      reporting CONFORMS for the EU AI Act and the EU Machinery
//      Regulation and the exact open clause for the two profiles the set
//      leaves gaps in; build_conformance_attestation then signs a
//      point-in-time attestation per profile and
//      verify_conformance_attestation checks it offline.
//   2. VLA accountability loop: verify_identity / verify_robot_credential
//      authenticate the robot before trusting it (the wrapper-side analogue
//      of provenance-on-load), and check_action reproduces the pre-actuation
//      scope gate, denying the over-speed and out-of-zone actions and
//      allowing the safe ones.
//
// Build and run (after building the core library):
//   make -C sdks/cpp/examples robotics_verify_example run-robotics
// or directly:
//   g++ -O2 -std=c++17 -I../include robotics_verify_example.cpp
//     -o robotics_verify_example -L../lib -lvouch_core_uniffi
//   LD_LIBRARY_PATH=../lib ./robotics_verify_example

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "vouch.hpp"

// The five built-in conformance profiles. The curated surface keeps the
// profile registry inside the core, so the ids are listed here.
static const char* kAllProfileIds[] = {
    "eu-ai-act-high-risk",
    "iso-10218",
    "iso-ts-15066",
    "eu-machinery-2023-1230",
    "ul-3300",
};

// A fixed assessor signing seed (0x03 x 32) and its Ed25519 public key, both
// standard base64, so the attestation round-trip is deterministic.
static const char* kAssessorSeedB64 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
static const char* kAssessorPubB64 = "7UkoxijRwsbq6QM4kFmVYSlZJzpcY/k2NsFGFKyHN9E=";

// ---- interop-vector helpers (the same controlled-JSON extraction the C++
// robotics tests use; the vector is well-formed by construction) -------------

static std::string load_vector(const char* path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    std::fprintf(stderr, "cannot open interop vector at %s\n", path);
    std::exit(2);
  }
  std::ostringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

// Return the raw JSON text of the value for a top-level key. Handles nested
// braces and brackets and skips over string contents (including escapes).
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
  }
  std::fprintf(stderr, "interop vector field %s is malformed\n", key.c_str());
  std::exit(2);
}

// Convert a base64url-no-pad string (a JWK "x") to standard base64.
static std::string b64url_to_std(const std::string& b64url) {
  std::string s = b64url;
  for (char& c : s) {
    if (c == '-') {
      c = '+';
    } else if (c == '_') {
      c = '/';
    }
  }
  while (s.size() % 4 != 0) s.push_back('=');
  return s;
}

static std::string pub_b64_from_jwk(const std::string& jwk) {
  return b64url_to_std(vouch::detail::json_string(jwk, "x"));
}

static bool contains(const std::string& s, const std::string& needle) {
  return s.find(needle) != std::string::npos;
}

int main(int argc, char** argv) {
  const char* vector_path =
      (argc > 1) ? argv[1] : "../../../test-vectors/robotics/vector.json";
  const std::string vec = load_vector(vector_path);
  const std::string robot_pub = pub_b64_from_jwk(field(vec, "robot_public_key_jwk"));
  const std::string identity = field(vec, "robot_identity_credential");
  const std::string credentials = field(vec, "conformance_credentials");

  // 1. Authenticate the robot before trusting anything it presents.
  const std::string subject = vouch::robotics::verify_identity(identity, robot_pub);
  const bool identity_ok = subject != "null" && contains(subject, "Acme Robotics");
  const bool proof_ok = vouch::robotics::verify_robot_credential(identity, robot_pub);
  std::printf("robot identity verifies: %s (%s)\n", identity_ok ? "true" : "false",
              proof_ok ? "proof ok" : "proof FAILED");

  // 2. The evidence pack from the verify side: CONFORMS or the open clause,
  //    per profile, then one signed attestation per profile.
  std::printf("\nconformance across the five profiles:\n");
  int attested = 0;
  int cited = 0;
  for (const char* pid : kAllProfileIds) {
    const std::string report = vouch::robotics::check_conformance(credentials, pid);
    const bool conforms = contains(report, "\"conforms\":true");
    std::printf("  %-24s %s\n", pid, conforms ? "CONFORMS" : "GAPS");

    // CONFORMS says the evidence covers the clauses this profile maps, which
    // is weaker than compliance with the regulation. Every report states how
    // well-sourced its clause references are.
    if (contains(report, "\"citations\":")) cited++;

    const std::string params =
        std::string("{\"issuerDid\":\"did:web:assessor.example.com\",") +
        "\"robotDid\":\"did:web:robot.example.com\"," + "\"report\":" + report +
        "," + "\"validFrom\":\"2026-01-01T00:00:00Z\"}";
    const std::string attestation =
        vouch::robotics::build_conformance_attestation(kAssessorSeedB64, params);
    const std::string att_subject =
        vouch::robotics::verify_conformance_attestation(attestation, kAssessorPubB64);
    if (att_subject != "null" && contains(att_subject, pid)) attested++;
  }
  std::printf("signed attestations verified: %d/5\n", attested);
  std::printf("reports carrying clause-citation provenance: %d/5\n", cited);

  // 3. The VLA pre-actuation scope gate: allow the safe actions, deny the
  //    over-speed and out-of-zone ones.
  const std::string scope =
      "{\"maxForceN\":80.0,\"maxSpeedMps\":1.5,"
      "\"maxSpeedNearHumansMps\":0.5,\"allowedZones\":[\"cell-3\"]}";
  struct Case {
    const char* task;
    const char* action;
    bool want_ok;
  } cases[] = {
      {"pick up the cup",
       "{\"forceN\":20.0,\"speedMps\":0.3,\"nearHumans\":true,\"zone\":\"cell-3\"}",
       true},
      {"hand cup to operator",
       "{\"forceN\":10.0,\"speedMps\":0.2,\"nearHumans\":true,\"zone\":\"cell-3\"}",
       true},
      {"sprint to the dock",
       "{\"speedMps\":2.5,\"nearHumans\":true,\"zone\":\"cell-3\"}", false},
      {"fetch from loading bay",
       "{\"forceN\":15.0,\"speedMps\":0.5,\"zone\":\"loading-bay\"}", false},
  };

  std::printf("\nVLA pre-actuation gate:\n");
  bool gate_ok = true;
  for (const Case& c : cases) {
    const std::string result = vouch::robotics::check_action(scope, c.action);
    const bool ok = contains(result, "\"ok\":true");
    if (ok != c.want_ok) gate_ok = false;
    std::printf("  [%s] %s\n", ok ? "ALLOW" : "DENY ", c.task);
  }

  const bool all_ok = identity_ok && proof_ok && attested == 5 && cited == 5 && gate_ok;
  std::printf("\n%s\n", all_ok ? "ALL ROBOTICS VERIFY EXAMPLE CHECKS PASSED"
                               : "SOME CHECKS FAILED");
  return all_ok ? 0 : 1;
}
