// Tests for the robotics wrappers in the C++ ergonomic layer (vouch.hpp).
// Build and run:
//   g++ -std=c++17 -I../include test_robotics.cpp -o test_robotics -L../lib -lvouch_core_uniffi
//   LD_LIBRARY_PATH=../lib ./test_robotics
//
// These two checks are keyless and deterministic: they exercise the physical
// action gate and the conformance report, neither of which needs a signer.

#include <cassert>
#include <cstdio>
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

  if (failures == 0) {
    std::printf("ALL C++ ROBOTICS TESTS PASSED\n");
    return 0;
  }
  std::printf("%d FAILURE(S)\n", failures);
  return 1;
}
