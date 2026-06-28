// Tests for the C++ ergonomic layer (vouch.hpp). Build and run:
//   g++ -std=c++17 -I../include test_agent.cpp -o test_agent -L../lib -lvouch_core_uniffi
//   LD_LIBRARY_PATH=../lib ./test_agent

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
  // did:web mint, sign, self-verify, and read back the intent.
  {
    vouch::Agent agent = vouch::Agent::create("agent.example");
    check(agent.did() == "did:web:agent.example", "did:web identity");
    std::string signed_cred = agent.sign("read", "did:web:files", "https://files/x");
    check(agent.verify(signed_cred), "self verify");
    vouch::Credential c(signed_cred);
    check(c.action() == "read", "credential action");
    check(c.target() == "did:web:files", "credential target");
    check(c.resource() == "https://files/x", "credential resource");
    check(c.issuer() == "did:web:agent.example", "credential issuer");
  }

  // did:key when no domain, and offline verification.
  {
    vouch::Agent agent = vouch::Agent::create();
    check(agent.did().rfind("did:key:", 0) == 0, "did:key identity");
    std::string signed_cred = agent.sign("write", "t", "r");
    check(agent.verify(signed_cred), "did:key self verify");
  }

  // did:key resolution across issuers.
  {
    vouch::Agent a = vouch::Agent::create();
    vouch::Agent b = vouch::Agent::create();
    std::string signed_by_b = b.sign("read", "t", "https://x/y");
    check(a.verify(signed_by_b), "did:key cross-issuer resolution");
  }

  // Wrong key fails.
  {
    vouch::Agent a = vouch::Agent::create("a.example");
    vouch::Agent b = vouch::Agent::create("b.example");
    std::string signed_cred = a.sign("read", "t", "https://x/y");
    check(!vouch::Agent::verify_with(signed_cred, b.public_key_b64()), "wrong key rejected");
  }

  // Missing intent field throws.
  {
    bool threw = false;
    try {
      vouch::build_credential("did:web:a", "", "t", "https://x/y",
                              "2026-01-01T00:00:00Z", "2026-01-01T00:05:00Z", "urn:uuid:1");
    } catch (const vouch::VouchError&) {
      threw = true;
    }
    check(threw, "missing intent field throws");
  }

  if (failures == 0) {
    std::printf("ALL C++ AGENT TESTS PASSED\n");
    return 0;
  }
  std::printf("%d FAILURE(S)\n", failures);
  return 1;
}
