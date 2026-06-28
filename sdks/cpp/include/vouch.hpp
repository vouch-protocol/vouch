// Vouch Protocol C++ ergonomic layer (header-only).
//
// Mirrors the Agent helper in the Python and TypeScript SDKs over the C ABI in
// vouch_core.h: one object that holds an identity and signs and verifies, so
// callers do not build credential JSON or pass seeds and public keys by hand.
// The credential body is built in-language, the same way the other SDKs build
// it, and the crypto goes through the core. The wire format is unchanged.
//
//   vouch::Agent agent = vouch::Agent::create("agent.example");
//   std::string signed_cred = agent.sign("read", "did:web:files", "https://files/x");
//   bool ok = agent.verify(signed_cred);

#ifndef VOUCH_HPP
#define VOUCH_HPP

#include <algorithm>
#include <ctime>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "vouch_core.h"

namespace vouch {

class VouchError : public std::runtime_error {
 public:
  explicit VouchError(const std::string& msg) : std::runtime_error(msg) {}
};

namespace detail {

// Take ownership of a heap C string returned by the core, freeing it. On a
// NULL result the error string (if any) is turned into a VouchError.
inline std::string take(char* result, char* err) {
  if (result == nullptr) {
    std::string msg = err ? std::string(err) : std::string("unknown error");
    if (err) vouch_string_free(err);
    throw VouchError(msg);
  }
  std::string out(result);
  vouch_string_free(result);
  return out;
}

// Read a JSON string field by simple scan (controlled inputs from the core).
inline std::string json_string(const std::string& json, const std::string& key) {
  std::string pat = "\"" + key + "\"";
  size_t k = json.find(pat);
  if (k == std::string::npos) return "";
  size_t colon = json.find(':', k + pat.size());
  if (colon == std::string::npos) return "";
  size_t q1 = json.find('"', colon + 1);
  if (q1 == std::string::npos) return "";
  std::string out;
  for (size_t i = q1 + 1; i < json.size(); i++) {
    char c = json[i];
    if (c == '\\' && i + 1 < json.size()) {
      out.push_back(json[++i]);
      continue;
    }
    if (c == '"') break;
    out.push_back(c);
  }
  return out;
}

inline std::string json_escape(const std::string& v) {
  std::string out;
  out.reserve(v.size() + 2);
  for (char c : v) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default: out.push_back(c);
    }
  }
  return out;
}

inline std::string iso_now(int64_t plus_seconds = 0) {
  std::time_t t = std::time(nullptr) + plus_seconds;
  std::tm tm_utc{};
#if defined(_WIN32)
  gmtime_s(&tm_utc, &t);
#else
  gmtime_r(&t, &tm_utc);
#endif
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
  return std::string(buf);
}

inline std::string base64_encode(const std::vector<uint8_t>& in) {
  static const char* tbl =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  size_t i = 0;
  for (; i + 2 < in.size(); i += 3) {
    uint32_t n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
    out.push_back(tbl[(n >> 18) & 63]);
    out.push_back(tbl[(n >> 12) & 63]);
    out.push_back(tbl[(n >> 6) & 63]);
    out.push_back(tbl[n & 63]);
  }
  if (i < in.size()) {
    uint32_t n = in[i] << 16;
    bool two = (i + 1 < in.size());
    if (two) n |= in[i + 1] << 8;
    out.push_back(tbl[(n >> 18) & 63]);
    out.push_back(tbl[(n >> 12) & 63]);
    out.push_back(two ? tbl[(n >> 6) & 63] : '=');
    out.push_back('=');
  }
  return out;
}

// base58btc decode (Bitcoin alphabet) into bytes.
inline std::vector<uint8_t> base58_decode(const std::string& s) {
  static const char* alpha =
      "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  std::vector<uint8_t> bytes;
  for (char c : s) {
    const char* pos = std::strchr(alpha, c);
    if (pos == nullptr || c == '\0') {
      throw VouchError(std::string("invalid base58 character: ") + c);
    }
    int carry = static_cast<int>(pos - alpha);
    for (size_t j = 0; j < bytes.size(); j++) {
      carry += bytes[j] * 58;
      bytes[j] = static_cast<uint8_t>(carry & 0xff);
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push_back(static_cast<uint8_t>(carry & 0xff));
      carry >>= 8;
    }
  }
  for (size_t k = 0; k < s.size() && s[k] == '1'; k++) bytes.push_back(0);
  std::reverse(bytes.begin(), bytes.end());
  return bytes;
}

// Resolve the Ed25519 public key (base64) embedded in a did:key, or "" if the
// issuer is not an Ed25519 did:key.
inline std::string public_b64_for_did_key(const std::string& issuer) {
  const std::string prefix = "did:key:";
  if (issuer.rfind(prefix, 0) != 0) return "";
  std::string mk = issuer.substr(prefix.size());
  if (mk.empty() || mk[0] != 'z') return "";
  try {
    std::vector<uint8_t> decoded = base58_decode(mk.substr(1));
    if (decoded.size() != 34 || decoded[0] != 0xed || decoded[1] != 0x01) return "";
    return base64_encode(std::vector<uint8_t>(decoded.begin() + 2, decoded.end()));
  } catch (const VouchError&) {
    return "";
  }
}

}  // namespace detail

// Build the unsigned Vouch Credential body. The shape matches the Rust core and
// the Python/TypeScript/Go SDKs; only crypto goes through the core.
inline std::string build_credential(const std::string& issuer_did,
                                    const std::string& action,
                                    const std::string& target,
                                    const std::string& resource,
                                    const std::string& valid_from,
                                    const std::string& valid_until,
                                    const std::string& credential_id) {
  if (action.empty() || target.empty() || resource.empty()) {
    throw VouchError("intent.action, intent.target and intent.resource are required");
  }
  using detail::json_escape;
  std::string j = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\",";
  j += "\"https://vouch-protocol.com/contexts/v1\"],";
  j += "\"id\":\"" + json_escape(credential_id) + "\",";
  j += "\"type\":[\"VerifiableCredential\",\"VouchCredential\"],";
  j += "\"issuer\":\"" + json_escape(issuer_did) + "\",";
  j += "\"validFrom\":\"" + json_escape(valid_from) + "\",";
  j += "\"validUntil\":\"" + json_escape(valid_until) + "\",";
  j += "\"credentialSubject\":{\"id\":\"" + json_escape(issuer_did) + "\",";
  j += "\"vouchVersion\":\"1.0\",\"intent\":{";
  j += "\"action\":\"" + json_escape(action) + "\",";
  j += "\"target\":\"" + json_escape(target) + "\",";
  j += "\"resource\":\"" + json_escape(resource) + "\"}}}";
  return j;
}

// A read-friendly view over a credential JSON.
class Credential {
 public:
  explicit Credential(std::string json) : json_(std::move(json)) {
    if (json_.empty()) throw VouchError("credential JSON is empty");
  }
  std::string action() const { return detail::json_string(intent_scope(), "action"); }
  std::string target() const { return detail::json_string(intent_scope(), "target"); }
  std::string resource() const { return detail::json_string(intent_scope(), "resource"); }
  std::string issuer() const { return detail::json_string(json_, "issuer"); }
  const std::string& to_json() const { return json_; }

 private:
  std::string intent_scope() const {
    size_t i = json_.find("\"intent\"");
    return i == std::string::npos ? json_ : json_.substr(i);
  }
  std::string json_;
};

// An identity bundled with its signer.
class Agent {
 public:
  static Agent create(const std::string& domain = "", int64_t default_expiry_seconds = 300) {
    char* err = nullptr;
    std::string kp = detail::take(vouch_generate_ed25519(&err), err);
    std::string seed = detail::json_string(kp, "seed_b64");
    std::string pub = detail::json_string(kp, "public_b64");
    std::string did = domain.empty() ? detail::json_string(kp, "did_key")
                                     : ("did:web:" + domain);
    return Agent(did, seed, pub, default_expiry_seconds);
  }

  static Agent load(const std::string& did, const std::string& seed_b64,
                    const std::string& public_b64) {
    return Agent(did, seed_b64, public_b64, 300);
  }

  const std::string& did() const { return did_; }
  const std::string& public_key_b64() const { return public_b64_; }

  std::string sign(const std::string& action, const std::string& target,
                   const std::string& resource) const {
    return sign(action, target, resource, default_expiry_);
  }

  std::string sign(const std::string& action, const std::string& target,
                   const std::string& resource, int64_t valid_seconds) const {
    std::string valid_from = detail::iso_now();
    std::string valid_until = detail::iso_now(valid_seconds);
    std::string credential_id = "urn:uuid:" + new_uuid();
    std::string unsigned_cred =
        build_credential(did_, action, target, resource, valid_from, valid_until, credential_id);
    std::string vm = did_ + "#key-1";
    char* err = nullptr;
    return detail::take(
        vouch_sign_credential(unsigned_cred.c_str(), seed_b64_.c_str(), vm.c_str(),
                              valid_from.c_str(), &err),
        err);
  }

  // Verify a credential: own key if self-issued, else resolve a did:key issuer.
  bool verify(const std::string& credential_json) const {
    std::string issuer = detail::json_string(credential_json, "issuer");
    std::string pub = (issuer == did_) ? public_b64_ : detail::public_b64_for_did_key(issuer);
    if (pub.empty()) return false;
    return verify_with(credential_json, pub);
  }

  static bool verify_with(const std::string& credential_json, const std::string& public_b64) {
    char* err = nullptr;
    std::string result = detail::take(
        vouch_verify_credential(credential_json.c_str(), public_b64.c_str(),
                                detail::iso_now().c_str(), 30, &err),
        err);
    return result.find("\"valid\":true") != std::string::npos;
  }

 private:
  Agent(std::string did, std::string seed_b64, std::string public_b64, int64_t default_expiry)
      : did_(std::move(did)),
        seed_b64_(std::move(seed_b64)),
        public_b64_(std::move(public_b64)),
        default_expiry_(default_expiry) {}

  static std::string new_uuid() {
    // A unique-enough credential id; the core does not require RFC 4122.
    char* err = nullptr;
    std::string kp = detail::take(vouch_generate_ed25519(&err), err);
    std::string mk = detail::json_string(kp, "multikey");
    return mk.substr(0, 32);
  }

  std::string did_;
  std::string seed_b64_;
  std::string public_b64_;
  int64_t default_expiry_;
};

}  // namespace vouch

#endif  // VOUCH_HPP
