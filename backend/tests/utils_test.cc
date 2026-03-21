#include "utils.h"
#include "crypto.h"

#include <iostream>
#include <string>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

}  // namespace

int main() {
  bool ok = true;

  const std::string now = now_utc();
  ok &= expect(now.size() == 20, "now_utc format length should be 20");
  ok &= expect(now[4] == '-' && now[7] == '-' && now[10] == 'T',
               "now_utc should be RFC3339-like UTC format");

  const auto epoch = parse_utc_epoch_seconds("2026-03-10T12:34:56Z");
  ok &= expect(epoch.has_value(), "parse_utc_epoch_seconds should parse valid UTC");

  const auto invalid = parse_utc_epoch_seconds("2026/03/10 12:34:56");
  ok &= expect(!invalid.has_value(), "parse_utc_epoch_seconds should reject invalid format");

  const std::string escaped = json_escape("a\"b\\c\n");
  ok &= expect(escaped == "a\\\"b\\\\c\\n", "json_escape should escape quote, slash, newline");

  const std::string from_epoch = utc_from_epoch_seconds(0);
  ok &= expect(from_epoch == "1970-01-01T00:00:00Z", "utc_from_epoch_seconds should format epoch zero");

  const std::string scrypt_hash = crypto::hash_password("Admin123");
  ok &= expect(scrypt_hash.rfind("scrypt:", 0) == 0,
               "hash_password should produce a scrypt hash");
  ok &= expect(crypto::verify_password("Admin123", scrypt_hash),
               "verify_password should validate scrypt hashes");
  ok &= expect(!crypto::password_hash_needs_rehash(scrypt_hash),
               "scrypt hashes should not require rehash");

  const std::string legacy_hash =
      crypto::hash_password_legacy_sha256("Admin123", "00112233445566778899aabbccddeeff");
  ok &= expect(crypto::verify_password("Admin123", legacy_hash),
               "verify_password should still support legacy sha256 hashes");
  ok &= expect(crypto::password_hash_needs_rehash(legacy_hash),
               "legacy sha256 hashes should require rehash");

  ok &= expect(crypto::verify_password("Admin123", "Admin123"),
               "verify_password should still support legacy plaintext migration");
  ok &= expect(crypto::password_hash_needs_rehash("Admin123"),
               "plaintext stored passwords should require rehash");

  UserAccount admin;
  admin.id = 42;
  admin.username = "admin";
  admin.role = "admin";
  admin.totpEnabled = false;
  admin.webauthnCredentialCount = 1;
  admin.bootstrapPasswordChangeRequired = true;
  admin.bootstrapMfaRequired = false;
  admin.preferredMfaMethod = "totp";
  admin.totpSecret = "TOP-SECRET";
  admin.password = "scrypt:example";

  const auto bootstrap = crow::json::load(build_bootstrap_payload(admin).dump());
  ok &= expect(bootstrap && bootstrap["required"].b(),
               "build_bootstrap_payload should mark bootstrap as required");
  ok &= expect(bootstrap && !bootstrap["totpEnabled"].b(),
               "build_bootstrap_payload should reflect TOTP state");
  ok &= expect(bootstrap && bootstrap["webauthnEnabled"].b(),
               "build_bootstrap_payload should reflect passkey state");
  ok &= expect(bootstrap &&
                   std::string(bootstrap["preferredMfaMethod"].s()) == "webauthn",
               "build_bootstrap_payload should expose effective fallback preference");

  crow::json::wvalue auth_payload;
  apply_auth_mfa_payload(auth_payload, admin);
  const auto auth_payload_json = crow::json::load(auth_payload.dump());
  ok &= expect(auth_payload_json && auth_payload_json["bootstrap"].has("required"),
               "apply_auth_mfa_payload should embed bootstrap payload");
  ok &= expect(auth_payload_json &&
                   std::string(auth_payload_json["preferredMfaMethod"].s()) ==
                       "webauthn",
               "apply_auth_mfa_payload should expose effective preference");

  const auto user_json = crow::json::load(user_to_json(admin).dump());
  ok &= expect(user_json && !user_json.has("password"),
               "user_to_json should never expose password hashes");
  ok &= expect(user_json && !user_json.has("totpSecret"),
               "user_to_json should never expose TOTP secrets");
  ok &= expect(user_json && user_json["webauthnEnabled"].b(),
               "user_to_json should expose passkey posture");

  Resource resource;
  resource.id = 7;
  resource.name = "db";
  resource.target = "db.internal";
  resource.protocol = "ssh";
  resource.port = 22;
  resource.httpPassword = "http-secret";
  resource.sshPassword = "ssh-secret";
  const auto resource_json = crow::json::load(resource_to_json(resource).dump());
  ok &= expect(resource_json && resource_json["hasCredentials"].b(),
               "resource_to_json should expose only the credential presence flag");
  ok &= expect(resource_json && !resource_json.has("httpPassword"),
               "resource_to_json should never expose HTTP credentials");
  ok &= expect(resource_json && !resource_json.has("sshPassword"),
               "resource_to_json should never expose SSH credentials");

  if (!ok) {
    return 1;
  }

  std::cout << "All backend utility tests passed." << std::endl;
  return 0;
}
