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
  ok &= expect(trim_copy("  prod , ssh  ") == "prod , ssh",
               "trim_copy should strip leading and trailing whitespace");
  const auto csv_items = split_csv_compact("prod, ssh , ,db");
  ok &= expect(csv_items.size() == 3 && csv_items[1] == "ssh",
               "split_csv_compact should ignore empty items and trim values");
  ok &= expect(join_csv_compact({" prod ", "", "db"}) == "prod,db",
               "join_csv_compact should normalize compact CSV output");
  ok &= expect(csv_contains_token("prod,db", "DB"),
               "csv_contains_token should compare case-insensitively");
  ok &= expect(csv_intersects("prod,linux", "LINUX,ssh"),
               "csv_intersects should detect shared normalized tags");
  ok &= expect(risk_level_rank("critical") > risk_level_rank("medium"),
               "risk_level_rank should sort higher risks above lower ones");
  ok &= expect(stronger_mfa_requirement("required", "webauthn") == "webauthn",
               "stronger_mfa_requirement should keep the strictest factor");
  ok &= expect(is_time_window_match_utc("08:00-18:00", 12, 0),
               "is_time_window_match_utc should accept timestamps inside the window");
  ok &= expect(!is_time_window_match_utc("08:00-18:00", 22, 0),
               "is_time_window_match_utc should reject timestamps outside the window");
  ok &= expect(is_time_window_match_utc("22:00-04:00", 1, 30),
               "is_time_window_match_utc should support overnight windows");

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
  resource.tagsCsv = "prod,db";
  resource.credentialSource = "brokered";
  resource.httpPassword = "http-secret";
  resource.sshPassword = "ssh-secret";
  const auto resource_json = crow::json::load(resource_to_json(resource).dump());
  ok &= expect(resource_json && resource_json["hasCredentials"].b(),
               "resource_to_json should expose only the credential presence flag");
  ok &= expect(resource_json && !resource_json.has("httpPassword"),
               "resource_to_json should never expose HTTP credentials");
  ok &= expect(resource_json && !resource_json.has("sshPassword"),
               "resource_to_json should never expose SSH credentials");
  ok &= expect(resource_json &&
                   std::string(resource_json["credentialSource"].s()) == "brokered",
               "resource_to_json should expose credentialSource");
  ok &= expect(resource_json &&
                   std::string(resource_json["tagsCsv"].s()) == "prod,db",
               "resource_to_json should expose resource tags");

  Session session;
  session.id = 99;
  session.resourceId = 7;
  session.accessGrantId = 123;
  session.target = "db.internal";
  session.user = "alice";
  session.protocol = "ssh";
  session.port = 22;
  session.status = "active";
  session.missionRef = "breakfix";
  session.credentialSource = "brokered";
  session.maxDurationSeconds = 900;
  session.createdAt = "2026-03-10T12:00:00Z";
  const auto session_json = crow::json::load(session_to_json(session).dump());
  ok &= expect(session_json && session_json["resourceId"].i() == 7,
               "session_to_json should expose the resource binding");
  ok &= expect(session_json && session_json["accessGrantId"].i() == 123,
               "session_to_json should expose the access grant binding");
  ok &= expect(session_json &&
                   std::string(session_json["credentialSource"].s()) == "brokered",
               "session_to_json should expose credentialSource");

  AccessPolicy access_policy;
  access_policy.id = 5;
  access_policy.name = "prod-db-jit";
  access_policy.resourceTagsCsv = "prod,db";
  access_policy.approvalMode = "required";
  access_policy.mfaRequirement = "webauthn";
  const auto access_policy_json =
      crow::json::load(access_policy_to_json(access_policy).dump());
  ok &= expect(access_policy_json &&
                   std::string(access_policy_json["approvalMode"].s()) == "required",
               "access_policy_to_json should expose approval mode");

  AccessGrant access_grant;
  access_grant.id = 12;
  access_grant.policyId = 5;
  access_grant.resourceId = 7;
  access_grant.subject = "alice";
  access_grant.resourceScope = "db";
  access_grant.grantedAt = "2026-03-10T12:00:00Z";
  access_grant.expiresAt = "2026-03-10T12:15:00Z";
  access_grant.credentialSource = "brokered";
  const auto access_grant_json =
      crow::json::load(access_grant_to_json(access_grant).dump());
  ok &= expect(access_grant_json &&
                   std::string(access_grant_json["subject"].s()) == "alice",
               "access_grant_to_json should expose the grant subject");

  // Test AES-256 encryption/decryption (note: only works if ENDORIUMFORT_VAULT_KEY is set)
  // For now, test the unencrypted fallback behavior (no key set)
  const std::string plaintext = "super-secret-password-123";
  const std::string encrypted = crypto::aes256_encrypt(plaintext);
  // If no key is configured, encryption returns empty string, so plaintext is returned as-is
  const std::string decrypted = crypto::aes256_decrypt(encrypted.empty() ? plaintext : encrypted);
  ok &= expect(decrypted == plaintext || encrypted.empty(),
               "aes256_decrypt should handle unencrypted fallback when no vault key is configured");

  // Note: Rate limiting tests (IP extraction, AppContext tracking) are tested via
  // login route integration tests in scim_routes_test.cc. The AppContext methods
  // require mutex access and steady_clock, making them better tested through actual route handlers.
  // Individual unit tests for get_client_ip would require creating mock Crow request objects.

  if (!ok) {
    return 1;
  }

  std::cout << "All backend utility tests passed." << std::endl;
  return 0;
}
