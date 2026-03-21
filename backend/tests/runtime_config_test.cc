#include "runtime_config.h"

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

void set_env_value(const std::string &name, const std::string &value) {
#ifdef _WIN32
  _putenv_s(name.c_str(), value.c_str());
#else
  setenv(name.c_str(), value.c_str(), 1);
#endif
}

void unset_env_value(const std::string &name) {
#ifdef _WIN32
  _putenv_s(name.c_str(), "");
#else
  unsetenv(name.c_str());
#endif
}

struct EnvGuard {
  explicit EnvGuard(std::vector<std::string> keys) : keys_(std::move(keys)) {
    for (const auto &key : keys_) {
      const char *raw = std::getenv(key.c_str());
      if (raw) {
        saved_.push_back({key, std::string(raw), true});
      } else {
        saved_.push_back({key, std::string(), false});
      }
    }
  }

  ~EnvGuard() {
    for (const auto &entry : saved_) {
      if (entry.had_value) {
        set_env_value(entry.key, entry.value);
      } else {
        unset_env_value(entry.key);
      }
    }
  }

  struct SavedValue {
    std::string key;
    std::string value;
    bool had_value = false;
  };

  std::vector<std::string> keys_;
  std::vector<SavedValue> saved_;
};

}  // namespace

int main() {
  bool ok = true;

  EnvGuard guard({
      "ENDORIUMFORT_PORT",
      "ENDORIUMFORT_TOKEN_TTL_SECONDS",
      "ENDORIUMFORT_WEBAUTHN_CHALLENGE_TTL_SECONDS",
      "ENDORIUMFORT_WEBAUTHN_RP_ID",
      "ENDORIUMFORT_WEBAUTHN_ORIGIN",
      "ENDORIUMFORT_RELAY_ENROLL_SECRET",
      "ENDORIUMFORT_RELAY_CERT_REQUIRED",
      "ENDORIUMFORT_RELAY_CERT_TTL_SECONDS",
      "ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS",
      "ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS",
      "ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS",
  });

  unset_env_value("ENDORIUMFORT_PORT");
  ok &= expect(parse_positive_int_env("ENDORIUMFORT_PORT", 8080) == 8080,
               "parse_positive_int_env should use default when env is absent");
  set_env_value("ENDORIUMFORT_PORT", "9443");
  ok &= expect(parse_positive_int_env("ENDORIUMFORT_PORT", 8080) == 9443,
               "parse_positive_int_env should parse positive ints");
  set_env_value("ENDORIUMFORT_PORT", "-1");
  ok &= expect(parse_positive_int_env("ENDORIUMFORT_PORT", 8080) == 8080,
               "parse_positive_int_env should reject non-positive ints");

  unset_env_value("ENDORIUMFORT_RELAY_CERT_REQUIRED");
  ok &= expect(parse_bool_env("ENDORIUMFORT_RELAY_CERT_REQUIRED", true),
               "parse_bool_env should use default when env is absent");
  set_env_value("ENDORIUMFORT_RELAY_CERT_REQUIRED", "false");
  ok &= expect(!parse_bool_env("ENDORIUMFORT_RELAY_CERT_REQUIRED", true),
               "parse_bool_env should parse false values");
  set_env_value("ENDORIUMFORT_RELAY_CERT_REQUIRED", "YES");
  ok &= expect(parse_bool_env("ENDORIUMFORT_RELAY_CERT_REQUIRED", false),
               "parse_bool_env should parse yes values case-insensitively");

  set_env_value("ENDORIUMFORT_PORT", "9443");
  set_env_value("ENDORIUMFORT_TOKEN_TTL_SECONDS", "7200");
  set_env_value("ENDORIUMFORT_WEBAUTHN_CHALLENGE_TTL_SECONDS", "240");
  set_env_value("ENDORIUMFORT_WEBAUTHN_RP_ID", "bastion.example.com");
  set_env_value("ENDORIUMFORT_WEBAUTHN_ORIGIN", "https://bastion.example.com");
  set_env_value("ENDORIUMFORT_RELAY_ENROLL_SECRET", "super-secret");
  set_env_value("ENDORIUMFORT_RELAY_CERT_REQUIRED", "false");
  set_env_value("ENDORIUMFORT_RELAY_CERT_TTL_SECONDS", "100");
  set_env_value("ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS", "200");
  set_env_value("ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS", "300");
  set_env_value("ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS", "400");

  AppContext ctx;
  const RuntimeConfig loaded = load_runtime_config(ctx);
  ok &= expect(loaded.port == 9443, "load_runtime_config should read backend port");
  ok &= expect(loaded.tokenTtlSeconds == 7200,
               "load_runtime_config should read auth token TTL");
  ok &= expect(loaded.webauthnChallengeTtlSeconds == 240,
               "load_runtime_config should read WebAuthn challenge TTL");
  ok &= expect(loaded.webauthnRpIdOverride == "bastion.example.com",
               "load_runtime_config should read WebAuthn RP ID");
  ok &= expect(loaded.webauthnOriginOverride == "https://bastion.example.com",
               "load_runtime_config should read WebAuthn origin");
  ok &= expect(loaded.relayEnrollmentEnabled,
               "load_runtime_config should mark relay enrollment enabled when secret exists");
  ok &= expect(!loaded.relayCertificateRequired,
               "load_runtime_config should read relay certificate policy");
  ok &= expect(loaded.relayCertificateTtlSeconds == 100,
               "load_runtime_config should read relay certificate TTL");
  ok &= expect(loaded.relayEnrollmentTokenTtlSeconds == 200,
               "load_runtime_config should read relay enrollment token TTL");
  ok &= expect(loaded.relayTokenTtlSeconds == 300,
               "load_runtime_config should read relay auth token TTL");
  ok &= expect(loaded.relayHeartbeatStaleSeconds == 400,
               "load_runtime_config should read relay heartbeat stale threshold");

  apply_runtime_config(ctx, loaded);
  ok &= expect(ctx.token_ttl_seconds == 7200,
               "apply_runtime_config should apply token TTL");
  ok &= expect(ctx.webauthn_challenge_ttl_seconds == 240,
               "apply_runtime_config should apply WebAuthn challenge TTL");
  ok &= expect(ctx.webauthn_rp_id_override == "bastion.example.com",
               "apply_runtime_config should apply WebAuthn RP ID");
  ok &= expect(ctx.webauthn_origin_override == "https://bastion.example.com",
               "apply_runtime_config should apply WebAuthn origin");
  ok &= expect(ctx.relay_enroll_secret == "super-secret",
               "apply_runtime_config should apply relay enrollment secret");
  ok &= expect(!ctx.relay_certificate_required,
               "apply_runtime_config should apply relay certificate policy");

  RuntimeConfig invalid_webauthn = loaded;
  invalid_webauthn.webauthnRpIdOverride = "bad_domain";
  invalid_webauthn.webauthnOriginOverride = "http://bad_domain:8080";
  invalid_webauthn.relayEnrollmentEnabled = false;
  std::ostringstream captured_err;
  auto *old_buffer = std::cerr.rdbuf(captured_err.rdbuf());
  log_runtime_config(invalid_webauthn);
  std::cerr.rdbuf(old_buffer);
  const std::string logged = captured_err.str();
  ok &= expect(logged.find("relay enrollment is disabled") != std::string::npos,
               "log_runtime_config should mention disabled relay enrollment");
  ok &= expect(logged.find("not a valid WebAuthn RP ID") != std::string::npos,
               "log_runtime_config should warn on invalid RP ID");
  ok &= expect(logged.find("not a valid WebAuthn origin") != std::string::npos,
               "log_runtime_config should warn on invalid origin");
  ok &= expect(logged.find("super-secret") == std::string::npos,
               "log_runtime_config should never print relay secrets");

  if (!ok) {
    return 1;
  }

  std::cout << "All runtime config tests passed." << std::endl;
  return 0;
}
