#pragma once

#include "app_context.h"
#include "webauthn.h"

#include <cctype>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>

struct RuntimeConfig {
  int port = 8080;
  int tokenTtlSeconds = 3600;
  int webauthnChallengeTtlSeconds = 180;
  std::string webauthnRpIdOverride;
  std::string webauthnOriginOverride;
  bool relayEnrollmentEnabled = false;
  bool relayCertificateRequired = true;
  int relayCertificateTtlSeconds = 2592000;
  int relayEnrollmentTokenTtlSeconds = 600;
  int relayTokenTtlSeconds = 86400;
  int relayHeartbeatStaleSeconds = 90;
};

inline int parse_positive_int_env(const char *name, int default_value) {
  const char *raw = std::getenv(name);
  if (!raw || *raw == '\0') return default_value;
  try {
    const int value = std::stoi(raw);
    return value > 0 ? value : default_value;
  } catch (...) {
    return default_value;
  }
}

inline bool parse_bool_env(const char *name, bool default_value) {
  const char *raw = std::getenv(name);
  if (!raw || *raw == '\0') return default_value;
  std::string value = raw;
  for (char &ch : value) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  if (value == "1" || value == "true" || value == "yes" || value == "on") {
    return true;
  }
  if (value == "0" || value == "false" || value == "no" || value == "off") {
    return false;
  }
  return default_value;
}

inline std::string parse_string_env(const char *name) {
  const char *raw = std::getenv(name);
  return (raw && *raw != '\0') ? std::string(raw) : std::string();
}

inline RuntimeConfig load_runtime_config(const AppContext &ctx) {
  RuntimeConfig config;
  config.port = parse_positive_int_env("ENDORIUMFORT_PORT", config.port);
  config.tokenTtlSeconds =
      parse_positive_int_env("ENDORIUMFORT_TOKEN_TTL_SECONDS", ctx.token_ttl_seconds);
  config.webauthnChallengeTtlSeconds = parse_positive_int_env(
      "ENDORIUMFORT_WEBAUTHN_CHALLENGE_TTL_SECONDS",
      ctx.webauthn_challenge_ttl_seconds);
  config.webauthnRpIdOverride = parse_string_env("ENDORIUMFORT_WEBAUTHN_RP_ID");
  config.webauthnOriginOverride = parse_string_env("ENDORIUMFORT_WEBAUTHN_ORIGIN");
  config.relayCertificateRequired = parse_bool_env(
      "ENDORIUMFORT_RELAY_CERT_REQUIRED", ctx.relay_certificate_required);
  config.relayCertificateTtlSeconds = parse_positive_int_env(
      "ENDORIUMFORT_RELAY_CERT_TTL_SECONDS", ctx.relay_certificate_ttl_seconds);
  config.relayTokenTtlSeconds = parse_positive_int_env(
      "ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS", ctx.relay_token_ttl_seconds);
  config.relayEnrollmentTokenTtlSeconds = parse_positive_int_env(
      "ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS",
      ctx.relay_enrollment_token_ttl_seconds);
  config.relayHeartbeatStaleSeconds = parse_positive_int_env(
      "ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS",
      ctx.relay_heartbeat_stale_seconds);
  const std::string relay_secret = parse_string_env("ENDORIUMFORT_RELAY_ENROLL_SECRET");
  config.relayEnrollmentEnabled = !relay_secret.empty();
  return config;
}

inline void apply_runtime_config(AppContext &ctx, const RuntimeConfig &config) {
  ctx.listen_port = config.port;
  ctx.token_ttl_seconds = config.tokenTtlSeconds;
  ctx.webauthn_challenge_ttl_seconds = config.webauthnChallengeTtlSeconds;
  ctx.webauthn_rp_id_override = config.webauthnRpIdOverride;
  ctx.webauthn_origin_override = config.webauthnOriginOverride;
  ctx.relay_certificate_required = config.relayCertificateRequired;
  ctx.relay_certificate_ttl_seconds = config.relayCertificateTtlSeconds;
  ctx.relay_token_ttl_seconds = config.relayTokenTtlSeconds;
  ctx.relay_enrollment_token_ttl_seconds = config.relayEnrollmentTokenTtlSeconds;
  ctx.relay_heartbeat_stale_seconds = config.relayHeartbeatStaleSeconds;

  const std::string relay_secret = parse_string_env("ENDORIUMFORT_RELAY_ENROLL_SECRET");
  if (!relay_secret.empty()) {
    ctx.relay_enroll_secret = relay_secret;
  }
}

inline void log_runtime_config(const RuntimeConfig &config) {
  std::ostringstream summary;
  summary << "[config] port=" << config.port
          << " token_ttl_seconds=" << config.tokenTtlSeconds
          << " webauthn_challenge_ttl_seconds=" << config.webauthnChallengeTtlSeconds
          << " relay_enrollment=" << (config.relayEnrollmentEnabled ? "enabled" : "disabled")
          << " relay_cert_required=" << (config.relayCertificateRequired ? "true" : "false")
          << " relay_cert_ttl_seconds=" << config.relayCertificateTtlSeconds
          << " relay_token_ttl_seconds=" << config.relayTokenTtlSeconds
          << " relay_enroll_token_ttl_seconds=" << config.relayEnrollmentTokenTtlSeconds
          << " relay_heartbeat_stale_seconds=" << config.relayHeartbeatStaleSeconds;
  if (!config.webauthnRpIdOverride.empty()) {
    summary << " webauthn_rp_id=" << config.webauthnRpIdOverride;
  }
  if (!config.webauthnOriginOverride.empty()) {
    summary << " webauthn_origin=" << config.webauthnOriginOverride;
  }
  std::cerr << summary.str() << '\n';

  if (!config.relayEnrollmentEnabled) {
    std::cerr
        << "[relay] ENDORIUMFORT_RELAY_ENROLL_SECRET is not set; relay enrollment is disabled"
        << '\n';
  }
  if (!config.webauthnRpIdOverride.empty() &&
      !webauthn::is_valid_rp_id(config.webauthnRpIdOverride)) {
    std::cerr << "[config] Warning: ENDORIUMFORT_WEBAUTHN_RP_ID is not a valid WebAuthn RP ID"
              << '\n';
  }
  if (!config.webauthnOriginOverride.empty() &&
      !webauthn::is_valid_origin(config.webauthnOriginOverride)) {
    std::cerr << "[config] Warning: ENDORIUMFORT_WEBAUTHN_ORIGIN is not a valid WebAuthn origin"
              << '\n';
  }
}
