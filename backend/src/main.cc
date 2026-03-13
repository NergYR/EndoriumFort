// ─── EndoriumFort — main entry point ────────────────────────────────────
// Slim launcher: creates the Crow app, initialises AppContext, registers
// all route groups, and starts the server.

#include "app_context.h"
#include "http_proxy.h"
#include "rdp.h"
#include "routes.h"
#include "security_middleware.h"
#include "ssh.h"
#include "tunnel.h"

#include <cstdlib>
#include <cctype>
#include <string>

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
#include <libssh2.h>
#endif
#endif

int main() {
  CrowApp app;
  AppContext ctx;

  auto parse_positive_int_env = [](const char *name,
                                   int default_value) -> int {
    const char *raw = std::getenv(name);
    if (!raw || *raw == '\0') return default_value;
    try {
      int value = std::stoi(raw);
      return value > 0 ? value : default_value;
    } catch (...) {
      return default_value;
    }
  };
  auto parse_bool_env = [](const char *name, bool default_value) -> bool {
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
  };

  // ── Initialise database and load data ──
  ctx.init_database();
  ctx.seed_default_admin();
  ctx.init_recordings_dir();

  if (const char *relay_secret = std::getenv("ENDORIUMFORT_RELAY_ENROLL_SECRET");
      relay_secret && *relay_secret != '\0') {
    ctx.relay_enroll_secret = relay_secret;
  } else {
    std::cerr
        << "[relay] ENDORIUMFORT_RELAY_ENROLL_SECRET is not set; relay enrollment is disabled"
        << '\n';
  }
  ctx.relay_certificate_required = parse_bool_env(
      "ENDORIUMFORT_RELAY_CERT_REQUIRED", ctx.relay_certificate_required);
  ctx.relay_certificate_ttl_seconds = parse_positive_int_env(
      "ENDORIUMFORT_RELAY_CERT_TTL_SECONDS",
      ctx.relay_certificate_ttl_seconds);
  ctx.relay_token_ttl_seconds = parse_positive_int_env(
      "ENDORIUMFORT_RELAY_TOKEN_TTL_SECONDS", ctx.relay_token_ttl_seconds);
  ctx.relay_enrollment_token_ttl_seconds = parse_positive_int_env(
      "ENDORIUMFORT_RELAY_ENROLL_TOKEN_TTL_SECONDS",
      ctx.relay_enrollment_token_ttl_seconds);
  ctx.relay_heartbeat_stale_seconds = parse_positive_int_env(
      "ENDORIUMFORT_RELAY_HEARTBEAT_STALE_SECONDS",
      ctx.relay_heartbeat_stale_seconds);

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  if (libssh2_init(0) != 0) {
    std::cerr << "libssh2 init failed" << '\n';
  }
#endif
#endif

  // ── Register all route groups ──
  register_health_routes(app, ctx);
  register_auth_routes(app, ctx);
  register_totp_routes(app, ctx);
  register_user_routes(app, ctx);
  register_resource_routes(app, ctx);
  register_access_request_routes(app, ctx);
  register_session_routes(app, ctx);
  register_audit_routes(app, ctx);
  register_recording_routes(app, ctx);
  register_stats_routes(app, ctx);
  register_proxy_routes(app, ctx);
  register_web_resource_routes(app, ctx);
  register_ssh_routes(app, ctx);
  register_relay_routes(app, ctx);
  register_tunnel_routes(app, ctx);
  register_rdp_routes(app, ctx);

  // ── Start server ──
  app.port(8080).multithreaded().run();

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  libssh2_exit();
#endif
#endif
  return 0;
}
