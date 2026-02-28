// ─── EndoriumFort — main entry point ────────────────────────────────────
// Slim launcher: creates the Crow app, initialises AppContext, registers
// all route groups, and starts the server.

#include "app_context.h"
#include "http_proxy.h"
#include "rdp.h"
#include "routes.h"
#include "ssh.h"
#include "tunnel.h"

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
#include <libssh2.h>
#endif
#endif

int main() {
  crow::SimpleApp app;
  AppContext ctx;

  // ── Initialise database and load data ──
  ctx.init_database();
  ctx.seed_default_admin();
  ctx.init_recordings_dir();

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
  register_session_routes(app, ctx);
  register_audit_routes(app, ctx);
  register_recording_routes(app, ctx);
  register_stats_routes(app, ctx);
  register_proxy_routes(app, ctx);
  register_web_resource_routes(app, ctx);
  register_ssh_routes(app, ctx);
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
