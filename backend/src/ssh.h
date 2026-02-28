#pragma once
// ─── EndoriumFort — SSH proxy (libssh2) ─────────────────────────────────
// TCP socket helpers, SSH connect/disconnect, and the /api/ws/ssh route.

#include "security_middleware.h"
#include "models.h"

#include <string>

struct AppContext;

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32

int open_tcp_socket(const std::string &host, int port, std::string &error);

bool ssh_connect(SshConnection &connection, const Session &session,
                 const std::string &password, int cols, int rows,
                 std::string &error);

void ssh_disconnect(SshConnection &connection);

#endif
#endif

// Registers /api/ws/ssh WebSocket route (or 501 stub on unsupported platforms).
void register_ssh_routes(CrowApp &app, AppContext &ctx);
