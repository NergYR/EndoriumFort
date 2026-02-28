#pragma once
// ─── EndoriumFort — WebSocket TCP tunnel for agent ──────────────────────
// Implements /ws/tunnel route: agent connects via WebSocket, backend opens
// a TCP connection to the target resource and relays data bidirectionally.

#include "crow.h"

struct AppContext;

void register_tunnel_routes(crow::SimpleApp &app, AppContext &ctx);
