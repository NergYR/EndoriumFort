#pragma once
// ─── EndoriumFort — RDP proxy (stub / framework) ────────────────────────
// WebSocket-based RDP proxy. Requires FreeRDP (libfreerdp) at build time.
// When FreeRDP is not available, a 501 stub is registered instead.

#include "security_middleware.h"

struct AppContext;

// Registers /api/ws/rdp WebSocket route (or 501 stub when unsupported).
void register_rdp_routes(CrowApp &app, AppContext &ctx);
