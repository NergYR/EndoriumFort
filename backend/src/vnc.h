#pragma once
// ─── EndoriumFort — VNC WebSocket proxy ─────────────────────────────────
// Browser-facing VNC path using a raw WebSocket bridge to the target VNC TCP
// endpoint.

#include "security_middleware.h"

struct AppContext;

void register_vnc_routes(CrowApp &app, AppContext &ctx);
