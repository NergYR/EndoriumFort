#pragma once
// ─── EndoriumFort — API route registration ──────────────────────────────
// Each function registers a group of CROW_ROUTE entries.

#include "security_middleware.h"

struct AppContext;

void register_health_routes(CrowApp &app, AppContext &ctx);
void register_auth_routes(CrowApp &app, AppContext &ctx);
void register_totp_routes(CrowApp &app, AppContext &ctx);
void register_user_routes(CrowApp &app, AppContext &ctx);
void register_resource_routes(CrowApp &app, AppContext &ctx);
void register_session_routes(CrowApp &app, AppContext &ctx);
void register_audit_routes(CrowApp &app, AppContext &ctx);
void register_recording_routes(CrowApp &app, AppContext &ctx);
void register_stats_routes(CrowApp &app, AppContext &ctx);
