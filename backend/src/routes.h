#pragma once
// ─── EndoriumFort — API route registration ──────────────────────────────
// Each function registers a group of CROW_ROUTE entries.

#include "crow.h"

struct AppContext;

void register_health_routes(crow::SimpleApp &app, AppContext &ctx);
void register_auth_routes(crow::SimpleApp &app, AppContext &ctx);
void register_totp_routes(crow::SimpleApp &app, AppContext &ctx);
void register_user_routes(crow::SimpleApp &app, AppContext &ctx);
void register_resource_routes(crow::SimpleApp &app, AppContext &ctx);
void register_session_routes(crow::SimpleApp &app, AppContext &ctx);
void register_audit_routes(crow::SimpleApp &app, AppContext &ctx);
void register_recording_routes(crow::SimpleApp &app, AppContext &ctx);
void register_stats_routes(crow::SimpleApp &app, AppContext &ctx);
