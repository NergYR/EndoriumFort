// ─── EndoriumFort — RDP proxy implementation ────────────────────────────
// Currently a framework / stub.  When ENDORIUMFORT_RDP_ENABLED is defined
// (i.e. FreeRDP was found by CMake), the full RDP proxy will be compiled.
// Without FreeRDP it registers a 501 "not-supported" endpoint.

#include "rdp.h"
#include "app_context.h"
#include "utils.h"

#include <iostream>

#ifdef ENDORIUMFORT_RDP_ENABLED
// ═════════════════════════════════════════════════════════════════════
//  Full RDP proxy (requires libfreerdp)
// ═════════════════════════════════════════════════════════════════════

// TODO — Future implementation:
// 1. Accept WebSocket connection at /api/ws/rdp?token=...&sessionId=...
// 2. Authenticate the token and look up the session.
// 3. Open a FreeRDP connection to the target RDP server.
// 4. Stream bitmap updates to the browser as binary WebSocket frames
//    (raw RGBA or compressed PNG tiles).
// 5. Receive mouse/keyboard events from the browser as JSON messages
//    and forward them to the RDP server via FreeRDP input API.
//
// Message protocol (browser → backend):
//   {"type":"mouse","x":100,"y":200,"button":1,"pressed":true}
//   {"type":"key","code":65,"pressed":true}
//   {"type":"resize","width":1920,"height":1080}
//
// Message protocol (backend → browser):
//   binary frame = [u16 x][u16 y][u16 w][u16 h][raw RGBA pixels]
//   or JSON:  {"type":"status","message":"connected"}

void register_rdp_routes(crow::SimpleApp &app, AppContext &ctx) {
  CROW_WEBSOCKET_ROUTE(app, "/api/ws/rdp")
      .onaccept([&ctx](const crow::request &request, void **) {
        std::string token;
        const char *p = request.url_params.get("token");
        if (p) token = p;
        if (token.empty()) return false;
        auto auth = ctx.find_auth_by_token(token);
        if (!auth) return false;
        return is_allowed_role(auth->role, {"operator", "admin"});
      })
      .onopen([](crow::websocket::connection &conn) {
        conn.send_text(
            "{\"type\":\"error\",\"message\":\"RDP proxy: not yet "
            "implemented (FreeRDP stub)\"}");
        conn.close("not-implemented");
      })
      .onclose([](crow::websocket::connection &, const std::string &) {})
      .onmessage([](crow::websocket::connection &, const std::string &, bool) {});
}

#else
// ═════════════════════════════════════════════════════════════════════
//  Stub – FreeRDP not found
// ═════════════════════════════════════════════════════════════════════

void register_rdp_routes(crow::SimpleApp &app, AppContext &ctx) {
  (void)ctx;
  CROW_ROUTE(app, "/api/ws/rdp")([] {
    crow::json::wvalue payload;
    payload["status"] = "error";
    payload["message"] =
        "RDP proxy is disabled (FreeRDP not found at build time). "
        "Install libfreerdp-dev and rebuild to enable RDP support.";
    auto resp = crow::response{501, payload};
    return resp;
  });
}

#endif
