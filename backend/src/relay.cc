// ─── EndoriumFort — Relay control-plane routes ─────────────────────────

#include "routes.h"
#include "app_context.h"
#include "utils.h"

#include <algorithm>
#include <sstream>

namespace {
std::string trim_copy(std::string value) {
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.front()))) {
    value.erase(value.begin());
  }
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.back()))) {
    value.pop_back();
  }
  return value;
}

std::string request_source_ip(const crow::request &request) {
  std::string forwarded = request.get_header_value("X-Forwarded-For");
  if (!forwarded.empty()) {
    size_t comma = forwarded.find(',');
    if (comma != std::string::npos) forwarded = forwarded.substr(0, comma);
    forwarded = trim_copy(forwarded);
    if (!forwarded.empty()) return forwarded;
  }
  std::string real_ip = trim_copy(request.get_header_value("X-Real-IP"));
  if (!real_ip.empty()) return real_ip;
  return trim_copy(request.remote_ip_address);
}

bool can_read_resource_scope(AppContext &ctx, const AuthSession &auth,
                             int resource_id) {
  if (ctx.has_permission(auth.userId, auth.role, "resources.manage") ||
      ctx.has_permission(auth.userId, auth.role, "resources.read")) {
    return true;
  }
  auto allowed = ctx.get_resource_permissions(auth.userId);
  return std::find(allowed.begin(), allowed.end(), resource_id) != allowed.end();
}

std::string join_capabilities(const crow::json::rvalue &value) {
  if (!value || value.t() != crow::json::type::List) return "";
  std::ostringstream oss;
  bool first = true;
  for (const auto &entry : value) {
    std::string cap = trim_copy(std::string(entry.s()));
    if (cap.empty()) continue;
    if (!first) oss << ',';
    oss << cap;
    first = false;
  }
  return oss.str();
}

bool is_relay_online(const RelayNode &relay, int stale_seconds) {
  auto last = parse_utc_epoch_seconds(relay.lastSeenAt);
  if (!last) return false;
  return (now_epoch_seconds() - *last) <= stale_seconds;
}

std::optional<std::string> find_relay_id_by_token(AppContext &ctx,
                                                   const std::string &token) {
  std::lock_guard<std::mutex> lock(ctx.relay_mutex);
  for (const auto &entry : ctx.relays) {
    if (entry.second.token == token) return entry.first;
  }
  return std::nullopt;
}
}

void register_relay_routes(CrowApp &app, AppContext &ctx) {
  // Relay-side: enroll using relay enrollment secret.
  CROW_ROUTE(app, "/api/relays/enroll").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto body = crow::json::load(request.body);
        if (!body || !body.has("relayId")) {
          return crow::response(400, "Missing relayId");
        }

        const std::string provided_secret =
            trim_copy(request.get_header_value("X-EndoriumFort-Relay-Secret"));
        if (ctx.relay_enroll_secret.empty() || provided_secret.empty() ||
            provided_secret != ctx.relay_enroll_secret) {
          return crow::response(401, "Relay enrollment denied");
        }

        const std::string relay_id = trim_copy(std::string(body["relayId"].s()));
        if (relay_id.empty()) {
          return crow::response(400, "Invalid relayId");
        }

        RelayNode relay;
        relay.relayId = relay_id;
        relay.label = body.has("label") ? trim_copy(std::string(body["label"].s())) : relay_id;
        relay.version = body.has("version") ? trim_copy(std::string(body["version"].s())) : "";
        relay.capabilitiesCsv = body.has("capabilities")
                                    ? join_capabilities(body["capabilities"])
                                    : "";
        relay.sourceIp = request_source_ip(request);
        relay.status = "online";
        relay.enrolledAt = now_utc();
        relay.lastSeenAt = relay.enrolledAt;
        relay.token = "efr_" + ctx.generate_token();
        relay.tokenExpiresAt =
            utc_from_epoch_seconds(now_epoch_seconds() + ctx.relay_token_ttl_seconds);

        {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          ctx.relays[relay_id] = relay;
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "relay.enroll.success";
        event.actor = relay.relayId;
        event.role = "relay";
        event.createdAt = now_utc();
        event.payloadJson =
            std::string("{\"relayId\":\"") + json_escape(relay.relayId) +
            "\",\"sourceIp\":\"" + json_escape(relay.sourceIp) +
            "\",\"version\":\"" + json_escape(relay.version) + "\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["relayId"] = relay.relayId;
        payload["label"] = relay.label;
        payload["token"] = relay.token;
        payload["tokenExpiresAt"] = relay.tokenExpiresAt;
        payload["status"] = relay.status;
        payload["message"] = "Relay enrolled";
        return crow::response{payload};
      });

  // Relay-side: heartbeat to keep online state fresh.
  CROW_ROUTE(app, "/api/relays/heartbeat").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        const std::string relay_token =
            trim_copy(request.get_header_value("X-EndoriumFort-Relay-Token"));
        if (relay_token.empty()) {
          return crow::response(401, "Missing relay token");
        }

        auto relay_id = find_relay_id_by_token(ctx, relay_token);
        if (!relay_id) return crow::response(401, "Invalid relay token");

        auto body = crow::json::load(request.body);
        const int managed = (body && body.has("managedResourceCount"))
                                ? body["managedResourceCount"].i()
                                : 0;

        RelayNode snapshot;
        {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          auto it = ctx.relays.find(*relay_id);
          if (it == ctx.relays.end()) return crow::response(404, "Relay not found");
          it->second.status = "online";
          it->second.lastSeenAt = now_utc();
          it->second.sourceIp = request_source_ip(request);
          it->second.managedResourceCount = std::max(0, managed);
          snapshot = it->second;
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["relayId"] = snapshot.relayId;
        payload["lastSeenAt"] = snapshot.lastSeenAt;
        return crow::response{payload};
      });

  // Admin: list relay inventory and health.
  CROW_ROUTE(app, "/api/relays").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.has_permission(auth->userId, auth->role, "resources.manage")) {
          return crow::response(403, "Forbidden");
        }

        crow::json::wvalue payload;
        payload["items"] = crow::json::wvalue::list();
        int idx = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          for (const auto &entry : ctx.relays) {
            RelayNode relay = entry.second;
            relay.status = is_relay_online(relay, ctx.relay_heartbeat_stale_seconds)
                               ? "online"
                               : "offline";
            payload["items"][idx]["relayId"] = relay.relayId;
            payload["items"][idx]["label"] = relay.label;
            payload["items"][idx]["version"] = relay.version;
            payload["items"][idx]["sourceIp"] = relay.sourceIp;
            payload["items"][idx]["status"] = relay.status;
            payload["items"][idx]["enrolledAt"] = relay.enrolledAt;
            payload["items"][idx]["lastSeenAt"] = relay.lastSeenAt;
            payload["items"][idx]["capabilities"] = relay.capabilitiesCsv;
            payload["items"][idx]["managedResourceCount"] = relay.managedResourceCount;
            idx++;
          }
        }
        return crow::response{payload};
      });

  // Admin: inspect relay control-plane runtime config (secret is never exposed).
  CROW_ROUTE(app, "/api/relays/config").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.has_permission(auth->userId, auth->role, "resources.manage")) {
          return crow::response(403, "Forbidden");
        }

        crow::json::wvalue payload;
        payload["enrollmentEnabled"] = !ctx.relay_enroll_secret.empty();
        payload["tokenTtlSeconds"] = ctx.relay_token_ttl_seconds;
        payload["heartbeatStaleSeconds"] = ctx.relay_heartbeat_stale_seconds;
        return crow::response{payload};
      });

  // Admin: assign/clear a relay for one resource.
  CROW_ROUTE(app, "/api/relays/assign").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.has_permission(auth->userId, auth->role, "resources.manage")) {
          return crow::response(403, "Forbidden");
        }

        auto body = crow::json::load(request.body);
        if (!body || !body.has("resourceId")) {
          return crow::response(400, "Missing resourceId");
        }

        const int resource_id = body["resourceId"].i();
        if (resource_id <= 0) return crow::response(400, "Invalid resourceId");

        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          if (ctx.resources.find(resource_id) == ctx.resources.end()) {
            return crow::response(404, "Resource not found");
          }
        }

        std::string relay_id;
        if (body.has("relayId")) {
          relay_id = trim_copy(std::string(body["relayId"].s()));
          if (relay_id.empty()) return crow::response(400, "Invalid relayId");
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          if (ctx.relays.find(relay_id) == ctx.relays.end()) {
            return crow::response(404, "Relay not found");
          }
          ctx.resource_relay_bindings[resource_id] = relay_id;
        } else {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          ctx.resource_relay_bindings.erase(resource_id);
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "relay.assignment.updated";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson =
            std::string("{\"resourceId\":") + std::to_string(resource_id) +
            ",\"relayId\":\"" + json_escape(relay_id) + "\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["resourceId"] = resource_id;
        payload["relayId"] = relay_id;
        return crow::response{payload};
      });

  // User/API: resolve whether to route direct or through relay.
  CROW_ROUTE(app, "/api/relays/resolve/<int>").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request, int resource_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (resource_id <= 0) return crow::response(400, "Invalid resourceId");

        Resource resource;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          auto it = ctx.resources.find(resource_id);
          if (it == ctx.resources.end()) return crow::response(404, "Resource not found");
          resource = it->second;
        }

        if (!can_read_resource_scope(ctx, *auth, resource_id)) {
          return crow::response(403, "Forbidden");
        }

        std::string relay_id;
        RelayNode relay;
        bool relay_found = false;
        {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          auto binding = ctx.resource_relay_bindings.find(resource_id);
          if (binding != ctx.resource_relay_bindings.end()) {
            relay_id = binding->second;
            auto it = ctx.relays.find(relay_id);
            if (it != ctx.relays.end()) {
              relay = it->second;
              relay_found = true;
            }
          }
        }

        crow::json::wvalue payload;
        payload["resourceId"] = resource_id;
        payload["resourceTarget"] = resource.target;
        payload["resourceProtocol"] = resource.protocol;
        payload["resourcePort"] = resource.port;

        if (!relay_found) {
          payload["route"] = "direct";
          payload["relayAssigned"] = false;
          return crow::response{payload};
        }

        const bool online = is_relay_online(relay, ctx.relay_heartbeat_stale_seconds);
        payload["route"] = online ? "relay" : "direct";
        payload["relayAssigned"] = true;
        payload["relay"]["relayId"] = relay.relayId;
        payload["relay"]["label"] = relay.label;
        payload["relay"]["status"] = online ? "online" : "offline";
        payload["relay"]["lastSeenAt"] = relay.lastSeenAt;
        payload["relay"]["sourceIp"] = relay.sourceIp;
        payload["relay"]["capabilities"] = relay.capabilitiesCsv;
        return crow::response{payload};
      });
}
