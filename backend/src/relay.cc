// ─── EndoriumFort — Relay control-plane routes ─────────────────────────

#include "routes.h"
#include "app_context.h"
#include "crypto.h"
#include "utils.h"

#include <algorithm>
#include <cctype>
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

void cleanup_relay_enrollment_tokens(AppContext &ctx, int64_t now_epoch) {
  std::lock_guard<std::mutex> lock(ctx.relay_mutex);
  for (auto it = ctx.relay_enrollment_tokens.begin();
       it != ctx.relay_enrollment_tokens.end();) {
    const bool expired = it->second.expiresAtEpoch <= now_epoch;
    if (expired || it->second.used) {
      it = ctx.relay_enrollment_tokens.erase(it);
    } else {
      ++it;
    }
  }
}

bool consume_relay_enrollment_token(AppContext &ctx, const std::string &token,
                                    int64_t now_epoch) {
  std::lock_guard<std::mutex> lock(ctx.relay_mutex);
  auto it = ctx.relay_enrollment_tokens.find(token);
  if (it == ctx.relay_enrollment_tokens.end()) return false;
  if (it->second.used || it->second.expiresAtEpoch <= now_epoch) {
    ctx.relay_enrollment_tokens.erase(it);
    return false;
  }
  it->second.used = true;
  return true;
}

void cleanup_relay_certificates(AppContext &ctx, int64_t now_epoch) {
  std::lock_guard<std::mutex> lock(ctx.relay_mutex);
  for (auto it = ctx.relay_certificates.begin();
       it != ctx.relay_certificates.end();) {
    if (it->second.revoked || it->second.expiresAtEpoch <= now_epoch) {
      it = ctx.relay_certificates.erase(it);
    } else {
      ++it;
    }
  }
}

bool is_secure_relay_transport(const crow::request &request) {
  std::string proto = trim_copy(request.get_header_value("X-Forwarded-Proto"));
  std::transform(proto.begin(), proto.end(), proto.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (proto == "https") return true;

  const std::string source = request_source_ip(request);
  return source == "127.0.0.1" || source == "::1" || source == "localhost";
}

bool validate_and_bind_relay_certificate(
    AppContext &ctx, const std::string &presented_certificate,
    const std::string &relay_id, int64_t now_epoch, bool bind_if_unbound,
    std::string *certificate_id) {
  std::lock_guard<std::mutex> lock(ctx.relay_mutex);
  for (auto it = ctx.relay_certificates.begin();
       it != ctx.relay_certificates.end();) {
    if (it->second.revoked || it->second.expiresAtEpoch <= now_epoch) {
      it = ctx.relay_certificates.erase(it);
      continue;
    }

    if (crypto::constant_time_equals(it->second.certificate,
                                     presented_certificate)) {
      if (!it->second.boundRelayId.empty() &&
          it->second.boundRelayId != relay_id) {
        return false;
      }
      if (bind_if_unbound && it->second.boundRelayId.empty()) {
        it->second.boundRelayId = relay_id;
      }
      if (certificate_id) *certificate_id = it->second.certificateId;
      return true;
    }
    ++it;
  }
  return false;
}
}

void register_relay_routes(CrowApp &app, AppContext &ctx) {
  // Admin: mint a relay certificate (presented by relay on enroll/heartbeat).
  CROW_ROUTE(app, "/api/relays/certificate").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.has_permission(auth->userId, auth->role, "resources.manage")) {
          return crow::response(403, "Forbidden");
        }

        int ttl_seconds = ctx.relay_certificate_ttl_seconds;
        auto body = crow::json::load(request.body);
        if (body && body.has("ttlSeconds")) {
          const int requested = body["ttlSeconds"].i();
          if (requested > 0) {
            ttl_seconds = std::max(3600, std::min(requested, 7776000));
          }
        }

        const int64_t now_epoch = now_epoch_seconds();
        cleanup_relay_certificates(ctx, now_epoch);

        RelayCertificate cert;
        cert.certificateId = "efrc_" + ctx.generate_token().substr(4);
        cert.certificate = "efrcert_" + ctx.generate_token().substr(4);
        cert.createdAt = now_utc();
        cert.expiresAtEpoch = now_epoch + ttl_seconds;
        cert.expiresAt = utc_from_epoch_seconds(cert.expiresAtEpoch);
        cert.createdBy = auth->user;

        {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          ctx.relay_certificates[cert.certificateId] = cert;
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "relay.certificate.issued";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = cert.createdAt;
        event.payloadJson = std::string("{\"certificateId\":\"") +
                            json_escape(cert.certificateId) +
                            "\",\"expiresAt\":\"" +
                            json_escape(cert.expiresAt) + "\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["certificateId"] = cert.certificateId;
        payload["certificate"] = cert.certificate;
        payload["expiresAt"] = cert.expiresAt;
        payload["ttlSeconds"] = ttl_seconds;
        return crow::response{payload};
      });

  // Admin: mint a short-lived one-time enrollment token for relay bootstrap.
  CROW_ROUTE(app, "/api/relays/enrollment-token").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.has_permission(auth->userId, auth->role, "resources.manage")) {
          return crow::response(403, "Forbidden");
        }
        if (ctx.relay_enroll_secret.empty()) {
          return crow::response(412,
                                "Relay enrollment secret is not configured");
        }

        int ttl_seconds = ctx.relay_enrollment_token_ttl_seconds;
        auto body = crow::json::load(request.body);
        if (body && body.has("ttlSeconds")) {
          const int requested = body["ttlSeconds"].i();
          if (requested > 0) {
            ttl_seconds = std::max(60, std::min(requested, 3600));
          }
        }

        const int64_t now_epoch = now_epoch_seconds();
        cleanup_relay_enrollment_tokens(ctx, now_epoch);

        RelayEnrollmentToken token;
        token.token = "efenr_" + ctx.generate_token();
        token.createdAt = now_utc();
        token.expiresAtEpoch = now_epoch + ttl_seconds;
        token.expiresAt = utc_from_epoch_seconds(token.expiresAtEpoch);
        token.createdBy = auth->user;

        {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          ctx.relay_enrollment_tokens[token.token] = token;
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "relay.enroll.token.issued";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = token.createdAt;
        event.payloadJson = std::string("{\"expiresAt\":\"") +
                            json_escape(token.expiresAt) + "\",\"ttlSeconds\":" +
                            std::to_string(ttl_seconds) + "}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["enrollmentToken"] = token.token;
        payload["expiresAt"] = token.expiresAt;
        payload["ttlSeconds"] = ttl_seconds;
        return crow::response{payload};
      });

  // Relay-side: enroll using relay enrollment secret.
  CROW_ROUTE(app, "/api/relays/enroll").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        if (!is_secure_relay_transport(request)) {
          return crow::response(426,
                                "Relay transport must be TLS (HTTPS)");
        }

        auto body = crow::json::load(request.body);
        if (!body || !body.has("relayId")) {
          return crow::response(400, "Missing relayId");
        }

        const std::string provided_secret =
            trim_copy(request.get_header_value("X-EndoriumFort-Relay-Secret"));
        const std::string enrollment_token = trim_copy(
            request.get_header_value("X-EndoriumFort-Relay-Enrollment-Token"));
        const int64_t now_epoch = now_epoch_seconds();
        bool enrollment_token_ok = false;
        if (!enrollment_token.empty()) {
          enrollment_token_ok = consume_relay_enrollment_token(
              ctx, enrollment_token, now_epoch);
        }

        const bool secret_ok = !ctx.relay_enroll_secret.empty() &&
                               !provided_secret.empty() &&
                               provided_secret == ctx.relay_enroll_secret;
        if (!secret_ok && !enrollment_token_ok) {
          return crow::response(401, "Relay enrollment denied");
        }

        const std::string relay_id = trim_copy(std::string(body["relayId"].s()));
        if (relay_id.empty()) {
          return crow::response(400, "Invalid relayId");
        }

        std::string certificate_id;
        if (ctx.relay_certificate_required) {
          const std::string presented_certificate = trim_copy(
              request.get_header_value("X-EndoriumFort-Relay-Certificate"));
          if (presented_certificate.empty()) {
            return crow::response(401, "Missing relay certificate");
          }
          if (!validate_and_bind_relay_certificate(
                  ctx, presented_certificate, relay_id, now_epoch, true,
                  &certificate_id)) {
            return crow::response(401, "Invalid relay certificate");
          }
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
        relay.certificateId = certificate_id;
        relay.certificateBoundAt = relay.enrolledAt;
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
          "\",\"version\":\"" + json_escape(relay.version) +
          "\",\"certificateId\":\"" + json_escape(relay.certificateId) +
          "\",\"authMethod\":\"" +
          std::string(enrollment_token_ok ? "token" : "secret") + "\"}";
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
        if (!is_secure_relay_transport(request)) {
          return crow::response(426,
                                "Relay transport must be TLS (HTTPS)");
        }

        const std::string relay_token =
            trim_copy(request.get_header_value("X-EndoriumFort-Relay-Token"));
        if (relay_token.empty()) {
          return crow::response(401, "Missing relay token");
        }

        auto relay_id = find_relay_id_by_token(ctx, relay_token);
        if (!relay_id) return crow::response(401, "Invalid relay token");

        if (ctx.relay_certificate_required) {
          const std::string presented_certificate = trim_copy(
              request.get_header_value("X-EndoriumFort-Relay-Certificate"));
          if (presented_certificate.empty()) {
            return crow::response(401, "Missing relay certificate");
          }
          std::string certificate_id;
          if (!validate_and_bind_relay_certificate(
                  ctx, presented_certificate, *relay_id, now_epoch_seconds(),
                  false, &certificate_id)) {
            return crow::response(401, "Invalid relay certificate");
          }
        }

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
            payload["items"][idx]["certificateId"] = relay.certificateId;
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
        payload["certificateRequired"] = ctx.relay_certificate_required;
        payload["certificateTtlSeconds"] = ctx.relay_certificate_ttl_seconds;
        payload["enrollmentTokenTtlSeconds"] =
            ctx.relay_enrollment_token_ttl_seconds;
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
