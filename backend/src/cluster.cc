#include "cluster.h"

#include "app_context.h"
#include "utils.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string cluster_trim_copy(std::string value) {
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

std::string normalize_cluster_role_value(std::string role) {
  role = cluster_trim_copy(std::move(role));
  std::transform(role.begin(), role.end(), role.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (role == "leader" || role == "follower" || role == "standalone") {
    return role;
  }
  return "standalone";
}

std::string request_source_ip(const crow::request &request) {
  std::string forwarded = request.get_header_value("X-Forwarded-For");
  if (!forwarded.empty()) {
    size_t comma = forwarded.find(',');
    if (comma != std::string::npos) forwarded = forwarded.substr(0, comma);
    forwarded = cluster_trim_copy(forwarded);
    if (!forwarded.empty()) return forwarded;
  }
  std::string real_ip = cluster_trim_copy(request.get_header_value("X-Real-IP"));
  if (!real_ip.empty()) return real_ip;
  return cluster_trim_copy(request.remote_ip_address);
}

bool has_cluster_read_access(AppContext &ctx, const AuthSession &auth) {
  return ctx.has_permission(auth.userId, auth.role, "resources.manage") ||
         ctx.has_permission(auth.userId, auth.role, "cluster.read");
}

bool has_cluster_manage_access(AppContext &ctx, const AuthSession &auth) {
  return ctx.has_permission(auth.userId, auth.role, "resources.manage") ||
         ctx.has_permission(auth.userId, auth.role, "cluster.manage");
}

std::string local_cluster_endpoint(const AppContext &ctx) {
  if (!ctx.cluster_advertise_addr.empty()) {
    return ctx.cluster_advertise_addr;
  }
  return std::string("127.0.0.1:") + std::to_string(ctx.listen_port);
}

bool is_cluster_node_online(const ClusterPeerNode &peer, int stale_seconds) {
  auto last_seen = parse_utc_epoch_seconds(peer.lastSeenAt);
  if (!last_seen) return false;
  return (now_epoch_seconds() - *last_seen) <= stale_seconds;
}

}  // namespace

void register_cluster_routes(CrowApp &app, AppContext &ctx) {
  CROW_ROUTE(app, "/api/cluster/status").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_cluster_read_access(ctx, *auth)) {
          return crow::response(403, "Forbidden");
        }

        const std::string local_now = now_utc();
        const std::string local_node_id =
            !ctx.cluster_node_id.empty() ? ctx.cluster_node_id : "node-local";
        const std::string local_node_label =
            !ctx.cluster_node_label.empty() ? ctx.cluster_node_label : local_node_id;
        const std::string local_role =
            normalize_cluster_role_value(ctx.cluster_role);

        int active_sessions = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.session_mutex);
          for (const auto &entry : ctx.sessions) {
            if (entry.second.status == "active") {
              ++active_sessions;
            }
          }
        }

        int relay_total = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          relay_total = static_cast<int>(ctx.relays.size());
        }

        std::vector<ClusterPeerNode> peers;
        {
          std::lock_guard<std::mutex> lock(ctx.cluster_mutex);
          peers.reserve(ctx.cluster_peers.size());
          for (const auto &entry : ctx.cluster_peers) {
            ClusterPeerNode peer = entry.second;
            peer.status = is_cluster_node_online(peer,
                                                 ctx.cluster_heartbeat_stale_seconds)
                              ? "online"
                              : "offline";
            peers.push_back(peer);
          }
        }

        std::sort(peers.begin(), peers.end(),
                  [](const ClusterPeerNode &lhs, const ClusterPeerNode &rhs) {
                    return lhs.nodeId < rhs.nodeId;
                  });

        int online_peer_count = 0;
        for (const auto &peer : peers) {
          if (peer.status == "online") {
            ++online_peer_count;
          }
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["enabled"] = ctx.cluster_enabled;
        payload["mode"] = ctx.cluster_enabled ? "ha" : "standalone";
        payload["heartbeatStaleSeconds"] = ctx.cluster_heartbeat_stale_seconds;

        payload["localNode"]["nodeId"] = local_node_id;
        payload["localNode"]["label"] = local_node_label;
        payload["localNode"]["role"] = local_role;
        payload["localNode"]["status"] = "online";
        payload["localNode"]["endpoint"] = local_cluster_endpoint(ctx);
        payload["localNode"]["lastSeenAt"] = local_now;
        payload["localNode"]["managedRelays"] = relay_total;
        payload["localNode"]["managedSessions"] = active_sessions;

        payload["summary"]["nodesTotal"] = 1 + static_cast<int>(peers.size());
        payload["summary"]["nodesOnline"] = 1 + online_peer_count;
        payload["summary"]["nodesOffline"] =
            static_cast<int>(peers.size()) - online_peer_count;
        payload["summary"]["managedRelays"] = relay_total;
        payload["summary"]["activeSessions"] = active_sessions;

        payload["peers"] = crow::json::wvalue::list();
        for (int i = 0; i < static_cast<int>(peers.size()); ++i) {
          payload["peers"][i]["nodeId"] = peers[i].nodeId;
          payload["peers"][i]["label"] = peers[i].label;
          payload["peers"][i]["endpoint"] = peers[i].endpoint;
          payload["peers"][i]["version"] = peers[i].version;
          payload["peers"][i]["role"] = peers[i].role;
          payload["peers"][i]["status"] = peers[i].status;
          payload["peers"][i]["sourceIp"] = peers[i].sourceIp;
          payload["peers"][i]["lastSeenAt"] = peers[i].lastSeenAt;
          payload["peers"][i]["managedRelays"] = peers[i].managedRelays;
          payload["peers"][i]["managedSessions"] = peers[i].managedSessions;
        }
        return crow::response{payload};
      });

  CROW_ROUTE(app, "/api/cluster/config").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_cluster_manage_access(ctx, *auth)) {
          return crow::response(403, "Forbidden");
        }

        int peer_count = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.cluster_mutex);
          peer_count = static_cast<int>(ctx.cluster_peers.size());
        }

        const std::string local_node_id =
            !ctx.cluster_node_id.empty() ? ctx.cluster_node_id : "node-local";
        const std::string local_node_label =
            !ctx.cluster_node_label.empty() ? ctx.cluster_node_label : local_node_id;

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["enabled"] = ctx.cluster_enabled;
        payload["nodeId"] = local_node_id;
        payload["nodeLabel"] = local_node_label;
        payload["role"] = normalize_cluster_role_value(ctx.cluster_role);
        payload["advertiseAddr"] = local_cluster_endpoint(ctx);
        payload["heartbeatStaleSeconds"] = ctx.cluster_heartbeat_stale_seconds;
        payload["peerAuthRequired"] = !ctx.cluster_shared_secret.empty();
        payload["heartbeatPath"] = "/api/cluster/heartbeat";
        payload["statusPath"] = "/api/cluster/status";
        payload["peerCount"] = peer_count;
        return crow::response{payload};
      });

  CROW_ROUTE(app, "/api/cluster/heartbeat").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        if (!ctx.cluster_enabled) {
          return crow::response(412, "Cluster mode is disabled");
        }
        if (ctx.cluster_shared_secret.empty()) {
          return crow::response(
              412,
              "Cluster shared secret is not configured");
        }

        const std::string secret =
            cluster_trim_copy(request.get_header_value(
                "X-EndoriumFort-Cluster-Secret"));
        if (secret.empty() || secret != ctx.cluster_shared_secret) {
          return crow::response(401, "Invalid cluster secret");
        }

        auto body = crow::json::load(request.body);
        if (!body || !body.has("nodeId")) {
          return crow::response(400, "Missing nodeId");
        }

        const std::string node_id =
            cluster_trim_copy(std::string(body["nodeId"].s()));
        if (node_id.empty()) {
          return crow::response(400, "Invalid nodeId");
        }

        const std::string local_node_id =
            !ctx.cluster_node_id.empty() ? ctx.cluster_node_id : "node-local";
        if (node_id == local_node_id) {
          return crow::response(409, "nodeId conflicts with local node");
        }

        ClusterPeerNode peer;
        peer.nodeId = node_id;
        peer.label = body.has("label")
                         ? cluster_trim_copy(std::string(body["label"].s()))
                         : node_id;
        if (peer.label.empty()) peer.label = node_id;
        peer.endpoint = body.has("endpoint")
                            ? cluster_trim_copy(std::string(body["endpoint"].s()))
                            : "";
        peer.version = body.has("version")
                           ? cluster_trim_copy(std::string(body["version"].s()))
                           : "";
        peer.role = body.has("role")
                        ? normalize_cluster_role_value(
                              std::string(body["role"].s()))
                        : "follower";
          peer.managedRelays = body.has("managedRelays")
                   ? static_cast<int>(
                     std::max<int64_t>(0, body["managedRelays"].i()))
                   : 0;
          peer.managedSessions = body.has("managedSessions")
                     ? static_cast<int>(std::max<int64_t>(
                       0, body["managedSessions"].i()))
                     : 0;
        peer.sourceIp = request_source_ip(request);
        peer.status = "online";
        peer.lastSeenAt = now_utc();
        if (peer.endpoint.empty()) {
          peer.endpoint = peer.sourceIp;
        }

        {
          std::lock_guard<std::mutex> lock(ctx.cluster_mutex);
          ctx.cluster_peers[node_id] = peer;
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "cluster.peer.heartbeat";
        event.actor = node_id;
        event.role = "cluster";
        event.createdAt = now_utc();
        event.payloadJson = std::string("{\"nodeId\":\"") +
                            json_escape(peer.nodeId) +
                            "\",\"endpoint\":\"" +
                            json_escape(peer.endpoint) +
                            "\",\"role\":\"" +
                            json_escape(peer.role) +
                            "\",\"sourceIp\":\"" +
                            json_escape(peer.sourceIp) + "\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["nodeId"] = peer.nodeId;
        payload["role"] = peer.role;
        payload["lastSeenAt"] = peer.lastSeenAt;
        return crow::response{payload};
      });

  CROW_ROUTE(app, "/api/cluster/peers/<string>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, std::string node_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_cluster_manage_access(ctx, *auth)) {
              return crow::response(403, "Forbidden");
            }

            node_id = cluster_trim_copy(std::move(node_id));
            if (node_id.empty()) {
              return crow::response(400, "Invalid nodeId");
            }

            bool removed = false;
            {
              std::lock_guard<std::mutex> lock(ctx.cluster_mutex);
              removed = ctx.cluster_peers.erase(node_id) > 0;
            }
            if (!removed) {
              return crow::response(404, "Cluster peer not found");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "cluster.peer.removed";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = std::string("{\"nodeId\":\"") +
                                json_escape(node_id) + "\"}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["nodeId"] = node_id;
            payload["removed"] = true;
            return crow::response{payload};
          });
}
