// ─── EndoriumFort — WebSocket TCP tunnel implementation ─────────────────

#include "tunnel.h"
#include "app_context.h"
#include "crypto.h"
#include "utils.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <thread>

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

std::string request_user_agent(const crow::request &request) {
  std::string user_agent = trim_copy(request.get_header_value("User-Agent"));
  if (user_agent.size() > 200) {
    user_agent = user_agent.substr(0, 200);
  }
  return user_agent;
}

bool check_tunnel_ticket_issue_limit(AppContext &ctx, int user_id) {
  const auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(ctx.tunnel_ticket_issue_limit_mutex);
  auto &entry = ctx.tunnel_ticket_issue_by_user[user_id];

  while (!entry.attempts.empty() &&
         (now - entry.attempts.front()) > ctx.tunnel_ticket_issue_window) {
    entry.attempts.pop();
  }

  if (static_cast<int>(entry.attempts.size()) >=
      ctx.tunnel_ticket_issue_max_attempts) {
    return false;
  }

  entry.attempts.push(now);
  return true;
}

void cleanup_expired_tunnel_tickets(AppContext &ctx) {
  const int64_t now_epoch = now_epoch_seconds();
  std::lock_guard<std::mutex> lock(ctx.tunnel_ticket_mutex);
  for (auto it = ctx.tunnel_tickets.begin(); it != ctx.tunnel_tickets.end();) {
    auto expires_epoch = parse_utc_epoch_seconds(it->second.expiresAt);
    if (!expires_epoch || *expires_epoch <= now_epoch) {
      it = ctx.tunnel_tickets.erase(it);
    } else {
      ++it;
    }
  }
}

bool register_tunnel_nonce_once(AppContext &ctx, const std::string &ticket,
                                const std::string &nonce,
                                int64_t now_epoch_seconds) {
  if (ticket.empty() || nonce.empty()) return false;
  const std::string key = ticket + "|" + nonce;
  std::lock_guard<std::mutex> lock(ctx.tunnel_nonce_mutex);

  const int64_t nonce_ttl =
      std::max<int64_t>(1, static_cast<int64_t>(ctx.tunnel_nonce_ttl_seconds));
  for (auto it = ctx.tunnel_seen_nonces.begin();
       it != ctx.tunnel_seen_nonces.end();) {
    if ((now_epoch_seconds - it->second) > nonce_ttl) {
      it = ctx.tunnel_seen_nonces.erase(it);
    } else {
      ++it;
    }
  }

  if (ctx.tunnel_seen_nonces.find(key) != ctx.tunnel_seen_nonces.end()) {
    return false;
  }

  ctx.tunnel_seen_nonces[key] = now_epoch_seconds;
  return true;
}

std::string refresh_tunnel_signing_key_id(AppContext &ctx,
                                          int64_t now_epoch_seconds) {
  std::lock_guard<std::mutex> lock(ctx.tunnel_signing_key_mutex);
  const int64_t rotation =
      std::max<int64_t>(30, static_cast<int64_t>(ctx.tunnel_signing_key_rotation_seconds));

  if (ctx.tunnel_signing_key_current_id.empty()) {
    ctx.tunnel_signing_key_current_id =
        "k" + std::to_string(now_epoch_seconds / rotation);
    ctx.tunnel_signing_key_current_secret = ctx.generate_token();
    ctx.tunnel_signing_key_current_epoch = now_epoch_seconds;
    return ctx.tunnel_signing_key_current_id;
  }

  if ((now_epoch_seconds - ctx.tunnel_signing_key_current_epoch) >= rotation) {
    ctx.tunnel_signing_key_previous_id = ctx.tunnel_signing_key_current_id;
    ctx.tunnel_signing_key_previous_secret =
        ctx.tunnel_signing_key_current_secret;
    ctx.tunnel_signing_key_previous_epoch = ctx.tunnel_signing_key_current_epoch;
    ctx.tunnel_signing_key_current_id =
        "k" + std::to_string(now_epoch_seconds / rotation);
    ctx.tunnel_signing_key_current_secret = ctx.generate_token();
    ctx.tunnel_signing_key_current_epoch = now_epoch_seconds;
  }

  return ctx.tunnel_signing_key_current_id;
}

bool is_allowed_tunnel_signing_key_id(AppContext &ctx,
                                      const std::string &key_id,
                                      int64_t now_epoch_seconds) {
  if (key_id.empty()) return false;
  std::lock_guard<std::mutex> lock(ctx.tunnel_signing_key_mutex);
  if (key_id == ctx.tunnel_signing_key_current_id) return true;
  if (key_id == ctx.tunnel_signing_key_previous_id) {
    const int64_t grace =
        std::max<int64_t>(1, static_cast<int64_t>(ctx.tunnel_signing_key_grace_seconds));
    return (now_epoch_seconds - ctx.tunnel_signing_key_previous_epoch) <= grace;
  }
  return false;
}

std::optional<std::string> tunnel_signing_secret_for_key_id(
    AppContext &ctx, const std::string &key_id, int64_t now_epoch_seconds) {
  if (key_id.empty()) return std::nullopt;
  std::lock_guard<std::mutex> lock(ctx.tunnel_signing_key_mutex);

  if (key_id == ctx.tunnel_signing_key_current_id &&
      !ctx.tunnel_signing_key_current_secret.empty()) {
    return ctx.tunnel_signing_key_current_secret;
  }

  if (key_id == ctx.tunnel_signing_key_previous_id &&
      !ctx.tunnel_signing_key_previous_secret.empty()) {
    const int64_t grace =
        std::max<int64_t>(1, static_cast<int64_t>(ctx.tunnel_signing_key_grace_seconds));
    if ((now_epoch_seconds - ctx.tunnel_signing_key_previous_epoch) <= grace) {
      return ctx.tunnel_signing_key_previous_secret;
    }
  }

  return std::nullopt;
}

std::string build_tunnel_server_attestation(const std::string &secret,
                                            const TunnelTicket &ticket) {
  const std::string payload =
      std::string("ws_tunnel_attestation_v1|") + ticket.ticket + "|" +
      ticket.challenge + "|" + ticket.signingKeyId + "|" +
      std::to_string(ticket.resourceId) + "|" + ticket.issuedAt + "|" +
      ticket.expiresAt;
  return crypto::hmac_sha256_hex(secret, payload);
}

std::optional<TunnelTicket> consume_tunnel_ticket(
    AppContext &ctx, const std::string &ticket, const std::string &proof,
    int resource_id, const std::string &source_ip,
    const std::string &user_agent, const std::string &signature,
    const std::string &timestamp_text, const std::string &nonce,
  const std::string &challenge, const std::string &signing_key_id,
  const std::string &server_attestation) {
  if (ticket.empty() || proof.empty() || resource_id <= 0) return std::nullopt;

  int64_t timestamp = 0;
  try {
    timestamp = std::stoll(timestamp_text);
  } catch (...) {
    return std::nullopt;
  }

  if (challenge.empty() || challenge.size() > 200 || nonce.empty() ||
      nonce.size() > 128 || signature.empty() ||
      signature.size() != 64) {
    return std::nullopt;
  }

  const int64_t now_epoch = now_epoch_seconds();
  if (std::llabs(now_epoch - timestamp) > ctx.tunnel_signature_max_skew_seconds) {
    return std::nullopt;
  }
  if (!is_allowed_tunnel_signing_key_id(ctx, signing_key_id, now_epoch)) {
    return std::nullopt;
  }
  if (!register_tunnel_nonce_once(ctx, ticket, nonce, now_epoch)) {
    return std::nullopt;
  }
  auto signing_secret =
      tunnel_signing_secret_for_key_id(ctx, signing_key_id, now_epoch);
  if (!signing_secret) {
    return std::nullopt;
  }

  std::lock_guard<std::mutex> lock(ctx.tunnel_ticket_mutex);

  auto it = ctx.tunnel_tickets.find(ticket);
  if (it == ctx.tunnel_tickets.end()) return std::nullopt;

  auto expires_epoch = parse_utc_epoch_seconds(it->second.expiresAt);
    std::string expected_attestation =
      build_tunnel_server_attestation(*signing_secret, it->second);
    std::string signature_payload =
      std::string("ws_tunnel_v1|") + it->second.ticket + "|" +
      std::to_string(resource_id) + "|" + it->second.issuedForIp + "|" +
      it->second.issuedForUserAgent + "|" + it->second.challenge + "|" +
      it->second.signingKeyId + "|" + it->second.serverAttestation + "|" +
      timestamp_text + "|" + nonce;
    std::string expected_signature =
      crypto::hmac_sha256_hex(it->second.proof, signature_payload);

    if (!expires_epoch || *expires_epoch <= now_epoch ||
      !crypto::constant_time_equals(it->second.proof, proof) ||
      !crypto::constant_time_equals(it->second.challenge, challenge) ||
      !crypto::constant_time_equals(it->second.signingKeyId, signing_key_id) ||
      !crypto::constant_time_equals(it->second.serverAttestation,
                                    server_attestation) ||
      !crypto::constant_time_equals(expected_attestation,
                                    server_attestation) ||
      !crypto::constant_time_equals(expected_signature, signature) ||
      it->second.resourceId != resource_id ||
      (!it->second.issuedForIp.empty() &&
       it->second.issuedForIp != source_ip) ||
      (!it->second.issuedForUserAgent.empty() &&
       it->second.issuedForUserAgent != user_agent)) {
    ctx.tunnel_tickets.erase(it);
    return std::nullopt;
  }

  TunnelTicket consumed = it->second;
  ctx.tunnel_tickets.erase(it);  // one-time use to prevent replay
  return consumed;
}
}

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

void register_tunnel_routes(CrowApp &app, AppContext &ctx) {
  CROW_ROUTE(app, "/api/tunnel/ticket").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.has_permission(auth->userId, auth->role, "tunnel.connect")) {
          return crow::response(403, "Forbidden");
        }
        if (!check_tunnel_ticket_issue_limit(ctx, auth->userId)) {
          AuditEvent event;
          event.id = ctx.next_audit_id.fetch_add(1);
          event.type = "security.tunnel.ticket.rate_limited";
          event.actor = auth->user;
          event.role = auth->role;
          event.createdAt = now_utc();
          event.payloadJson =
              "{\"userId\":" + std::to_string(auth->userId) + "}";
          event.payloadIsJson = true;
          ctx.append_audit(event);
          return crow::response(429, "Tunnel ticket rate limit exceeded");
        }

        auto body = crow::json::load(request.body);
        if (!body || !body.has("resourceId")) {
          return crow::response(400, "Missing resourceId");
        }

        const int resource_id = body["resourceId"].i();
        if (resource_id <= 0) {
          return crow::response(400, "Invalid resourceId");
        }

        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          if (ctx.resources.find(resource_id) == ctx.resources.end()) {
            return crow::response(404, "Resource not found");
          }
        }

        std::vector<int> allowed_ids;
        if (ctx.has_permission(auth->userId, auth->role, "resources.manage")) {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          for (const auto &r : ctx.resources) allowed_ids.push_back(r.first);
        } else {
          allowed_ids = ctx.get_resource_permissions(auth->userId);
        }

        bool has_perm = false;
        for (int id : allowed_ids) {
          if (id == resource_id) {
            has_perm = true;
            break;
          }
        }
        if (!has_perm) return crow::response(403, "Forbidden");

        cleanup_expired_tunnel_tickets(ctx);
        const int64_t now_epoch = now_epoch_seconds();
        const std::string signing_key_id =
          refresh_tunnel_signing_key_id(ctx, now_epoch);
        const std::string source_ip = request_source_ip(request);
        const std::string source_user_agent = request_user_agent(request);

        TunnelTicket ticket;
        ticket.ticket = "eftt_" + ctx.generate_token();
        ticket.proof = "efp_" + ctx.generate_token();
        ticket.challenge = "efc_" + ctx.generate_token();
        ticket.signingKeyId = signing_key_id;
        ticket.userId = auth->userId;
        ticket.user = auth->user;
        ticket.role = auth->role;
        ticket.resourceId = resource_id;
        ticket.issuedForIp = source_ip;
        ticket.issuedForUserAgent = source_user_agent;
        ticket.issuedAt = now_utc();
        ticket.expiresAt =
          utc_from_epoch_seconds(now_epoch + ctx.tunnel_ticket_ttl_seconds);
        auto signing_secret =
            tunnel_signing_secret_for_key_id(ctx, signing_key_id, now_epoch);
        if (!signing_secret) {
          return crow::response(500, "Signing key unavailable");
        }
        ticket.serverAttestation =
            build_tunnel_server_attestation(*signing_secret, ticket);

        {
          std::lock_guard<std::mutex> lock(ctx.tunnel_ticket_mutex);
          ctx.tunnel_tickets[ticket.ticket] = ticket;
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "security.tunnel.ticket.issued";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson =
            "{\"resourceId\":" + std::to_string(resource_id) +
            ",\"sourceIp\":\"" + json_escape(source_ip) + "\"" +
            ",\"sourceUserAgent\":\"" + json_escape(source_user_agent) +
            "\"" +
            ",\"expiresAt\":\"" + json_escape(ticket.expiresAt) +
            "\",\"ttlSeconds\":" + std::to_string(ctx.tunnel_ticket_ttl_seconds) +
            "}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["ticket"] = ticket.ticket;
        payload["proof"] = ticket.proof;
        payload["challenge"] = ticket.challenge;
        payload["signingKeyId"] = ticket.signingKeyId;
        payload["serverAttestation"] = ticket.serverAttestation;
        payload["resourceId"] = ticket.resourceId;
        payload["sourceIp"] = ticket.issuedForIp;
        payload["sourceUserAgent"] = ticket.issuedForUserAgent;
        payload["expiresAt"] = ticket.expiresAt;
        payload["ttlSeconds"] = ctx.tunnel_ticket_ttl_seconds;
        return crow::response{payload};
      });

  CROW_WEBSOCKET_ROUTE(app, "/ws/tunnel")
      .onaccept([&ctx](const crow::request &req, void **userdata) -> bool {
        try {
          CROW_LOG_INFO << "Tunnel: onaccept called, raw_url=" << req.raw_url;

          // Get resource_id
          const char *res_param = req.url_params.get("resource_id");
          if (!res_param) {
            CROW_LOG_WARNING << "Tunnel: rejected - no resource_id";
            return false;
          }
          int resource_id = 0;
          try {
            resource_id = std::stoi(res_param);
          } catch (...) {
            CROW_LOG_WARNING << "Tunnel: rejected - invalid resource_id";
            return false;
          }
          CROW_LOG_INFO << "Tunnel: resource_id=" << resource_id;
          const std::string source_ip = request_source_ip(req);
          const std::string source_user_agent = request_user_agent(req);

          // Authenticate with one-time tunnel ticket
          const char *ticket_param = req.url_params.get("ticket");
          const std::string proof =
              trim_copy(req.get_header_value("X-EndoriumFort-Tunnel-Proof"));
            const std::string signature = trim_copy(
              req.get_header_value("X-EndoriumFort-Tunnel-Signature"));
            const std::string signature_timestamp = trim_copy(
              req.get_header_value("X-EndoriumFort-Tunnel-Timestamp"));
            const std::string signature_nonce = trim_copy(
              req.get_header_value("X-EndoriumFort-Tunnel-Nonce"));
              const std::string challenge = trim_copy(
                req.get_header_value("X-EndoriumFort-Tunnel-Challenge"));
                const std::string signing_key_id = trim_copy(
                  req.get_header_value("X-EndoriumFort-Tunnel-Key-Id"));
                  const std::string server_attestation = trim_copy(
                    req.get_header_value("X-EndoriumFort-Tunnel-Attestation"));
          const std::string ticket = ticket_param ? ticket_param : "";
          auto consumed = consume_tunnel_ticket(ctx, ticket, proof, resource_id,
                               source_ip, source_user_agent,
                               signature, signature_timestamp,
                                   signature_nonce, challenge,
                                     signing_key_id,
                                     server_attestation);
          if (!consumed) {
            CROW_LOG_WARNING << "Tunnel: rejected - invalid/expired tunnel ticket";
            AuditEvent reject_event;
            reject_event.id = ctx.next_audit_id.fetch_add(1);
            reject_event.type = "security.tunnel.ticket.rejected";
            reject_event.actor = "unknown";
            reject_event.role = "";
            reject_event.createdAt = now_utc();
            reject_event.payloadJson =
                "{\"resourceId\":" + std::to_string(resource_id) +
                ",\"sourceIp\":\"" + json_escape(source_ip) +
              "\",\"sourceUserAgent\":\"" +
              json_escape(source_user_agent) +
                "\"}";
            reject_event.payloadIsJson = true;
            ctx.append_audit(reject_event);
            return false;
          }
          CROW_LOG_INFO << "Tunnel: auth ticket OK user=" << consumed->user
                        << " role=" << consumed->role;

          // Look up resource
          Resource target_resource;
          {
            std::lock_guard<std::mutex> lock(ctx.resource_mutex);
            auto it = ctx.resources.find(resource_id);
            if (it == ctx.resources.end()) {
              CROW_LOG_WARNING << "Tunnel: rejected - resource not found: "
                               << resource_id;
              return false;
            }
            target_resource = it->second;
          }
          CROW_LOG_INFO << "Tunnel: resource found target="
                        << target_resource.target
                        << " port=" << target_resource.port;

          // Check permission
          std::vector<int> allowed_ids;
          if (ctx.has_permission(consumed->userId, consumed->role,
                                 "resources.manage")) {
            std::lock_guard<std::mutex> lock(ctx.resource_mutex);
            for (const auto &r : ctx.resources)
              allowed_ids.push_back(r.first);
          } else {
            allowed_ids = ctx.get_resource_permissions(consumed->userId);
          }
          bool has_perm = false;
          for (int id : allowed_ids) {
            if (id == resource_id) {
              has_perm = true;
              break;
            }
          }
          if (!has_perm) {
            CROW_LOG_WARNING << "Tunnel: rejected - no permission for resource "
                             << resource_id;
            return false;
          }
          CROW_LOG_INFO << "Tunnel: permission OK";

          // Create tunnel state
          auto state = std::make_shared<TunnelState>();
          state->resource_id = resource_id;
          state->user = consumed->user;
          state->token = "";

          // Parse target host/port
          std::string target_host = target_resource.target;
          int target_port = target_resource.port;
          size_t port_sep = target_host.rfind(':');
          if (port_sep != std::string::npos &&
              target_host.find(']') == std::string::npos) {
            std::string port_text = target_host.substr(port_sep + 1);
            if (!port_text.empty() &&
                std::all_of(port_text.begin(), port_text.end(),
                            [](unsigned char ch) {
                              return std::isdigit(ch);
                            })) {
              target_port = std::stoi(port_text);
              target_host = target_host.substr(0, port_sep);
            }
          }
          CROW_LOG_INFO << "Tunnel: connecting TCP to " << target_host << ":"
                        << target_port;

          // Connect upstream — using thread-safe getaddrinfo
          int sock = ::socket(AF_INET, SOCK_STREAM, 0);
          if (sock < 0) {
            CROW_LOG_ERROR << "Tunnel: failed to create socket errno=" << errno;
            return false;
          }

          struct timeval send_tv;
          send_tv.tv_sec = 30;
          send_tv.tv_usec = 0;
          setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &send_tv, sizeof(send_tv));
          struct timeval recv_tv;
          recv_tv.tv_sec = 60;
          recv_tv.tv_usec = 0;
          setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));

          struct addrinfo hints{}, *result = nullptr;
          hints.ai_family = AF_INET;
          hints.ai_socktype = SOCK_STREAM;
          std::string port_str = std::to_string(target_port);
          int gai_err = getaddrinfo(target_host.c_str(), port_str.c_str(), &hints, &result);
          if (gai_err != 0 || !result) {
            CROW_LOG_ERROR << "Tunnel: failed to resolve " << target_host;
            ::close(sock);
            if (result) freeaddrinfo(result);
            return false;
          }
          CROW_LOG_INFO << "Tunnel: resolved " << target_host;

          int conn_err = ::connect(sock, result->ai_addr, result->ai_addrlen);
          freeaddrinfo(result);
          if (conn_err < 0) {
            CROW_LOG_ERROR << "Tunnel: failed to connect to " << target_host
                           << ":" << target_port << " errno=" << errno;
            ::close(sock);
            return false;
          }
          CROW_LOG_INFO << "Tunnel: TCP connected to " << target_host << ":"
                        << target_port;

          state->upstream_sock = sock;
          state->active = true;

          auto *raw_state = new std::shared_ptr<TunnelState>(state);
          *userdata = raw_state;

          CROW_LOG_INFO << "Tunnel: accepted for user=" << consumed->user
                        << " resource=" << resource_id
                        << " target=" << target_host << ":" << target_port;

          // Audit
          AuditEvent event;
          event.id = ctx.next_audit_id.fetch_add(1);
          event.type = "tunnel.open";
          event.actor = consumed->user;
          event.role = consumed->role;
          event.createdAt = now_utc();
          event.payloadJson =
              "{\"resourceId\":" + std::to_string(resource_id) +
              ",\"target\":\"" + json_escape(target_host) + ":" +
              std::to_string(target_port) +
              "\",\"authMode\":\"ticket+proof\",\"sourceIp\":\"" +
              json_escape(source_ip) + "\"}";
          event.payloadIsJson = true;
          ctx.append_audit(event);

          return true;
        } catch (const std::exception &ex) {
          CROW_LOG_ERROR << "Tunnel: onaccept exception: " << ex.what();
          return false;
        } catch (...) {
          CROW_LOG_ERROR << "Tunnel: onaccept unknown exception";
          return false;
        }
      })
      .onopen([&ctx](crow::websocket::connection &conn) {
        auto *raw_state =
            static_cast<std::shared_ptr<TunnelState> *>(conn.userdata());
        if (!raw_state) {
          conn.close("Internal error");
          return;
        }
        auto state = *raw_state;
        delete raw_state;
        conn.userdata(nullptr);

        {
          std::lock_guard<std::mutex> lock(ctx.tunnel_mutex);
          ctx.tunnel_connections[&conn] = state;
        }

        // Reader thread: upstream → WebSocket
        state->reader_thread = std::thread([state, &conn]() {
          char buffer[16384];
          while (state->active) {
            ssize_t n = recv(state->upstream_sock, buffer, sizeof(buffer), 0);
            if (n < 0) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
              break;
            }
            if (n == 0) break;
            try {
              conn.send_binary(std::string(buffer, n));
            } catch (...) {
              break;
            }
          }
          state->active = false;
          try {
            conn.close("upstream closed");
          } catch (...) {
          }
        });
      })
      .onmessage([&ctx](crow::websocket::connection &conn,
                         const std::string &data, bool) {
        std::shared_ptr<TunnelState> state;
        {
          std::lock_guard<std::mutex> lock(ctx.tunnel_mutex);
          auto it = ctx.tunnel_connections.find(&conn);
          if (it == ctx.tunnel_connections.end()) return;
          state = it->second;
        }
        if (!state || !state->active || state->upstream_sock < 0) return;

        const char *ptr = data.data();
        size_t remaining = data.size();
        while (remaining > 0) {
          ssize_t sent =
              send(state->upstream_sock, ptr, remaining, MSG_NOSIGNAL);
          if (sent <= 0) {
            state->active = false;
            conn.close("upstream write error");
            return;
          }
          ptr += sent;
          remaining -= sent;
        }
      })
      .onclose([&ctx](crow::websocket::connection &conn,
                       const std::string &reason) {
        std::shared_ptr<TunnelState> state;
        {
          std::lock_guard<std::mutex> lock(ctx.tunnel_mutex);
          auto it = ctx.tunnel_connections.find(&conn);
          if (it != ctx.tunnel_connections.end()) {
            state = it->second;
            ctx.tunnel_connections.erase(it);
          }
        }
        if (state) {
          state->active = false;
          if (state->upstream_sock >= 0) {
            shutdown(state->upstream_sock, SHUT_RDWR);
            ::close(state->upstream_sock);
            state->upstream_sock = -1;
          }
          if (state->reader_thread.joinable()) state->reader_thread.join();

          CROW_LOG_INFO << "Tunnel: closed for user=" << state->user
                        << " resource=" << state->resource_id
                        << " reason=" << reason;

          AuditEvent event;
          event.id = ctx.next_audit_id.fetch_add(1);
          event.type = "tunnel.close";
          event.actor = state->user;
          event.role = "";
          event.createdAt = now_utc();
          event.payloadJson =
              "{\"resourceId\":" + std::to_string(state->resource_id) +
              ",\"reason\":\"" + json_escape(reason) + "\"}";
          event.payloadIsJson = true;
          ctx.append_audit(event);
        }
      });
}
