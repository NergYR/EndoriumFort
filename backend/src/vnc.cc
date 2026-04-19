#include "vnc.h"

#include "app_context.h"
#include "utils.h"

#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace {

bool parse_target_endpoint(const std::string &raw_target, int fallback_port,
                           std::string &host, int &port) {
  host = trim_copy(raw_target);
  port = std::clamp(fallback_port, 1, 65535);
  if (host.empty()) return false;

  if (host.front() == '[') {
    const size_t closing = host.find(']');
    if (closing == std::string::npos) return false;
    std::string parsed_host = host.substr(1, closing - 1);
    if (parsed_host.empty()) return false;
    if (closing + 1 < host.size()) {
      if (host[closing + 1] != ':') return false;
      const std::string port_text = trim_copy(host.substr(closing + 2));
      if (port_text.empty() ||
          !std::all_of(port_text.begin(), port_text.end(),
                       [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
        return false;
      }
      port = std::clamp(std::stoi(port_text), 1, 65535);
    }
    host = parsed_host;
    return true;
  }

  const size_t first_colon = host.find(':');
  const size_t last_colon = host.rfind(':');
  if (first_colon != std::string::npos && first_colon == last_colon) {
    const std::string port_text = trim_copy(host.substr(last_colon + 1));
    if (!port_text.empty() &&
        std::all_of(port_text.begin(), port_text.end(),
                    [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
      const std::string parsed_host = trim_copy(host.substr(0, last_colon));
      if (parsed_host.empty()) return false;
      host = parsed_host;
      port = std::clamp(std::stoi(port_text), 1, 65535);
    }
  }

  return !host.empty();
}

bool has_resource_access(AppContext &ctx, int user_id, const std::string &role,
                         int resource_id) {
  if (resource_id <= 0) return false;
  if (ctx.has_permission(user_id, role, "resources.manage")) return true;
  const auto allowed_ids = ctx.get_resource_permissions(user_id);
  return std::find(allowed_ids.begin(), allowed_ids.end(), resource_id) !=
         allowed_ids.end();
}

#ifndef _WIN32

int open_tcp_socket(const std::string &host, int port, std::string &error) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo *result = nullptr;
  const std::string port_text = std::to_string(port);
  const int rc = getaddrinfo(host.c_str(), port_text.c_str(), &hints, &result);
  if (rc != 0 || !result) {
    error = "Unable to resolve VNC target";
    return -1;
  }

  int sock = -1;
  for (addrinfo *ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
    sock = static_cast<int>(
        ::socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol));
    if (sock < 0) continue;
    if (::connect(sock, ptr->ai_addr, ptr->ai_addrlen) == 0) break;
    ::close(sock);
    sock = -1;
  }

  freeaddrinfo(result);
  if (sock < 0) error = "Unable to connect to VNC target";
  return sock;
}

#endif

}  // namespace

void register_vnc_routes(CrowApp &app, AppContext &ctx) {
  CROW_ROUTE(app, "/api/vnc/capabilities").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!ctx.has_permission(auth->userId, auth->role, "vnc.connect")) {
          return crow::response(403, "Forbidden");
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
#ifdef _WIN32
        payload["enabled"] = false;
        payload["message"] =
            "VNC browser proxy is not supported on Windows builds.";
#else
        payload["enabled"] = true;
        payload["wsPath"] = "/api/ws/vnc";
        payload["requiresSessionId"] = true;
        payload["viewer"] = "novnc";
#endif
        return crow::response{payload};
      });

#ifdef _WIN32
  CROW_ROUTE(app, "/api/ws/vnc")([] {
    crow::json::wvalue payload;
    payload["status"] = "error";
    payload["message"] =
        "VNC browser proxy is unavailable on this platform build.";
    return crow::response{501, payload};
  });
#else

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

  CROW_WEBSOCKET_ROUTE(app, "/api/ws/vnc")
      .onaccept([&ctx](const crow::request &request, void **userdata) {
        if (userdata) *userdata = nullptr;

        auto token = extract_auth_token_from_request(request);
        if (!token || token->empty()) return false;
        const auto auth = ctx.find_auth_by_token(*token);
        if (!auth) return false;
        if (!ctx.has_permission(auth->userId, auth->role, "vnc.connect")) {
          return false;
        }

        const char *session_param = request.url_params.get("sessionId");
        if (!session_param) return false;

        int session_id = 0;
        try {
          session_id = std::stoi(session_param);
        } catch (...) {
          return false;
        }
        if (session_id <= 0) return false;

        Session target_session;
        {
          std::lock_guard<std::mutex> lock(ctx.session_mutex);
          const auto it = ctx.sessions.find(session_id);
          if (it == ctx.sessions.end()) return false;
          if (it->second.status != "active") return false;
          if (to_lower(it->second.protocol) != "vnc") return false;
          target_session = it->second;
        }

        if (!has_resource_access(ctx, auth->userId, auth->role,
                                 target_session.resourceId)) {
          return false;
        }

        std::string target_host;
        int target_port = 0;
        if (!parse_target_endpoint(target_session.target, target_session.port,
                                   target_host, target_port)) {
          return false;
        }

        std::string connect_error;
        const int upstream_sock = open_tcp_socket(target_host, target_port,
                                                  connect_error);
        if (upstream_sock < 0) {
          return false;
        }

        auto connection = std::make_shared<VncConnection>();
        connection->upstream_sock = upstream_sock;
        connection->session_id = session_id;
        connection->resource_id = target_session.resourceId;
        connection->user = auth->user;
        connection->role = auth->role;
        connection->active = true;

        auto *raw_state = new std::shared_ptr<VncConnection>(connection);
        if (userdata) *userdata = raw_state;
        return true;
      })
      .onopen([&ctx](crow::websocket::connection &conn) {
        auto *raw_state =
            static_cast<std::shared_ptr<VncConnection> *>(conn.userdata());
        if (!raw_state) {
          conn.close("internal_error");
          return;
        }
        const auto state = *raw_state;
        delete raw_state;
        conn.userdata(nullptr);

        {
          std::lock_guard<std::mutex> lock(ctx.vnc_mutex);
          ctx.vnc_connections[&conn] = state;
        }

        AuditEvent open_event;
        open_event.id = ctx.next_audit_id.fetch_add(1);
        open_event.type = "vnc.open";
        open_event.actor = state->user;
        open_event.role = state->role;
        open_event.createdAt = now_utc();
        open_event.payloadJson =
            "{\"sessionId\":" + std::to_string(state->session_id) +
            ",\"resourceId\":" + std::to_string(state->resource_id) + "}";
        open_event.payloadIsJson = true;
        ctx.append_audit(open_event);

        state->reader_thread = std::thread([state, &conn]() {
          char buffer[16384];
          while (state->active) {
            const ssize_t count =
                recv(state->upstream_sock, buffer, sizeof(buffer), 0);
            if (count < 0) {
              if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
              break;
            }
            if (count == 0) break;
            try {
              conn.send_binary(std::string(buffer, static_cast<size_t>(count)));
            } catch (...) {
              break;
            }
          }
          state->active = false;
          try {
            conn.close("upstream_closed");
          } catch (...) {
          }
        });
      })
      .onmessage([&ctx](crow::websocket::connection &conn,
                        const std::string &data, bool) {
        std::shared_ptr<VncConnection> state;
        {
          std::lock_guard<std::mutex> lock(ctx.vnc_mutex);
          const auto it = ctx.vnc_connections.find(&conn);
          if (it == ctx.vnc_connections.end()) return;
          state = it->second;
        }
        if (!state || !state->active || state->upstream_sock < 0) return;

        const char *ptr = data.data();
        size_t remaining = data.size();
        while (remaining > 0) {
          const ssize_t sent =
              send(state->upstream_sock, ptr, remaining, MSG_NOSIGNAL);
          if (sent <= 0) {
            state->active = false;
            conn.close("upstream_write_error");
            return;
          }
          ptr += sent;
          remaining -= static_cast<size_t>(sent);
        }
      })
      .onclose([&ctx](crow::websocket::connection &conn,
                      const std::string &reason) {
        std::shared_ptr<VncConnection> state;
        {
          std::lock_guard<std::mutex> lock(ctx.vnc_mutex);
          const auto it = ctx.vnc_connections.find(&conn);
          if (it != ctx.vnc_connections.end()) {
            state = it->second;
            ctx.vnc_connections.erase(it);
          }
        }
        if (!state) return;

        state->active = false;
        if (state->upstream_sock >= 0) {
          shutdown(state->upstream_sock, SHUT_RDWR);
          ::close(state->upstream_sock);
          state->upstream_sock = -1;
        }
        if (state->reader_thread.joinable()) state->reader_thread.join();

        ctx.terminate_session(state->session_id, "system", "system",
                              "session.close");

        AuditEvent close_event;
        close_event.id = ctx.next_audit_id.fetch_add(1);
        close_event.type = "vnc.close";
        close_event.actor = state->user;
        close_event.role = state->role;
        close_event.createdAt = now_utc();
        close_event.payloadJson =
            "{\"sessionId\":" + std::to_string(state->session_id) +
            ",\"resourceId\":" + std::to_string(state->resource_id) +
            ",\"reason\":\"" + json_escape(reason) + "\"}";
        close_event.payloadIsJson = true;
        ctx.append_audit(close_event);
      });
#endif
}
