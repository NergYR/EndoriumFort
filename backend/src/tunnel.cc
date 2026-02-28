// ─── EndoriumFort — WebSocket TCP tunnel implementation ─────────────────

#include "tunnel.h"
#include "app_context.h"
#include "utils.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <memory>
#include <thread>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

void register_tunnel_routes(CrowApp &app, AppContext &ctx) {
  CROW_WEBSOCKET_ROUTE(app, "/ws/tunnel")
      .onaccept([&ctx](const crow::request &req, void **userdata) -> bool {
        try {
          CROW_LOG_INFO << "Tunnel: onaccept called, raw_url=" << req.raw_url;

          // Authenticate
          std::string token_str;
          const char *token_param = req.url_params.get("token");
          if (token_param) token_str = token_param;
          if (token_str.empty()) {
            const char *ef_token_param = req.url_params.get("ef_token");
            if (ef_token_param) token_str = ef_token_param;
          }
          CROW_LOG_INFO << "Tunnel: token=" << (token_str.size() > 8 ? token_str.substr(0, 8) + "..." : "(short)");
          if (token_str.empty()) {
            CROW_LOG_WARNING << "Tunnel: rejected - no token";
            return false;
          }

          auto auth = ctx.find_auth_by_token(token_str);
          if (!auth) {
            CROW_LOG_WARNING << "Tunnel: rejected - invalid token";
            return false;
          }
          CROW_LOG_INFO << "Tunnel: auth OK user=" << auth->user
                        << " role=" << auth->role;

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
          if (auth->role == "admin") {
            std::lock_guard<std::mutex> lock(ctx.resource_mutex);
            for (const auto &r : ctx.resources)
              allowed_ids.push_back(r.first);
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
          if (!has_perm) {
            CROW_LOG_WARNING << "Tunnel: rejected - no permission for resource "
                             << resource_id;
            return false;
          }
          CROW_LOG_INFO << "Tunnel: permission OK";

          // Create tunnel state
          auto state = std::make_shared<TunnelState>();
          state->resource_id = resource_id;
          state->user = auth->user;
          state->token = token_str;

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

          CROW_LOG_INFO << "Tunnel: accepted for user=" << auth->user
                        << " resource=" << resource_id
                        << " target=" << target_host << ":" << target_port;

          // Audit
          AuditEvent event;
          event.id = ctx.next_audit_id.fetch_add(1);
          event.type = "tunnel.open";
          event.actor = auth->user;
          event.role = auth->role;
          event.createdAt = now_utc();
          event.payloadJson =
              "{\"resourceId\":" + std::to_string(resource_id) +
              ",\"target\":\"" + json_escape(target_host) + ":" +
              std::to_string(target_port) + "\"}";
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
