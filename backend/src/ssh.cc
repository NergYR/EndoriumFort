// ─── EndoriumFort — SSH proxy implementation ────────────────────────────

#include "ssh.h"
#include "app_context.h"
#include "session_recording.h"
#include "utils.h"

#include <iostream>
#include <thread>

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <libssh2.h>
#endif
#endif

// ═══════════════════════════════════════════════════════════════════════
//  TCP / SSH helpers (only when libssh2 is available on non-Windows)
// ═══════════════════════════════════════════════════════════════════════

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32

int open_tcp_socket(const std::string &host, int port, std::string &error) {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  addrinfo *result = nullptr;
  const std::string port_str = std::to_string(port);
  int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
  if (rc != 0 || !result) {
    error = "Unable to resolve host";
    return -1;
  }

  int sock = -1;
  for (addrinfo *ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
    sock = static_cast<int>(
        socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol));
    if (sock < 0) continue;
    if (connect(sock, ptr->ai_addr, ptr->ai_addrlen) == 0) break;
    close(sock);
    sock = -1;
  }

  freeaddrinfo(result);
  if (sock < 0) error = "Unable to connect";
  return sock;
}

bool ssh_connect(SshConnection &connection, const Session &session,
                 const std::string &password, int cols, int rows,
                 std::string &error) {
  connection.socket_fd = open_tcp_socket(session.target, session.port, error);
  if (connection.socket_fd < 0) return false;

  connection.session = libssh2_session_init();
  if (!connection.session) {
    error = "libssh2 init failed";
    close(connection.socket_fd);
    connection.socket_fd = -1;
    return false;
  }

  libssh2_session_set_blocking(connection.session, 1);
  if (libssh2_session_handshake(connection.session, connection.socket_fd) != 0) {
    error = "SSH handshake failed";
    ssh_disconnect(connection);
    return false;
  }

  if (libssh2_userauth_password(connection.session, session.user.c_str(),
                                password.c_str()) != 0) {
    error = "SSH authentication failed";
    ssh_disconnect(connection);
    return false;
  }

  connection.channel = libssh2_channel_open_session(connection.session);
  if (!connection.channel) {
    error = "SSH channel open failed";
    ssh_disconnect(connection);
    return false;
  }

  if (libssh2_channel_request_pty_ex(connection.channel, "xterm-256color", 13,
                                     nullptr, 0, cols, rows, 0, 0) != 0) {
    error = "SSH pty request failed";
    ssh_disconnect(connection);
    return false;
  }

  if (libssh2_channel_shell(connection.channel) != 0) {
    error = "SSH shell request failed";
    ssh_disconnect(connection);
    return false;
  }

  libssh2_session_set_blocking(connection.session, 0);
  connection.running = true;
  return true;
}

void ssh_disconnect(SshConnection &connection) {
  connection.running = false;
  if (connection.reader.joinable()) connection.reader.join();
  if (connection.channel) {
    libssh2_channel_close(connection.channel);
    libssh2_channel_free(connection.channel);
    connection.channel = nullptr;
  }
  if (connection.session) {
    libssh2_session_disconnect(connection.session, "Session closed");
    libssh2_session_free(connection.session);
    connection.session = nullptr;
  }
  if (connection.socket_fd >= 0) {
    close(connection.socket_fd);
    connection.socket_fd = -1;
  }
}

#endif
#endif

// ═══════════════════════════════════════════════════════════════════════
//  Route registration
// ═══════════════════════════════════════════════════════════════════════

void register_ssh_routes(crow::SimpleApp &app, AppContext &ctx) {
#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32

  // Initialise SSH close callback on AppContext
  ctx.close_ssh_for_session = [&ctx](int session_id) {
    std::vector<std::pair<crow::websocket::connection *,
                          std::shared_ptr<SshConnection>>>
        to_close;
    {
      std::lock_guard<std::mutex> lock(ctx.ws_mutex);
      for (auto it = ctx.ws_connections.begin();
           it != ctx.ws_connections.end();) {
        if (it->second && it->second->session_id == session_id) {
          to_close.push_back(*it);
          it = ctx.ws_connections.erase(it);
        } else {
          ++it;
        }
      }
    }
    for (const auto &entry : to_close) {
      if (entry.second) ssh_disconnect(*entry.second);
      if (entry.first) entry.first->close("terminated");
    }
  };

  CROW_WEBSOCKET_ROUTE(app, "/api/ws/ssh")
      .onaccept([&ctx](const crow::request &request, void **userdata) {
        if (userdata) *userdata = nullptr;
        std::string token;
        const char *token_param = request.url_params.get("token");
        token = token_param ? token_param : "";

        if (token.empty()) {
          auto cookie = request.get_header_value("Cookie");
          if (!cookie.empty()) {
            size_t pos = cookie.find("endoriumfort_token=");
            if (pos != std::string::npos) {
              size_t start = pos + 19;
              size_t end = cookie.find(';', start);
              if (end == std::string::npos) end = cookie.length();
              token = cookie.substr(start, end - start);
            }
          }
        }

        std::cerr << "[WS] onaccept: token=" << token << std::endl;
        auto auth = ctx.find_auth_by_token(token);
        if (!auth) {
          std::cerr << "[WS] onaccept: auth not found for token" << std::endl;
          return false;
        }
        std::cerr << "[WS] onaccept: auth found, user=" << auth->user
                  << " role=" << auth->role << std::endl;
        bool allowed = is_allowed_role(auth->role, {"operator", "admin"});
        std::cerr << "[WS] onaccept: allowed=" << allowed << std::endl;
        return allowed;
      })
      .onopen([&ctx](crow::websocket::connection &conn) {
        std::cerr << "[WS] onopen: connection opened" << std::endl;
        auto connection = std::make_shared<SshConnection>();
        {
          std::lock_guard<std::mutex> lock(ctx.ws_mutex);
          ctx.ws_connections[&conn] = connection;
        }
        std::cerr << "[WS] onopen: connection registered" << std::endl;
      })
      .onclose([&ctx](crow::websocket::connection &conn, const std::string &) {
        std::shared_ptr<SshConnection> connection;
        {
          std::lock_guard<std::mutex> lock(ctx.ws_mutex);
          auto it = ctx.ws_connections.find(&conn);
          if (it != ctx.ws_connections.end()) {
            connection = it->second;
            ctx.ws_connections.erase(it);
          }
        }
        if (connection) {
          if (connection->session_id > 0) {
            ctx.terminate_session(connection->session_id, "system",
                                  "system", "session.close");
          }
          ssh_disconnect(*connection);
        }
      })
      .onmessage([&ctx](crow::websocket::connection &conn,
                         const std::string &data, bool is_binary) {
        std::cerr << "[WS] onmessage: received message, is_binary="
                  << is_binary << std::endl;
        if (is_binary) return;

        std::shared_ptr<SshConnection> connection;
        {
          std::lock_guard<std::mutex> lock(ctx.ws_mutex);
          auto it = ctx.ws_connections.find(&conn);
          if (it != ctx.ws_connections.end()) connection = it->second;
        }
        if (!connection) {
          std::cerr << "[WS] onmessage: connection not found" << std::endl;
          return;
        }

        std::cerr << "[WS] onmessage: parsing JSON" << std::endl;
        auto payload = crow::json::load(data);
        if (!payload) {
          std::cerr << "[WS] onmessage: invalid JSON" << std::endl;
          conn.send_text("{\"type\":\"error\",\"message\":\"Invalid JSON\"}");
          return;
        }
        std::string type;
        if (payload.has("type")) type = std::string(payload["type"].s());
        std::cerr << "[WS] onmessage: type=" << type << std::endl;

        if (type == "start") {
          if (connection->running) {
            conn.send_text(
                "{\"type\":\"error\",\"message\":\"Already started\"}");
            return;
          }
          if (!payload.has("sessionId") || !payload.has("password")) {
            conn.send_text(
                "{\"type\":\"error\",\"message\":\"Missing fields\"}");
            return;
          }
          int session_id = payload["sessionId"].i();
          std::string password = payload["password"].s();
          int cols = payload.has("cols") ? payload["cols"].i() : 120;
          int rows = payload.has("rows") ? payload["rows"].i() : 32;

          Session target_session;
          {
            std::lock_guard<std::mutex> lock(ctx.session_mutex);
            auto it = ctx.sessions.find(session_id);
            if (it == ctx.sessions.end()) {
              conn.send_text(
                  "{\"type\":\"error\",\"message\":\"Session not found\"}");
              return;
            }
            if (it->second.status != "active") {
              conn.send_text(
                  "{\"type\":\"error\",\"message\":\"Session closed\"}");
              return;
            }
            target_session = it->second;
          }

          std::string error;
          if (!ssh_connect(*connection, target_session, password, cols, rows,
                           error)) {
            ssh_disconnect(*connection);
            conn.send_text("{\"type\":\"error\",\"message\":\"" +
                           json_escape(error) + "\"}");
            return;
          }

          connection->session_id = session_id;

          // ── Start session recording ──
          ctx.init_recordings_dir();
          auto recorder = std::make_shared<SessionRecorder>();
          int rec_id = ctx.next_recording_id.fetch_add(1);
          std::string rec_filename = ctx.recordings_dir + "/session_" +
                                     std::to_string(session_id) + "_" +
                                     std::to_string(rec_id) + ".cast";
          std::string rec_title = "Session #" + std::to_string(session_id) +
                                  " " + target_session.user + "@" +
                                  target_session.target;
          if (recorder->open(rec_filename, session_id, cols, rows, rec_title)) {
            connection->recorder = recorder;
            SessionRecording rec;
            rec.id = rec_id;
            rec.sessionId = session_id;
            rec.filePath = rec_filename;
            rec.createdAt = now_utc();
            {
              std::lock_guard<std::mutex> rlock(ctx.recording_mutex);
              ctx.recordings[rec.id] = rec;
            }
            ctx.insert_recording(rec);
            std::cerr << "[WS] Recording started: " << rec_filename << std::endl;
          } else {
            std::cerr << "[WS] Failed to open recording: " << rec_filename << std::endl;
          }

          connection->reader =
              std::thread([&conn, connection, &ctx]() {
                std::vector<char> buffer(4096);
                while (connection->running) {
                  ssize_t rc = libssh2_channel_read(
                      connection->channel, buffer.data(), buffer.size());
                  if (rc == LIBSSH2_ERROR_EAGAIN) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(12));
                    continue;
                  }
                  if (rc <= 0) break;
                  std::string output(buffer.data(), static_cast<size_t>(rc));
                  // Record output
                  if (connection->recorder && connection->recorder->is_open()) {
                    connection->recorder->append_output(
                        output.data(), output.size());
                  }
                  conn.send_binary(output);
                  // Broadcast to shadow watchers
                  {
                    std::lock_guard<std::mutex> slock(ctx.shadow_mutex);
                    auto sit = ctx.shadow_connections.find(connection->session_id);
                    if (sit != ctx.shadow_connections.end()) {
                      for (auto *shadow : sit->second) {
                        try { shadow->send_binary(output); } catch (...) {}
                      }
                    }
                  }
                }
                // Close recording
                if (connection->recorder && connection->recorder->is_open()) {
                  int64_t dur = connection->recorder->duration_ms();
                  size_t fsize = connection->recorder->file_size();
                  connection->recorder->close();
                  // Update recording in DB
                  std::lock_guard<std::mutex> rlock(ctx.recording_mutex);
                  for (auto &entry : ctx.recordings) {
                    if (entry.second.sessionId == connection->session_id &&
                        entry.second.closedAt.empty()) {
                      entry.second.closedAt = now_utc();
                      entry.second.durationMs = dur;
                      entry.second.fileSize = fsize;
                      ctx.update_recording_close(entry.second);
                      break;
                    }
                  }
                }
                if (connection->running) {
                  conn.send_text(
                      "{\"type\":\"status\",\"message\":\"SSH closed\"}");
                }
                connection->running = false;
                if (connection->session_id > 0) {
                  ctx.terminate_session(connection->session_id, "system",
                                        "system", "session.close");
                }
                conn.close("ssh-closed");
              });
          return;
        }

        if (type == "input") {
          if (!payload.has("data")) return;
          if (!connection->channel) return;
          std::string input = payload["data"].s();
          // Record input
          if (connection->recorder && connection->recorder->is_open()) {
            connection->recorder->append_input(input.c_str(), input.size());
          }
          std::lock_guard<std::mutex> lock(connection->write_mutex);
          libssh2_channel_write(connection->channel, input.c_str(),
                                input.size());
          return;
        }

        if (type == "resize") {
          if (!payload.has("cols") || !payload.has("rows")) return;
          if (!connection->channel) return;
          int cols = payload["cols"].i();
          int rows = payload["rows"].i();
          libssh2_channel_request_pty_size(connection->channel, cols, rows);
          return;
        }
      });

  // ── Shadow WebSocket route (admin read-only monitoring) ──
  CROW_WEBSOCKET_ROUTE(app, "/api/ws/shadow")
      .onaccept([&ctx](const crow::request &request, void **userdata) {
        if (userdata) *userdata = nullptr;
        std::string token;
        const char *tp = request.url_params.get("token");
        token = tp ? tp : "";
        if (token.empty()) return false;

        auto auth = ctx.find_auth_by_token(token);
        if (!auth) return false;
        // Only admin and auditor can shadow
        if (!is_allowed_role(auth->role, {"admin", "auditor"})) return false;

        const char *sid_param = request.url_params.get("sessionId");
        if (!sid_param) return false;
        int session_id = 0;
        try { session_id = std::stoi(sid_param); } catch (...) { return false; }
        if (session_id <= 0) return false;

        // Store the session_id in userdata
        auto *data = new int(session_id);
        *userdata = data;

        // Audit shadow access
        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "session.shadow";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = "{\"sessionId\":" + std::to_string(session_id) + "}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        return true;
      })
      .onopen([&ctx](crow::websocket::connection &conn) {
        auto *data = static_cast<int *>(conn.userdata());
        if (!data) { conn.close("no-session"); return; }
        int session_id = *data;
        {
          std::lock_guard<std::mutex> lock(ctx.shadow_mutex);
          ctx.shadow_connections[session_id].push_back(&conn);
        }
        conn.send_text("{\"type\":\"status\",\"message\":\"Shadow connected to session #" +
                       std::to_string(session_id) + " (read-only)\"}");
      })
      .onclose([&ctx](crow::websocket::connection &conn, const std::string &) {
        auto *data = static_cast<int *>(conn.userdata());
        if (data) {
          int session_id = *data;
          std::lock_guard<std::mutex> lock(ctx.shadow_mutex);
          auto it = ctx.shadow_connections.find(session_id);
          if (it != ctx.shadow_connections.end()) {
            auto &vec = it->second;
            vec.erase(std::remove(vec.begin(), vec.end(), &conn), vec.end());
            if (vec.empty()) ctx.shadow_connections.erase(it);
          }
          delete data;
        }
      })
      .onmessage([](crow::websocket::connection &conn, const std::string &, bool) {
        // Shadow is read-only — ignore all input
        conn.send_text("{\"type\":\"info\",\"message\":\"Shadow mode is read-only\"}");
      });

#else
  // Windows stub
  CROW_ROUTE(app, "/api/ws/ssh")([] {
    return crow::response(501, "SSH proxy is not supported on Windows.");
  });
#endif
#else
  // No libssh2 stub
  (void)ctx;
  CROW_ROUTE(app, "/api/ws/ssh")([] {
    return crow::response(501, "SSH proxy disabled (libssh2 not found).");
  });
#endif
}
