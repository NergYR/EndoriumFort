#include "crow.h"

#include <sqlite3.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

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

struct Session {
  int id = 0;
  std::string target;
  std::string user;
  std::string protocol;
  std::string status;
  std::string createdAt;
  std::string terminatedAt;
  int port = 22;
};

struct AuthSession {
  std::string user;
  std::string role;
  std::string token;
  std::string issuedAt;
};

struct AuditEvent {
  int id = 0;
  std::string type;
  std::string actor;
  std::string role;
  std::string createdAt;
  std::string payloadJson;
  bool payloadIsJson = false;
};

struct SessionEvent {
  int id = 0;
  std::string type;
  std::string createdAt;
  std::string payloadJson;
};

struct SqliteDb {
  sqlite3 *db = nullptr;
  std::mutex mutex;

  bool open(const std::string &path, std::string &error) {
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
      error = sqlite3_errmsg(db ? db : nullptr);
      return false;
    }
    return true;
  }

  bool exec(const std::string &sql, std::string &error) {
    char *errmsg = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errmsg) !=
        SQLITE_OK) {
      if (errmsg) {
        error = errmsg;
        sqlite3_free(errmsg);
      } else {
        error = "SQLite exec failed";
      }
      return false;
    }
    return true;
  }

  ~SqliteDb() {
    if (db) {
      sqlite3_close(db);
    }
  }
};

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
struct SshConnection {
  int socket_fd = -1;
  LIBSSH2_SESSION *session = nullptr;
  LIBSSH2_CHANNEL *channel = nullptr;
  std::thread reader;
  std::atomic<bool> running{false};
  std::mutex write_mutex;
  int session_id = 0;
};

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
    sock = static_cast<int>(socket(ptr->ai_family, ptr->ai_socktype,
                                   ptr->ai_protocol));
    if (sock < 0) {
      continue;
    }
    if (connect(sock, ptr->ai_addr, ptr->ai_addrlen) == 0) {
      break;
    }
    close(sock);
    sock = -1;
  }

  freeaddrinfo(result);
  if (sock < 0) {
    error = "Unable to connect";
  }
  return sock;
}

bool ssh_connect(SshConnection &connection, const Session &session,
                 const std::string &password, int cols, int rows,
                 std::string &error) {
  connection.socket_fd = open_tcp_socket(session.target, session.port, error);
  if (connection.socket_fd < 0) {
    return false;
  }

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
  if (connection.reader.joinable()) {
    connection.reader.join();
  }
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

std::string now_utc() {
  auto now = std::chrono::system_clock::now();
  std::time_t now_time = std::chrono::system_clock::to_time_t(now);
  std::tm utc_tm{};
#ifdef _WIN32
  gmtime_s(&utc_tm, &now_time);
#else
  gmtime_r(&now_time, &utc_tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

std::string json_escape(const std::string &value) {
  std::ostringstream oss;
  for (char ch : value) {
    switch (ch) {
      case '\\':
        oss << "\\\\";
        break;
      case '"':
        oss << "\\\"";
        break;
      case '\n':
        oss << "\\n";
        break;
      case '\r':
        oss << "\\r";
        break;
      case '\t':
        oss << "\\t";
        break;
      default:
        oss << ch;
        break;
    }
  }
  return oss.str();
}

std::string build_session_payload_json(const Session &session) {
  std::ostringstream oss;
  oss << '{';
  oss << "\"sessionId\":" << session.id << ',';
  oss << "\"target\":\"" << json_escape(session.target) << "\",";
  oss << "\"user\":\"" << json_escape(session.user) << "\",";
  oss << "\"protocol\":\"" << json_escape(session.protocol) << "\",";
  oss << "\"port\":" << session.port << ',';
  oss << "\"status\":\"" << json_escape(session.status) << "\",";
  oss << "\"createdAt\":\"" << json_escape(session.createdAt) << "\"";
  if (!session.terminatedAt.empty()) {
    oss << ",\"terminatedAt\":\"" << json_escape(session.terminatedAt)
        << "\"";
  }
  oss << '}';
  return oss.str();
}

bool is_allowed_role(const std::string &role,
                     const std::vector<std::string> &allowed) {
  for (const auto &item : allowed) {
    if (item == role) {
      return true;
    }
  }
  return false;
}

std::optional<std::string> extract_bearer_token(
    const crow::request &request) {
  auto header = request.get_header_value("Authorization");
  const std::string prefix = "Bearer ";
  if (header.rfind(prefix, 0) == 0 && header.size() > prefix.size()) {
    return header.substr(prefix.size());
  }
  return std::nullopt;
}

crow::json::wvalue session_to_json(const Session &session) {
  crow::json::wvalue payload;
  payload["id"] = session.id;
  payload["target"] = session.target;
  payload["user"] = session.user;
  payload["protocol"] = session.protocol;
  payload["port"] = session.port;
  payload["status"] = session.status;
  payload["createdAt"] = session.createdAt;
  if (!session.terminatedAt.empty()) {
    payload["terminatedAt"] = session.terminatedAt;
  }
  return payload;
}

std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return value;
}

std::optional<int> parse_int_param(const char *value) {
  if (!value) {
    return std::nullopt;
  }
  try {
    return std::stoi(value);
  } catch (const std::exception &) {
    return std::nullopt;
  }
}

int main() {
  crow::SimpleApp app;
  std::mutex session_mutex;
  std::unordered_map<int, Session> sessions;
  std::atomic<int> next_id{1};

  std::mutex auth_mutex;
  std::unordered_map<std::string, AuthSession> auth_sessions;
  std::atomic<int> next_token{1000};

  std::mutex audit_mutex;
  std::vector<AuditEvent> audit_events;
  std::atomic<int> next_audit_id{1};
  const std::string audit_path = "audit-log.jsonl";

  SqliteDb sqlite;
  std::string sqlite_error;
  if (!sqlite.open("endoriumfort.db", sqlite_error)) {
    std::cerr << "SQLite open failed: " << sqlite_error << '\n';
  } else {
    const std::string schema =
        "CREATE TABLE IF NOT EXISTS sessions ("
        "id INTEGER PRIMARY KEY,"
        "target TEXT NOT NULL,"
        "user TEXT NOT NULL,"
        "protocol TEXT NOT NULL,"
        "port INTEGER NOT NULL DEFAULT 22,"
        "status TEXT NOT NULL,"
        "created_at TEXT NOT NULL,"
        "terminated_at TEXT"
        ");";
    if (!sqlite.exec(schema, sqlite_error)) {
      std::cerr << "SQLite schema failed: " << sqlite_error << '\n';
    }
    sqlite.exec("ALTER TABLE sessions ADD COLUMN port INTEGER DEFAULT 22;",
                sqlite_error);
  }

  std::mutex event_mutex;
  std::vector<SessionEvent> session_events;
  std::atomic<int> next_event_id{1};

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  if (libssh2_init(0) != 0) {
    std::cerr << "libssh2 init failed" << '\n';
  }
#endif
#endif

  auto find_auth = [&](const crow::request &request)
      -> std::optional<AuthSession> {
    auto token = extract_bearer_token(request);
    if (!token) {
      return std::nullopt;
    }
    std::lock_guard<std::mutex> lock(auth_mutex);
    auto it = auth_sessions.find(*token);
    if (it == auth_sessions.end()) {
      return std::nullopt;
    }
    return it->second;
  };

  auto find_auth_by_token = [&](const std::string &token)
      -> std::optional<AuthSession> {
    if (token.empty()) {
      return std::nullopt;
    }
    std::lock_guard<std::mutex> lock(auth_mutex);
    auto it = auth_sessions.find(token);
    if (it == auth_sessions.end()) {
      return std::nullopt;
    }
    return it->second;
  };

  auto append_audit = [&](const AuditEvent &event) {
    std::lock_guard<std::mutex> lock(audit_mutex);
    audit_events.push_back(event);
    if (audit_events.size() > 200) {
      audit_events.erase(audit_events.begin(), audit_events.begin() + 50);
    }
    std::ofstream out(audit_path, std::ios::app);
    if (out) {
      out << '{'
          << "\"id\":" << event.id << ','
          << "\"type\":\"" << json_escape(event.type) << "\","
          << "\"actor\":\"" << json_escape(event.actor) << "\","
          << "\"role\":\"" << json_escape(event.role) << "\","
          << "\"createdAt\":\"" << json_escape(event.createdAt) << "\","
          << "\"payload\":"
          << (event.payloadIsJson ? event.payloadJson
                                  : "\"" + json_escape(event.payloadJson) +
                                        "\"")
          << "}\n";
    }
  };

  auto append_session_event = [&](const std::string &type,
                                  const Session &session) {
    SessionEvent event;
    event.id = next_event_id.fetch_add(1);
    event.type = type;
    event.createdAt = now_utc();
    event.payloadJson = build_session_payload_json(session);
    std::lock_guard<std::mutex> lock(event_mutex);
    session_events.push_back(event);
    if (session_events.size() > 200) {
      session_events.erase(session_events.begin(),
                           session_events.begin() + 50);
    }
  };

  auto load_sessions_from_db = [&]() {
    if (!sqlite.db) {
      return;
    }
    std::lock_guard<std::mutex> db_lock(sqlite.mutex);
    const char *sql =
      "SELECT id, target, user, protocol, port, status, created_at, "
      "terminated_at FROM sessions";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      std::cerr << "SQLite select failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
      return;
    }

    int max_id = 0;
    {
      std::lock_guard<std::mutex> lock(session_mutex);
      while (sqlite3_step(stmt) == SQLITE_ROW) {
        Session session;
        session.id = sqlite3_column_int(stmt, 0);
        session.target =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        session.user =
            reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
        session.protocol =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
        session.port = sqlite3_column_int(stmt, 4);
        if (session.port <= 0) {
          session.port = 22;
        }
        session.status =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
        session.createdAt =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
        const unsigned char *terminated = sqlite3_column_text(stmt, 7);
        if (terminated) {
          session.terminatedAt = reinterpret_cast<const char *>(terminated);
        }
        sessions[session.id] = session;
        if (session.id > max_id) {
          max_id = session.id;
        }
      }
    }
    sqlite3_finalize(stmt);
    if (max_id > 0) {
      next_id.store(max_id + 1);
    }
  };

  auto insert_session = [&](const Session &session) -> bool {
    if (!sqlite.db) {
      return true;
    }
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql =
        "INSERT INTO sessions (id, target, user, protocol, status, "
      "port, created_at, terminated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      std::cerr << "SQLite insert prepare failed: "
                << sqlite3_errmsg(sqlite.db) << '\n';
      return false;
    }
    sqlite3_bind_int(stmt, 1, session.id);
    sqlite3_bind_text(stmt, 2, session.target.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, session.user.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, session.protocol.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, session.status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 6, session.port);
    sqlite3_bind_text(stmt, 7, session.createdAt.c_str(), -1, SQLITE_TRANSIENT);
    if (session.terminatedAt.empty()) {
      sqlite3_bind_null(stmt, 8);
    } else {
      sqlite3_bind_text(stmt, 8, session.terminatedAt.c_str(), -1,
                        SQLITE_TRANSIENT);
    }
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) {
      std::cerr << "SQLite insert failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
    }
    sqlite3_finalize(stmt);
    return ok;
  };

  auto update_session_termination = [&](const Session &session) -> bool {
    if (!sqlite.db) {
      return true;
    }
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    const char *sql =
        "UPDATE sessions SET status = ?, terminated_at = ? WHERE id = ?";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      std::cerr << "SQLite update prepare failed: "
                << sqlite3_errmsg(sqlite.db) << '\n';
      return false;
    }
    sqlite3_bind_text(stmt, 1, session.status.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, session.terminatedAt.c_str(), -1,
                      SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, session.id);
    bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok) {
      std::cerr << "SQLite update failed: " << sqlite3_errmsg(sqlite.db)
                << '\n';
    }
    sqlite3_finalize(stmt);
    return ok;
  };

  load_sessions_from_db();

  CROW_ROUTE(app, "/api/health")([] {
    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["message"] = "EndoriumFort API online";
    return payload;
  });

  CROW_ROUTE(app, "/api/auth/login").methods(crow::HTTPMethod::Post)(
      [&](const crow::request &request) {
        auto body = crow::json::load(request.body);
        if (!body) {
          return crow::response(400, "Invalid JSON body");
        }
        std::string user = body["user"].s();
        std::string role = body["role"].s();
        if (user.empty() || role.empty()) {
          return crow::response(400, "Missing user or role");
        }
        if (!is_allowed_role(role, {"operator", "admin", "auditor"})) {
          return crow::response(400, "Invalid role");
        }

        AuthSession auth;
        auth.user = user;
        auth.role = role;
        auth.issuedAt = now_utc();
        auth.token = "tok-" + std::to_string(next_token.fetch_add(1));

        {
          std::lock_guard<std::mutex> lock(auth_mutex);
          auth_sessions[auth.token] = auth;
        }

        crow::json::wvalue payload;
        payload["token"] = auth.token;
        payload["user"] = auth.user;
        payload["role"] = auth.role;
        payload["issuedAt"] = auth.issuedAt;
        return crow::response{payload};
      });

  CROW_ROUTE(app, "/api/sessions")([&](const crow::request &request) {
    auto auth = find_auth(request);
    if (!auth) {
      return crow::response(401, "Unauthorized");
    }
    const char *status_param = request.url_params.get("status");
    const char *user_param = request.url_params.get("user");
    const char *target_param = request.url_params.get("target");
    const char *protocol_param = request.url_params.get("protocol");
    const char *sort_param = request.url_params.get("sort");
    auto limit = parse_int_param(request.url_params.get("limit"));
    auto offset = parse_int_param(request.url_params.get("offset"));
    std::string status_filter = status_param ? to_lower(status_param) : "";
    std::string user_filter = user_param ? to_lower(user_param) : "";
    std::string target_filter = target_param ? to_lower(target_param) : "";
    std::string protocol_filter =
        protocol_param ? to_lower(protocol_param) : "";
    std::string sort_order = sort_param ? to_lower(sort_param) : "desc";

    std::vector<Session> snapshot;
    {
      std::lock_guard<std::mutex> lock(session_mutex);
      snapshot.reserve(sessions.size());
      for (const auto &entry : sessions) {
        snapshot.push_back(entry.second);
      }
    }

    std::vector<Session> filtered;
    for (const auto &session : snapshot) {
      if (!status_filter.empty() &&
          to_lower(session.status) != status_filter) {
        continue;
      }
      if (!user_filter.empty() && to_lower(session.user) != user_filter) {
        continue;
      }
      if (!target_filter.empty() && to_lower(session.target) != target_filter) {
        continue;
      }
      if (!protocol_filter.empty() &&
          to_lower(session.protocol) != protocol_filter) {
        continue;
      }
      filtered.push_back(session);
    }

    std::sort(filtered.begin(), filtered.end(), [&](const Session &a,
                                                    const Session &b) {
      if (sort_order == "asc") {
        return a.id < b.id;
      }
      return a.id > b.id;
    });

    int start_index = offset.value_or(0);
    if (start_index < 0) {
      start_index = 0;
    }
    int end_index = static_cast<int>(filtered.size());
    if (limit && *limit > 0) {
      end_index = std::min(end_index, start_index + *limit);
    }
    if (start_index > end_index) {
      start_index = end_index;
    }

    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["items"] = crow::json::wvalue::list();
    payload["total"] = static_cast<int>(snapshot.size());
    payload["count"] = end_index - start_index;
    int index = 0;
    for (int i = start_index; i < end_index; ++i) {
      payload["items"][index++] = session_to_json(filtered[i]);
    }
    return crow::response{payload};
  });

  CROW_ROUTE(app, "/api/sessions").methods(crow::HTTPMethod::Post)(
      [&](const crow::request &request) {
        auto auth = find_auth(request);
        if (!auth) {
          return crow::response(401, "Unauthorized");
        }
        if (!is_allowed_role(auth->role, {"operator", "admin"})) {
          return crow::response(403, "Forbidden");
        }
        auto body = crow::json::load(request.body);
        if (!body) {
          return crow::response(400, "Invalid JSON body");
        }
        std::string target = body["target"].s();
        std::string user = body["user"].s();
        std::string protocol = body["protocol"].s();
        int port = 22;
        if (body.has("port")) {
          port = body["port"].i();
        }
        if (target.empty() || user.empty() || protocol.empty()) {
          return crow::response(400, "Missing target, user, or protocol");
        }
        if (port <= 0 || port > 65535) {
          return crow::response(400, "Invalid port");
        }

        Session session;
        session.id = next_id.fetch_add(1);
        session.target = target;
        session.user = user;
        session.protocol = protocol;
        session.port = port;
        session.status = "active";
        session.createdAt = now_utc();

        {
          std::lock_guard<std::mutex> lock(session_mutex);
          sessions.emplace(session.id, session);
        }

        if (!insert_session(session)) {
          return crow::response(500, "Failed to persist session");
        }

        AuditEvent event;
        event.id = next_audit_id.fetch_add(1);
        event.type = "session.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_session_payload_json(session);
        event.payloadIsJson = true;
        append_audit(event);
        append_session_event("session.create", session);

        crow::json::wvalue payload = session_to_json(session);
        return crow::response{payload};
      });

  CROW_ROUTE(app, "/api/sessions/<int>")([&](const crow::request &request,
                                               int session_id) {
    auto auth = find_auth(request);
    if (!auth) {
      return crow::response(401, "Unauthorized");
    }
    std::lock_guard<std::mutex> lock(session_mutex);
    auto it = sessions.find(session_id);
    if (it == sessions.end()) {
      return crow::response(404, "Session not found");
    }
    crow::json::wvalue payload = session_to_json(it->second);
    return crow::response{payload};
  });

  CROW_ROUTE(app, "/api/sessions/<int>/terminate")
      .methods(crow::HTTPMethod::Post)([&](const crow::request &request,
                                           int session_id) {
        auto auth = find_auth(request);
        if (!auth) {
          return crow::response(401, "Unauthorized");
        }
        if (!is_allowed_role(auth->role, {"operator", "admin"})) {
          return crow::response(403, "Forbidden");
        }
        std::lock_guard<std::mutex> lock(session_mutex);
        auto it = sessions.find(session_id);
        if (it == sessions.end()) {
          return crow::response(404, "Session not found");
        }
        it->second.status = "terminated";
        it->second.terminatedAt = now_utc();
        if (!update_session_termination(it->second)) {
          return crow::response(500, "Failed to persist session");
        }
        AuditEvent event;
        event.id = next_audit_id.fetch_add(1);
        event.type = "session.terminate";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_session_payload_json(it->second);
        event.payloadIsJson = true;
        append_audit(event);
        append_session_event("session.terminate", it->second);
        crow::json::wvalue payload = session_to_json(it->second);
        return crow::response{payload};
      });

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  std::mutex ws_mutex;
  std::unordered_map<crow::websocket::connection *,
                     std::shared_ptr<SshConnection>>
      ws_connections;

  CROW_WEBSOCKET_ROUTE(app, "/api/ws/ssh")
      .onopen([&](crow::websocket::connection &conn,
                  const crow::request &request) {
        const char *token_param = request.url_params.get("token");
        std::string token = token_param ? token_param : "";
        auto auth = find_auth_by_token(token);
        if (!auth || !is_allowed_role(auth->role, {"operator", "admin"})) {
          conn.send_text("{\"type\":\"error\",\"message\":\"Unauthorized\"}");
          conn.close();
          return;
        }

        auto connection = std::make_shared<SshConnection>();
        {
          std::lock_guard<std::mutex> lock(ws_mutex);
          ws_connections[&conn] = connection;
        }
      })
      .onclose([&](crow::websocket::connection &conn, const std::string &) {
        std::shared_ptr<SshConnection> connection;
        {
          std::lock_guard<std::mutex> lock(ws_mutex);
          auto it = ws_connections.find(&conn);
          if (it != ws_connections.end()) {
            connection = it->second;
            ws_connections.erase(it);
          }
        }
        if (connection) {
          ssh_disconnect(*connection);
        }
      })
      .onmessage([&](crow::websocket::connection &conn, const std::string &data,
                     bool is_binary) {
        if (is_binary) {
          return;
        }
        std::shared_ptr<SshConnection> connection;
        {
          std::lock_guard<std::mutex> lock(ws_mutex);
          auto it = ws_connections.find(&conn);
          if (it != ws_connections.end()) {
            connection = it->second;
          }
        }
        if (!connection) {
          return;
        }

        auto payload = crow::json::load(data);
        if (!payload) {
          conn.send_text("{\"type\":\"error\",\"message\":\"Invalid JSON\"}");
          return;
        }
        std::string type = payload.has("type") ? payload["type"].s() : "";
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
            std::lock_guard<std::mutex> lock(session_mutex);
            auto it = sessions.find(session_id);
            if (it == sessions.end()) {
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
          connection->reader = std::thread([&conn, connection]() {
            std::vector<char> buffer(4096);
            while (connection->running) {
              ssize_t rc = libssh2_channel_read(
                  connection->channel, buffer.data(), buffer.size());
              if (rc == LIBSSH2_ERROR_EAGAIN) {
                std::this_thread::sleep_for(std::chrono::milliseconds(12));
                continue;
              }
              if (rc <= 0) {
                break;
              }
              conn.send_binary(std::string(buffer.data(),
                                            static_cast<size_t>(rc)));
            }
            if (connection->running) {
              conn.send_text(
                  "{\"type\":\"status\",\"message\":\"SSH closed\"}");
            }
          });
          return;
        }

        if (type == "input") {
          if (!payload.has("data")) {
            return;
          }
          if (!connection->channel) {
            return;
          }
          std::string input = payload["data"].s();
          std::lock_guard<std::mutex> lock(connection->write_mutex);
          libssh2_channel_write(connection->channel, input.c_str(),
                                input.size());
          return;
        }

        if (type == "resize") {
          if (!payload.has("cols") || !payload.has("rows")) {
            return;
          }
          if (!connection->channel) {
            return;
          }
          int cols = payload["cols"].i();
          int rows = payload["rows"].i();
          libssh2_channel_request_pty_size(connection->channel, cols, rows);
          return;
        }
      });
#else
  CROW_ROUTE(app, "/api/ws/ssh")([] {
    return crow::response(501, "SSH proxy is not supported on Windows.");
  });
#endif
#else
  CROW_ROUTE(app, "/api/ws/ssh")([] {
    return crow::response(501, "SSH proxy disabled (libssh2 not found).");
  });
#endif

  CROW_ROUTE(app, "/api/sessions/stream")(
      [&](const crow::request &request) {
        auto auth = find_auth(request);
        if (!auth) {
          return crow::response(401, "Unauthorized");
        }
        const char *since_param = request.url_params.get("since");
        auto since = parse_int_param(since_param).value_or(0);
        auto header = request.get_header_value("Last-Event-ID");
        if (!header.empty()) {
          auto parsed = parse_int_param(header.c_str());
          if (parsed) {
            since = std::max(since, *parsed);
          }
        }

        std::vector<SessionEvent> snapshot;
        {
          std::lock_guard<std::mutex> lock(event_mutex);
          snapshot.reserve(session_events.size());
          for (const auto &event : session_events) {
            if (event.id > since) {
              snapshot.push_back(event);
            }
          }
        }

        std::ostringstream body;
        body << "retry: 5000\n";
        int sent = 0;
        for (const auto &event : snapshot) {
          body << "id: " << event.id << "\n";
          body << "event: " << event.type << "\n";
          body << "data: " << event.payloadJson << "\n\n";
          if (++sent >= 100) {
            break;
          }
        }

        crow::response response;
        response.code = 200;
        response.set_header("Content-Type", "text/event-stream");
        response.set_header("Cache-Control", "no-cache");
        response.set_header("Connection", "keep-alive");
        response.body = body.str();
        return response;
      });

  CROW_ROUTE(app, "/api/audit").methods(crow::HTTPMethod::Post)(
      [&](const crow::request &request) {
        auto auth = find_auth(request);
        if (!auth) {
          return crow::response(401, "Unauthorized");
        }
        if (!is_allowed_role(auth->role, {"auditor", "admin"})) {
          return crow::response(403, "Forbidden");
        }

        AuditEvent event;
        event.id = next_audit_id.fetch_add(1);
        event.type = "audit.custom";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        auto body = crow::json::load(request.body);
        if (body) {
          event.payloadJson = request.body;
          event.payloadIsJson = true;
        } else {
          event.payloadJson = request.body;
          event.payloadIsJson = false;
        }
        append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "accepted";
        payload["id"] = event.id;
        return crow::response{payload};
      });

  CROW_ROUTE(app, "/api/audit")([&](const crow::request &request) {
    auto auth = find_auth(request);
    if (!auth) {
      return crow::response(401, "Unauthorized");
    }
    if (!is_allowed_role(auth->role, {"auditor", "admin"})) {
      return crow::response(403, "Forbidden");
    }
    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["items"] = crow::json::wvalue::list();
    {
      std::lock_guard<std::mutex> lock(audit_mutex);
      int index = 0;
      for (auto it = audit_events.rbegin();
           it != audit_events.rend() && index < 50; ++it) {
        payload["items"][index]["id"] = it->id;
        payload["items"][index]["type"] = it->type;
        payload["items"][index]["actor"] = it->actor;
        payload["items"][index]["role"] = it->role;
        payload["items"][index]["createdAt"] = it->createdAt;
        payload["items"][index]["payloadRaw"] = it->payloadJson;
        payload["items"][index]["payloadIsJson"] = it->payloadIsJson;
        ++index;
      }
    }
    return crow::response{payload};
  });

  app.port(8080).multithreaded().run();
#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  libssh2_exit();
#endif
#endif
  return 0;
}
