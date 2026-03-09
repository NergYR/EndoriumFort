// ─── EndoriumFort — AppContext implementation ───────────────────────────

#include "app_context.h"
#include "crypto.h"
#include "utils.h"

#include <fstream>
#include <iostream>
#include <random>
#include <sys/stat.h>
#ifdef _WIN32
#include <direct.h>
#else
#include <arpa/inet.h>
#endif

// ── Secure token generation (using /dev/urandom on Linux/macOS) ─────────

std::string AppContext::generate_token() {
#ifndef _WIN32
  unsigned char bytes[32];
  std::ifstream urandom("/dev/urandom", std::ios::binary);
  if (urandom.good()) {
    urandom.read(reinterpret_cast<char *>(bytes), sizeof(bytes));
    if (urandom.gcount() == sizeof(bytes)) {
      char buf[70];
      int offset = snprintf(buf, sizeof(buf), "eft_");
      for (size_t i = 0; i < sizeof(bytes); ++i)
        offset += snprintf(buf + offset, sizeof(buf) - offset, "%02x", bytes[i]);
      return std::string(buf);
    }
  }
#endif
  // Fallback (Windows or /dev/urandom failure)
  std::random_device rd;
  unsigned char fbytes[32];
  for (size_t i = 0; i < sizeof(fbytes); i += 4) {
    uint32_t val = rd();
    memcpy(fbytes + i, &val, std::min(sizeof(val), sizeof(fbytes) - i));
  }
  char buf[70];
  int offset = snprintf(buf, sizeof(buf), "eft_");
  for (size_t i = 0; i < sizeof(fbytes); ++i)
    offset += snprintf(buf + offset, sizeof(buf) - offset, "%02x", fbytes[i]);
  return std::string(buf);
}

// ── Rate limiting ───────────────────────────────────────────────────────

bool AppContext::check_rate_limit(const std::string &key) {
  std::lock_guard<std::mutex> lock(rate_limit_mutex);
  auto now = std::chrono::steady_clock::now();

  // Cleanup old entries (older than window)
  auto &entry = rate_limit_map[key];
  while (!entry.attempts.empty() &&
         (now - entry.attempts.front()) > rate_limit_window) {
    entry.attempts.pop();
  }

  if (static_cast<int>(entry.attempts.size()) >= rate_limit_max_attempts) {
    return false;  // Rate limited
  }

  entry.attempts.push(now);
  return true;
}

// ── SSRF protection ─────────────────────────────────────────────────────

bool AppContext::is_safe_target(const std::string &host, bool allow_loopback) {
  // Block obvious loopback unless explicitly allowed (e.g. SSH dev jump hosts).
  if (!allow_loopback &&
      (host == "localhost" || host == "127.0.0.1" || host == "::1")) {
    return false;
  }

  // Always block unspecified address.
  if (host == "0.0.0.0") {
    return false;
  }

  // Block metadata endpoints (cloud providers)
  if (host == "169.254.169.254" || host == "metadata.google.internal" ||
      host == "metadata.internal") {
    return false;
  }

#ifndef _WIN32
  // Check if it's an IP address in blocked ranges
  struct in_addr addr;
  if (inet_pton(AF_INET, host.c_str(), &addr) == 1) {
    uint32_t ip = ntohl(addr.s_addr);
    // 127.0.0.0/8 (loopback)
    if (!allow_loopback && (ip >> 24) == 127) return false;
    // 169.254.0.0/16 (link-local)
    if ((ip >> 16) == 0xA9FE) return false;
    // 0.0.0.0/8
    if ((ip >> 24) == 0) return false;
  }
#endif

  return true;
}

// ── Auth helpers ────────────────────────────────────────────────────────

std::optional<AuthSession> AppContext::find_auth(const crow::request &request) {
  auto token = extract_auth_token_from_request(request);

  if (!token) return std::nullopt;
  std::lock_guard<std::mutex> lock(auth_mutex);
  auto it = auth_sessions.find(*token);
  if (it == auth_sessions.end()) return std::nullopt;

  // Check expiration
  if (!it->second.expiresAt.empty() && it->second.expiresAt < now_utc()) {
    auth_sessions.erase(it);
    return std::nullopt;
  }

  return it->second;
}

std::optional<AuthSession> AppContext::find_auth_by_token(
    const std::string &token) {
  if (token.empty()) return std::nullopt;
  std::lock_guard<std::mutex> lock(auth_mutex);
  auto it = auth_sessions.find(token);
  if (it == auth_sessions.end()) return std::nullopt;

  // Check expiration
  if (!it->second.expiresAt.empty() && it->second.expiresAt < now_utc()) {
    auth_sessions.erase(it);
    return std::nullopt;
  }

  return it->second;
}

// ── Token management ────────────────────────────────────────────────────

bool AppContext::invalidate_token(const std::string &token) {
  std::lock_guard<std::mutex> lock(auth_mutex);
  return auth_sessions.erase(token) > 0;
}

void AppContext::invalidate_user_tokens(int user_id) {
  std::lock_guard<std::mutex> lock(auth_mutex);
  for (auto it = auth_sessions.begin(); it != auth_sessions.end();) {
    if (it->second.userId == user_id)
      it = auth_sessions.erase(it);
    else
      ++it;
  }
}

void AppContext::cleanup_expired_tokens() {
  std::string current = now_utc();
  std::lock_guard<std::mutex> lock(auth_mutex);
  for (auto it = auth_sessions.begin(); it != auth_sessions.end();) {
    if (!it->second.expiresAt.empty() && it->second.expiresAt < current)
      it = auth_sessions.erase(it);
    else
      ++it;
  }
}

std::string AppContext::compute_expiry() {
  auto now = std::chrono::system_clock::now();
  auto expiry = now + std::chrono::seconds(token_ttl_seconds);
  std::time_t exp_time = std::chrono::system_clock::to_time_t(expiry);
  std::tm utc_tm{};
#ifdef _WIN32
  gmtime_s(&utc_tm, &exp_time);
#else
  gmtime_r(&exp_time, &utc_tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// ── Audit ───────────────────────────────────────────────────────────────

void AppContext::append_audit(const AuditEvent &event) {
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
                                : "\"" + json_escape(event.payloadJson) + "\"")
        << "}\n";
  }
}

void AppContext::append_session_event(const std::string &type,
                                     const Session &session) {
  SessionEvent event;
  event.id = next_event_id.fetch_add(1);
  event.type = type;
  event.createdAt = now_utc();
  event.payloadJson = build_session_payload_json(session);
  std::lock_guard<std::mutex> lock(event_mutex);
  session_events.push_back(event);
  if (session_events.size() > 200) {
    session_events.erase(session_events.begin(), session_events.begin() + 50);
  }
}

// ── Database initialization ─────────────────────────────────────────────

void AppContext::init_database() {
  std::string err;
  if (!sqlite.open("endoriumfort.db", err)) {
    std::cerr << "SQLite open failed: " << err << '\n';
    return;
  }

  const std::string session_schema =
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
  if (!sqlite.exec(session_schema, err))
    std::cerr << "SQLite schema failed: " << err << '\n';
  sqlite.exec("ALTER TABLE sessions ADD COLUMN port INTEGER DEFAULT 22;", err);

  const std::string resource_schema =
      "CREATE TABLE IF NOT EXISTS resources ("
      "id INTEGER PRIMARY KEY,"
      "name TEXT NOT NULL,"
      "target TEXT NOT NULL,"
      "protocol TEXT NOT NULL,"
      "port INTEGER NOT NULL DEFAULT 22,"
      "description TEXT,"
      "image_url TEXT,"
      "created_at TEXT NOT NULL,"
      "updated_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(resource_schema, err))
    std::cerr << "SQLite resource schema failed: " << err << '\n';
  sqlite.exec("ALTER TABLE resources ADD COLUMN image_url TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN http_username TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN http_password TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN ssh_username TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN ssh_password TEXT;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN require_access_justification INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN require_dual_approval INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN enable_command_guard INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN adaptive_access_policy INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE resources ADD COLUMN risk_level TEXT DEFAULT 'low';", err);

  const std::string user_schema =
      "CREATE TABLE IF NOT EXISTS users ("
      "id INTEGER PRIMARY KEY,"
      "username TEXT NOT NULL UNIQUE,"
      "password TEXT NOT NULL,"
      "role TEXT NOT NULL,"
      "created_at TEXT NOT NULL,"
      "updated_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(user_schema, err))
    std::cerr << "SQLite user schema failed: " << err << '\n';

  const std::string perm_schema =
      "CREATE TABLE IF NOT EXISTS user_resource_permissions ("
      "id INTEGER PRIMARY KEY,"
      "user_id INTEGER NOT NULL,"
      "resource_id INTEGER NOT NULL,"
      "created_at TEXT NOT NULL,"
      "FOREIGN KEY (user_id) REFERENCES users(id),"
      "FOREIGN KEY (resource_id) REFERENCES resources(id),"
      "UNIQUE(user_id, resource_id)"
      ");";
  if (!sqlite.exec(perm_schema, err))
    std::cerr << "SQLite user_resource_permissions schema failed: " << err << '\n';

  const std::string perm_override_schema =
      "CREATE TABLE IF NOT EXISTS user_permission_overrides ("
      "id INTEGER PRIMARY KEY,"
      "user_id INTEGER NOT NULL,"
      "permission TEXT NOT NULL,"
      "effect TEXT NOT NULL,"
      "created_at TEXT NOT NULL,"
      "updated_at TEXT NOT NULL,"
      "FOREIGN KEY (user_id) REFERENCES users(id),"
      "UNIQUE(user_id, permission)"
      ");";
  if (!sqlite.exec(perm_override_schema, err))
    std::cerr << "SQLite user_permission_overrides schema failed: " << err
              << '\n';

  // Session recordings table
  const std::string rec_schema =
      "CREATE TABLE IF NOT EXISTS session_recordings ("
      "id INTEGER PRIMARY KEY,"
      "session_id INTEGER NOT NULL,"
      "file_path TEXT NOT NULL,"
      "created_at TEXT NOT NULL,"
      "closed_at TEXT,"
      "duration_ms INTEGER DEFAULT 0,"
      "file_size INTEGER DEFAULT 0,"
      "FOREIGN KEY (session_id) REFERENCES sessions(id)"
      ");";
  if (!sqlite.exec(rec_schema, err))
    std::cerr << "SQLite session_recordings schema failed: " << err << '\n';

  const std::string access_req_schema =
      "CREATE TABLE IF NOT EXISTS access_requests ("
      "id INTEGER PRIMARY KEY,"
      "resource_id INTEGER NOT NULL,"
      "resource_name TEXT,"
      "requester TEXT NOT NULL,"
      "requester_role TEXT NOT NULL,"
      "status TEXT NOT NULL,"
      "justification TEXT,"
      "ticket_id TEXT,"
      "created_at TEXT NOT NULL,"
      "reviewed_at TEXT,"
      "reviewed_by TEXT"
      ");";
  if (!sqlite.exec(access_req_schema, err))
    std::cerr << "SQLite access_requests schema failed: " << err << '\n';

  const std::string behavior_schema =
      "CREATE TABLE IF NOT EXISTS user_behavior_stats ("
      "username TEXT PRIMARY KEY,"
      "total_sessions INTEGER NOT NULL DEFAULT 0,"
      "total_duration_ms INTEGER NOT NULL DEFAULT 0,"
      "total_input_events INTEGER NOT NULL DEFAULT 0,"
      "updated_at TEXT NOT NULL"
      ");";
  if (!sqlite.exec(behavior_schema, err))
    std::cerr << "SQLite user_behavior_stats schema failed: " << err << '\n';

  const std::string ephemeral_schema =
      "CREATE TABLE IF NOT EXISTS ephemeral_credentials ("
      "id INTEGER PRIMARY KEY,"
      "resource_id INTEGER NOT NULL,"
      "requester TEXT NOT NULL,"
      "username TEXT NOT NULL,"
      "status TEXT NOT NULL,"
      "issued_at TEXT NOT NULL,"
      "expires_at TEXT NOT NULL,"
      "used_at TEXT"
      ");";
  if (!sqlite.exec(ephemeral_schema, err))
    std::cerr << "SQLite ephemeral_credentials schema failed: " << err << '\n';

  // TOTP columns on users
  sqlite.exec("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0;", err);
  sqlite.exec("ALTER TABLE users ADD COLUMN totp_secret TEXT;", err);

  // Load data into memory
  load_sessions_from_db();
  load_resources_from_db();
  load_users_from_db();
  load_recordings_from_db();
  load_access_requests_from_db();
  load_ephemeral_credentials_from_db();
}

void AppContext::seed_default_admin() {
  std::lock_guard<std::mutex> lock(user_mutex);
  if (!users.empty()) return;

  UserAccount admin;
  admin.id = next_user_id.fetch_add(1);
  admin.username = "admin";
  admin.password = crypto::hash_password("Admin123");
  admin.role = "admin";
  admin.createdAt = now_utc();
  admin.updatedAt = admin.createdAt;
  users[admin.id] = admin;
  if (!insert_user(admin))
    std::cerr << "Failed to persist default admin user" << '\n';
  else
    std::cerr << "[SECURITY] Default admin created — change password immediately!" << '\n';
}

// ── Session CRUD ────────────────────────────────────────────────────────

void AppContext::load_sessions_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, target, user, protocol, port, status, created_at, "
      "terminated_at FROM sessions";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite select failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(session_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      Session s;
      s.id = sqlite3_column_int(stmt, 0);
      s.target  = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
      s.user    = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      s.protocol = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      s.port = sqlite3_column_int(stmt, 4);
      if (s.port <= 0) s.port = 22;
      s.status  = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      s.createdAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
      const unsigned char *term = sqlite3_column_text(stmt, 7);
      if (term) s.terminatedAt = reinterpret_cast<const char *>(term);
      sessions[s.id] = s;
      if (s.id > max_id) max_id = s.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_session_id.store(max_id + 1);
}

bool AppContext::insert_session(const Session &session) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO sessions (id, target, user, protocol, status, port, "
      "created_at, terminated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite insert prepare failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, session.id);
  sqlite3_bind_text(stmt, 2, session.target.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, session.user.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, session.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, session.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 6, session.port);
  sqlite3_bind_text(stmt, 7, session.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  if (session.terminatedAt.empty()) sqlite3_bind_null(stmt, 8);
  else sqlite3_bind_text(stmt, 8, session.terminatedAt.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_session_termination(const Session &session) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql = "UPDATE sessions SET status = ?, terminated_at = ? WHERE id = ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite update prepare failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, session.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, session.terminatedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, session.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

void AppContext::terminate_session(int session_id, const std::string &actor,
                                  const std::string &role,
                                  const std::string &event_type) {
  Session terminated;
  {
    std::lock_guard<std::mutex> lock(session_mutex);
    auto it = sessions.find(session_id);
    if (it == sessions.end() || it->second.status != "active") return;
    it->second.status = "terminated";
    it->second.terminatedAt = now_utc();
    terminated = it->second;
  }
  if (!update_session_termination(terminated)) return;

  AuditEvent event;
  event.id = next_audit_id.fetch_add(1);
  event.type = event_type;
  event.actor = actor;
  event.role = role;
  event.createdAt = now_utc();
  event.payloadJson = build_session_payload_json(terminated);
  event.payloadIsJson = true;
  append_audit(event);
  append_session_event(event_type, terminated);

  // Behavioral baseline update: maintain per-user stats and emit anomaly
  // events when command volume spikes significantly vs historical average.
  const int64_t input_events = consume_session_input_events(session_id);
  int prior_sessions = 0;
  int64_t prior_inputs = 0;
  bool behavior_ok = true;
  if (sqlite.db) {
    std::lock_guard<std::mutex> lock(sqlite.mutex);
    sqlite3_stmt *stmt = nullptr;
    const char *select_sql =
        "SELECT total_sessions, total_input_events FROM user_behavior_stats "
        "WHERE username=?";
    if (sqlite3_prepare_v2(sqlite.db, select_sql, -1, &stmt, nullptr) ==
        SQLITE_OK) {
      sqlite3_bind_text(stmt, 1, terminated.user.c_str(), -1, SQLITE_TRANSIENT);
      if (sqlite3_step(stmt) == SQLITE_ROW) {
        prior_sessions = sqlite3_column_int(stmt, 0);
        prior_inputs = sqlite3_column_int64(stmt, 1);
      }
    }
    sqlite3_finalize(stmt);

    const char *upsert_sql =
        "INSERT INTO user_behavior_stats "
        "(username,total_sessions,total_duration_ms,total_input_events,"
        "updated_at) "
        "VALUES (?,1,?, ?,?) "
        "ON CONFLICT(username) DO UPDATE SET "
        "total_sessions=total_sessions+1,"
        "total_duration_ms=total_duration_ms+excluded.total_duration_ms,"
        "total_input_events=total_input_events+excluded.total_input_events,"
        "updated_at=excluded.updated_at";
    stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, upsert_sql, -1, &stmt, nullptr) !=
        SQLITE_OK) {
      behavior_ok = false;
    } else {
      int64_t duration_ms = 0;
      if (!terminated.createdAt.empty() && !terminated.terminatedAt.empty()) {
        duration_ms = 0;  // ISO conversion omitted; event counts are primary signal.
      }
      std::string updated_at = now_utc();
      sqlite3_bind_text(stmt, 1, terminated.user.c_str(), -1, SQLITE_TRANSIENT);
      sqlite3_bind_int64(stmt, 2, duration_ms);
      sqlite3_bind_int64(stmt, 3, input_events);
      sqlite3_bind_text(stmt, 4, updated_at.c_str(), -1, SQLITE_TRANSIENT);
      behavior_ok = sqlite3_step(stmt) == SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
  }

  if (behavior_ok && prior_sessions >= 5) {
    const double avg_inputs =
        static_cast<double>(prior_inputs) / static_cast<double>(prior_sessions);
    if (input_events > 0 && avg_inputs > 0.0 &&
        static_cast<double>(input_events) > avg_inputs * 3.0) {
      AuditEvent anomaly;
      anomaly.id = next_audit_id.fetch_add(1);
      anomaly.type = "behavior.anomaly.command_spike";
      anomaly.actor = terminated.user;
      anomaly.role = "operator";
      anomaly.createdAt = now_utc();
      anomaly.payloadJson =
          "{\"sessionId\":" + std::to_string(session_id) +
          ",\"inputEvents\":" + std::to_string(input_events) +
          ",\"historicalAvg\":" +
          std::to_string(static_cast<int64_t>(avg_inputs)) + "}";
      anomaly.payloadIsJson = true;
      append_audit(anomaly);
    }
  }
}

// ── Resource CRUD ───────────────────────────────────────────────────────

void AppContext::load_resources_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, name, target, protocol, port, description, image_url, "
      "http_username, http_password, created_at, updated_at, "
      "ssh_username, ssh_password, require_access_justification, "
      "require_dual_approval, enable_command_guard, adaptive_access_policy, "
      "risk_level FROM resources";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite resource select failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(resource_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      Resource r;
      r.id       = sqlite3_column_int(stmt, 0);
      r.name     = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
      r.target   = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      r.protocol = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      r.port     = sqlite3_column_int(stmt, 4);
      if (r.port <= 0) r.port = 22;
      auto desc  = sqlite3_column_text(stmt, 5);
      if (desc) r.description = reinterpret_cast<const char *>(desc);
      auto img   = sqlite3_column_text(stmt, 6);
      if (img) r.imageUrl = reinterpret_cast<const char *>(img);
      auto hu    = sqlite3_column_text(stmt, 7);
      if (hu) r.httpUsername = reinterpret_cast<const char *>(hu);
      auto hp    = sqlite3_column_text(stmt, 8);
      if (hp) r.httpPassword = reinterpret_cast<const char *>(hp);
      r.createdAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 9));
      r.updatedAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 10));
      auto su    = sqlite3_column_text(stmt, 11);
      if (su) r.sshUsername = reinterpret_cast<const char *>(su);
      auto sp    = sqlite3_column_text(stmt, 12);
      if (sp) r.sshPassword = reinterpret_cast<const char *>(sp);
      r.requireAccessJustification = sqlite3_column_int(stmt, 13) != 0;
      r.requireDualApproval = sqlite3_column_int(stmt, 14) != 0;
      r.enableCommandGuard = sqlite3_column_int(stmt, 15) != 0;
      r.adaptiveAccessPolicy = sqlite3_column_int(stmt, 16) != 0;
      auto rl = sqlite3_column_text(stmt, 17);
      if (rl) r.riskLevel = reinterpret_cast<const char *>(rl);
      if (r.riskLevel.empty()) r.riskLevel = "low";
      resources[r.id] = r;
      if (r.id > max_id) max_id = r.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_resource_id.store(max_id + 1);
}

bool AppContext::insert_resource(const Resource &r) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO resources (id, name, target, protocol, port, description, "
      "image_url, http_username, http_password, created_at, updated_at, "
      "ssh_username, ssh_password, require_access_justification, "
      "require_dual_approval, enable_command_guard, adaptive_access_policy, "
      "risk_level) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite resource insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, r.id);
  sqlite3_bind_text(stmt, 2, r.name.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, r.target.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, r.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 5, r.port);
  r.description.empty() ? sqlite3_bind_null(stmt, 6)
      : sqlite3_bind_text(stmt, 6, r.description.c_str(), -1, SQLITE_TRANSIENT);
  r.imageUrl.empty() ? sqlite3_bind_null(stmt, 7)
      : sqlite3_bind_text(stmt, 7, r.imageUrl.c_str(), -1, SQLITE_TRANSIENT);
  r.httpUsername.empty() ? sqlite3_bind_null(stmt, 8)
      : sqlite3_bind_text(stmt, 8, r.httpUsername.c_str(), -1, SQLITE_TRANSIENT);
  r.httpPassword.empty() ? sqlite3_bind_null(stmt, 9)
      : sqlite3_bind_text(stmt, 9, r.httpPassword.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 10, r.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 11, r.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  r.sshUsername.empty() ? sqlite3_bind_null(stmt, 12)
      : sqlite3_bind_text(stmt, 12, r.sshUsername.c_str(), -1, SQLITE_TRANSIENT);
  r.sshPassword.empty() ? sqlite3_bind_null(stmt, 13)
      : sqlite3_bind_text(stmt, 13, r.sshPassword.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 14, r.requireAccessJustification ? 1 : 0);
  sqlite3_bind_int(stmt, 15, r.requireDualApproval ? 1 : 0);
  sqlite3_bind_int(stmt, 16, r.enableCommandGuard ? 1 : 0);
  sqlite3_bind_int(stmt, 17, r.adaptiveAccessPolicy ? 1 : 0);
  sqlite3_bind_text(stmt, 18, r.riskLevel.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite resource insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_resource_db(const Resource &r) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE resources SET name=?, target=?, protocol=?, port=?, "
      "description=?, image_url=?, http_username=?, http_password=?, "
      "updated_at=?, ssh_username=?, ssh_password=?, "
      "require_access_justification=?, require_dual_approval=?, "
      "enable_command_guard=?, adaptive_access_policy=?, risk_level=? "
      "WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite resource update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, r.name.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, r.target.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, r.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, r.port);
  r.description.empty() ? sqlite3_bind_null(stmt, 5)
      : sqlite3_bind_text(stmt, 5, r.description.c_str(), -1, SQLITE_TRANSIENT);
  r.imageUrl.empty() ? sqlite3_bind_null(stmt, 6)
      : sqlite3_bind_text(stmt, 6, r.imageUrl.c_str(), -1, SQLITE_TRANSIENT);
  r.httpUsername.empty() ? sqlite3_bind_null(stmt, 7)
      : sqlite3_bind_text(stmt, 7, r.httpUsername.c_str(), -1, SQLITE_TRANSIENT);
  r.httpPassword.empty() ? sqlite3_bind_null(stmt, 8)
      : sqlite3_bind_text(stmt, 8, r.httpPassword.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, r.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  r.sshUsername.empty() ? sqlite3_bind_null(stmt, 10)
      : sqlite3_bind_text(stmt, 10, r.sshUsername.c_str(), -1, SQLITE_TRANSIENT);
  r.sshPassword.empty() ? sqlite3_bind_null(stmt, 11)
      : sqlite3_bind_text(stmt, 11, r.sshPassword.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 12, r.requireAccessJustification ? 1 : 0);
  sqlite3_bind_int(stmt, 13, r.requireDualApproval ? 1 : 0);
  sqlite3_bind_int(stmt, 14, r.enableCommandGuard ? 1 : 0);
  sqlite3_bind_int(stmt, 15, r.adaptiveAccessPolicy ? 1 : 0);
  sqlite3_bind_text(stmt, 16, r.riskLevel.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 17, r.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite resource update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::delete_resource_db(int resource_id) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql = "DELETE FROM resources WHERE id = ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite resource delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, resource_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite resource delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── User CRUD ───────────────────────────────────────────────────────────

void AppContext::load_users_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, username, password, role, created_at, updated_at, "
      "totp_enabled, totp_secret FROM users";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite user select failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      UserAccount u;
      u.id       = sqlite3_column_int(stmt, 0);
      u.username = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
      u.password = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      u.role     = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      u.createdAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
      u.updatedAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      u.totpEnabled = sqlite3_column_int(stmt, 6) != 0;
      auto secret = sqlite3_column_text(stmt, 7);
      if (secret) u.totpSecret = reinterpret_cast<const char *>(secret);
      users[u.id] = u;
      if (u.id > max_id) max_id = u.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_user_id.store(max_id + 1);
}

bool AppContext::insert_user(const UserAccount &u) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO users (id, username, password, role, created_at, "
      "updated_at) VALUES (?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite user insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, u.id);
  sqlite3_bind_text(stmt, 2, u.username.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, u.password.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, u.role.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, u.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, u.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite user insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_user_db(const UserAccount &u) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql = "UPDATE users SET password=?, role=?, updated_at=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite user update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, u.password.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, u.role.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, u.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, u.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite user update failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::delete_user_db(int user_id) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql = "DELETE FROM users WHERE id = ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite user delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, user_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite user delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── Permissions ─────────────────────────────────────────────────────────

std::vector<int> AppContext::get_resource_permissions(int user_id) {
  std::vector<int> ids;
  if (!sqlite.db) return ids;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "SELECT resource_id FROM user_resource_permissions WHERE user_id = ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite perm select failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return ids;
  }
  sqlite3_bind_int(stmt, 1, user_id);
  while (sqlite3_step(stmt) == SQLITE_ROW)
    ids.push_back(sqlite3_column_int(stmt, 0));
  sqlite3_finalize(stmt);
  return ids;
}

bool AppContext::grant_resource_permission(int user_id, int resource_id) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT OR IGNORE INTO user_resource_permissions "
      "(user_id, resource_id, created_at) VALUES (?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite perm insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_int(stmt, 2, resource_id);
  sqlite3_bind_text(stmt, 3, now_utc().c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite perm insert failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::revoke_resource_permission(int user_id, int resource_id) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "DELETE FROM user_resource_permissions WHERE user_id=? AND resource_id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite perm delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_int(stmt, 2, resource_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok) std::cerr << "SQLite perm delete failed: " << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

std::unordered_map<std::string, bool> AppContext::get_user_permission_overrides(
    int user_id) {
  std::unordered_map<std::string, bool> overrides;
  if (!sqlite.db) return overrides;

  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "SELECT permission, effect FROM user_permission_overrides WHERE user_id = ?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite permission override select failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return overrides;
  }
  sqlite3_bind_int(stmt, 1, user_id);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const auto *perm = sqlite3_column_text(stmt, 0);
    const auto *effect = sqlite3_column_text(stmt, 1);
    if (!perm || !effect) continue;
    std::string permission = reinterpret_cast<const char *>(perm);
    std::string effect_str = reinterpret_cast<const char *>(effect);
    overrides[permission] = effect_str == "allow";
  }
  sqlite3_finalize(stmt);
  return overrides;
}

std::unordered_set<std::string> AppContext::get_effective_permissions(
    int user_id, const std::string &role) {
  auto effective = default_permissions_for_role(role);
  const auto overrides = get_user_permission_overrides(user_id);
  for (const auto &entry : overrides) {
    if (entry.second) {
      effective.insert(entry.first);
    } else {
      effective.erase(entry.first);
      if (entry.first == "*") effective.erase("*");
    }
  }
  return effective;
}

bool AppContext::has_permission(int user_id, const std::string &role,
                                const std::string &permission) {
  if (!is_known_permission(permission)) return false;
  const auto effective = get_effective_permissions(user_id, role);
  return permissions_contain(effective, permission);
}

bool AppContext::set_user_permission_override(
    int user_id, const std::string &permission,
    std::optional<bool> allow_effect) {
  if (!is_known_permission(permission) && permission != "*") return false;
  if (!sqlite.db) return true;

  std::lock_guard<std::mutex> lock(sqlite.mutex);
  if (!allow_effect.has_value()) {
    const char *sql =
        "DELETE FROM user_permission_overrides WHERE user_id=? AND permission=?";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
      std::cerr << "SQLite permission override delete failed: "
                << sqlite3_errmsg(sqlite.db) << '\n';
      return false;
    }
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_text(stmt, 2, permission.c_str(), -1, SQLITE_TRANSIENT);
    const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
    if (!ok)
      std::cerr << "SQLite permission override delete failed: "
                << sqlite3_errmsg(sqlite.db) << '\n';
    sqlite3_finalize(stmt);
    return ok;
  }

  const char *sql =
      "INSERT INTO user_permission_overrides "
      "(user_id, permission, effect, created_at, updated_at) "
      "VALUES (?, ?, ?, ?, ?) "
      "ON CONFLICT(user_id, permission) DO UPDATE SET "
      "effect=excluded.effect, updated_at=excluded.updated_at";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite permission override upsert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  const std::string now = now_utc();
  const std::string effect = *allow_effect ? "allow" : "deny";
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_text(stmt, 2, permission.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, effect.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, now.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, now.c_str(), -1, SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite permission override upsert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── 2FA / TOTP ─────────────────────────────────────────────────────────

bool AppContext::update_user_totp(int user_id, bool enabled,
                                   const std::string &secret) {
  // Update in-memory
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto it = users.find(user_id);
    if (it == users.end()) return false;
    it->second.totpEnabled = enabled;
    it->second.totpSecret = secret;
  }
  // Persist
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE users SET totp_enabled=?, totp_secret=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite TOTP update failed: " << sqlite3_errmsg(sqlite.db)
              << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, enabled ? 1 : 0);
  secret.empty()
      ? sqlite3_bind_null(stmt, 2)
      : sqlite3_bind_text(stmt, 2, secret.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, user_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite TOTP update failed: " << sqlite3_errmsg(sqlite.db)
              << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── Password management ────────────────────────────────────────────────

bool AppContext::update_user_password_hash(int user_id,
                                           const std::string &hash) {
  {
    std::lock_guard<std::mutex> lock(user_mutex);
    auto it = users.find(user_id);
    if (it == users.end()) return false;
    it->second.password = hash;
    it->second.updatedAt = now_utc();
  }
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql = "UPDATE users SET password=?, updated_at=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite password update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  std::string ts = now_utc();
  sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, ts.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 3, user_id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite password update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── Session Recordings ─────────────────────────────────────────────────

void AppContext::init_recordings_dir() {
  // Create recordings directory if it doesn't exist
#ifdef _WIN32
  _mkdir(recordings_dir.c_str());
#else
  mkdir(recordings_dir.c_str(), 0755);
#endif
}

void AppContext::load_recordings_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, session_id, file_path, created_at, closed_at, "
      "duration_ms, file_size FROM session_recordings";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite recording select failed: " << sqlite3_errmsg(sqlite.db)
              << '\n';
    return;
  }
  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(recording_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      SessionRecording r;
      r.id = sqlite3_column_int(stmt, 0);
      r.sessionId = sqlite3_column_int(stmt, 1);
      r.filePath =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      r.createdAt =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      auto closed = sqlite3_column_text(stmt, 4);
      if (closed) r.closedAt = reinterpret_cast<const char *>(closed);
      r.durationMs = sqlite3_column_int64(stmt, 5);
      r.fileSize = static_cast<size_t>(sqlite3_column_int64(stmt, 6));
      recordings[r.id] = r;
      if (r.id > max_id) max_id = r.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_recording_id.store(max_id + 1);
}

bool AppContext::insert_recording(const SessionRecording &rec) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO session_recordings (id, session_id, file_path, created_at) "
      "VALUES (?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite recording insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, rec.id);
  sqlite3_bind_int(stmt, 2, rec.sessionId);
  sqlite3_bind_text(stmt, 3, rec.filePath.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite recording insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_recording_close(const SessionRecording &rec) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE session_recordings SET closed_at=?, duration_ms=?, file_size=? "
      "WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite recording update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, rec.closedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(stmt, 2, rec.durationMs);
  sqlite3_bind_int64(stmt, 3, static_cast<int64_t>(rec.fileSize));
  sqlite3_bind_int(stmt, 4, rec.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite recording update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── Access Requests ────────────────────────────────────────────────────

void AppContext::load_access_requests_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, resource_id, resource_name, requester, requester_role, "
      "status, justification, ticket_id, created_at, reviewed_at, reviewed_by "
      "FROM access_requests";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite access request select failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }

  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(access_request_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      AccessRequest req;
      req.id = sqlite3_column_int(stmt, 0);
      req.resourceId = sqlite3_column_int(stmt, 1);
      auto name = sqlite3_column_text(stmt, 2);
      if (name) req.resourceName = reinterpret_cast<const char *>(name);
      req.requester = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      req.requesterRole =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
      req.status = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      auto just = sqlite3_column_text(stmt, 6);
      if (just) req.justification = reinterpret_cast<const char *>(just);
      auto ticket = sqlite3_column_text(stmt, 7);
      if (ticket) req.ticketId = reinterpret_cast<const char *>(ticket);
      req.createdAt = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 8));
      auto reviewed_at = sqlite3_column_text(stmt, 9);
      if (reviewed_at) req.reviewedAt = reinterpret_cast<const char *>(reviewed_at);
      auto reviewed_by = sqlite3_column_text(stmt, 10);
      if (reviewed_by) req.reviewedBy = reinterpret_cast<const char *>(reviewed_by);

      access_requests[req.id] = req;
      if (req.id > max_id) max_id = req.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_access_request_id.store(max_id + 1);
}

bool AppContext::insert_access_request(const AccessRequest &req) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO access_requests "
      "(id, resource_id, resource_name, requester, requester_role, status, "
      "justification, ticket_id, created_at, reviewed_at, reviewed_by) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite access request insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_int(stmt, 1, req.id);
  sqlite3_bind_int(stmt, 2, req.resourceId);
  req.resourceName.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, req.resourceName.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, req.requester.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, req.requesterRole.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, req.status.c_str(), -1, SQLITE_TRANSIENT);
  req.justification.empty()
      ? sqlite3_bind_null(stmt, 7)
      : sqlite3_bind_text(stmt, 7, req.justification.c_str(), -1,
                          SQLITE_TRANSIENT);
  req.ticketId.empty()
      ? sqlite3_bind_null(stmt, 8)
      : sqlite3_bind_text(stmt, 8, req.ticketId.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, req.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  req.reviewedAt.empty()
      ? sqlite3_bind_null(stmt, 10)
      : sqlite3_bind_text(stmt, 10, req.reviewedAt.c_str(), -1,
                          SQLITE_TRANSIENT);
  req.reviewedBy.empty()
      ? sqlite3_bind_null(stmt, 11)
      : sqlite3_bind_text(stmt, 11, req.reviewedBy.c_str(), -1,
                          SQLITE_TRANSIENT);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite access request insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_access_request(const AccessRequest &req) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE access_requests SET status=?, reviewed_at=?, reviewed_by=? "
      "WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite access request update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }
  sqlite3_bind_text(stmt, 1, req.status.c_str(), -1, SQLITE_TRANSIENT);
  req.reviewedAt.empty()
      ? sqlite3_bind_null(stmt, 2)
      : sqlite3_bind_text(stmt, 2, req.reviewedAt.c_str(), -1,
                          SQLITE_TRANSIENT);
  req.reviewedBy.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, req.reviewedBy.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, req.id);
  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite access request update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

// ── Runtime Behavior Counters ─────────────────────────────────────────

void AppContext::increment_session_input_event(int session_id) {
  if (session_id <= 0) return;
  std::lock_guard<std::mutex> lock(behavior_mutex);
  session_input_events[session_id] += 1;
}

int64_t AppContext::consume_session_input_events(int session_id) {
  std::lock_guard<std::mutex> lock(behavior_mutex);
  auto it = session_input_events.find(session_id);
  if (it == session_input_events.end()) return 0;
  const int64_t value = it->second;
  session_input_events.erase(it);
  return value;
}

// ── Ephemeral Credential Leases ───────────────────────────────────────

void AppContext::load_ephemeral_credentials_from_db() {
  if (!sqlite.db) return;
  std::lock_guard<std::mutex> db_lock(sqlite.mutex);
  const char *sql =
      "SELECT id, resource_id, requester, username, status, issued_at, "
      "expires_at, used_at FROM ephemeral_credentials";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite ephemeral credential select failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return;
  }

  int max_id = 0;
  {
    std::lock_guard<std::mutex> lock(ephemeral_credential_mutex);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      EphemeralCredentialLease lease;
      lease.id = sqlite3_column_int(stmt, 0);
      lease.resourceId = sqlite3_column_int(stmt, 1);
      lease.requester =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 2));
      lease.username =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3));
      lease.status = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 4));
      lease.issuedAt =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 5));
      lease.expiresAt =
          reinterpret_cast<const char *>(sqlite3_column_text(stmt, 6));
      auto used_at = sqlite3_column_text(stmt, 7);
      if (used_at) lease.usedAt = reinterpret_cast<const char *>(used_at);
      ephemeral_credentials[lease.id] = lease;
      if (lease.id > max_id) max_id = lease.id;
    }
  }
  sqlite3_finalize(stmt);
  if (max_id > 0) next_ephemeral_credential_id.store(max_id + 1);
}

bool AppContext::insert_ephemeral_credential(
    const EphemeralCredentialLease &lease) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "INSERT INTO ephemeral_credentials "
      "(id, resource_id, requester, username, status, issued_at, expires_at, "
      "used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite ephemeral credential insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }

  sqlite3_bind_int(stmt, 1, lease.id);
  sqlite3_bind_int(stmt, 2, lease.resourceId);
  sqlite3_bind_text(stmt, 3, lease.requester.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, lease.username.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, lease.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, lease.issuedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 7, lease.expiresAt.c_str(), -1, SQLITE_TRANSIENT);
  lease.usedAt.empty()
      ? sqlite3_bind_null(stmt, 8)
      : sqlite3_bind_text(stmt, 8, lease.usedAt.c_str(), -1, SQLITE_TRANSIENT);

  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite ephemeral credential insert failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}

bool AppContext::update_ephemeral_credential(
    const EphemeralCredentialLease &lease) {
  if (!sqlite.db) return true;
  std::lock_guard<std::mutex> lock(sqlite.mutex);
  const char *sql =
      "UPDATE ephemeral_credentials SET status=?, expires_at=?, used_at=? "
      "WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    std::cerr << "SQLite ephemeral credential update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
    return false;
  }

  sqlite3_bind_text(stmt, 1, lease.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, lease.expiresAt.c_str(), -1, SQLITE_TRANSIENT);
  lease.usedAt.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, lease.usedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, lease.id);

  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  if (!ok)
    std::cerr << "SQLite ephemeral credential update failed: "
              << sqlite3_errmsg(sqlite.db) << '\n';
  sqlite3_finalize(stmt);
  return ok;
}
