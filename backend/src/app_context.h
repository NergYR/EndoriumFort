#pragma once
// ─── EndoriumFort — Application context ─────────────────────────────────
// Holds all shared state and provides core operations (auth, audit, CRUD).

#include "crow.h"
#include "models.h"
#include "database.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

// ── Rate limiting state ──
struct RateLimitEntry {
  std::queue<std::chrono::steady_clock::time_point> attempts;
};

struct AppContext {
  // ── Session state ──
  std::mutex session_mutex;
  std::unordered_map<int, Session> sessions;
  std::atomic<int> next_session_id{1};

  // ── Auth state ──
  std::mutex auth_mutex;
  std::unordered_map<std::string, AuthSession> auth_sessions;
  int token_ttl_seconds = 3600;  // 1 hour default

  // ── Resource state ──
  std::mutex resource_mutex;
  std::unordered_map<int, Resource> resources;
  std::atomic<int> next_resource_id{1};

  // ── User state ──
  std::mutex user_mutex;
  std::unordered_map<int, UserAccount> users;
  std::atomic<int> next_user_id{1};

  // ── Audit state ──
  std::mutex audit_mutex;
  std::vector<AuditEvent> audit_events;
  std::atomic<int> next_audit_id{1};
  std::string audit_path = "audit-log.jsonl";

  // ── Session recordings ──
  std::mutex recording_mutex;
  std::unordered_map<int, SessionRecording> recordings;
  std::atomic<int> next_recording_id{1};
  std::string recordings_dir = "recordings";

  // ── Proxy cookie jar ──
  std::mutex proxy_cookie_mutex;
  std::unordered_map<std::string, std::unordered_map<std::string, std::string>>
      proxy_cookie_jar;

  // ── SSE events ──
  std::mutex event_mutex;
  std::vector<SessionEvent> session_events;
  std::atomic<int> next_event_id{1};

  // ── Rate limiting ──
  std::mutex rate_limit_mutex;
  std::unordered_map<std::string, RateLimitEntry> rate_limit_map;
  int rate_limit_max_attempts = 10;  // max attempts per window
  std::chrono::seconds rate_limit_window{300};  // 5 minute window

  // ── Database ──
  SqliteDb sqlite;

  // ── SSH session closure callback ──
  std::function<void(int)> close_ssh_for_session = [](int) {};

  // ── Tunnel state ──
  std::mutex tunnel_mutex;
  std::unordered_map<crow::websocket::connection *,
                     std::shared_ptr<TunnelState>>
      tunnel_connections;

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
  // ── SSH WebSocket state ──
  std::mutex ws_mutex;
  std::unordered_map<crow::websocket::connection *,
                     std::shared_ptr<SshConnection>>
      ws_connections;

  // ── Shadow (admin live monitoring) state ──
  std::mutex shadow_mutex;
  std::unordered_map<int, std::vector<crow::websocket::connection *>>
      shadow_connections;  // session_id -> list of shadow watchers
#endif
#endif

  // ── Core operations ──
  std::string generate_token();
  std::optional<AuthSession> find_auth(const crow::request &req);
  std::optional<AuthSession> find_auth_by_token(const std::string &token);
  void append_audit(const AuditEvent &event);
  void append_session_event(const std::string &type, const Session &session);
  bool invalidate_token(const std::string &token);
  void invalidate_user_tokens(int user_id);
  void cleanup_expired_tokens();
  std::string compute_expiry();

  // ── Security ──
  bool check_rate_limit(const std::string &key);
  bool is_safe_target(const std::string &host);

  // ── DB init ──
  void init_database();
  void seed_default_admin();

  // ── Session CRUD ──
  void load_sessions_from_db();
  bool insert_session(const Session &session);
  bool update_session_termination(const Session &session);
  void terminate_session(int session_id, const std::string &actor,
                         const std::string &role, const std::string &event_type);

  // ── Resource CRUD ──
  void load_resources_from_db();
  bool insert_resource(const Resource &resource);
  bool update_resource_db(const Resource &resource);
  bool delete_resource_db(int resource_id);

  // ── User CRUD ──
  void load_users_from_db();
  bool insert_user(const UserAccount &user);
  bool update_user_db(const UserAccount &user);
  bool delete_user_db(int user_id);

  // ── 2FA / TOTP ──
  bool update_user_totp(int user_id, bool enabled, const std::string &secret);

  // ── Password management ──
  bool update_user_password_hash(int user_id, const std::string &hash);

  // ── Session recordings ──
  void init_recordings_dir();
  bool insert_recording(const SessionRecording &rec);
  bool update_recording_close(const SessionRecording &rec);
  void load_recordings_from_db();

  // ── Permissions ──
  std::vector<int> get_resource_permissions(int user_id);
  bool grant_resource_permission(int user_id, int resource_id);
  bool revoke_resource_permission(int user_id, int resource_id);
};
