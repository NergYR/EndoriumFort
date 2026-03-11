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
#include <unordered_set>
#include <unordered_map>
#include <vector>

// ── Rate limiting state ──
struct RateLimitEntry {
  std::queue<std::chrono::steady_clock::time_point> attempts;
};

struct TunnelTicket {
  std::string ticket;
  std::string proof;
  std::string challenge;
  std::string signingKeyId;
  std::string serverAttestation;
  int userId = 0;
  std::string user;
  std::string role;
  int resourceId = 0;
  std::string issuedForIp;
  std::string issuedForUserAgent;
  std::string issuedAt;
  std::string expiresAt;
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

  // ── Session DNA chain (tamper-evident audit lineage) ──
  std::mutex session_dna_mutex;

  // ── Incident containment mode ──
  std::mutex containment_mutex;
  bool containment_mode_enabled = false;
  std::string containment_updated_at;
  std::string containment_updated_by;
  std::string containment_reason;

  // ── Active security incident lifecycle ──
  std::mutex incident_mutex;
  std::atomic<int> next_incident_id{1};
  bool incident_active = false;
  int incident_id = 0;
  int incident_critical_count = 0;
  int incident_window_seconds = 0;
  std::string incident_profile;
  std::string incident_title;
  std::string incident_summary;
  std::string incident_opened_at;
  std::string incident_opened_by;
  std::string incident_closed_at;
  std::string incident_closed_by;
  std::string incident_close_reason;

  // ── Access requests (dual control) ──
  std::mutex access_request_mutex;
  std::unordered_map<int, AccessRequest> access_requests;
  std::atomic<int> next_access_request_id{1};

  // ── Runtime session behavior counters ──
  std::mutex behavior_mutex;
  std::unordered_map<int, int64_t> session_input_events;

  // ── Ephemeral credential leases ──
  std::mutex ephemeral_credential_mutex;
  std::unordered_map<int, EphemeralCredentialLease> ephemeral_credentials;
  std::atomic<int> next_ephemeral_credential_id{1};

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

  // ── One-time tunnel tickets ──
  std::mutex tunnel_ticket_mutex;
  std::unordered_map<std::string, TunnelTicket> tunnel_tickets;
  int tunnel_ticket_ttl_seconds = 30;
  int tunnel_signature_max_skew_seconds = 45;

  // ── Tunnel nonce anti-replay cache ──
  std::mutex tunnel_nonce_mutex;
  std::unordered_map<std::string, int64_t> tunnel_seen_nonces;
  int tunnel_nonce_ttl_seconds = 90;

  // ── Tunnel cryptographic key-id rotation (agility window) ──
  std::mutex tunnel_signing_key_mutex;
  std::string tunnel_signing_key_current_id;
  std::string tunnel_signing_key_previous_id;
  std::string tunnel_signing_key_current_secret;
  std::string tunnel_signing_key_previous_secret;
  int64_t tunnel_signing_key_current_epoch = 0;
  int64_t tunnel_signing_key_previous_epoch = 0;
  int tunnel_signing_key_rotation_seconds = 300;
  int tunnel_signing_key_grace_seconds = 600;

  // ── Tunnel ticket issuance throttle ──
  std::mutex tunnel_ticket_issue_limit_mutex;
  std::unordered_map<int, RateLimitEntry> tunnel_ticket_issue_by_user;
  int tunnel_ticket_issue_max_attempts = 20;
  std::chrono::seconds tunnel_ticket_issue_window{60};

  // ── Relay control-plane state ──
  std::mutex relay_mutex;
  std::unordered_map<std::string, RelayNode> relays;
  std::unordered_map<int, std::string> resource_relay_bindings;
  std::string relay_enroll_secret;
  int relay_token_ttl_seconds = 86400;  // 24h
  int relay_heartbeat_stale_seconds = 90;

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
  bool is_safe_target(const std::string &host, bool allow_loopback = false);

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

  // ── Session DNA chain ──
  bool append_session_dna_entry(int session_id, int audit_event_id,
                                const std::string &event_type,
                                const std::string &payload_json,
                                const std::string &created_at);
  std::vector<SessionDnaEntry> get_session_dna_chain(int session_id);

  // ── Access request CRUD ──
  void load_access_requests_from_db();
  bool insert_access_request(const AccessRequest &req);
  bool update_access_request(const AccessRequest &req);

  // ── Behavior counters ──
  void increment_session_input_event(int session_id);
  int64_t consume_session_input_events(int session_id);

  // ── Ephemeral credential lease CRUD ──
  void load_ephemeral_credentials_from_db();
  bool insert_ephemeral_credential(const EphemeralCredentialLease &lease);
  bool update_ephemeral_credential(const EphemeralCredentialLease &lease);

  // ── Permissions ──
  std::vector<int> get_resource_permissions(int user_id);
  bool grant_resource_permission(int user_id, int resource_id);
  bool revoke_resource_permission(int user_id, int resource_id);

  // ── Granular permission overrides ──
  std::unordered_map<std::string, bool> get_user_permission_overrides(
      int user_id);
  std::unordered_set<std::string> get_effective_permissions(
      int user_id, const std::string &role);
  bool has_permission(int user_id, const std::string &role,
                      const std::string &permission);
  bool set_user_permission_override(int user_id, const std::string &permission,
                                    std::optional<bool> allow_effect);
};
