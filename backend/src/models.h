#pragma once
// ─── EndoriumFort — Data models ─────────────────────────────────────────
// Pure data structures used across the application.

#include <atomic>
#include <memory>
#include <string>
#include <thread>

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

struct Resource {
  int id = 0;
  std::string name;
  std::string target;
  std::string protocol;
  int port = 22;
  std::string description;
  std::string imageUrl;
  std::string httpUsername;
  std::string httpPassword;
  std::string sshUsername;
  std::string sshPassword;
  std::string createdAt;
  std::string updatedAt;
};

struct UserAccount {
  int id = 0;
  std::string username;
  std::string password;
  std::string role;
  std::string createdAt;
  std::string updatedAt;
  // 2FA / TOTP
  bool totpEnabled = false;
  std::string totpSecret;  // Base32-encoded secret
};

struct AuthSession {
  int userId = 0;
  std::string user;
  std::string role;
  std::string token;
  std::string issuedAt;
  std::string expiresAt;
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

struct SessionRecording {
  int id = 0;
  int sessionId = 0;
  std::string filePath;
  std::string createdAt;
  std::string closedAt;
  int64_t durationMs = 0;
  size_t fileSize = 0;
};

struct HttpProxyResponse {
  int status_code = 0;
  std::string body;
  std::unordered_map<std::string, std::string> headers;
  std::vector<std::string> set_cookie_headers;
};

class SessionRecorder;

#ifdef ENDORIUMFORT_SSH_ENABLED
#ifndef _WIN32
#include <libssh2.h>
struct SshConnection {
  int socket_fd = -1;
  LIBSSH2_SESSION *session = nullptr;
  LIBSSH2_CHANNEL *channel = nullptr;
  std::thread reader;
  std::atomic<bool> running{false};
  std::mutex write_mutex;
  int session_id = 0;
  // Session recording
  std::shared_ptr<SessionRecorder> recorder;
};
#endif
#endif

// Tunnel state for agent WebSocket tunnels
struct TunnelState {
  int upstream_sock = -1;
  int resource_id = 0;
  std::string user;
  std::string token;
  std::atomic<bool> active{false};
  std::thread reader_thread;
};
