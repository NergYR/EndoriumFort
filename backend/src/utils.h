#pragma once
// ─── EndoriumFort — Utility functions ───────────────────────────────────
// Small standalone helpers (header-only).

#include "crow.h"
#include "models.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

inline std::string now_utc() {
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

inline std::optional<int64_t> parse_utc_epoch_seconds(
    const std::string &timestamp) {
  if (timestamp.empty()) return std::nullopt;
  std::tm utc_tm{};
  std::istringstream iss(timestamp);
  iss >> std::get_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
  if (iss.fail()) return std::nullopt;
#ifdef _WIN32
  const std::time_t epoch = _mkgmtime(&utc_tm);
#else
  const std::time_t epoch = timegm(&utc_tm);
#endif
  if (epoch < 0) return std::nullopt;
  return static_cast<int64_t>(epoch);
}

inline int64_t now_epoch_seconds() {
  return static_cast<int64_t>(std::time(nullptr));
}

inline std::string utc_from_epoch_seconds(int64_t epoch_seconds) {
  std::time_t raw_time = static_cast<std::time_t>(epoch_seconds);
  std::tm utc_tm{};
#ifdef _WIN32
  gmtime_s(&utc_tm, &raw_time);
#else
  gmtime_r(&raw_time, &utc_tm);
#endif
  std::ostringstream oss;
  oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

inline std::string json_escape(const std::string &value) {
  std::ostringstream oss;
  for (char ch : value) {
    switch (ch) {
      case '\\': oss << "\\\\"; break;
      case '"':  oss << "\\\""; break;
      case '\n': oss << "\\n";  break;
      case '\r': oss << "\\r";  break;
      case '\t': oss << "\\t";  break;
      default:   oss << ch;     break;
    }
  }
  return oss.str();
}

inline std::string build_session_payload_json(const Session &session) {
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
    oss << ",\"terminatedAt\":\"" << json_escape(session.terminatedAt) << "\"";
  }
  oss << '}';
  return oss.str();
}

inline std::string build_resource_payload_json(const Resource &resource) {
  std::ostringstream oss;
  oss << '{';
  oss << "\"resourceId\":" << resource.id << ',';
  oss << "\"name\":\"" << json_escape(resource.name) << "\",";
  oss << "\"target\":\"" << json_escape(resource.target) << "\",";
  oss << "\"protocol\":\"" << json_escape(resource.protocol) << "\",";
  oss << "\"port\":" << resource.port;
  oss << ",\"requireAccessJustification\":"
      << (resource.requireAccessJustification ? "true" : "false");
    oss << ",\"requireDualApproval\":"
      << (resource.requireDualApproval ? "true" : "false");
    oss << ",\"enableCommandGuard\":"
      << (resource.enableCommandGuard ? "true" : "false");
    oss << ",\"adaptiveAccessPolicy\":"
      << (resource.adaptiveAccessPolicy ? "true" : "false");
    oss << ",\"riskLevel\":\"" << json_escape(resource.riskLevel) << "\"";
  if (!resource.description.empty()) {
    oss << ",\"description\":\"" << json_escape(resource.description) << "\"";
  }
  if (!resource.imageUrl.empty()) {
    oss << ",\"imageUrl\":\"" << json_escape(resource.imageUrl) << "\"";
  }
  if (!resource.createdAt.empty()) {
    oss << ",\"createdAt\":\"" << json_escape(resource.createdAt) << "\"";
  }
  if (!resource.updatedAt.empty()) {
    oss << ",\"updatedAt\":\"" << json_escape(resource.updatedAt) << "\"";
  }
  oss << '}';
  return oss.str();
}

inline std::string build_user_payload_json(const UserAccount &user) {
  std::ostringstream oss;
  oss << '{';
  oss << "\"userId\":" << user.id << ',';
  oss << "\"username\":\"" << json_escape(user.username) << "\",";
  oss << "\"role\":\"" << json_escape(user.role) << "\"";
  if (!user.createdAt.empty()) {
    oss << ",\"createdAt\":\"" << json_escape(user.createdAt) << "\"";
  }
  if (!user.updatedAt.empty()) {
    oss << ",\"updatedAt\":\"" << json_escape(user.updatedAt) << "\"";
  }
  oss << '}';
  return oss.str();
}

inline bool is_allowed_role(const std::string &role,
                            const std::vector<std::string> &allowed) {
  for (const auto &item : allowed) {
    if (item == role) return true;
  }
  return false;
}

inline std::string normalize_user_role(const std::string &role) {
  std::string lowered = role;
  std::transform(
      lowered.begin(), lowered.end(), lowered.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

  if (lowered == "admin" || lowered == "platform_admin" ||
      lowered == "access_admin") {
    return "admin";
  }
  if (lowered == "operator" || lowered == "session_operator") {
    return "operator";
  }
  if (lowered == "auditor" || lowered == "security_auditor" ||
      lowered == "security_analyst") {
    return "auditor";
  }
  return lowered;
}

inline bool is_user_role(const std::string &role, const std::string &expected) {
  return normalize_user_role(role) == normalize_user_role(expected);
}

inline bool is_allowed_user_role(const std::string &role,
                                 const std::vector<std::string> &allowed) {
  const std::string normalized_role = normalize_user_role(role);
  for (const auto &item : allowed) {
    if (normalized_role == normalize_user_role(item)) return true;
  }
  return false;
}

inline const std::vector<std::string> &permission_catalog() {
  static const std::vector<std::string> catalog = {
      "users.read",
      "users.manage",
      "users.permissions.manage",
      "resources.read",
      "resources.manage",
      "resources.assign",
      "sessions.read",
      "sessions.create",
      "sessions.terminate",
      "audit.read",
      "recordings.read",
      "stats.read",
      "totp.manage",
      "access_requests.read",
      "access_requests.create",
      "access_requests.review",
      "credentials.ephemeral.issue",
      "credentials.ephemeral.consume",
      "ssh.connect",
      "ssh.shadow.watch",
      "rdp.connect",
      "web.proxy.access",
      "tunnel.connect"};
  return catalog;
}

inline bool is_known_permission(const std::string &permission) {
  const auto &catalog = permission_catalog();
  return std::find(catalog.begin(), catalog.end(), permission) != catalog.end();
}

inline std::unordered_set<std::string> default_permissions_for_role(
    const std::string &role) {
  const std::string normalized = normalize_user_role(role);
  if (normalized == "admin") {
    std::unordered_set<std::string> all;
    for (const auto &item : permission_catalog()) all.insert(item);
    all.insert("*");
    return all;
  }
  if (normalized == "auditor") {
    return {"resources.read", "sessions.read", "audit.read", "recordings.read",
            "stats.read", "access_requests.read", "ssh.shadow.watch"};
  }
  return {"resources.read", "sessions.read", "sessions.create",
          "sessions.terminate", "stats.read", "access_requests.read",
          "access_requests.create", "credentials.ephemeral.issue",
          "credentials.ephemeral.consume", "ssh.connect", "rdp.connect",
          "web.proxy.access", "tunnel.connect"};
}

inline bool permission_match(const std::string &granted,
                             const std::string &required) {
  if (granted == "*") return true;
  if (granted == required) return true;
  if (granted.size() > 2 && granted.back() == '*') {
    const std::string prefix = granted.substr(0, granted.size() - 1);
    if (required.rfind(prefix, 0) == 0) return true;
  }
  return false;
}

inline bool permissions_contain(const std::unordered_set<std::string> &granted,
                                const std::string &required) {
  for (const auto &item : granted) {
    if (permission_match(item, required)) return true;
  }
  return false;
}

inline std::optional<std::string> extract_bearer_token(
    const crow::request &request) {
  auto header = request.get_header_value("Authorization");
  const std::string prefix = "Bearer ";
  if (header.rfind(prefix, 0) == 0 && header.size() > prefix.size()) {
    return header.substr(prefix.size());
  }
  return std::nullopt;
}

inline std::optional<std::string> extract_cookie_value(
    const crow::request &request, const std::string &name) {
  const std::string cookie_header = request.get_header_value("Cookie");
  if (cookie_header.empty() || name.empty()) return std::nullopt;

  size_t start = 0;
  while (start < cookie_header.size()) {
    size_t end = cookie_header.find(';', start);
    if (end == std::string::npos) end = cookie_header.size();

    size_t eq = cookie_header.find('=', start);
    if (eq != std::string::npos && eq < end) {
      std::string key = cookie_header.substr(start, eq - start);
      while (!key.empty() && std::isspace(static_cast<unsigned char>(key.front()))) {
        key.erase(key.begin());
      }
      while (!key.empty() && std::isspace(static_cast<unsigned char>(key.back()))) {
        key.pop_back();
      }
      if (key == name) {
        return cookie_header.substr(eq + 1, end - (eq + 1));
      }
    }

    start = end + 1;
  }

  return std::nullopt;
}

inline std::optional<std::string> extract_auth_token_from_request(
    const crow::request &request) {
  auto bearer = extract_bearer_token(request);
  if (bearer && !bearer->empty()) return bearer;
  return extract_cookie_value(request, "endoriumfort_token");
}

inline bool request_uses_https(const crow::request &request) {
  auto lower_copy = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
  };

  std::string proto = lower_copy(request.get_header_value("X-Forwarded-Proto"));
  if (!proto.empty()) {
    size_t comma = proto.find(',');
    if (comma != std::string::npos) proto = proto.substr(0, comma);
    while (!proto.empty() && std::isspace(static_cast<unsigned char>(proto.front()))) {
      proto.erase(proto.begin());
    }
    while (!proto.empty() && std::isspace(static_cast<unsigned char>(proto.back()))) {
      proto.pop_back();
    }
    if (proto == "https") return true;
  }

  std::string origin = lower_copy(request.get_header_value("Origin"));
  if (origin.rfind("https://", 0) == 0) return true;

  std::string referer = lower_copy(request.get_header_value("Referer"));
  if (referer.rfind("https://", 0) == 0) return true;

  return false;
}

inline std::string build_auth_cookie(const std::string &token, bool secure,
                                     int max_age_seconds) {
  std::ostringstream oss;
  oss << "endoriumfort_token=" << token
      << "; Path=/; HttpOnly; SameSite=Strict; Max-Age="
      << max_age_seconds;
  if (secure) oss << "; Secure";
  return oss.str();
}

inline std::string build_cleared_auth_cookie(bool secure) {
  std::string value =
      "endoriumfort_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
  if (secure) value += "; Secure";
  return value;
}

inline std::string base64_encode(const std::string &input) {
  static const char base64_chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  int i = 0;
  unsigned char array_3[3];
  unsigned char array_4[4];

  for (unsigned char c : input) {
    array_3[i++] = c;
    if (i == 3) {
      array_4[0] = (array_3[0] & 0xfc) >> 2;
      array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
      array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
      array_4[3] = array_3[2] & 0x3f;
      for (i = 0; i < 4; i++) result += base64_chars[array_4[i]];
      i = 0;
    }
  }

  if (i) {
    for (int j = i; j < 3; j++) array_3[j] = '\0';
    array_4[0] = (array_3[0] & 0xfc) >> 2;
    array_4[1] = ((array_3[0] & 0x03) << 4) + ((array_3[1] & 0xf0) >> 4);
    array_4[2] = ((array_3[1] & 0x0f) << 2) + ((array_3[2] & 0xc0) >> 6);
    for (int j = 0; j < i + 1; j++) result += base64_chars[array_4[j]];
    while (i++ < 3) result += '=';
  }
  return result;
}

inline crow::json::wvalue session_to_json(const Session &session) {
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

inline crow::json::wvalue resource_to_json(const Resource &resource) {
  crow::json::wvalue payload;
  payload["id"] = resource.id;
  payload["name"] = resource.name;
  payload["target"] = resource.target;
  payload["protocol"] = resource.protocol;
  payload["port"] = resource.port;
  payload["description"] = resource.description;
  payload["imageUrl"] = resource.imageUrl;
  payload["httpUsername"] = resource.httpUsername;
  payload["sshUsername"] = resource.sshUsername;
  payload["hasCredentials"] = !resource.sshPassword.empty();
  payload["requireAccessJustification"] = resource.requireAccessJustification;
  payload["requireDualApproval"] = resource.requireDualApproval;
  payload["enableCommandGuard"] = resource.enableCommandGuard;
  payload["adaptiveAccessPolicy"] = resource.adaptiveAccessPolicy;
  payload["riskLevel"] = resource.riskLevel;
  payload["createdAt"] = resource.createdAt;
  payload["updatedAt"] = resource.updatedAt;
  return payload;
}

inline crow::json::wvalue access_request_to_json(const AccessRequest &request) {
  crow::json::wvalue payload;
  payload["id"] = request.id;
  payload["resourceId"] = request.resourceId;
  payload["resourceName"] = request.resourceName;
  payload["requester"] = request.requester;
  payload["requesterRole"] = request.requesterRole;
  payload["status"] = request.status;
  payload["justification"] = request.justification;
  payload["ticketId"] = request.ticketId;
  payload["createdAt"] = request.createdAt;
  payload["reviewedAt"] = request.reviewedAt;
  payload["reviewedBy"] = request.reviewedBy;
  return payload;
}

inline crow::json::wvalue user_to_json(const UserAccount &user) {
  crow::json::wvalue payload;
  payload["id"] = user.id;
  payload["username"] = user.username;
  payload["role"] = user.role;
  payload["createdAt"] = user.createdAt;
  payload["updatedAt"] = user.updatedAt;
  payload["totpEnabled"] = user.totpEnabled;
  return payload;
}

inline std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

inline std::optional<int> parse_int_param(const char *value) {
  if (!value) return std::nullopt;
  try { return std::stoi(value); }
  catch (const std::exception &) { return std::nullopt; }
}
