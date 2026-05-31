#pragma once
// ─── EndoriumFort — Utility functions ───────────────────────────────────
// Small standalone helpers (header-only).

#include "crow.h"
#include "auth_mfa.h"
#include "models.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <limits>
#include <map>
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

inline std::optional<int64_t> checked_epoch_seconds_after(
    int64_t epoch_seconds, int64_t delta_seconds) {
  if (delta_seconds < 0) return std::nullopt;
  if (epoch_seconds >
      std::numeric_limits<int64_t>::max() - delta_seconds) {
    return std::nullopt;
  }
  return epoch_seconds + delta_seconds;
}

inline uint64_t absolute_epoch_second_delta(int64_t left, int64_t right) {
  if (left >= right) {
    return static_cast<uint64_t>(left) - static_cast<uint64_t>(right);
  }
  return static_cast<uint64_t>(right) - static_cast<uint64_t>(left);
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

inline std::string to_lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

inline std::string trim_copy(std::string value) {
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

inline std::vector<std::string> split_csv_compact(const std::string &value) {
  std::vector<std::string> items;
  std::istringstream iss(value);
  std::string token;
  while (std::getline(iss, token, ',')) {
    token = trim_copy(token);
    if (!token.empty()) items.push_back(token);
  }
  return items;
}

inline std::string join_csv_compact(const std::vector<std::string> &values) {
  std::ostringstream oss;
  bool first = true;
  for (const auto &raw : values) {
    const std::string token = trim_copy(raw);
    if (token.empty()) continue;
    if (!first) oss << ',';
    oss << token;
    first = false;
  }
  return oss.str();
}

inline std::vector<std::string> unique_csv_tokens(const std::string &value) {
  std::vector<std::string> ordered;
  std::unordered_set<std::string> seen;
  for (const auto &item : split_csv_compact(value)) {
    const std::string lowered = to_lower(item);
    if (!seen.insert(lowered).second) continue;
    ordered.push_back(item);
  }
  return ordered;
}

inline bool csv_contains_token(const std::string &csv, const std::string &token) {
  const std::string wanted = to_lower(trim_copy(token));
  if (wanted.empty()) return false;
  for (const auto &item : split_csv_compact(csv)) {
    if (to_lower(item) == wanted) return true;
  }
  return false;
}

inline bool csv_intersects(const std::string &left, const std::string &right) {
  const auto left_items = split_csv_compact(left);
  const auto right_items = split_csv_compact(right);
  if (left_items.empty() || right_items.empty()) return false;
  std::unordered_set<std::string> right_index;
  for (const auto &item : right_items) right_index.insert(to_lower(item));
  for (const auto &item : left_items) {
    if (right_index.count(to_lower(item))) return true;
  }
  return false;
}

inline int risk_level_rank(const std::string &risk_level) {
  const std::string normalized = to_lower(trim_copy(risk_level));
  if (normalized == "critical") return 4;
  if (normalized == "high") return 3;
  if (normalized == "medium") return 2;
  if (normalized == "low") return 1;
  return 0;
}

inline int mfa_requirement_rank(const std::string &value) {
  const std::string normalized = to_lower(trim_copy(value));
  if (normalized == "webauthn") return 3;
  if (normalized == "totp") return 2;
  if (normalized == "any" || normalized == "required") return 1;
  return 0;
}

inline std::string stronger_mfa_requirement(const std::string &left,
                                            const std::string &right) {
  return mfa_requirement_rank(right) > mfa_requirement_rank(left) ? right : left;
}

inline bool is_time_window_match_utc(const std::string &window, int hour_utc,
                                     int minute_utc = 0) {
  const std::string normalized = to_lower(trim_copy(window));
  if (normalized.empty() || normalized == "any") return true;

  const auto parse_minutes = [](const std::string &raw) -> std::optional<int> {
    if (raw.size() != 5 || raw[2] != ':') return std::nullopt;
    if (!std::isdigit(static_cast<unsigned char>(raw[0])) ||
        !std::isdigit(static_cast<unsigned char>(raw[1])) ||
        !std::isdigit(static_cast<unsigned char>(raw[3])) ||
        !std::isdigit(static_cast<unsigned char>(raw[4]))) {
      return std::nullopt;
    }
    const int hours = std::stoi(raw.substr(0, 2));
    const int minutes = std::stoi(raw.substr(3, 2));
    if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) {
      return std::nullopt;
    }
    return hours * 60 + minutes;
  };

  const size_t dash = normalized.find('-');
  if (dash == std::string::npos) return false;
  const auto start = parse_minutes(normalized.substr(0, dash));
  const auto end = parse_minutes(normalized.substr(dash + 1));
  if (!start || !end) return false;

  const int current = (hour_utc * 60) + std::max(0, minute_utc);
  if (*start <= *end) {
    return current >= *start && current <= *end;
  }
  return current >= *start || current <= *end;
}

inline std::string build_session_payload_json(const Session &session) {
  std::ostringstream oss;
  oss << '{';
  oss << "\"sessionId\":" << session.id << ',';
  oss << "\"resourceId\":" << session.resourceId << ',';
  if (session.accessGrantId > 0) {
    oss << "\"accessGrantId\":" << session.accessGrantId << ',';
  }
  oss << "\"target\":\"" << json_escape(session.target) << "\",";
  oss << "\"user\":\"" << json_escape(session.user) << "\",";
  oss << "\"protocol\":\"" << json_escape(session.protocol) << "\",";
  oss << "\"port\":" << session.port << ',';
  oss << "\"credentialSource\":\"" << json_escape(session.credentialSource)
      << "\",";
  if (!session.missionRef.empty()) {
    oss << "\"missionRef\":\"" << json_escape(session.missionRef) << "\",";
  }
  if (session.maxDurationSeconds > 0) {
    oss << "\"maxDurationSeconds\":" << session.maxDurationSeconds << ',';
  }
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
  oss << ",\"tunnelTicketRateLimitMaxAttempts\":"
      << resource.tunnelTicketRateLimitMaxAttempts;
  if (!resource.tagsCsv.empty()) {
    oss << ",\"tagsCsv\":\"" << json_escape(resource.tagsCsv) << "\"";
  }
  oss << ",\"credentialSource\":\"" << json_escape(resource.credentialSource)
      << "\"";
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

inline crow::json::wvalue build_bootstrap_payload(const UserAccount &user) {
  crow::json::wvalue payload;
  payload["required"] =
      user.bootstrapPasswordChangeRequired || user.bootstrapMfaRequired;
  payload["passwordChangeRequired"] = user.bootstrapPasswordChangeRequired;
  payload["mfaSetupRequired"] = user.bootstrapMfaRequired;
  payload["totpEnabled"] = user.totpEnabled;
  payload["webauthnEnabled"] = user_has_webauthn_enabled(user);
  payload["preferredMfaMethod"] = effective_mfa_preference(user);
  return payload;
}

inline void apply_auth_mfa_payload(crow::json::wvalue &payload,
                                   const UserAccount &user,
                                   bool include_bootstrap = true) {
  payload["totpEnabled"] = user.totpEnabled;
  payload["webauthnEnabled"] = user_has_webauthn_enabled(user);
  payload["preferredMfaMethod"] = effective_mfa_preference(user);
  if (include_bootstrap) {
    payload["bootstrap"] = build_bootstrap_payload(user);
  }
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
      "vnc.connect",
      "cluster.read",
      "cluster.manage",
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
            "stats.read", "access_requests.read", "ssh.shadow.watch",
            "cluster.read"};
  }
  return {"resources.read", "sessions.read", "sessions.create",
          "sessions.terminate", "stats.read", "access_requests.read",
          "access_requests.create", "credentials.ephemeral.issue",
      "credentials.ephemeral.consume", "ssh.connect", "rdp.connect",
      "vnc.connect",
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
  payload["resourceId"] = session.resourceId;
  payload["accessGrantId"] = session.accessGrantId;
  payload["target"] = session.target;
  payload["user"] = session.user;
  payload["protocol"] = session.protocol;
  payload["port"] = session.port;
  payload["status"] = session.status;
  payload["missionRef"] = session.missionRef;
  payload["credentialSource"] = session.credentialSource;
  payload["maxDurationSeconds"] = session.maxDurationSeconds;
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
  payload["tunnelTicketRateLimitMaxAttempts"] =
      resource.tunnelTicketRateLimitMaxAttempts;
  payload["description"] = resource.description;
  payload["imageUrl"] = resource.imageUrl;
  payload["imageData"] = resource.imageData;
  payload["tagsCsv"] = resource.tagsCsv;
  payload["credentialSource"] = resource.credentialSource;
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

inline crow::json::wvalue access_policy_to_json(const AccessPolicy &policy) {
  crow::json::wvalue payload;
  payload["id"] = policy.id;
  payload["name"] = policy.name;
  payload["description"] = policy.description;
  payload["identityPattern"] = policy.identityPattern;
  payload["groupName"] = policy.groupName;
  payload["role"] = policy.role;
  payload["resourceTagsCsv"] = policy.resourceTagsCsv;
  payload["riskLevel"] = policy.riskLevel;
  payload["ticketRequired"] = policy.ticketRequired;
  payload["requireJustification"] = policy.requireJustification;
  payload["approvalMode"] = policy.approvalMode;
  payload["mfaRequirement"] = policy.mfaRequirement;
  payload["timeWindow"] = policy.timeWindow;
  payload["maxDurationSeconds"] = policy.maxDurationSeconds;
  payload["routingConstraint"] = policy.routingConstraint;
  payload["enabled"] = policy.enabled;
  payload["createdAt"] = policy.createdAt;
  payload["updatedAt"] = policy.updatedAt;
  return payload;
}

inline crow::json::wvalue access_profile_to_json(const AccessProfile &profile) {
  crow::json::wvalue payload;
  payload["id"] = profile.id;
  payload["name"] = profile.name;
  payload["description"] = profile.description;
  payload["resourceTagsCsv"] = profile.resourceTagsCsv;
  payload["resourceIdsCsv"] = profile.resourceIdsCsv;
  payload["policyId"] = profile.policyId;
  payload["createdAt"] = profile.createdAt;
  payload["updatedAt"] = profile.updatedAt;
  return payload;
}

inline crow::json::wvalue access_grant_to_json(const AccessGrant &grant) {
  crow::json::wvalue payload;
  payload["id"] = grant.id;
  payload["policyId"] = grant.policyId;
  payload["profileId"] = grant.profileId;
  payload["resourceId"] = grant.resourceId;
  payload["sessionId"] = grant.sessionId;
  payload["approvalRef"] = grant.approvalRef;
  payload["subject"] = grant.subject;
  payload["resourceScope"] = grant.resourceScope;
  payload["grantedAt"] = grant.grantedAt;
  payload["expiresAt"] = grant.expiresAt;
  payload["usedAt"] = grant.usedAt;
  payload["missionRef"] = grant.missionRef;
  payload["elevationScope"] = grant.elevationScope;
  payload["status"] = grant.status;
  payload["credentialSource"] = grant.credentialSource;
  payload["routingConstraint"] = grant.routingConstraint;
  payload["ticketId"] = grant.ticketId;
  payload["purpose"] = grant.purpose;
  payload["justification"] = grant.justification;
  payload["mfaRequirement"] = grant.mfaRequirement;
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
  payload["bootstrapPasswordChangeRequired"] = user.bootstrapPasswordChangeRequired;
  payload["bootstrapMfaRequired"] = user.bootstrapMfaRequired;
  payload["totpEnabled"] = user.totpEnabled;
  payload["webauthnEnabled"] = user_has_webauthn_enabled(user);
  payload["webauthnCredentialCount"] = user.webauthnCredentialCount;
  payload["preferredMfaMethod"] = effective_mfa_preference(user);
  return payload;
}

inline std::optional<int> parse_int_param(const char *value) {
  if (!value) return std::nullopt;
  try { return std::stoi(value); }
  catch (const std::exception &) { return std::nullopt; }
}

inline std::string get_client_ip(const crow::request &request) {
  // Check X-Forwarded-For header first (for reverse proxy scenarios)
  if (request.get_header_value("X-Forwarded-For") != "") {
    std::string forwarded_for = request.get_header_value("X-Forwarded-For");
    // X-Forwarded-For can contain comma-separated IPs; take the first (original client)
    size_t comma_pos = forwarded_for.find(',');
    if (comma_pos != std::string::npos) {
      std::string first_ip = forwarded_for.substr(0, comma_pos);
      first_ip = trim_copy(first_ip);
      if (!first_ip.empty()) return first_ip;
    } else {
      std::string trimmed = trim_copy(forwarded_for);
      if (!trimmed.empty()) return trimmed;
    }
  }
  
  // Fall back to direct connection IP
  std::string remote_ip = request.remote_ip_address;
  return remote_ip.empty() ? "unknown" : remote_ip;
}
