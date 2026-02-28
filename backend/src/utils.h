#pragma once
// ─── EndoriumFort — Utility functions ───────────────────────────────────
// Small standalone helpers (header-only).

#include "crow.h"
#include "models.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
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

inline std::optional<std::string> extract_bearer_token(
    const crow::request &request) {
  auto header = request.get_header_value("Authorization");
  const std::string prefix = "Bearer ";
  if (header.rfind(prefix, 0) == 0 && header.size() > prefix.size()) {
    return header.substr(prefix.size());
  }
  return std::nullopt;
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
  payload["createdAt"] = resource.createdAt;
  payload["updatedAt"] = resource.updatedAt;
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
