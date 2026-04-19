#include "app_context.h"
#include "crypto.h"
#include "routes.h"
#include "utils.h"

#include <iostream>
#include <string>
#include <unordered_map>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

std::string request_path(const std::string &raw_url) {
  const size_t query_pos = raw_url.find('?');
  if (query_pos == std::string::npos) return raw_url;
  return raw_url.substr(0, query_pos);
}

crow::response dispatch_request(
    CrowApp &app, crow::HTTPMethod method, const std::string &raw_url,
    const std::string &token = "", const std::string &body = "",
    const std::unordered_map<std::string, std::string> &extra_headers = {}) {
  crow::request request;
  request.method = method;
  request.raw_url = raw_url;
  request.url = request_path(raw_url);
  request.url_params = crow::query_string(raw_url);
  request.body = body;
  request.http_ver_major = 1;
  request.http_ver_minor = 1;
  request.keep_alive = false;
  request.close_connection = false;
  request.upgrade = false;
  request.remote_ip_address = "127.0.0.1";

  if (!token.empty()) {
    request.add_header("Authorization", "Bearer " + token);
  }
  if (!body.empty()) {
    request.add_header("Content-Type", "application/json");
  }
  for (const auto &entry : extra_headers) {
    request.add_header(entry.first, entry.second);
  }

  crow::response response;
  app.handle_full(request, response);
  if (!response.is_completed()) response.end();
  return response;
}

void seed_user(AppContext &ctx, int id, const std::string &username,
               const std::string &password, const std::string &role) {
  UserAccount user;
  user.id = id;
  user.username = username;
  user.password = password;
  user.role = role;
  user.createdAt = now_utc();
  user.updatedAt = user.createdAt;

  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  ctx.users[user.id] = user;
}

void seed_auth_session(AppContext &ctx, int user_id, const std::string &username,
                       const std::string &role, const std::string &token) {
  AuthSession auth;
  auth.userId = user_id;
  auth.user = username;
  auth.role = role;
  auth.token = token;
  auth.issuedAt = now_utc();
  auth.expiresAt = "9999-12-31T23:59:59Z";

  std::lock_guard<std::mutex> lock(ctx.auth_mutex);
  ctx.auth_sessions[token] = auth;
}

bool has_security_alert(const crow::json::rvalue &items,
                        const std::string &event_type,
                        const std::string &severity,
                        int expected_session_id = 0) {
  for (int i = 0; i < items.size(); ++i) {
    const auto item = items[i];
    const std::string current_type = item.has("eventType")
                                         ? std::string(item["eventType"].s())
                                         : "";
    if (current_type != event_type) continue;

    if (!severity.empty()) {
      const std::string current_severity =
          item.has("severity") ? std::string(item["severity"].s()) : "";
      if (current_severity != severity) continue;
    }

    if (expected_session_id > 0) {
      if (!item.has("sessionId") || item["sessionId"].i() != expected_session_id) {
        continue;
      }
    }

    return true;
  }
  return false;
}

bool test_auth_failure_burst_alert() {
  AppContext ctx;
  CrowApp app;
  register_auth_routes(app, ctx);
  register_audit_routes(app, ctx);
  app.validate();

  seed_user(ctx, 1, "admin", crypto::hash_password("Admin123"), "admin");
  seed_user(ctx, 2, "operator", crypto::hash_password("GoodPassword!"),
            "operator");
  seed_auth_session(ctx, 1, "admin", "admin", "test-admin-token");

  const std::unordered_map<std::string, std::string> headers = {
      {"X-Forwarded-For", "198.51.100.14"}};

  for (int i = 0; i < 8; ++i) {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/auth/login", "",
        "{\"user\":\"operator\",\"password\":\"WrongPassword!\"}",
        headers);
    if (response.code != 401 && response.code != 429) {
      return false;
    }
  }

  auto alerts_response = dispatch_request(
      app, crow::HTTPMethod::Get, "/api/security/alerts?sinceId=0",
      "test-admin-token");
  if (alerts_response.code != 200) return false;

  auto payload = crow::json::load(alerts_response.body);
  if (!payload || !payload.has("items")) return false;

  return has_security_alert(payload["items"],
                            "behavior.anomaly.auth_failure_burst", "critical");
}

bool test_stale_session_alert() {
  AppContext ctx;
  CrowApp app;
  register_audit_routes(app, ctx);
  app.validate();

  seed_user(ctx, 1, "admin", crypto::hash_password("Admin123"), "admin");
  seed_auth_session(ctx, 1, "admin", "admin", "test-admin-token");

  Session stale;
  stale.id = 77;
  stale.user = "operator";
  stale.target = "srv-legacy-01.internal";
  stale.protocol = "ssh";
  stale.status = "active";
  stale.createdAt = utc_from_epoch_seconds(now_epoch_seconds() - 10800);
  stale.port = 22;

  {
    std::lock_guard<std::mutex> lock(ctx.session_mutex);
    ctx.sessions[stale.id] = stale;
  }

  const int since_id = std::max(0, ctx.next_audit_id.load() - 1);
  auto alerts_response = dispatch_request(
      app, crow::HTTPMethod::Get,
      "/api/security/alerts?sinceId=" + std::to_string(since_id),
      "test-admin-token");
  if (alerts_response.code != 200) return false;

  auto payload = crow::json::load(alerts_response.body);
  if (!payload || !payload.has("items")) return false;

  return has_security_alert(payload["items"], "behavior.anomaly.stale_session",
                            "warning", stale.id);
}

}  // namespace

int main() {
  bool ok = true;

  ok &= expect(test_auth_failure_burst_alert(),
               "security alerts should include auth failure burst anomalies");
  ok &= expect(test_stale_session_alert(),
               "security alerts should include stale session anomalies");

  if (!ok) {
    return 1;
  }

  std::cout << "All security alert tests passed." << std::endl;
  return 0;
}
