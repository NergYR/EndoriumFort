#include "app_context.h"
#include "routes.h"
#include "utils.h"
#include "vnc.h"

#include <cstdlib>
#include <iostream>
#include <optional>
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

void set_test_env(const std::string &key, const std::string &value) {
#if defined(_WIN32)
  _putenv_s(key.c_str(), value.c_str());
#else
  setenv(key.c_str(), value.c_str(), 1);
#endif
}

crow::response dispatch_request(CrowApp &app, crow::HTTPMethod method,
                                const std::string &raw_url,
                                const std::string &token = "",
                const std::string &body = "",
                const std::unordered_map<std::string, std::string>
                  &extra_headers = {}) {
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

  // Direct unit dispatch via handle_full can skip middleware hooks depending
  // on Crow internals; apply security headers explicitly when absent.
  bool has_referrer_policy = false;
  for (const auto &entry : response.headers) {
    if (to_lower(entry.first) == "referrer-policy") {
      has_referrer_policy = true;
      break;
    }
  }
  if (!has_referrer_policy) {
    SecurityHeadersMiddleware middleware;
    SecurityHeadersMiddleware::context middleware_context;
    middleware.after_handle(request, response, middleware_context);
  }

  if (!response.is_completed()) response.end();
  return response;
}

void seed_user(AppContext &ctx, int user_id, const std::string &username,
               const std::string &role) {
  UserAccount user;
  user.id = user_id;
  user.username = username;
  user.password = "test-password";
  user.role = role;
  user.createdAt = now_utc();
  user.updatedAt = user.createdAt;
  user.bootstrapPasswordChangeRequired = false;
  user.bootstrapMfaRequired = false;

  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  ctx.users[user.id] = user;
}

void seed_auth_session(AppContext &ctx, int user_id, const std::string &username,
                       const std::string &role, const std::string &token) {
  AuthSession session;
  session.userId = user_id;
  session.user = username;
  session.role = role;
  session.token = token;
  session.issuedAt = now_utc();
  session.expiresAt = "9999-12-31T23:59:59Z";

  std::lock_guard<std::mutex> lock(ctx.auth_mutex);
  ctx.auth_sessions[session.token] = session;
}

bool auth_token_exists(AppContext &ctx, const std::string &token) {
  std::lock_guard<std::mutex> lock(ctx.auth_mutex);
  return ctx.auth_sessions.find(token) != ctx.auth_sessions.end();
}

std::optional<int> user_id_by_username(AppContext &ctx,
                                       const std::string &username) {
  const std::string wanted = to_lower(username);
  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  for (const auto &entry : ctx.users) {
    if (to_lower(entry.second.username) == wanted) {
      return entry.first;
    }
  }
  return std::nullopt;
}

bool user_exists(AppContext &ctx, int user_id) {
  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  return ctx.users.find(user_id) != ctx.users.end();
}

std::string user_role(AppContext &ctx, int user_id) {
  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  auto it = ctx.users.find(user_id);
  if (it == ctx.users.end()) return "";
  return it->second.role;
}

std::string user_name(AppContext &ctx, int user_id) {
  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  auto it = ctx.users.find(user_id);
  if (it == ctx.users.end()) return "";
  return it->second.username;
}

int audit_event_count(AppContext &ctx, const std::string &type) {
  std::lock_guard<std::mutex> lock(ctx.audit_mutex);
  int count = 0;
  for (const auto &event : ctx.audit_events) {
    if (event.type == type) ++count;
  }
  return count;
}

std::optional<AuditEvent> last_audit_event_of_type(AppContext &ctx,
                                                    const std::string &type) {
  std::lock_guard<std::mutex> lock(ctx.audit_mutex);
  for (auto it = ctx.audit_events.rbegin(); it != ctx.audit_events.rend(); ++it) {
    if (it->type == type) return *it;
  }
  return std::nullopt;
}

bool audit_payload_contains(const AuditEvent &event,
                            const std::string &fragment) {
  return event.payloadJson.find(fragment) != std::string::npos;
}

bool json_list_contains_string(const crow::json::rvalue &list,
                               const std::string &wanted) {
  for (int i = 0; i < list.size(); ++i) {
    try {
      if (std::string(list[i].s()) == wanted) return true;
    } catch (...) {
    }
  }
  return false;
}

std::string response_header_value(const crow::response &response,
                                  const std::string &key) {
  auto it = response.headers.find(key);
  if (it != response.headers.end()) return it->second;

  const std::string wanted = to_lower(key);
  for (const auto &entry : response.headers) {
    if (to_lower(entry.first) == wanted) {
      return entry.second;
    }
  }
  return "";
}

bool expect_scim_hardening_headers(const crow::response &response,
                                   const std::string &context) {
  bool ok = true;

  const std::string x_content_type =
    response_header_value(response, "X-Content-Type-Options");
  ok &= expect(x_content_type == "nosniff",
         context + " should set X-Content-Type-Options=nosniff");

  const std::string x_frame_options =
    response_header_value(response, "X-Frame-Options");
  ok &= expect(x_frame_options == "SAMEORIGIN",
         context + " should set X-Frame-Options=SAMEORIGIN");

  const std::string referrer_policy =
    response_header_value(response, "Referrer-Policy");
  ok &= expect(referrer_policy == "strict-origin-when-cross-origin",
         context + " should set strict Referrer-Policy");

  const std::string cross_origin_opener =
    response_header_value(response, "Cross-Origin-Opener-Policy");
  ok &= expect(cross_origin_opener == "same-origin",
         context + " should set COOP same-origin");

  const std::string cross_origin_resource =
    response_header_value(response, "Cross-Origin-Resource-Policy");
  ok &= expect(cross_origin_resource == "same-origin",
         context + " should set CORP same-origin");

  const std::string x_permitted =
    response_header_value(response, "X-Permitted-Cross-Domain-Policies");
  ok &= expect(x_permitted == "none",
         context + " should disable cross-domain policies");

  const std::string permissions =
    response_header_value(response, "Permissions-Policy");
  ok &= expect(permissions.find("camera=()") != std::string::npos,
         context + " should disable camera permissions");
  ok &= expect(permissions.find("microphone=()") != std::string::npos,
         context + " should disable microphone permissions");
  ok &= expect(permissions.find("geolocation=()") != std::string::npos,
         context + " should disable geolocation permissions");

  const std::string cache_control =
    response_header_value(response, "Cache-Control");
  ok &= expect(cache_control.find("no-store") != std::string::npos,
         context + " should disable caching with no-store");

  const std::string csp = response_header_value(response, "Content-Security-Policy");
  ok &= expect(!csp.empty(),
         context + " should set Content-Security-Policy");
  if (!csp.empty()) {
  ok &= expect(csp.find("default-src 'self'") != std::string::npos,
         context + " CSP should restrict default-src to self");
  ok &= expect(csp.find("object-src 'none'") != std::string::npos,
         context + " CSP should disable object-src");
  ok &= expect(csp.find("frame-ancestors 'self'") != std::string::npos,
         context + " CSP should restrict frame ancestors");
  ok &= expect(csp.find("base-uri 'self'") != std::string::npos,
         context + " CSP should restrict base-uri");
  }

  return ok;
}

bool expect_scim_error_contract(const crow::response &response,
                                int expected_status,
                                const std::string &detail_fragment,
                const std::string &context,
                const std::optional<std::string> &expected_scim_type =
                  std::nullopt) {
  bool ok = true;
  auto payload = crow::json::load(response.body);
  ok &= expect(static_cast<bool>(payload),
               context + " should return a JSON payload");
  ok &= expect(payload && payload.has("schemas"),
               context + " should include schemas field");
  if (payload && payload.has("schemas")) {
    ok &= expect(json_list_contains_string(
                     payload["schemas"],
                     "urn:ietf:params:scim:api:messages:2.0:Error"),
                 context + " should include SCIM Error schema");
  }
  const bool has_status = payload && payload.has("status");
  ok &= expect(has_status,
               context + " should expose status as SCIM string value");
  if (has_status) {
    ok &= expect(std::string(payload["status"].s()) ==
                            std::to_string(expected_status),
                 context + " should expose status as SCIM string value");
  }
  const bool has_detail = payload && payload.has("detail");
  ok &= expect(has_detail,
               context + " should include detail field");
  if (has_detail) {
    ok &= expect(std::string(payload["detail"].s()).find(detail_fragment) !=
                     std::string::npos,
                 context + " should include expected detail text");
  }
  if (expected_scim_type.has_value()) {
    ok &= expect(payload && payload.has("scimType"),
                 context + " should include scimType field");
    if (payload && payload.has("scimType")) {
      ok &= expect(std::string(payload["scimType"].s()) == *expected_scim_type,
                   context + " should expose expected scimType value");
    }
  }
  ok &= expect(response_header_value(response, "Content-Type").find(
                   "application/json") != std::string::npos,
               context + " should return JSON content-type");
  ok &= expect_scim_hardening_headers(response, context);
  return ok;
}

bool expect_scim_user_metadata_contract(const crow::json::rvalue &payload,
                                        const crow::response &response,
                                        const std::string &expected_id,
                                        const std::string &context) {
  bool ok = true;
  const bool has_meta = payload && payload.has("meta");
  ok &= expect(has_meta,
               context + " should expose meta object");
  if (has_meta) {
    const bool has_resource_type = payload["meta"].has("resourceType");
    ok &= expect(has_resource_type,
                 context + " should expose User resourceType metadata");
    if (has_resource_type) {
      ok &= expect(std::string(payload["meta"]["resourceType"].s()) == "User",
                   context + " should expose User resourceType metadata value");
    }
  }
  const std::string expected_location =
      "/api/scim/v2/Users/" + expected_id;
  const bool has_location = has_meta && payload["meta"].has("location");
  ok &= expect(has_location,
               context + " should expose deterministic meta.location");
  if (has_location) {
    ok &= expect(std::string(payload["meta"]["location"].s()) ==
                     expected_location,
                 context + " should expose deterministic meta.location value");
  }
  const bool has_version = has_meta && payload["meta"].has("version");
  ok &= expect(has_version, context + " should expose meta.version");
  std::string meta_version;
  if (has_version) {
    meta_version = std::string(payload["meta"]["version"].s());
    ok &= expect(!meta_version.empty(),
                 context + " should expose non-empty meta.version");
  }
  const std::string etag = response_header_value(response, "ETag");
  ok &= expect(!etag.empty(), context + " should return ETag header");
  if (!etag.empty() && !meta_version.empty()) {
    ok &= expect(etag == meta_version,
                 context + " should align ETag header with meta.version");
  }
  return ok;
}

}  // namespace

int main() {
  bool ok = true;

  AppContext ctx;
  seed_user(ctx, 1, "admin", "admin");
  seed_user(ctx, 2, "alice", "operator");
  seed_user(ctx, 3, "bob", "operator");
  seed_user(ctx, 4, "charlie", "auditor");
  ctx.next_user_id.store(5);

  const std::string admin_token = "scim-route-test-token";
  seed_auth_session(ctx, 1, "admin", "admin", admin_token);
  const std::string operator_token = "scim-route-test-operator-token";
  seed_auth_session(ctx, 2, "alice", "operator", operator_token);

  CrowApp app;
  register_enterprise_routes(app, ctx);
  register_vnc_routes(app, ctx);
  app.validate();

  // Keep LDAP runtime settings deterministic for route tests.
  set_test_env("ENDORIUMFORT_LDAP_ENABLED", "0");
  set_test_env("ENDORIUMFORT_LDAP_HOST", "ldaps://dc1.example.org:636");
  set_test_env("ENDORIUMFORT_LDAP_PORT", "");
  set_test_env("ENDORIUMFORT_LDAP_USE_TLS", "0");
  set_test_env("ENDORIUMFORT_LDAP_BASE_DN", "dc=example,dc=org");
  set_test_env("ENDORIUMFORT_LDAP_USER_TEMPLATE",
               "uid={username},ou=People,dc=example,dc=org");
  set_test_env("ENDORIUMFORT_LDAP_ROLE_MAP", "alice=admin,bob=auditor");
  set_test_env("ENDORIUMFORT_LDAP_ROLE_ADMIN_MATCHERS",
               "cn=prod-admins,ou=groups");
  set_test_env("ENDORIUMFORT_LDAP_ROLE_AUDITOR_MATCHERS",
               "cn=auditors,ou=groups");

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/auth/directory/providers");
    ok &= expect(response.code == 401,
                 "Directory providers should reject requests without auth token");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/auth/directory/providers",
        admin_token);
    ok &= expect(response.code == 200,
                 "Directory providers should be available for enterprise admins");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload.has("items") && payload["items"].size() > 0,
                 "Directory providers response should include at least one provider");
    ok &= expect(payload && std::string(payload["items"][0]["id"].s()) == "ldap_ad",
                 "Directory providers should expose LDAP/AD provider id");
    ok &= expect(payload && !payload["items"][0]["enabled"].b(),
                 "Directory providers should reflect disabled LDAP runtime by default");
    ok &= expect(payload && payload["items"][0]["supportsRoleMapping"].b(),
           "Directory providers should expose role mapping capability");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/auth/directory/ldap/config",
        admin_token);
    ok &= expect(response.code == 200,
                 "LDAP config route should be available for enterprise admins");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload.has("config"),
                 "LDAP config route should include config object");
    ok &= expect(payload && !payload["config"]["enabled"].b(),
                 "LDAP config should expose enabled=false for deterministic tests");
    ok &= expect(payload && std::string(payload["config"]["host"].s()) ==
                 "dc1.example.org",
           "LDAP config should normalize URI host into hostname");
    ok &= expect(payload && payload["config"]["port"].i() == 636,
           "LDAP config should honor URI port when LDAP_PORT is unset");
    ok &= expect(payload && payload["config"]["useTls"].b(),
           "LDAP config should infer TLS from ldaps:// host URI");
    ok &= expect(payload &&
             std::string(payload["config"]["bindDnTemplate"].s()) ==
               "uid={username},ou=People,dc=example,dc=org",
           "LDAP config should support USER_TEMPLATE compatibility alias");
    ok &= expect(payload && payload["config"]["roleMapConfigured"].b(),
           "LDAP config should expose configured role map state");
    ok &= expect(payload && payload["config"]["roleMapEntries"].i() == 2,
           "LDAP config should expose count of parsed role map entries");
    ok &= expect(payload && payload["config"]["roleMappingEnabled"].b(),
           "LDAP config should expose roleMappingEnabled when rules exist");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/auth/directory/ldap/test-bind",
        admin_token,
        R"({"username":"alice","password":"Secret123!"})");
    ok &= expect(response.code == 503,
                 "LDAP bind test should return 503 when LDAP integration is disabled");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload.has("status") &&
                     std::string(payload["status"].s()) == "error",
                 "LDAP bind test disabled-path should return status=error");
    ok &= expect(payload && payload.has("authenticated") &&
                     !payload["authenticated"].b(),
                 "LDAP bind test disabled-path should expose authenticated=false");
    ok &= expect(payload && payload.has("provider") &&
                     std::string(payload["provider"].s()) == "ldap_ad",
                 "LDAP bind test should include ldap_ad provider marker");
    ok &= expect(payload && payload.has("mappedRole") &&
             std::string(payload["mappedRole"].s()) == "admin",
           "LDAP bind test should expose mapped role from LDAP role map");
    ok &= expect(payload && payload.has("mappingStrategy") &&
             std::string(payload["mappingStrategy"].s()) ==
               "role_map_user",
           "LDAP bind test should expose mapping strategy for mapped role");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/vnc/capabilities");
    ok &= expect(response.code == 401,
                 "VNC capabilities should reject requests without auth token");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/vnc/capabilities", admin_token);
    ok &= expect(response.code == 200,
                 "VNC capabilities should be available for authorized users");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload.has("status") &&
                     std::string(payload["status"].s()) == "ok",
                 "VNC capabilities should return status=ok");
    ok &= expect(payload && payload.has("enabled"),
                 "VNC capabilities should expose enabled state");
    if (payload && payload.has("enabled") && payload["enabled"].b()) {
      ok &= expect(payload.has("wsPath") &&
                       std::string(payload["wsPath"].s()) == "/api/ws/vnc",
                   "VNC capabilities should expose websocket path when enabled");
    }
  }

  {
    auto response =
        dispatch_request(app, crow::HTTPMethod::Get, "/api/scim/v2/Users");
    ok &= expect(response.code == 401,
                 "SCIM Users should reject requests without auth token");
    ok &= expect_scim_error_contract(
      response, 401, "Unauthorized",
      "SCIM Users unauthorized response");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/scim/v2/Users", operator_token);
    ok &= expect(response.code == 403,
                 "SCIM Users should reject reads for users without users.read permission");
    ok &= expect_scim_error_contract(
        response, 403, "Forbidden",
        "SCIM Users forbidden read response");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", operator_token,
        R"({"userName":"forbidden-create","role":"operator"})");
    ok &= expect(response.code == 403,
                 "SCIM Users should reject writes for users without users.manage permission");
    ok &= expect_scim_error_contract(
        response, 403, "Forbidden",
        "SCIM Users forbidden write response");
    ok &= expect(!user_id_by_username(ctx, "forbidden-create").has_value(),
                 "SCIM forbidden write should not create a user");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/scim/v2/ServiceProviderConfig",
        admin_token);
    ok &= expect(response.code == 200,
                 "SCIM ServiceProviderConfig should be available for authorized admins");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM ServiceProviderConfig should expose schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(json_list_contains_string(
                       payload["schemas"],
                       "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"),
                   "SCIM ServiceProviderConfig should include its core schema");
    }
    ok &= expect(payload && payload["patch"]["supported"].b(),
                 "SCIM ServiceProviderConfig should advertise PATCH support");
    ok &= expect(payload && payload["filter"]["maxResults"].i() == 200,
                 "SCIM ServiceProviderConfig should advertise maxResults=200");
    ok &= expect(payload && payload["authenticationSchemes"].size() > 0,
                 "SCIM ServiceProviderConfig should advertise auth schemes");
    ok &= expect(payload && std::string(payload["authenticationSchemes"][0]["type"].s()) ==
                            "oauthbearertoken",
                 "SCIM ServiceProviderConfig should advertise oauth bearer auth");

    ok &= expect(response_header_value(response, "Content-Type").find(
                         "application/json") != std::string::npos,
                 "SCIM ServiceProviderConfig should return JSON content-type");
    ok &= expect_scim_hardening_headers(
        response, "SCIM ServiceProviderConfig response");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/scim/v2/ServiceProviderConfig",
        admin_token, "",
        {{"X-Forwarded-Proto", "https"}, {"Host", "pam.example.com"}});
    const std::string hsts =
        response_header_value(response, "Strict-Transport-Security");
    ok &= expect(hsts.find("max-age=") != std::string::npos,
                 "SCIM hardening should enable HSTS when transport is HTTPS");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/scim/v2/ServiceProviderConfig",
        admin_token, "",
        {{"X-Forwarded-Proto", "https"}, {"Host", "localhost:8080"}});
    const std::string hsts =
        response_header_value(response, "Strict-Transport-Security");
    ok &= expect(hsts.empty(),
                 "SCIM hardening should not enable HSTS for localhost");
  }

  {
    auto response = dispatch_request(
      app, crow::HTTPMethod::Get,
      "/api/scim/v2/Users?startIndex=0&count=1", admin_token);
    ok &= expect(response.code == 400,
           "SCIM Users should reject startIndex values below 1");
    ok &= expect_scim_error_contract(
      response, 400, "startIndex must be >= 1",
      "SCIM Users invalid startIndex response", "invalidValue");
    }

    {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get,
        "/api/scim/v2/Users?startIndex=2&count=1", admin_token);
    ok &= expect(response.code == 200,
                 "SCIM Users should accept valid paginated request");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload["totalResults"].i() == 4,
                 "SCIM Users totalResults should include all matching users");
    ok &= expect(payload && payload["startIndex"].i() == 2,
                 "SCIM Users startIndex should echo query value");
    ok &= expect(payload && payload["itemsPerPage"].i() == 1,
                 "SCIM Users itemsPerPage should match selected page size");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM Users list should expose ListResponse schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(json_list_contains_string(
                       payload["schemas"],
                       "urn:ietf:params:scim:api:messages:2.0:ListResponse"),
                   "SCIM Users list should include ListResponse schema");
    }
    ok &= expect(payload && payload["Resources"].size() == 1,
                 "SCIM Users page should contain one resource");
    ok &= expect(payload && std::string(payload["Resources"][0]["id"].s()) == "2",
                 "SCIM Users page should be ordered by user id");
    ok &= expect(payload && std::string(payload["Resources"][0]["userName"].s()) ==
                            "alice",
                 "SCIM Users page should expose the expected username");
    ok &= expect(payload && payload["Resources"][0]["active"].b(),
                 "SCIM Users page should expose active flag");
    ok &= expect(payload && payload["Resources"][0].has("schemas"),
                 "SCIM User resource should expose schemas");
    if (payload && payload["Resources"][0].has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["Resources"][0]["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM User resource should include core User schema");
    }
    ok &= expect(payload && payload["Resources"][0]["roles"].size() > 0,
                 "SCIM User resource should expose roles list");
    ok &= expect(payload && std::string(payload["Resources"][0]["roles"][0]["value"].s()) ==
                            "operator",
                 "SCIM User resource should expose normalized role value");
    ok &= expect(payload && payload["Resources"][0].has("meta"),
           "SCIM User resource should expose meta object");
    if (payload && payload["Resources"][0].has("meta")) {
      ok &= expect(payload["Resources"][0]["meta"].has("location"),
             "SCIM User resource should expose deterministic meta.location");
      if (payload["Resources"][0]["meta"].has("location")) {
      ok &= expect(
        std::string(payload["Resources"][0]["meta"]["location"].s()) ==
          "/api/scim/v2/Users/2",
        "SCIM User resource should expose deterministic meta.location value");
      }
      ok &= expect(payload["Resources"][0]["meta"].has("version"),
             "SCIM User resource should expose meta.version");
    }
    ok &= expect(response_header_value(response, "Content-Type").find(
                         "application/json") != std::string::npos,
                 "SCIM Users list should return JSON content-type");
    ok &= expect_scim_hardening_headers(response, "SCIM Users list response");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/scim/v2/Users/2", admin_token);
    ok &= expect(response.code == 200,
                 "SCIM Users lookup by id should succeed for existing users");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["id"].s()) == "2",
                 "SCIM Users lookup should return requested id");
    ok &= expect(payload && std::string(payload["userName"].s()) == "alice",
                 "SCIM Users lookup should return requested username");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM Users lookup should expose schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM Users lookup should include core User schema");
    }
    ok &= expect_scim_user_metadata_contract(
      payload, response, "2", "SCIM Users lookup by id response");
  }

      {
      auto response = dispatch_request(
        app, crow::HTTPMethod::Get, "/api/scim/v2/Users/9999", admin_token);
      ok &= expect(response.code == 404,
             "SCIM Users lookup should return 404 for unknown identifiers");
      ok &= expect_scim_error_contract(
        response, 404, "User not found",
        "SCIM Users lookup unknown response", "noTarget");
      }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get,
        "/api/scim/v2/Users?startIndex=50&count=20", admin_token);
    ok &= expect(response.code == 200,
                 "SCIM Users should allow startIndex beyond total results");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload["totalResults"].i() == 4,
                 "SCIM Users totalResults should remain stable");
    ok &= expect(payload && payload["startIndex"].i() == 50,
                 "SCIM Users should echo out-of-range startIndex");
    ok &= expect(payload && payload["itemsPerPage"].i() == 0,
                 "SCIM Users out-of-range page should return itemsPerPage=0");
    ok &= expect(payload && payload["Resources"].size() == 0,
                 "SCIM Users out-of-range page should return no resources");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get,
        "/api/scim/v2/Users?startIndex=1&count=999", admin_token);
    ok &= expect(response.code == 200,
                 "SCIM Users should accept oversized count and clamp it");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload["itemsPerPage"].i() == 4,
                 "SCIM Users oversized count should be clamped while preserving all rows");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get,
        "/api/scim/v2/Users?filter=role%20eq%20%22operator%22&startIndex=1&count=10",
        admin_token);
    ok &= expect(response.code == 200,
                 "SCIM Users should accept supported role filter");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload["totalResults"].i() == 2,
                 "SCIM Users filter should reduce totalResults");
    ok &= expect(payload && payload["itemsPerPage"].i() == 2,
                 "SCIM Users filter page should expose matching items count");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get,
        "/api/scim/v2/Users?filter=userName%20neq%20%22admin%22", admin_token);
    ok &= expect(response.code == 400,
                 "SCIM Users should reject unsupported filter operators");
    ok &= expect(
        response.body.find("Unsupported SCIM filter operator") != std::string::npos,
        "SCIM Users unsupported operator should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "Unsupported SCIM filter operator",
      "SCIM Users unsupported operator response", "invalidFilter");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get,
        "/api/scim/v2/Groups?filter=externalId%20eq%20%22x%22", admin_token);
    ok &= expect(response.code == 400,
                 "SCIM Groups should reject unsupported filter attributes");
    ok &= expect(
        response.body.find("Unsupported SCIM filter attribute for Groups") !=
            std::string::npos,
        "SCIM Groups unsupported attribute should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "Unsupported SCIM filter attribute for Groups",
      "SCIM Groups unsupported attribute response", "invalidFilter");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Get,
        "/api/scim/v2/Groups?startIndex=2&count=1", admin_token);
    ok &= expect(response.code == 200,
                 "SCIM Groups should accept valid paginated request");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload["totalResults"].i() == 3,
                 "SCIM Groups totalResults should match distinct roles");
    ok &= expect(payload && payload["startIndex"].i() == 2,
                 "SCIM Groups startIndex should echo query value");
    ok &= expect(payload && payload["itemsPerPage"].i() == 1,
                 "SCIM Groups itemsPerPage should match selected page size");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM Groups list should expose ListResponse schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(json_list_contains_string(
               payload["schemas"],
               "urn:ietf:params:scim:api:messages:2.0:ListResponse"),
             "SCIM Groups list should include ListResponse schema");
    }
    ok &= expect(payload && payload["Resources"].size() == 1,
                 "SCIM Groups page should contain one resource");
    ok &= expect(
        payload && std::string(payload["Resources"][0]["displayName"].s()) ==
                       "auditor",
        "SCIM Groups should return deterministic alphabetical ordering");
    ok &= expect(payload && payload["Resources"][0].has("schemas"),
           "SCIM Group resource should expose schemas");
    if (payload && payload["Resources"][0].has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["Resources"][0]["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:Group"),
        "SCIM Group resource should include core Group schema");
    }
  }

  {
    auto response = dispatch_request(
      app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
      "{\"userName\":" );
    ok &= expect(response.code == 400,
           "SCIM POST Users should reject malformed JSON payloads");
    ok &= expect_scim_error_contract(
      response, 400, "Invalid JSON body",
      "SCIM POST malformed JSON response", "invalidSyntax");
    }

    {
    auto response = dispatch_request(
      app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
      R"({"role":"operator"})");
    ok &= expect(response.code == 400,
           "SCIM POST Users should reject payloads missing userName");
    ok &= expect_scim_error_contract(
      response, 400, "Missing userName",
      "SCIM POST missing userName response", "invalidValue");
    }

    {
    const int before_provisioned =
        audit_event_count(ctx, "user.scim.provisioned");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
        R"({"userName":"delta","role":"auditor"})");
    ok &= expect(response.code == 201,
                 "SCIM POST Users should create a user");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["userName"].s()) == "delta",
                 "SCIM POST Users should return created username");
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "auditor",
                 "SCIM POST Users should return created role");
    ok &= expect(payload && std::string(payload["id"].s()) == "5",
                 "SCIM POST Users should allocate deterministic id for seeded state");
    ok &= expect(user_exists(ctx, 5),
                 "SCIM POST Users should update in-memory user map");
    ok &= expect(user_role(ctx, 5) == "auditor",
                 "SCIM POST Users should persist normalized role in-memory");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM POST Users should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM POST Users should return core User schema");
    }
    ok &= expect_scim_user_metadata_contract(
        payload, response, "5", "SCIM POST Users created resource response");

    const int after_provisioned =
        audit_event_count(ctx, "user.scim.provisioned");
    ok &= expect(after_provisioned == before_provisioned + 1,
                 "SCIM POST Users should append one provisioned audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.provisioned");
    ok &= expect(audit.has_value(),
                 "SCIM POST Users should expose a provisioned audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM POST Users audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM POST Users audit role should match authenticated admin");
      ok &= expect(audit->payloadIsJson,
                   "SCIM POST Users audit payload should be JSON");
      ok &= expect(audit_payload_contains(*audit, "\"userId\":5"),
                   "SCIM POST Users audit payload should contain created user id");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM POST Users audit payload should contain created username");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"auditor\""),
                   "SCIM POST Users audit payload should contain created role");
    }
  }

  {
    const int before_provisioned =
        audit_event_count(ctx, "user.scim.provisioned");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
        R"({"userName":"DELTA","role":"operator"})");
    ok &= expect(response.code == 409,
                 "SCIM POST Users should reject duplicate usernames case-insensitively");
    ok &= expect_scim_error_contract(
      response, 409, "User already exists",
      "SCIM POST duplicate response", "uniqueness");
    ok &= expect(audit_event_count(ctx, "user.scim.provisioned") ==
                     before_provisioned,
                 "SCIM POST duplicate should not append provisioned audit event");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        "{\"userName\":" );
    ok &= expect(response.code == 400,
                 "SCIM PUT Users should reject malformed JSON payloads");
    ok &= expect_scim_error_contract(
        response, 400, "Invalid JSON body",
        "SCIM PUT malformed JSON response", "invalidSyntax");
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/9999", admin_token,
        R"({"role":"operator"})");
    ok &= expect(response.code == 404,
                 "SCIM PUT Users should return 404 when target user does not exist");
    ok &= expect_scim_error_contract(
        response, 404, "User not found",
        "SCIM PUT unknown user response", "noTarget");
    ok &= expect(audit_event_count(ctx, "user.scim.updated") == before_updated,
                 "SCIM PUT unknown user should not append updated audit event");
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"userName":"alice"})");
    ok &= expect(response.code == 409,
                 "SCIM PUT Users should reject username conflicts");
    ok &= expect_scim_error_contract(
      response, 409, "userName already exists",
      "SCIM PUT username conflict response", "uniqueness");
    ok &= expect(audit_event_count(ctx, "user.scim.updated") == before_updated,
                 "SCIM PUT conflict should not append updated audit event");
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"role":"superuser"})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should coerce unsupported roles to fallback operator");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["userName"].s()) == "delta",
           "SCIM PUT fallback should preserve current username");
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                "operator",
           "SCIM PUT fallback should return normalized fallback role");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PUT invalid role should normalize to operator");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT invalid role fallback should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT invalid role fallback should expose updated audit event");
    if (audit) {
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM PUT invalid role fallback audit should keep original username");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                   "SCIM PUT invalid role fallback audit should contain fallback role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");
    const int before_deprovisioned =
        audit_event_count(ctx, "user.scim.deprovisioned");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"active":"false","role":"auditor"})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should ignore non-boolean active payloads");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["userName"].s()) == "delta",
                 "SCIM PUT active string payload should preserve username");
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "auditor",
                 "SCIM PUT active string payload should still apply valid role updates");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM PUT active string payload should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM PUT active string payload should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                "User",
           "SCIM PUT active string payload should return User resourceType metadata");
    ok &= expect(user_exists(ctx, 5),
                 "SCIM PUT active string payload should not deprovision user");
    ok &= expect(user_role(ctx, 5) == "auditor",
                 "SCIM PUT active string payload should persist requested role");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT active string payload should append updated audit event");
    ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") ==
                     before_deprovisioned,
                 "SCIM PUT active string payload should not append deprovisioned audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT active string payload should expose updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT active string payload audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT active string payload audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM PUT active string payload audit should keep original username");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"auditor\""),
                   "SCIM PUT active string payload audit should contain updated role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"userName":"   "})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should treat blank userName as absent payload field");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["userName"].s()) == "delta",
                 "SCIM PUT blank userName should keep existing username");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM PUT blank userName should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM PUT blank userName should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                "User",
           "SCIM PUT blank userName should return User resourceType metadata");
    ok &= expect(user_name(ctx, 5) == "delta",
                 "SCIM PUT blank userName should preserve username in-memory");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT blank userName should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT blank userName should expose updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT blank userName audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT blank userName audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM PUT blank userName audit should keep username unchanged");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"userName":{"value":"epsilon"}})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should ignore non-string userName payloads");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["userName"].s()) == "delta",
                 "SCIM PUT non-string userName should preserve existing username");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM PUT non-string userName should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM PUT non-string userName should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                "User",
           "SCIM PUT non-string userName should return User resourceType metadata");
    ok &= expect(user_name(ctx, 5) == "delta",
                 "SCIM PUT non-string userName should preserve in-memory username");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT non-string userName should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT non-string userName should expose updated audit event");
    if (audit) {
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM PUT non-string userName audit should keep username unchanged");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"role":{"value":"auditor"}})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should coerce non-string role payloads to fallback operator");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "operator",
                 "SCIM PUT non-string role payload should return fallback operator");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM PUT non-string role payload should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM PUT non-string role payload should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                "User",
           "SCIM PUT non-string role payload should return User resourceType metadata");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PUT non-string role payload should persist fallback operator");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT non-string role payload should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT non-string role payload should expose updated audit event");
    if (audit) {
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                   "SCIM PUT non-string role payload audit should contain fallback role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"roles":[]})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should coerce empty roles arrays to fallback operator");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "operator",
                 "SCIM PUT empty roles array should return fallback operator");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM PUT empty roles array should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM PUT empty roles array should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                            "User",
                 "SCIM PUT empty roles array should return User resourceType metadata");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PUT empty roles array should persist fallback operator");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT empty roles array should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT empty roles array should expose updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT empty roles array audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT empty roles array audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                   "SCIM PUT empty roles array audit should contain fallback role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"roles":[{}]})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should coerce roles objects without value to fallback operator");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "operator",
                 "SCIM PUT roles object without value should return fallback operator");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM PUT roles object without value should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM PUT roles object without value should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                            "User",
                 "SCIM PUT roles object without value should return User resourceType metadata");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PUT roles object without value should persist fallback operator");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT roles object without value should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT roles object without value should expose updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT roles object without value audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT roles object without value audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                   "SCIM PUT roles object without value audit should contain fallback role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"roles":["auditor",{"value":"admin"}]})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should resolve mixed roles arrays from first valid string item");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "auditor",
                 "SCIM PUT mixed roles array should select first role candidate");
    ok &= expect(user_role(ctx, 5) == "auditor",
                 "SCIM PUT mixed roles array should persist resolved role");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT mixed roles array should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT mixed roles array should expose updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT mixed roles array audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT mixed roles array audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM PUT mixed roles array audit should keep username unchanged");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"auditor\""),
                   "SCIM PUT mixed roles array audit should contain resolved role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"roles":[{},"admin"]})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should fallback when first mixed roles item is unsupported");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "operator",
                 "SCIM PUT mixed roles array with unsupported first item should fallback operator");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PUT mixed roles array unsupported first item should persist fallback role");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT mixed roles array unsupported first item should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT mixed roles array unsupported first item should expose updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT mixed roles array unsupported first item audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT mixed roles array unsupported first item audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM PUT mixed roles array unsupported first item audit should keep username unchanged");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                   "SCIM PUT mixed roles array unsupported first item audit should contain fallback role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"roles":[{"value":"   "},"admin"]})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should fallback when first roles value is blank");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "operator",
                 "SCIM PUT roles blank-first array should return fallback operator");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM PUT roles blank-first array should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM PUT roles blank-first array should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                "User",
           "SCIM PUT roles blank-first array should return User resourceType metadata");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PUT roles blank-first array should persist fallback role");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT roles blank-first array should append updated audit event");
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"roles":[1,"admin"]})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should fallback when first roles item is numeric");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "operator",
                 "SCIM PUT roles numeric-first array should return fallback operator");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM PUT roles numeric-first array should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM PUT roles numeric-first array should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                "User",
           "SCIM PUT roles numeric-first array should return User resourceType metadata");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PUT roles numeric-first array should persist fallback role");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT roles numeric-first array should append updated audit event");
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"roles":["admin",{}]})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should keep first valid roles item even when later items are unsupported");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "admin",
                 "SCIM PUT roles valid-then-invalid array should keep first valid role");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM PUT roles valid-then-invalid array should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM PUT roles valid-then-invalid array should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                            "User",
                 "SCIM PUT roles valid-then-invalid array should return User resourceType metadata");
    ok &= expect(user_role(ctx, 5) == "admin",
                 "SCIM PUT roles valid-then-invalid array should persist first valid role");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT roles valid-then-invalid array should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT roles valid-then-invalid array should expose updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT roles valid-then-invalid array audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT roles valid-then-invalid array audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM PUT roles valid-then-invalid array audit should keep username unchanged");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"admin\""),
                   "SCIM PUT roles valid-then-invalid array audit should contain resolved first role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"roles":[{"value":"auditor"},1]})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should keep first valid nested roles item even when trailing items are unsupported");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "auditor",
                 "SCIM PUT roles nested-valid-then-invalid array should keep first valid role");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM PUT roles nested-valid-then-invalid array should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM PUT roles nested-valid-then-invalid array should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                            "User",
                 "SCIM PUT roles nested-valid-then-invalid array should return User resourceType metadata");
    ok &= expect(user_role(ctx, 5) == "auditor",
                 "SCIM PUT roles nested-valid-then-invalid array should persist first valid role");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT roles nested-valid-then-invalid array should append updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT roles nested-valid-then-invalid array should expose updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT roles nested-valid-then-invalid array audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT roles nested-valid-then-invalid array audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta\""),
                   "SCIM PUT roles nested-valid-then-invalid array audit should keep username unchanged");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"auditor\""),
                   "SCIM PUT roles nested-valid-then-invalid array audit should contain resolved first role");
    }
  }

  {
    const int before_updated = audit_event_count(ctx, "user.scim.updated");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/delta", admin_token,
        R"({"userName":"delta-renamed","role":"operator"})");
    ok &= expect(response.code == 200,
                 "SCIM PUT Users should update username and role");
    auto payload = crow::json::load(response.body);
    ok &= expect(
        payload && std::string(payload["userName"].s()) == "delta-renamed",
        "SCIM PUT Users should return updated username");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM PUT Users should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM PUT Users should return core User schema");
    }
    ok &= expect_scim_user_metadata_contract(
        payload, response, "5", "SCIM PUT Users updated resource response");
    const auto delta_id = user_id_by_username(ctx, "delta-renamed");
    ok &= expect(delta_id.has_value() && *delta_id == 5,
                 "SCIM PUT Users should keep original id while renaming");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PUT Users should persist updated role in-memory");

    const int after_updated = audit_event_count(ctx, "user.scim.updated");
    ok &= expect(after_updated == before_updated + 1,
                 "SCIM PUT Users should append one updated audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.updated");
    ok &= expect(audit.has_value(),
                 "SCIM PUT Users should expose an updated audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT Users audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT Users audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"userId\":5"),
                   "SCIM PUT Users audit payload should contain updated user id");
      ok &= expect(
          audit_payload_contains(*audit, "\"username\":\"delta-renamed\""),
          "SCIM PUT Users audit payload should contain updated username");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                   "SCIM PUT Users audit payload should contain updated role");
    }
  }

  {
    auto response = dispatch_request(
      app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
      admin_token, "{\"Operations\":" );
    ok &= expect(response.code == 400,
           "SCIM PATCH Users should reject malformed JSON payloads");
    ok &= expect_scim_error_contract(
      response, 400, "Invalid JSON body",
      "SCIM PATCH malformed JSON response", "invalidSyntax");
    }

    {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/9999",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"role","value":"operator"}]})");
    ok &= expect(response.code == 404,
                 "SCIM PATCH Users should return 404 when target user does not exist");
    ok &= expect_scim_error_contract(
      response, 404, "User not found",
      "SCIM PATCH unknown user response", "noTarget");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH unknown user should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject payloads without Operations");
    ok &= expect(response.body.find("Missing Operations") != std::string::npos,
                 "SCIM PATCH missing Operations should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "Missing Operations",
      "SCIM PATCH missing Operations response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH missing Operations should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject empty Operations arrays");
    ok &= expect(response.body.find("Operations must contain at least one item") !=
                     std::string::npos,
                 "SCIM PATCH empty Operations should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "Operations must contain at least one item",
      "SCIM PATCH empty Operations response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH empty Operations should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"path":"active","value":true}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject operations without op");
    ok &= expect(response.body.find("Each SCIM operation must define op") !=
                     std::string::npos,
                 "SCIM PATCH missing op should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "Each SCIM operation must define op",
      "SCIM PATCH missing op response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH missing op should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"active","value":"true"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject non-boolean active values");
    ok &= expect(response.body.find("active patch value must be a boolean") !=
                     std::string::npos,
                 "SCIM PATCH active non-boolean should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "active patch value must be a boolean",
      "SCIM PATCH active non-boolean response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH active non-boolean should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"role"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject role updates without value");
    ok &= expect(response.body.find("role patch requires value") !=
                     std::string::npos,
                 "SCIM PATCH role missing value should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "role patch requires value",
      "SCIM PATCH role missing value response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH role missing value should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","value":{"displayName":"Delta"}}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject value objects without supported fields");
    ok &= expect(response.body.find("SCIM operation does not include supported fields") !=
                     std::string::npos,
                 "SCIM PATCH unsupported value object should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "SCIM operation does not include supported fields",
      "SCIM PATCH unsupported value object response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH unsupported value object should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"remove"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject remove operations without explicit path");
    ok &= expect(response.body.find("SCIM remove requires an explicit path") !=
                     std::string::npos,
                 "SCIM PATCH remove without path should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "SCIM remove requires an explicit path",
      "SCIM PATCH remove without path response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH remove without path should not append patched audit event");
  }

    {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"emails","value":"delta@example.com"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject unsupported paths");
    ok &= expect(response.body.find("Unsupported SCIM path") != std::string::npos,
                 "SCIM PATCH unsupported path should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "Unsupported SCIM path",
      "SCIM PATCH unsupported path response", "invalidPath");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH unsupported path should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"remove","path":"userName"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject remove on userName");
    ok &= expect(response.body.find("Removing userName is not supported") !=
                     std::string::npos,
                 "SCIM PATCH remove userName should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "Removing userName is not supported",
      "SCIM PATCH remove userName response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH remove userName should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"userName","value":"   "}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject empty userName values");
    ok &= expect(response.body.find("userName patch value must be a non-empty string") !=
                     std::string::npos,
                 "SCIM PATCH empty userName should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "userName patch value must be a non-empty string",
      "SCIM PATCH empty userName response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH empty userName should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"role","value":"root"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject invalid role values");
    ok &= expect(
        response.body.find("role patch value must resolve to operator/admin/auditor") !=
            std::string::npos,
        "SCIM PATCH invalid role should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "role patch value must resolve to operator/admin/auditor",
      "SCIM PATCH invalid role response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH invalid role should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","value":{"role":"root"}}]})");
    ok &= expect(
        response.code == 200,
        "SCIM PATCH Users no-path role payload should keep compatibility fallback behavior");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && payload.has("roles"),
                 "SCIM PATCH no-path role payload should return roles list");
    if (payload && payload.has("roles") && payload["roles"].size() > 0) {
      ok &= expect(std::string(payload["roles"][0]["value"].s()) == "operator",
                   "SCIM PATCH no-path invalid role should normalize to operator");
    }
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PATCH no-path invalid role should persist fallback operator role");

    const int after_patched = audit_event_count(ctx, "user.scim.patched");
    ok &= expect(after_patched == before_patched + 1,
                 "SCIM PATCH no-path invalid role should append one patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"move","path":"userName","value":"x"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should reject unsupported operations");
    ok &= expect(response.body.find("Unsupported SCIM op") != std::string::npos,
                 "SCIM PATCH Users unsupported operation should return explicit error");
    ok &= expect_scim_error_contract(
      response, 400, "Unsupported SCIM op",
      "SCIM PATCH unsupported op response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH invalid op should not append patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"role","value":"operator"},{"op":"replace","path":"role","value":"auditor"}]})");
    ok &= expect(response.code == 200,
                 "SCIM PATCH Users should apply the last role operation when the same path is repeated");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "auditor",
                 "SCIM PATCH repeated role operations should keep the last value");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM PATCH repeated role operations should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM PATCH repeated role operations should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                            "User",
                 "SCIM PATCH repeated role operations should return User resourceType metadata");
    ok &= expect(user_role(ctx, 5) == "auditor",
                 "SCIM PATCH repeated role operations should persist the last role value");

    const int after_patched = audit_event_count(ctx, "user.scim.patched");
    ok &= expect(after_patched == before_patched + 1,
                 "SCIM PATCH repeated role operations should append one patched audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.patched");
    ok &= expect(audit.has_value(),
                 "SCIM PATCH repeated role operations should expose patched audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PATCH repeated role operations audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PATCH repeated role operations audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta-renamed\""),
                   "SCIM PATCH repeated role operations audit should keep username unchanged");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"auditor\""),
                   "SCIM PATCH repeated role operations audit should contain last role value");
    }
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");
    const int before_deprovisioned =
        audit_event_count(ctx, "user.scim.deprovisioned");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"active","value":false},{"op":"replace","path":"active","value":true},{"op":"replace","path":"role","value":"operator"}]})");
    ok &= expect(response.code == 200,
                 "SCIM PATCH Users should not deprovision when a later active operation sets true");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["userName"].s()) == "delta-renamed",
                 "SCIM PATCH active false then true should keep target user");
    ok &= expect(payload && std::string(payload["roles"][0]["value"].s()) ==
                            "operator",
                 "SCIM PATCH active false then true should still apply role mutation");
    ok &= expect(user_exists(ctx, 5),
                 "SCIM PATCH active false then true should keep user in-memory");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PATCH active false then true should persist role mutation");

    const int after_patched = audit_event_count(ctx, "user.scim.patched");
    ok &= expect(after_patched == before_patched + 1,
                 "SCIM PATCH active false then true should append one patched audit event");
    ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") ==
                     before_deprovisioned,
                 "SCIM PATCH active false then true should not append deprovisioned audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.patched");
    ok &= expect(audit.has_value(),
                 "SCIM PATCH active false then true should expose patched audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PATCH active false then true audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PATCH active false then true audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta-renamed\""),
                   "SCIM PATCH active false then true audit should keep username unchanged");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                   "SCIM PATCH active false then true audit should contain resulting role");
    }
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");
    const std::string role_before = user_role(ctx, 5);

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"role","value":"auditor"},{"op":"move","path":"userName","value":"x"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should fail atomically when a later operation is unsupported");
    ok &= expect_scim_error_contract(
      response, 400, "Unsupported SCIM op",
      "SCIM PATCH mixed valid and invalid op response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH mixed valid and invalid op should not append patched audit event");
    ok &= expect(user_role(ctx, 5) == role_before,
                 "SCIM PATCH mixed valid and invalid op should not persist partial role updates");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");
    const std::string role_before = user_role(ctx, 5);

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"role","value":"auditor"},{"op":"replace","path":"emails","value":"delta@example.com"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should fail atomically when a later operation uses invalidPath");
    ok &= expect_scim_error_contract(
      response, 400, "Unsupported SCIM path",
      "SCIM PATCH mixed valid and invalid path response", "invalidPath");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH mixed valid and invalid path should not append patched audit event");
    ok &= expect(user_role(ctx, 5) == role_before,
                 "SCIM PATCH mixed valid and invalid path should not persist partial role updates");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");
    const std::string user_before = user_name(ctx, 5);
    const std::string role_before = user_role(ctx, 5);

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"userName","value":"delta-candidate-a"},{"op":"replace","path":"userName","value":"delta-candidate-b"},{"op":"replace","path":"emails","value":"delta@example.com"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should fail atomically when repeated userName ops are followed by invalidPath");
    ok &= expect_scim_error_contract(
      response, 400, "Unsupported SCIM path",
      "SCIM PATCH repeated userName then invalidPath response", "invalidPath");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH repeated userName then invalidPath should not append patched audit event");
    ok &= expect(user_name(ctx, 5) == user_before,
                 "SCIM PATCH repeated userName then invalidPath should not persist partial userName updates");
    ok &= expect(user_role(ctx, 5) == role_before,
                 "SCIM PATCH repeated userName then invalidPath should not persist partial role updates");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");
    const std::string role_before = user_role(ctx, 5);

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"userName","value":"delta-patched-a"},{"op":"replace","path":"userName","value":"delta-patched-b"}]})");
    ok &= expect(response.code == 200,
                 "SCIM PATCH Users should apply the last userName operation when the same path is repeated");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["userName"].s()) ==
                            "delta-patched-b",
                 "SCIM PATCH repeated userName operations should keep the last value");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM PATCH repeated userName operations should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM PATCH repeated userName operations should return core User schema");
    }
    ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                            "User",
                 "SCIM PATCH repeated userName operations should return User resourceType metadata");
    ok &= expect(user_name(ctx, 5) == "delta-patched-b",
                 "SCIM PATCH repeated userName operations should persist last userName value");
    ok &= expect(user_role(ctx, 5) == role_before,
                 "SCIM PATCH repeated userName operations should preserve existing role");

    const int after_patched = audit_event_count(ctx, "user.scim.patched");
    ok &= expect(after_patched == before_patched + 1,
                 "SCIM PATCH repeated userName operations should append one patched audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.patched");
    ok &= expect(audit.has_value(),
                 "SCIM PATCH repeated userName operations should expose patched audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PATCH repeated userName operations audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PATCH repeated userName operations audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"delta-patched-b\""),
                   "SCIM PATCH repeated userName operations audit should contain last userName value");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"" + role_before + "\""),
                   "SCIM PATCH repeated userName operations audit should preserve role in payload");
    }
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");
    const std::string user_before = user_name(ctx, 5);
    const std::string role_before = user_role(ctx, 5);

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-patched-b",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"role","value":"auditor"},{"op":"replace","path":"active","value":"false"}]})");
    ok &= expect(response.code == 400,
                 "SCIM PATCH Users should fail atomically when a later operation returns invalidValue");
    ok &= expect_scim_error_contract(
      response, 400, "active patch value must be a boolean",
      "SCIM PATCH mixed valid and invalid value response", "invalidValue");
    ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched,
                 "SCIM PATCH mixed valid and invalid value should not append patched audit event");
    ok &= expect(user_name(ctx, 5) == user_before,
                 "SCIM PATCH mixed valid and invalid value should not persist partial userName updates");
    ok &= expect(user_role(ctx, 5) == role_before,
                 "SCIM PATCH mixed valid and invalid value should not persist partial role updates");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-patched-b",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"userName","value":"delta-renamed"},{"op":"replace","path":"role","value":"operator"}]})");
    ok &= expect(response.code == 200,
                 "SCIM PATCH Users should restore the canonical identifier for later assertions");
    auto payload = crow::json::load(response.body);
    ok &= expect(payload && std::string(payload["userName"].s()) == "delta-renamed",
                 "SCIM PATCH restore should return the canonical username");
    ok &= expect(payload && payload.has("schemas"),
                 "SCIM PATCH restore should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
          json_list_contains_string(
              payload["schemas"],
              "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM PATCH restore should return core User schema");
    }
    ok &= expect_scim_user_metadata_contract(
        payload, response, "5", "SCIM PATCH canonical identifier restore response");
    ok &= expect(user_name(ctx, 5) == "delta-renamed",
                 "SCIM PATCH restore should persist the canonical username");
    ok &= expect(user_role(ctx, 5) == "operator",
                 "SCIM PATCH restore should persist the canonical operator role");

    const int after_patched = audit_event_count(ctx, "user.scim.patched");
    ok &= expect(after_patched == before_patched + 1,
                 "SCIM PATCH restore should append one patched audit event");
  }

  {
    const int before_patched = audit_event_count(ctx, "user.scim.patched");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-renamed",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"role","value":"auditor"},{"op":"replace","path":"userName","value":"delta-patched"}]})");
    ok &= expect(response.code == 200,
                 "SCIM PATCH Users should support role and username updates");
    auto payload = crow::json::load(response.body);
    ok &= expect(
        payload && std::string(payload["userName"].s()) == "delta-patched",
        "SCIM PATCH Users should return patched username");
    ok &= expect(payload && payload.has("schemas"),
           "SCIM PATCH Users should return SCIM resource schemas");
    if (payload && payload.has("schemas")) {
      ok &= expect(
        json_list_contains_string(
          payload["schemas"],
          "urn:ietf:params:scim:schemas:core:2.0:User"),
        "SCIM PATCH Users should return core User schema");
    }
    ok &= expect_scim_user_metadata_contract(
        payload, response, "5", "SCIM PATCH Users updated resource response");
    ok &= expect(user_name(ctx, 5) == "delta-patched",
                 "SCIM PATCH Users should persist patched username in-memory");
    ok &= expect(user_role(ctx, 5) == "auditor",
                 "SCIM PATCH Users should persist patched role in-memory");

    const int after_patched = audit_event_count(ctx, "user.scim.patched");
    ok &= expect(after_patched == before_patched + 1,
                 "SCIM PATCH Users should append one patched audit event");
    const auto audit = last_audit_event_of_type(ctx, "user.scim.patched");
    ok &= expect(audit.has_value(),
                 "SCIM PATCH Users should expose a patched audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PATCH Users audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PATCH Users audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"userId\":5"),
                   "SCIM PATCH Users audit payload should contain patched user id");
      ok &= expect(
          audit_payload_contains(*audit, "\"username\":\"delta-patched\""),
          "SCIM PATCH Users audit payload should contain patched username");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"auditor\""),
                   "SCIM PATCH Users audit payload should contain patched role");
    }
  }

  {
    const int before_deprovisioned =
        audit_event_count(ctx, "user.scim.deprovisioned");
    const std::string delta_token = "delta-session-token";
    seed_auth_session(ctx, 5, "delta-patched", "auditor", delta_token);
    ok &= expect(auth_token_exists(ctx, delta_token),
                 "Test setup should register target user session token");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/delta-patched",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"active","value":false}]})");
    ok &= expect(response.code == 204,
                 "SCIM PATCH Users active=false should deprovision the user");
    ok &= expect(response.body.empty(),
           "SCIM PATCH deprovision should return empty body for HTTP 204");
    ok &= expect(!user_exists(ctx, 5),
                 "SCIM PATCH Users deprovision should remove user in-memory");
    ok &= expect(!auth_token_exists(ctx, delta_token),
                 "SCIM PATCH Users deprovision should invalidate target user sessions");

    const int after_deprovisioned =
        audit_event_count(ctx, "user.scim.deprovisioned");
    ok &= expect(after_deprovisioned == before_deprovisioned + 1,
                 "SCIM PATCH deprovision should append one deprovisioned audit event");
    const auto audit =
        last_audit_event_of_type(ctx, "user.scim.deprovisioned");
    ok &= expect(audit.has_value(),
                 "SCIM PATCH deprovision should expose a deprovisioned audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PATCH deprovision audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PATCH deprovision audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"userId\":5"),
                   "SCIM PATCH deprovision audit payload should contain user id");
      ok &= expect(
          audit_payload_contains(*audit, "\"username\":\"delta-patched\""),
          "SCIM PATCH deprovision audit payload should contain user name");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"auditor\""),
                   "SCIM PATCH deprovision audit payload should contain user role");
    }
  }

  {
    const int before_provisioned =
        audit_event_count(ctx, "user.scim.provisioned");
    auto create_response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
        R"({"userName":"zeta-temp","role":"operator"})");
    ok &= expect(create_response.code == 201,
                 "SCIM PATCH active true then false test should create a temporary user");
    const auto temp_id = user_id_by_username(ctx, "zeta-temp");
    ok &= expect(temp_id.has_value(),
                 "SCIM PATCH active true then false test should resolve temporary user id");
    ok &= expect(audit_event_count(ctx, "user.scim.provisioned") == before_provisioned + 1,
                 "SCIM PATCH active true then false test setup should append provisioned audit event");

    if (temp_id) {
      const std::string temp_token = "zeta-temp-session-token";
      seed_auth_session(ctx, *temp_id, "zeta-temp", "operator", temp_token);
      ok &= expect(auth_token_exists(ctx, temp_token),
                   "SCIM PATCH active true then false test should seed temporary user session token");

      const int before_deprovisioned_case =
          audit_event_count(ctx, "user.scim.deprovisioned");
      const int before_patched_case = audit_event_count(ctx, "user.scim.patched");

      auto response = dispatch_request(
          app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/zeta-temp",
          admin_token,
          R"({"Operations":[{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false}]})");
      ok &= expect(response.code == 204,
                   "SCIM PATCH Users should deprovision when active=true is followed by active=false");
      ok &= expect(response.body.empty(),
                   "SCIM PATCH active true then false deprovision should return empty body");
      ok &= expect(!user_exists(ctx, *temp_id),
                   "SCIM PATCH active true then false should remove temporary user");
      ok &= expect(!auth_token_exists(ctx, temp_token),
                   "SCIM PATCH active true then false should invalidate temporary user sessions");
      ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") ==
                       before_deprovisioned_case + 1,
                   "SCIM PATCH active true then false should append one deprovisioned audit event");
      ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched_case,
                   "SCIM PATCH active true then false should not append patched audit event");
        const auto audit =
          last_audit_event_of_type(ctx, "user.scim.deprovisioned");
        ok &= expect(audit.has_value(),
               "SCIM PATCH active true then false should expose deprovisioned audit event");
        if (audit) {
        ok &= expect(audit->actor == "admin",
               "SCIM PATCH active true then false audit actor should match authenticated admin");
        ok &= expect(audit->role == "admin",
               "SCIM PATCH active true then false audit role should match authenticated admin");
        ok &= expect(audit_payload_contains(*audit, "\"userId\":" + std::to_string(*temp_id)),
               "SCIM PATCH active true then false audit payload should contain temporary user id");
        ok &= expect(audit_payload_contains(*audit, "\"username\":\"zeta-temp\""),
               "SCIM PATCH active true then false audit payload should contain temporary user name");
        ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
               "SCIM PATCH active true then false audit payload should contain temporary user role");
        }
    }
  }

      {
      const int before_provisioned =
        audit_event_count(ctx, "user.scim.provisioned");
      auto create_response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
        R"({"userName":"zeta-triplet","role":"operator"})");
      ok &= expect(create_response.code == 201,
             "SCIM PATCH active true false true test should create a temporary user");
      const auto temp_id = user_id_by_username(ctx, "zeta-triplet");
      ok &= expect(temp_id.has_value(),
             "SCIM PATCH active true false true test should resolve temporary user id");
      ok &= expect(audit_event_count(ctx, "user.scim.provisioned") == before_provisioned + 1,
             "SCIM PATCH active true false true setup should append provisioned audit event");

      if (temp_id) {
        const std::string temp_token = "zeta-triplet-session-token";
        seed_auth_session(ctx, *temp_id, "zeta-triplet", "operator", temp_token);
        ok &= expect(auth_token_exists(ctx, temp_token),
               "SCIM PATCH active true false true test should seed temporary user session token");

        const int before_deprovisioned_case =
          audit_event_count(ctx, "user.scim.deprovisioned");
        const int before_patched_case = audit_event_count(ctx, "user.scim.patched");

        auto response = dispatch_request(
          app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/zeta-triplet",
          admin_token,
          R"({"Operations":[{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false},{"op":"replace","path":"active","value":true}]})");
        ok &= expect(response.code == 200,
               "SCIM PATCH Users should not deprovision when active=true follows active=false in a triplet");
        auto payload = crow::json::load(response.body);
        ok &= expect(payload && std::string(payload["userName"].s()) == "zeta-triplet",
               "SCIM PATCH active true false true should keep temporary user name");
        ok &= expect(payload && payload.has("schemas"),
               "SCIM PATCH active true false true should return SCIM resource schemas");
        if (payload && payload.has("schemas")) {
        ok &= expect(
          json_list_contains_string(
            payload["schemas"],
            "urn:ietf:params:scim:schemas:core:2.0:User"),
          "SCIM PATCH active true false true should return core User schema");
        }
        ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                    "User",
               "SCIM PATCH active true false true should return User resourceType metadata");
        ok &= expect(user_exists(ctx, *temp_id),
               "SCIM PATCH active true false true should keep temporary user in-memory");
        ok &= expect(auth_token_exists(ctx, temp_token),
               "SCIM PATCH active true false true should keep temporary user sessions valid");
        ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") ==
                 before_deprovisioned_case,
               "SCIM PATCH active true false true should not append deprovisioned audit event");
        ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched_case,
               "SCIM PATCH active true false true should not append patched audit event");
      }
      }

  {
    const int before_provisioned =
        audit_event_count(ctx, "user.scim.provisioned");
    auto create_response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
        R"({"userName":"zeta-mirror","role":"operator"})");
    ok &= expect(create_response.code == 201,
                 "SCIM PATCH active false true false test should create a temporary user");
    const auto temp_id = user_id_by_username(ctx, "zeta-mirror");
    ok &= expect(temp_id.has_value(),
                 "SCIM PATCH active false true false test should resolve temporary user id");
    ok &= expect(audit_event_count(ctx, "user.scim.provisioned") == before_provisioned + 1,
                 "SCIM PATCH active false true false setup should append provisioned audit event");

    if (temp_id) {
      const std::string temp_token = "zeta-mirror-session-token";
      seed_auth_session(ctx, *temp_id, "zeta-mirror", "operator", temp_token);
      ok &= expect(auth_token_exists(ctx, temp_token),
                   "SCIM PATCH active false true false test should seed temporary user session token");

      const int before_deprovisioned_case =
          audit_event_count(ctx, "user.scim.deprovisioned");
      const int before_patched_case = audit_event_count(ctx, "user.scim.patched");

      auto response = dispatch_request(
          app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/zeta-mirror",
          admin_token,
          R"({"Operations":[{"op":"replace","path":"active","value":false},{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false}]})");
      ok &= expect(response.code == 204,
                   "SCIM PATCH Users should deprovision when active=false is the last operation in a triplet");
      ok &= expect(response.body.empty(),
                   "SCIM PATCH active false true false deprovision should return empty body");
      ok &= expect(!user_exists(ctx, *temp_id),
                   "SCIM PATCH active false true false should remove temporary user");
      ok &= expect(!user_id_by_username(ctx, "zeta-mirror").has_value(),
           "SCIM PATCH active false true false should leave no temporary user lookup residue");
      ok &= expect(!auth_token_exists(ctx, temp_token),
                   "SCIM PATCH active false true false should invalidate temporary user sessions");
      ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") ==
                       before_deprovisioned_case + 1,
                   "SCIM PATCH active false true false should append one deprovisioned audit event");
      ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched_case,
                   "SCIM PATCH active false true false should not append patched audit event");

      const auto audit =
          last_audit_event_of_type(ctx, "user.scim.deprovisioned");
      ok &= expect(audit.has_value(),
                   "SCIM PATCH active false true false should expose deprovisioned audit event");
      if (audit) {
        ok &= expect(audit->actor == "admin",
                     "SCIM PATCH active false true false audit actor should match authenticated admin");
        ok &= expect(audit->role == "admin",
                     "SCIM PATCH active false true false audit role should match authenticated admin");
        ok &= expect(audit_payload_contains(*audit, "\"userId\":" + std::to_string(*temp_id)),
                     "SCIM PATCH active false true false audit payload should contain temporary user id");
        ok &= expect(audit_payload_contains(*audit, "\"username\":\"zeta-mirror\""),
                     "SCIM PATCH active false true false audit payload should contain temporary user name");
        ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                     "SCIM PATCH active false true false audit payload should contain temporary user role");
      }
    }
  }

  {
    const int before_provisioned =
        audit_event_count(ctx, "user.scim.provisioned");
    auto create_response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
        R"({"userName":"zeta-quad","role":"operator"})");
    ok &= expect(create_response.code == 201,
                 "SCIM PATCH active true false true false test should create a temporary user");
    const auto temp_id = user_id_by_username(ctx, "zeta-quad");
    ok &= expect(temp_id.has_value(),
                 "SCIM PATCH active true false true false test should resolve temporary user id");
    ok &= expect(audit_event_count(ctx, "user.scim.provisioned") == before_provisioned + 1,
                 "SCIM PATCH active true false true false setup should append provisioned audit event");

    if (temp_id) {
      const std::string temp_token = "zeta-quad-session-token";
      seed_auth_session(ctx, *temp_id, "zeta-quad", "operator", temp_token);
      ok &= expect(auth_token_exists(ctx, temp_token),
                   "SCIM PATCH active true false true false test should seed temporary user session token");

      const int before_deprovisioned_case =
          audit_event_count(ctx, "user.scim.deprovisioned");
      const int before_patched_case = audit_event_count(ctx, "user.scim.patched");

      auto response = dispatch_request(
          app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/zeta-quad",
          admin_token,
          R"({"Operations":[{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false},{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false}]})");
      ok &= expect(response.code == 204,
                   "SCIM PATCH Users should deprovision when active=false is the last operation in a quadruplet");
      ok &= expect(response.body.empty(),
                   "SCIM PATCH active true false true false deprovision should return empty body");
      ok &= expect(!user_exists(ctx, *temp_id),
                   "SCIM PATCH active true false true false should remove temporary user");
      ok &= expect(!user_id_by_username(ctx, "zeta-quad").has_value(),
                   "SCIM PATCH active true false true false should leave no temporary user lookup residue");
      ok &= expect(!auth_token_exists(ctx, temp_token),
                   "SCIM PATCH active true false true false should invalidate temporary user sessions");
      ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") ==
                       before_deprovisioned_case + 1,
                   "SCIM PATCH active true false true false should append one deprovisioned audit event");
      ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched_case,
                   "SCIM PATCH active true false true false should not append patched audit event");

      const auto audit =
          last_audit_event_of_type(ctx, "user.scim.deprovisioned");
      ok &= expect(audit.has_value(),
                   "SCIM PATCH active true false true false should expose deprovisioned audit event");
      if (audit) {
        ok &= expect(audit->actor == "admin",
                     "SCIM PATCH active true false true false audit actor should match authenticated admin");
        ok &= expect(audit->role == "admin",
                     "SCIM PATCH active true false true false audit role should match authenticated admin");
        ok &= expect(audit_payload_contains(*audit, "\"userId\":" + std::to_string(*temp_id)),
                     "SCIM PATCH active true false true false audit payload should contain temporary user id");
        ok &= expect(audit_payload_contains(*audit, "\"username\":\"zeta-quad\""),
                     "SCIM PATCH active true false true false audit payload should contain temporary user name");
        ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                     "SCIM PATCH active true false true false audit payload should contain temporary user role");
      }
    }
  }

  {
    const int before_provisioned =
        audit_event_count(ctx, "user.scim.provisioned");
    auto create_response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
        R"({"userName":"zeta-quad-keep","role":"operator"})");
    ok &= expect(create_response.code == 201,
                 "SCIM PATCH active false true false true test should create a temporary user");
    const auto temp_id = user_id_by_username(ctx, "zeta-quad-keep");
    ok &= expect(temp_id.has_value(),
                 "SCIM PATCH active false true false true test should resolve temporary user id");
    ok &= expect(audit_event_count(ctx, "user.scim.provisioned") == before_provisioned + 1,
                 "SCIM PATCH active false true false true setup should append provisioned audit event");

    if (temp_id) {
      const std::string temp_token = "zeta-quad-keep-session-token";
      seed_auth_session(ctx, *temp_id, "zeta-quad-keep", "operator", temp_token);
      ok &= expect(auth_token_exists(ctx, temp_token),
                   "SCIM PATCH active false true false true test should seed temporary user session token");

      const int before_deprovisioned_case =
          audit_event_count(ctx, "user.scim.deprovisioned");
      const int before_patched_case = audit_event_count(ctx, "user.scim.patched");

      auto response = dispatch_request(
          app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/zeta-quad-keep",
          admin_token,
          R"({"Operations":[{"op":"replace","path":"active","value":false},{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false},{"op":"replace","path":"active","value":true}]})");
      ok &= expect(response.code == 200,
                   "SCIM PATCH Users should keep user when active=true is the last operation in a mirrored quadruplet");
      auto payload = crow::json::load(response.body);
      ok &= expect(payload && std::string(payload["userName"].s()) == "zeta-quad-keep",
                   "SCIM PATCH active false true false true should keep temporary user name");
      ok &= expect(payload && payload.has("schemas"),
                   "SCIM PATCH active false true false true should return SCIM resource schemas");
      if (payload && payload.has("schemas")) {
        ok &= expect(
            json_list_contains_string(
                payload["schemas"],
                "urn:ietf:params:scim:schemas:core:2.0:User"),
            "SCIM PATCH active false true false true should return core User schema");
      }
      ok &= expect(payload && std::string(payload["meta"]["resourceType"].s()) ==
                              "User",
                   "SCIM PATCH active false true false true should return User resourceType metadata");
      ok &= expect(user_exists(ctx, *temp_id),
                   "SCIM PATCH active false true false true should keep temporary user in-memory");
      ok &= expect(auth_token_exists(ctx, temp_token),
                   "SCIM PATCH active false true false true should keep temporary user sessions valid");
      ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") ==
                       before_deprovisioned_case,
                   "SCIM PATCH active false true false true should not append deprovisioned audit event");
      ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched_case,
                   "SCIM PATCH active false true false true should not append patched audit event");
    }
  }

  {
    const int before_provisioned =
      audit_event_count(ctx, "user.scim.provisioned");
    auto create_response = dispatch_request(
      app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
      R"({"userName":"zeta-penta","role":"operator"})");
    ok &= expect(create_response.code == 201,
           "SCIM PATCH active false true false true false test should create a temporary user");
    const auto temp_id = user_id_by_username(ctx, "zeta-penta");
    ok &= expect(temp_id.has_value(),
           "SCIM PATCH active false true false true false test should resolve temporary user id");
    ok &= expect(audit_event_count(ctx, "user.scim.provisioned") == before_provisioned + 1,
           "SCIM PATCH active false true false true false setup should append provisioned audit event");

    if (temp_id) {
      const std::string temp_token = "zeta-penta-session-token";
      seed_auth_session(ctx, *temp_id, "zeta-penta", "operator", temp_token);
      ok &= expect(auth_token_exists(ctx, temp_token),
             "SCIM PATCH active false true false true false test should seed temporary user session token");

      const int before_deprovisioned_case =
        audit_event_count(ctx, "user.scim.deprovisioned");
      const int before_patched_case = audit_event_count(ctx, "user.scim.patched");

      auto response = dispatch_request(
        app, crow::HTTPMethod::Patch, "/api/scim/v2/Users/zeta-penta",
        admin_token,
        R"({"Operations":[{"op":"replace","path":"active","value":false},{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false},{"op":"replace","path":"active","value":true},{"op":"replace","path":"active","value":false}]})");
      ok &= expect(response.code == 204,
             "SCIM PATCH Users should deprovision when active=false is the last operation in a 5-step alternation");
      ok &= expect(response.body.empty(),
             "SCIM PATCH active false true false true false deprovision should return empty body");
      ok &= expect(!user_exists(ctx, *temp_id),
             "SCIM PATCH active false true false true false should remove temporary user");
      ok &= expect(!user_id_by_username(ctx, "zeta-penta").has_value(),
             "SCIM PATCH active false true false true false should leave no temporary user lookup residue");
      ok &= expect(!auth_token_exists(ctx, temp_token),
             "SCIM PATCH active false true false true false should invalidate temporary user sessions");
      ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") ==
               before_deprovisioned_case + 1,
             "SCIM PATCH active false true false true false should append one deprovisioned audit event");
      ok &= expect(audit_event_count(ctx, "user.scim.patched") == before_patched_case,
             "SCIM PATCH active false true false true false should not append patched audit event");

      const auto audit =
        last_audit_event_of_type(ctx, "user.scim.deprovisioned");
      ok &= expect(audit.has_value(),
             "SCIM PATCH active false true false true false should expose deprovisioned audit event");
      if (audit) {
      ok &= expect(audit->actor == "admin",
             "SCIM PATCH active false true false true false audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
             "SCIM PATCH active false true false true false audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*audit, "\"userId\":" + std::to_string(*temp_id)),
             "SCIM PATCH active false true false true false audit payload should contain temporary user id");
      ok &= expect(audit_payload_contains(*audit, "\"username\":\"zeta-penta\""),
             "SCIM PATCH active false true false true false audit payload should contain temporary user name");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
             "SCIM PATCH active false true false true false audit payload should contain temporary user role");
      }
    }
    }

    {
    ok &= expect(!user_id_by_username(ctx, "zeta-temp").has_value(),
                 "SCIM PATCH temporary deprovisioned zeta-temp user should not leak in username lookup");
    ok &= expect(!auth_token_exists(ctx, "zeta-temp-session-token"),
                 "SCIM PATCH temporary deprovisioned zeta-temp session token should not leak");
    ok &= expect(!user_id_by_username(ctx, "zeta-mirror").has_value(),
                 "SCIM PATCH temporary deprovisioned zeta-mirror user should not leak in username lookup");
    ok &= expect(!auth_token_exists(ctx, "zeta-mirror-session-token"),
                 "SCIM PATCH temporary deprovisioned zeta-mirror session token should not leak");
    ok &= expect(!user_id_by_username(ctx, "zeta-quad").has_value(),
                 "SCIM PATCH temporary deprovisioned zeta-quad user should not leak in username lookup");
    ok &= expect(!auth_token_exists(ctx, "zeta-quad-session-token"),
                 "SCIM PATCH temporary deprovisioned zeta-quad session token should not leak");
    ok &= expect(!user_id_by_username(ctx, "zeta-penta").has_value(),
           "SCIM PATCH temporary deprovisioned zeta-penta user should not leak in username lookup");
    ok &= expect(!auth_token_exists(ctx, "zeta-penta-session-token"),
           "SCIM PATCH temporary deprovisioned zeta-penta session token should not leak");
  }

  {
    auto response = dispatch_request(
        app, crow::HTTPMethod::Post, "/api/scim/v2/Users", admin_token,
        R"({"userName":"putdrop","role":"operator"})");
    ok &= expect(response.code == 201,
                 "SCIM POST Users should create helper user for PUT deprovision test");
    auto payload = crow::json::load(response.body);
    const std::string putdrop_id_str =
        payload ? std::string(payload["id"].s()) : "";
    int putdrop_id = 0;
    if (!putdrop_id_str.empty()) {
      try {
        putdrop_id = std::stoi(putdrop_id_str);
      } catch (...) {
        putdrop_id = 0;
      }
    }
    ok &= expect(putdrop_id > 0,
                 "SCIM POST Users helper user should return a valid id");

    const int before_deprovisioned =
        audit_event_count(ctx, "user.scim.deprovisioned");
    const std::string putdrop_token = "putdrop-session-token";
    seed_auth_session(ctx, putdrop_id, "putdrop", "operator", putdrop_token);
    ok &= expect(auth_token_exists(ctx, putdrop_token),
                 "Test setup should register putdrop session token");

    auto deprovision_response = dispatch_request(
        app, crow::HTTPMethod::Put, "/api/scim/v2/Users/putdrop", admin_token,
        R"({"active":false})");
    ok &= expect(deprovision_response.code == 204,
                 "SCIM PUT Users active=false should deprovision the user");
    ok &= expect(deprovision_response.body.empty(),
           "SCIM PUT deprovision should return empty body for HTTP 204");
    ok &= expect(!user_exists(ctx, putdrop_id),
                 "SCIM PUT Users deprovision should remove user in-memory");
    ok &= expect(!auth_token_exists(ctx, putdrop_token),
                 "SCIM PUT Users deprovision should invalidate target user sessions");

    const int after_deprovisioned =
        audit_event_count(ctx, "user.scim.deprovisioned");
    ok &= expect(after_deprovisioned == before_deprovisioned + 1,
                 "SCIM PUT deprovision should append one deprovisioned audit event");
    const auto audit =
        last_audit_event_of_type(ctx, "user.scim.deprovisioned");
    ok &= expect(audit.has_value(),
                 "SCIM PUT deprovision should expose a deprovisioned audit event");
    if (audit) {
      ok &= expect(audit->actor == "admin",
                   "SCIM PUT deprovision audit actor should match authenticated admin");
      ok &= expect(audit->role == "admin",
                   "SCIM PUT deprovision audit role should match authenticated admin");
      ok &= expect(
          audit_payload_contains(*audit, "\"username\":\"putdrop\""),
          "SCIM PUT deprovision audit payload should contain user name");
      ok &= expect(audit_payload_contains(*audit, "\"role\":\"operator\""),
                   "SCIM PUT deprovision audit payload should contain user role");
    }
  }

  {
    const int before_deprovisioned =
        audit_event_count(ctx, "user.scim.deprovisioned");
    const std::string bob_token = "bob-session-token";
    seed_auth_session(ctx, 3, "bob", "operator", bob_token);
    ok &= expect(auth_token_exists(ctx, bob_token),
                 "Test setup should register bob session token");

    auto response = dispatch_request(
        app, crow::HTTPMethod::Delete, "/api/scim/v2/Users/3", admin_token);
    ok &= expect(response.code == 204,
                 "SCIM DELETE Users should deprovision by numeric id");
    ok &= expect(response.body.empty(),
           "SCIM DELETE should return empty body for HTTP 204");
    ok &= expect(!user_exists(ctx, 3),
                 "SCIM DELETE Users should remove user in-memory");
    ok &= expect(!auth_token_exists(ctx, bob_token),
                 "SCIM DELETE Users should invalidate target user sessions");

    const int after_delete = audit_event_count(ctx, "user.scim.deprovisioned");
    ok &= expect(after_delete == before_deprovisioned + 1,
                 "SCIM DELETE should append one deprovisioned audit event");
    const auto delete_audit =
        last_audit_event_of_type(ctx, "user.scim.deprovisioned");
    ok &= expect(delete_audit.has_value(),
                 "SCIM DELETE should expose a deprovisioned audit event");
    if (delete_audit) {
      ok &= expect(delete_audit->actor == "admin",
                   "SCIM DELETE audit actor should match authenticated admin");
      ok &= expect(delete_audit->role == "admin",
                   "SCIM DELETE audit role should match authenticated admin");
      ok &= expect(audit_payload_contains(*delete_audit, "\"userId\":3"),
                   "SCIM DELETE audit payload should contain deleted user id");
      ok &= expect(audit_payload_contains(*delete_audit, "\"username\":\"bob\""),
                   "SCIM DELETE audit payload should contain deleted username");
      ok &= expect(audit_payload_contains(*delete_audit, "\"role\":\"operator\""),
                   "SCIM DELETE audit payload should contain deleted role");
    }

    auto second_delete = dispatch_request(
        app, crow::HTTPMethod::Delete, "/api/scim/v2/Users/3", admin_token);
    ok &= expect(second_delete.code == 404,
                 "SCIM DELETE Users should return 404 for unknown user");
    ok &= expect_scim_error_contract(
      second_delete, 404, "User not found",
      "SCIM DELETE unknown user response", "noTarget");
    ok &= expect(audit_event_count(ctx, "user.scim.deprovisioned") == after_delete,
                 "SCIM DELETE 404 should not append additional deprovision audit event");
  }

  if (!ok) {
    return 1;
  }

  std::cout << "All SCIM route tests passed." << std::endl;
  return 0;
}