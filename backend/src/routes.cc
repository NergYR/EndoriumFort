// ─── EndoriumFort — API routes implementation ──────────────────────────

#include "routes.h"
#include "app_context.h"
#include "crypto.h"
#include "totp.h"
#include "utils.h"
#include "version.h"

#include <algorithm>
#include <fstream>
#include <sstream>

// ══════════════════════════════════════════════════════════════════════
//  Health
// ══════════════════════════════════════════════════════════════════════

void register_health_routes(CrowApp &app, AppContext &) {
  CROW_ROUTE(app, "/api/health")([] {
    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["message"] = "EndoriumFort API online";
    payload["version"] = APP_VERSION;
    return payload;
  });
}

// ══════════════════════════════════════════════════════════════════════
//  Auth (login / logout / change-password)
// ══════════════════════════════════════════════════════════════════════

void register_auth_routes(CrowApp &app, AppContext &ctx) {
  // POST /api/auth/login
  CROW_ROUTE(app, "/api/auth/login").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");
        std::string user = body["user"].s();
        std::string password = body["password"].s();
        if (user.empty() || password.empty())
          return crow::response(400, "Missing user or password");

        // Rate limiting (by username)
        if (!ctx.check_rate_limit("login:" + user)) {
          AuditEvent rl_evt;
          rl_evt.id = ctx.next_audit_id.fetch_add(1);
          rl_evt.type = "auth.login.rate_limited";
          rl_evt.actor = user;
          rl_evt.role = "";
          rl_evt.createdAt = now_utc();
          rl_evt.payloadJson = "{\"username\":\"" + json_escape(user) + "\"}";
          rl_evt.payloadIsJson = true;
          ctx.append_audit(rl_evt);
          return crow::response(429, "Too many login attempts. Try again later.");
        }

        // Optional TOTP code for 2FA
        std::string totp_code;
        if (body.has("totpCode"))
          totp_code = body["totpCode"].s();

        std::optional<UserAccount> matched;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          for (const auto &entry : ctx.users) {
            if (entry.second.username == user) {
              matched = entry.second;
              break;
            }
          }
        }

        // Verify password (supports hashed and legacy plaintext)
        if (!matched || !crypto::verify_password(password, matched->password)) {
          // Audit: login failure
          AuditEvent evt;
          evt.id = ctx.next_audit_id.fetch_add(1);
          evt.type = "auth.login.failure";
          evt.actor = user;
          evt.role = "";
          evt.createdAt = now_utc();
          evt.payloadJson = "{\"reason\":\"invalid_credentials\",\"username\":\"" +
                            json_escape(user) + "\"}";
          evt.payloadIsJson = true;
          ctx.append_audit(evt);
          return crow::response(401, "Invalid credentials");
        }

        // Auto-migrate plaintext password to hashed
        if (matched->password.rfind("sha256:", 0) != 0) {
          std::string hashed = crypto::hash_password(password);
          ctx.update_user_password_hash(matched->id, hashed);
        }

        // Check 2FA if enabled for this user
        if (matched->totpEnabled) {
          if (totp_code.empty()) {
            crow::json::wvalue payload;
            payload["status"] = "2fa_required";
            payload["message"] = "TOTP code required";
            payload["user"] = matched->username;
            return crow::response{payload};
          }
          if (!totp::verify_code(matched->totpSecret, totp_code)) {
            // Audit: 2FA failure
            AuditEvent evt;
            evt.id = ctx.next_audit_id.fetch_add(1);
            evt.type = "auth.login.2fa_failure";
            evt.actor = user;
            evt.role = matched->role;
            evt.createdAt = now_utc();
            evt.payloadJson = "{\"userId\":" + std::to_string(matched->id) + "}";
            evt.payloadIsJson = true;
            ctx.append_audit(evt);
            return crow::response(401, "Invalid TOTP code");
          }
        }

        // Cleanup expired tokens periodically
        ctx.cleanup_expired_tokens();

        AuthSession auth;
        auth.userId = matched->id;
        auth.user = matched->username;
        auth.role = matched->role;
        auth.issuedAt = now_utc();
        auth.expiresAt = ctx.compute_expiry();
        auth.token = ctx.generate_token();

        {
          std::lock_guard<std::mutex> lock(ctx.auth_mutex);
          ctx.auth_sessions[auth.token] = auth;
        }

        // Audit: login success
        AuditEvent evt;
        evt.id = ctx.next_audit_id.fetch_add(1);
        evt.type = "auth.login.success";
        evt.actor = matched->username;
        evt.role = matched->role;
        evt.createdAt = now_utc();
        evt.payloadJson = "{\"userId\":" + std::to_string(matched->id) +
                          ",\"username\":\"" + json_escape(matched->username) + "\"}";
        evt.payloadIsJson = true;
        ctx.append_audit(evt);

        crow::json::wvalue payload;
        payload["token"] = auth.token;
        payload["user"] = auth.user;
        payload["role"] = auth.role;
        payload["issuedAt"] = auth.issuedAt;
        payload["expiresAt"] = auth.expiresAt;
        payload["totpEnabled"] = matched->totpEnabled;
        return crow::response{payload};
      });

  // POST /api/auth/logout
  CROW_ROUTE(app, "/api/auth/logout").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        // Audit: logout
        AuditEvent evt;
        evt.id = ctx.next_audit_id.fetch_add(1);
        evt.type = "auth.logout";
        evt.actor = auth->user;
        evt.role = auth->role;
        evt.createdAt = now_utc();
        evt.payloadJson = "{\"userId\":" + std::to_string(auth->userId) + "}";
        evt.payloadIsJson = true;
        ctx.append_audit(evt);

        ctx.invalidate_token(auth->token);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["message"] = "Logged out";
        return crow::response{payload};
      });

  // POST /api/auth/change-password
  CROW_ROUTE(app, "/api/auth/change-password").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");
        std::string current_password = body["currentPassword"].s();
        std::string new_password = body["newPassword"].s();
        if (current_password.empty() || new_password.empty())
          return crow::response(400, "Missing currentPassword or newPassword");

        // Verify current password
        std::string stored;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it == ctx.users.end())
            return crow::response(404, "User not found");
          stored = it->second.password;
        }
        if (!crypto::verify_password(current_password, stored))
          return crow::response(401, "Current password is incorrect");

        // Validate new password
        auto policy = crypto::validate_password(new_password);
        if (!policy.valid)
          return crow::response(400, policy.message);

        // Hash and store
        std::string hashed = crypto::hash_password(new_password);
        if (!ctx.update_user_password_hash(auth->userId, hashed))
          return crow::response(500, "Failed to update password");

        // Invalidate all existing tokens for this user (force re-login)
        std::string current_token = auth->token;
        ctx.invalidate_user_tokens(auth->userId);

        // Audit
        AuditEvent evt;
        evt.id = ctx.next_audit_id.fetch_add(1);
        evt.type = "user.password.change";
        evt.actor = auth->user;
        evt.role = auth->role;
        evt.createdAt = now_utc();
        evt.payloadJson = "{\"userId\":" + std::to_string(auth->userId) + ",\"tokensInvalidated\":true}";
        evt.payloadIsJson = true;
        ctx.append_audit(evt);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["message"] = "Password changed. All sessions invalidated — please log in again.";
        return crow::response{payload};
      });
}

// ══════════════════════════════════════════════════════════════════════
//  Users
// ══════════════════════════════════════════════════════════════════════

void register_user_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/users
  CROW_ROUTE(app, "/api/users").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"admin"}))
          return crow::response(403, "Forbidden");

        std::vector<UserAccount> snapshot;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          snapshot.reserve(ctx.users.size());
          for (const auto &entry : ctx.users)
            snapshot.push_back(entry.second);
        }
        std::sort(snapshot.begin(), snapshot.end(),
                  [](const UserAccount &a, const UserAccount &b) {
                    return a.id < b.id;
                  });
        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < snapshot.size(); ++i)
          payload["items"][static_cast<int>(i)] = user_to_json(snapshot[i]);
        return crow::response{payload};
      });

  // POST /api/users
  CROW_ROUTE(app, "/api/users").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"admin"}))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string username = body["username"].s();
        std::string password = body["password"].s();
        std::string role = body["role"].s();
        if (username.empty() || password.empty() || role.empty())
          return crow::response(400, "Missing username, password, or role");
        if (!is_allowed_role(role, {"operator", "admin", "auditor"}))
          return crow::response(400, "Invalid role");

        // Validate password policy
        auto policy = crypto::validate_password(password);
        if (!policy.valid)
          return crow::response(400, policy.message);

        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          for (const auto &entry : ctx.users) {
            if (entry.second.username == username)
              return crow::response(409, "User already exists");
          }
        }

        UserAccount user;
        user.id = ctx.next_user_id.fetch_add(1);
        user.username = username;
        user.password = crypto::hash_password(password);
        user.role = role;
        user.createdAt = now_utc();
        user.updatedAt = user.createdAt;

        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          ctx.users[user.id] = user;
        }
        if (!ctx.insert_user(user))
          return crow::response(500, "Failed to persist user");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "user.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_user_payload_json(user);
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload = user_to_json(user);
        return crow::response{payload};
      });

  // PUT /api/users/<int>
  CROW_ROUTE(app, "/api/users/<int>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!is_allowed_role(auth->role, {"admin"}))
              return crow::response(403, "Forbidden");
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            std::string password = body["password"].s();
            std::string role = body["role"].s();
            if (password.empty() || role.empty())
              return crow::response(400, "Missing password or role");
            if (!is_allowed_role(role, {"operator", "admin", "auditor"}))
              return crow::response(400, "Invalid role");

            // Validate password policy
            auto policy = crypto::validate_password(password);
            if (!policy.valid)
              return crow::response(400, policy.message);

            UserAccount user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(user_id);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              user = it->second;
              user.password = crypto::hash_password(password);
              user.role = role;
              user.updatedAt = now_utc();
              it->second = user;
            }
            if (!ctx.update_user_db(user))
              return crow::response(500, "Failed to persist user");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.update";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_user_payload_json(user);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload = user_to_json(user);
            return crow::response{payload};
          });

  // DELETE /api/users/<int>
  CROW_ROUTE(app, "/api/users/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!is_allowed_role(auth->role, {"admin"}))
              return crow::response(403, "Forbidden");

            UserAccount user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(user_id);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              user = it->second;
              ctx.users.erase(it);
            }
            if (!ctx.delete_user_db(user_id))
              return crow::response(500, "Failed to delete user");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.delete";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_user_payload_json(user);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "deleted";
            payload["id"] = user_id;
            return crow::response{payload};
          });

  // GET /api/users/<int>/resources
  CROW_ROUTE(app, "/api/users/<int>/resources")
      .methods(crow::HTTPMethod::Get)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!is_allowed_role(auth->role, {"admin"}))
              return crow::response(403, "Forbidden");

            auto allowed_ids = ctx.get_resource_permissions(user_id);
            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["userId"] = user_id;
            payload["resourceIds"] = crow::json::wvalue::list();
            for (size_t i = 0; i < allowed_ids.size(); ++i)
              payload["resourceIds"][static_cast<int>(i)] = allowed_ids[i];
            return crow::response{payload};
          });

  // POST /api/users/<int>/resources/<int>
  CROW_ROUTE(app, "/api/users/<int>/resources/<int>")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int user_id, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!is_allowed_role(auth->role, {"admin"}))
              return crow::response(403, "Forbidden");
            if (!ctx.grant_resource_permission(user_id, resource_id))
              return crow::response(500, "Failed to grant permission");

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "Permission granted";
            payload["userId"] = user_id;
            payload["resourceId"] = resource_id;
            return crow::response{payload};
          });

  // DELETE /api/users/<int>/resources/<int>
  CROW_ROUTE(app, "/api/users/<int>/resources/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int user_id, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!is_allowed_role(auth->role, {"admin"}))
              return crow::response(403, "Forbidden");
            if (!ctx.revoke_resource_permission(user_id, resource_id))
              return crow::response(500, "Failed to revoke permission");

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "Permission revoked";
            payload["userId"] = user_id;
            payload["resourceId"] = resource_id;
            return crow::response{payload};
          });
}

// ══════════════════════════════════════════════════════════════════════
//  Resources
// ══════════════════════════════════════════════════════════════════════

void register_resource_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/resources
  CROW_ROUTE(app, "/api/resources").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        std::vector<int> allowed_resource_ids;
        if (auth->role == "admin") {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          for (const auto &entry : ctx.resources)
            allowed_resource_ids.push_back(entry.first);
        } else {
          allowed_resource_ids = ctx.get_resource_permissions(auth->userId);
        }

        std::vector<Resource> snapshot;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          for (int rid : allowed_resource_ids) {
            auto it = ctx.resources.find(rid);
            if (it != ctx.resources.end()) snapshot.push_back(it->second);
          }
        }
        std::sort(snapshot.begin(), snapshot.end(),
                  [](const Resource &a, const Resource &b) {
                    return a.id < b.id;
                  });
        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < snapshot.size(); ++i)
          payload["items"][static_cast<int>(i)] = resource_to_json(snapshot[i]);
        return crow::response{payload};
      });

  // POST /api/resources
  CROW_ROUTE(app, "/api/resources").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"admin"}))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string name = body["name"].s();
        std::string target = body["target"].s();
        std::string protocol = body["protocol"].s();
        int port = 22;
        if (body.has("port")) port = body["port"].i();
        std::string description;
        if (body.has("description")) description = body["description"].s();
        std::string image_url;
        if (body.has("imageUrl")) image_url = body["imageUrl"].s();
        std::string http_username;
        if (body.has("httpUsername")) http_username = body["httpUsername"].s();
        std::string http_password;
        if (body.has("httpPassword")) http_password = body["httpPassword"].s();
        std::string ssh_username;
        if (body.has("sshUsername")) ssh_username = body["sshUsername"].s();
        std::string ssh_password;
        if (body.has("sshPassword")) ssh_password = body["sshPassword"].s();

        if (name.empty() || target.empty() || protocol.empty())
          return crow::response(400, "Missing name, target, or protocol");
        if (port <= 0 || port > 65535)
          return crow::response(400, "Invalid port");

        // Validate protocol whitelist
        if (!is_allowed_role(protocol, {"ssh", "rdp", "vnc", "http", "https", "agent"}))
          return crow::response(400, "Invalid protocol. Allowed: ssh, rdp, vnc, http, https, agent");

        // Input length limits
        if (name.size() > 255 || target.size() > 255 || description.size() > 1024)
          return crow::response(400, "Field too long");

        // SSRF protection: validate target is not a dangerous address
        if (!ctx.is_safe_target(target))
          return crow::response(400, "Target address is not allowed (loopback/metadata/reserved)");

        // Validate imageUrl scheme if provided
        if (!image_url.empty() && image_url.rfind("http", 0) != 0 && image_url.rfind("/", 0) != 0)
          return crow::response(400, "Invalid imageUrl: must be HTTP(S) or relative path");

        Resource resource;
        resource.id = ctx.next_resource_id.fetch_add(1);
        resource.name = name;
        resource.target = target;
        resource.protocol = protocol;
        resource.port = port;
        resource.description = description;
        resource.imageUrl = image_url;
        resource.httpUsername = http_username;
        resource.httpPassword = http_password;
        resource.sshUsername = ssh_username;
        resource.sshPassword = ssh_password;
        resource.createdAt = now_utc();
        resource.updatedAt = resource.createdAt;

        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          ctx.resources.emplace(resource.id, resource);
        }
        if (!ctx.insert_resource(resource))
          return crow::response(500, "Failed to persist resource");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "resource.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_resource_payload_json(resource);
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload = resource_to_json(resource);
        return crow::response{payload};
      });

  // PUT /api/resources/<int>
  CROW_ROUTE(app, "/api/resources/<int>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!is_allowed_role(auth->role, {"admin"}))
              return crow::response(403, "Forbidden");
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            std::string name = body["name"].s();
            std::string target = body["target"].s();
            std::string protocol = body["protocol"].s();
            int port = 22;
            if (body.has("port")) port = body["port"].i();
            std::string description;
            if (body.has("description")) description = body["description"].s();
            std::string image_url;
            if (body.has("imageUrl")) image_url = body["imageUrl"].s();
            std::string http_username;
            if (body.has("httpUsername")) http_username = body["httpUsername"].s();
            std::string http_password;
            if (body.has("httpPassword")) http_password = body["httpPassword"].s();
            std::string ssh_username;
            if (body.has("sshUsername")) ssh_username = body["sshUsername"].s();
            std::string ssh_password;
            if (body.has("sshPassword")) ssh_password = body["sshPassword"].s();

            if (name.empty() || target.empty() || protocol.empty())
              return crow::response(400, "Missing name, target, or protocol");
            if (port <= 0 || port > 65535)
              return crow::response(400, "Invalid port");

            // Validate protocol whitelist
            if (!is_allowed_role(protocol, {"ssh", "rdp", "vnc", "http", "https", "agent"}))
              return crow::response(400, "Invalid protocol");

            // Input length limits
            if (name.size() > 255 || target.size() > 255 || description.size() > 1024)
              return crow::response(400, "Field too long");

            // SSRF protection
            if (!ctx.is_safe_target(target))
              return crow::response(400, "Target address is not allowed");

            Resource resource;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(resource_id);
              if (it == ctx.resources.end())
                return crow::response(404, "Resource not found");
              resource = it->second;
              resource.name = name;
              resource.target = target;
              resource.protocol = protocol;
              resource.port = port;
              resource.description = description;
              resource.imageUrl = image_url;
              resource.httpUsername = http_username;
              resource.httpPassword = http_password;
              resource.sshUsername = ssh_username;
              // Only update sshPassword if provided (non-empty)
              if (!ssh_password.empty()) resource.sshPassword = ssh_password;
              resource.updatedAt = now_utc();
              it->second = resource;
            }
            if (!ctx.update_resource_db(resource))
              return crow::response(500, "Failed to persist resource");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "resource.update";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_resource_payload_json(resource);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload = resource_to_json(resource);
            return crow::response{payload};
          });

  // DELETE /api/resources/<int>
  CROW_ROUTE(app, "/api/resources/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!is_allowed_role(auth->role, {"admin"}))
              return crow::response(403, "Forbidden");

            Resource resource;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(resource_id);
              if (it == ctx.resources.end())
                return crow::response(404, "Resource not found");
              resource = it->second;
              ctx.resources.erase(it);
            }
            if (!ctx.delete_resource_db(resource_id))
              return crow::response(500, "Failed to delete resource");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "resource.delete";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_resource_payload_json(resource);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "deleted";
            payload["id"] = resource_id;
            return crow::response{payload};
          });
}

// ══════════════════════════════════════════════════════════════════════
//  Sessions
// ══════════════════════════════════════════════════════════════════════

void register_session_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/sessions
  CROW_ROUTE(app, "/api/sessions")([&ctx](const crow::request &request) {
    auto auth = ctx.find_auth(request);
    if (!auth) return crow::response(401, "Unauthorized");
    if (!is_allowed_role(auth->role, {"admin", "auditor", "operator"}))
      return crow::response(403, "Forbidden");

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
    std::string protocol_filter = protocol_param ? to_lower(protocol_param) : "";
    std::string sort_order = sort_param ? to_lower(sort_param) : "desc";

    std::vector<Session> snapshot;
    {
      std::lock_guard<std::mutex> lock(ctx.session_mutex);
      snapshot.reserve(ctx.sessions.size());
      for (const auto &entry : ctx.sessions)
        snapshot.push_back(entry.second);
    }

    std::vector<Session> filtered;
    for (const auto &session : snapshot) {
      if (!status_filter.empty() && to_lower(session.status) != status_filter) continue;
      if (!user_filter.empty() && to_lower(session.user) != user_filter) continue;
      if (!target_filter.empty() && to_lower(session.target) != target_filter) continue;
      if (!protocol_filter.empty() && to_lower(session.protocol) != protocol_filter) continue;
      filtered.push_back(session);
    }

    std::sort(filtered.begin(), filtered.end(),
              [&](const Session &a, const Session &b) {
                if (sort_order == "asc") return a.id < b.id;
                return a.id > b.id;
              });

    int start_index = offset.value_or(0);
    if (start_index < 0) start_index = 0;
    int end_index = static_cast<int>(filtered.size());
    if (limit && *limit > 0) end_index = std::min(end_index, start_index + *limit);
    if (start_index > end_index) start_index = end_index;

    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["items"] = crow::json::wvalue::list();
    payload["total"] = static_cast<int>(snapshot.size());
    payload["count"] = end_index - start_index;
    int index = 0;
    for (int i = start_index; i < end_index; ++i)
      payload["items"][index++] = session_to_json(filtered[i]);
    return crow::response{payload};
  });

  // POST /api/sessions
  CROW_ROUTE(app, "/api/sessions").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"operator", "admin"}))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string target = body["target"].s();
        std::string user = body["user"].s();
        std::string protocol = body["protocol"].s();
        int port = 22;
        if (body.has("port")) port = body["port"].i();
        if (target.empty() || user.empty() || protocol.empty())
          return crow::response(400, "Missing target, user, or protocol");
        if (port <= 0 || port > 65535)
          return crow::response(400, "Invalid port");

        Session session;
        session.id = ctx.next_session_id.fetch_add(1);
        session.target = target;
        session.user = user;
        session.protocol = protocol;
        session.port = port;
        session.status = "active";
        session.createdAt = now_utc();

        {
          std::lock_guard<std::mutex> lock(ctx.session_mutex);
          ctx.sessions.emplace(session.id, session);
        }
        if (!ctx.insert_session(session))
          return crow::response(500, "Failed to persist session");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "session.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_session_payload_json(session);
        event.payloadIsJson = true;
        ctx.append_audit(event);
        ctx.append_session_event("session.create", session);

        crow::json::wvalue payload = session_to_json(session);
        return crow::response{payload};
      });

  // GET /api/sessions/<int>
  CROW_ROUTE(app, "/api/sessions/<int>")(
      [&ctx](const crow::request &request, int session_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"admin", "auditor", "operator"}))
          return crow::response(403, "Forbidden");
        std::lock_guard<std::mutex> lock(ctx.session_mutex);
        auto it = ctx.sessions.find(session_id);
        if (it == ctx.sessions.end())
          return crow::response(404, "Session not found");
        crow::json::wvalue payload = session_to_json(it->second);
        return crow::response{payload};
      });

  // POST /api/sessions/<int>/terminate
  CROW_ROUTE(app, "/api/sessions/<int>/terminate")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int session_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!is_allowed_role(auth->role, {"operator", "admin"}))
              return crow::response(403, "Forbidden");
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              if (ctx.sessions.find(session_id) == ctx.sessions.end())
                return crow::response(404, "Session not found");
            }

            ctx.terminate_session(session_id, auth->user, auth->role,
                                  "session.terminate");
            ctx.close_ssh_for_session(session_id);

            Session updated;
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              updated = ctx.sessions.at(session_id);
            }
            crow::json::wvalue payload = session_to_json(updated);
            return crow::response{payload};
          });

  // GET /api/sessions/stream (SSE)
  CROW_ROUTE(app, "/api/sessions/stream")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"admin", "auditor", "operator"}))
          return crow::response(403, "Forbidden");
        const char *since_param = request.url_params.get("since");
        auto since = parse_int_param(since_param).value_or(0);
        auto header = request.get_header_value("Last-Event-ID");
        if (!header.empty()) {
          auto parsed = parse_int_param(header.c_str());
          if (parsed) since = std::max(since, *parsed);
        }

        std::vector<SessionEvent> snapshot;
        {
          std::lock_guard<std::mutex> lock(ctx.event_mutex);
          snapshot.reserve(ctx.session_events.size());
          for (const auto &event : ctx.session_events) {
            if (event.id > since) snapshot.push_back(event);
          }
        }

        std::ostringstream body;
        body << "retry: 5000\n";
        int sent = 0;
        for (const auto &event : snapshot) {
          body << "id: " << event.id << "\n";
          body << "event: " << event.type << "\n";
          body << "data: " << event.payloadJson << "\n\n";
          if (++sent >= 100) break;
        }

        crow::response response;
        response.code = 200;
        response.set_header("Content-Type", "text/event-stream");
        response.set_header("Cache-Control", "no-cache");
        response.set_header("Connection", "keep-alive");
        response.body = body.str();
        return response;
      });
}

// ══════════════════════════════════════════════════════════════════════
//  Audit
// ══════════════════════════════════════════════════════════════════════

void register_audit_routes(CrowApp &app, AppContext &ctx) {
  // POST /api/audit
  CROW_ROUTE(app, "/api/audit").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"auditor", "admin"}))
          return crow::response(403, "Forbidden");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
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
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "accepted";
        payload["id"] = event.id;
        return crow::response{payload};
      });

  // GET /api/audit
  CROW_ROUTE(app, "/api/audit")([&ctx](const crow::request &request) {
    auto auth = ctx.find_auth(request);
    if (!auth) return crow::response(401, "Unauthorized");
    if (!is_allowed_role(auth->role, {"auditor", "admin"}))
      return crow::response(403, "Forbidden");

    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["items"] = crow::json::wvalue::list();
    {
      std::lock_guard<std::mutex> lock(ctx.audit_mutex);
      int index = 0;
      for (auto it = ctx.audit_events.rbegin();
           it != ctx.audit_events.rend() && index < 50; ++it) {
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
}

// ══════════════════════════════════════════════════════════════════════
//  TOTP / 2FA
// ══════════════════════════════════════════════════════════════════════

void register_totp_routes(CrowApp &app, AppContext &ctx) {
  // POST /api/auth/setup-2fa — Generate a TOTP secret for the current user
  CROW_ROUTE(app, "/api/auth/setup-2fa")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            // Check if already enabled
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end() && it->second.totpEnabled)
                return crow::response(400, "2FA is already enabled");
            }

            // Generate a new TOTP secret
            std::string secret = totp::generate_secret();
            std::string uri = totp::build_otpauth_uri(
                "EndoriumFort", auth->user, secret);

            // Store secret but don't enable yet (user must verify first)
            ctx.update_user_totp(auth->userId, false, secret);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["secret"] = secret;
            payload["otpauthUri"] = uri;
            payload["message"] =
                "Scan the QR code with your authenticator app, then call "
                "/api/auth/verify-2fa with a code to enable.";
            return crow::response{payload};
          });

  // POST /api/auth/verify-2fa — Verify a TOTP code and enable 2FA
  CROW_ROUTE(app, "/api/auth/verify-2fa")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");
            std::string code;
            if (body.has("code")) code = body["code"].s();
            if (code.empty())
              return crow::response(400, "Missing TOTP code");

            std::string secret;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              secret = it->second.totpSecret;
            }
            if (secret.empty())
              return crow::response(400, "Call /api/auth/setup-2fa first");

            if (!totp::verify_code(secret, code))
              return crow::response(401, "Invalid TOTP code");

            // Enable 2FA
            ctx.update_user_totp(auth->userId, true, secret);

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.2fa.enable";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = "{\"userId\":" + std::to_string(auth->userId) + "}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "2FA has been enabled successfully";
            payload["totpEnabled"] = true;
            return crow::response{payload};
          });

  // POST /api/auth/disable-2fa — Disable 2FA (requires current TOTP code)
  CROW_ROUTE(app, "/api/auth/disable-2fa")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");
            std::string code;
            if (body.has("code")) code = body["code"].s();
            if (code.empty())
              return crow::response(400, "Missing TOTP code");

            std::string secret;
            bool enabled = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              secret = it->second.totpSecret;
              enabled = it->second.totpEnabled;
            }
            if (!enabled)
              return crow::response(400, "2FA is not enabled");

            if (!totp::verify_code(secret, code))
              return crow::response(401, "Invalid TOTP code");

            ctx.update_user_totp(auth->userId, false, "");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.2fa.disable";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = "{\"userId\":" + std::to_string(auth->userId) + "}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "2FA has been disabled";
            payload["totpEnabled"] = false;
            return crow::response{payload};
          });

  // GET /api/auth/2fa-status — Check the current 2FA status
  CROW_ROUTE(app, "/api/auth/2fa-status")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        bool enabled = false;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it != ctx.users.end()) enabled = it->second.totpEnabled;
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["totpEnabled"] = enabled;
        return crow::response{payload};
      });
}

// ══════════════════════════════════════════════════════════════════════
//  Session Recordings
// ══════════════════════════════════════════════════════════════════════

void register_recording_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/recordings — List all recordings
  CROW_ROUTE(app, "/api/recordings")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"auditor", "admin"}))
          return crow::response(403, "Forbidden");

        // Optional filter by sessionId
        const char *sid = request.url_params.get("sessionId");
        std::optional<int> session_filter;
        if (sid) session_filter = parse_int_param(sid);

        std::vector<SessionRecording> snapshot;
        {
          std::lock_guard<std::mutex> lock(ctx.recording_mutex);
          for (const auto &entry : ctx.recordings) {
            if (session_filter && entry.second.sessionId != *session_filter)
              continue;
            snapshot.push_back(entry.second);
          }
        }
        std::sort(snapshot.begin(), snapshot.end(),
                  [](const SessionRecording &a, const SessionRecording &b) {
                    return a.id > b.id;
                  });

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < snapshot.size(); ++i) {
          auto &r = snapshot[i];
          int idx = static_cast<int>(i);
          payload["items"][idx]["id"] = r.id;
          payload["items"][idx]["sessionId"] = r.sessionId;
          payload["items"][idx]["createdAt"] = r.createdAt;
          payload["items"][idx]["closedAt"] = r.closedAt;
          payload["items"][idx]["durationMs"] = static_cast<int64_t>(r.durationMs);
          payload["items"][idx]["fileSize"] = static_cast<int64_t>(r.fileSize);
        }
        return crow::response{payload};
      });

  // GET /api/recordings/<int> — Get a single recording's metadata
  CROW_ROUTE(app, "/api/recordings/<int>")(
      [&ctx](const crow::request &request, int rec_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"auditor", "admin"}))
          return crow::response(403, "Forbidden");

        SessionRecording rec;
        {
          std::lock_guard<std::mutex> lock(ctx.recording_mutex);
          auto it = ctx.recordings.find(rec_id);
          if (it == ctx.recordings.end())
            return crow::response(404, "Recording not found");
          rec = it->second;
        }

        crow::json::wvalue payload;
        payload["id"] = rec.id;
        payload["sessionId"] = rec.sessionId;
        payload["createdAt"] = rec.createdAt;
        payload["closedAt"] = rec.closedAt;
        payload["durationMs"] = static_cast<int64_t>(rec.durationMs);
        payload["fileSize"] = static_cast<int64_t>(rec.fileSize);
        return crow::response{payload};
      });

  // GET /api/recordings/<int>/cast — Download the .cast file content
  CROW_ROUTE(app, "/api/recordings/<int>/cast")(
      [&ctx](const crow::request &request, int rec_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"auditor", "admin"}))
          return crow::response(403, "Forbidden");

        SessionRecording rec;
        {
          std::lock_guard<std::mutex> lock(ctx.recording_mutex);
          auto it = ctx.recordings.find(rec_id);
          if (it == ctx.recordings.end())
            return crow::response(404, "Recording not found");
          rec = it->second;
        }

        std::ifstream file(rec.filePath);
        if (!file.is_open())
          return crow::response(404, "Recording file not found on disk");

        std::ostringstream oss;
        oss << file.rdbuf();
        crow::response resp;
        resp.code = 200;
        resp.set_header("Content-Type", "application/x-asciicast");
        resp.set_header("Content-Disposition",
                        "inline; filename=\"session_" +
                            std::to_string(rec.sessionId) + ".cast\"");
        resp.body = oss.str();
        return resp;
      });
}

// ══════════════════════════════════════════════════════════════════════
//  Stats / Dashboard
// ══════════════════════════════════════════════════════════════════════

void register_stats_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/stats — Dashboard statistics
  CROW_ROUTE(app, "/api/stats")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"admin", "auditor"}))
          return crow::response(403, "Forbidden");

        int total_sessions = 0, active_sessions = 0, terminated_sessions = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.session_mutex);
          total_sessions = static_cast<int>(ctx.sessions.size());
          for (const auto &entry : ctx.sessions) {
            if (entry.second.status == "active") ++active_sessions;
            else ++terminated_sessions;
          }
        }

        int total_resources = 0, ssh_resources = 0, http_resources = 0, rdp_resources = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          total_resources = static_cast<int>(ctx.resources.size());
          for (const auto &entry : ctx.resources) {
            if (entry.second.protocol == "ssh") ++ssh_resources;
            else if (entry.second.protocol == "http" || entry.second.protocol == "https") ++http_resources;
            else if (entry.second.protocol == "rdp") ++rdp_resources;
          }
        }

        int total_users = 0, admin_users = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          total_users = static_cast<int>(ctx.users.size());
          for (const auto &entry : ctx.users)
            if (entry.second.role == "admin") ++admin_users;
        }

        int total_recordings = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.recording_mutex);
          total_recordings = static_cast<int>(ctx.recordings.size());
        }

        int total_audit = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.audit_mutex);
          total_audit = static_cast<int>(ctx.audit_events.size());
        }

        int active_tokens = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.auth_mutex);
          active_tokens = static_cast<int>(ctx.auth_sessions.size());
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["sessions"]["total"] = total_sessions;
        payload["sessions"]["active"] = active_sessions;
        payload["sessions"]["terminated"] = terminated_sessions;
        payload["resources"]["total"] = total_resources;
        payload["resources"]["ssh"] = ssh_resources;
        payload["resources"]["http"] = http_resources;
        payload["resources"]["rdp"] = rdp_resources;
        payload["users"]["total"] = total_users;
        payload["users"]["admins"] = admin_users;
        payload["recordings"]["total"] = total_recordings;
        payload["audit"]["total"] = total_audit;
        payload["auth"]["activeTokens"] = active_tokens;
        return crow::response{payload};
      });

  // GET /api/resources/<int>/credentials — Fetch stored SSH creds for auto-inject
  CROW_ROUTE(app, "/api/resources/<int>/credentials")(
      [&ctx](const crow::request &request, int resource_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!is_allowed_role(auth->role, {"operator", "admin"}))
          return crow::response(403, "Forbidden");

        // Permission check
        std::vector<int> allowed_ids;
        if (auth->role == "admin") {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          for (const auto &r : ctx.resources) allowed_ids.push_back(r.first);
        } else {
          allowed_ids = ctx.get_resource_permissions(auth->userId);
        }
        bool has_perm = false;
        for (int id : allowed_ids)
          if (id == resource_id) { has_perm = true; break; }
        if (!has_perm) return crow::response(403, "No access to this resource");

        Resource target_resource;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          auto it = ctx.resources.find(resource_id);
          if (it == ctx.resources.end())
            return crow::response(404, "Resource not found");
          target_resource = it->second;
        }

        // Audit the credential access
        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "credential.access";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = "{\"resourceId\":" + std::to_string(resource_id) +
                            ",\"resourceName\":\"" + json_escape(target_resource.name) + "\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["resourceId"] = resource_id;
        payload["sshUsername"] = target_resource.sshUsername;
        payload["sshPassword"] = target_resource.sshPassword;
        payload["hasCredentials"] = !target_resource.sshPassword.empty();
        return crow::response{payload};
      });
}
