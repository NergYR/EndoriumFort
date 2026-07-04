// ─── EndoriumFort — API routes implementation ──────────────────────────

#include "routes.h"
#include "app_context.h"
#include "auth_mfa.h"
#include "crypto.h"
#include "http_proxy.h"
#include "scim_query.h"
#include "totp.h"
#include "utils.h"
#include "version.h"
#include "webauthn.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <sstream>

namespace {
constexpr int64_t kApprovedAccessTtlSeconds = 3600;
constexpr int64_t kEphemeralLeaseTtlSeconds = 120;

int base_risk_score_for_level(const std::string &risk_level) {
  if (risk_level == "critical") return 85;
  if (risk_level == "high") return 70;
  if (risk_level == "medium") return 40;
  return 15;
}

std::string risk_level_for_score(int score) {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 35) return "medium";
  return "low";
}

bool is_off_hours_utc() {
  const std::time_t now = std::time(nullptr);
  std::tm utc_tm{};
#ifdef _WIN32
  gmtime_s(&utc_tm, &now);
#else
  gmtime_r(&now, &utc_tm);
#endif
  return utc_tm.tm_hour < 6 || utc_tm.tm_hour >= 20;
}

bool env_flag_enabled(const char *name, bool fallback) {
  if (!name || !*name) return fallback;
  const char *raw = std::getenv(name);
  if (!raw) return fallback;
  const std::string normalized = to_lower(trim_copy(raw));
  if (normalized == "1" || normalized == "true" || normalized == "yes" ||
      normalized == "on") {
    return true;
  }
  if (normalized == "0" || normalized == "false" || normalized == "no" ||
      normalized == "off") {
    return false;
  }
  return fallback;
}

std::string env_string_value(const char *name, const std::string &fallback) {
  if (!name || !*name) return fallback;
  const char *raw = std::getenv(name);
  if (!raw) return fallback;
  const std::string value = trim_copy(raw);
  return value.empty() ? fallback : value;
}

int env_int_value(const char *name, int fallback, int min_value,
                  int max_value) {
  if (!name || !*name) return fallback;
  const char *raw = std::getenv(name);
  if (!raw) return fallback;
  try {
    const int parsed = std::stoi(trim_copy(raw));
    return std::clamp(parsed, min_value, max_value);
  } catch (...) {
    return fallback;
  }
}

std::string auth_user_anomaly_key(const std::string &username) {
  return "anomaly:auth:user:" + to_lower(trim_copy(username));
}

std::string auth_ip_anomaly_key(const std::string &client_ip) {
  return "anomaly:auth:ip:" + trim_copy(client_ip);
}

void append_behavior_anomaly_event(AppContext &ctx, const std::string &event_type,
                                   const std::string &actor,
                                   const std::string &payload_json) {
  AuditEvent anomaly;
  anomaly.id = ctx.next_audit_id.fetch_add(1);
  anomaly.type = event_type;
  anomaly.actor = actor;
  anomaly.role = "";
  anomaly.createdAt = now_utc();
  anomaly.payloadJson = payload_json;
  anomaly.payloadIsJson = true;
  ctx.append_audit(anomaly);
}

void maybe_emit_auth_failure_burst_anomaly(AppContext &ctx,
                                           const std::string &username,
                                           const std::string &client_ip,
                                           const std::string &trigger_type) {
  const int window_seconds = env_int_value(
      "ENDORIUMFORT_ALERT_AUTH_WINDOW_SECONDS", 180, 30, 3600);
  const int user_threshold = env_int_value(
      "ENDORIUMFORT_ALERT_AUTH_FAILURE_THRESHOLD", 5, 2, 100);
  const int ip_threshold = env_int_value(
      "ENDORIUMFORT_ALERT_AUTH_IP_THRESHOLD", 8, 2, 200);
  const int cooldown_seconds = env_int_value(
      "ENDORIUMFORT_ALERT_AUTH_COOLDOWN_SECONDS", 90, 10, 3600);

  const std::string normalized_user = trim_copy(username);
  if (!normalized_user.empty()) {
    const std::string user_key = auth_user_anomaly_key(normalized_user);
    const int signal_count =
        ctx.record_anomaly_signal(user_key, std::chrono::seconds(window_seconds));
    if (signal_count >= user_threshold &&
        ctx.should_emit_anomaly_signal(user_key + ":emit",
                                       std::chrono::seconds(cooldown_seconds))) {
      append_behavior_anomaly_event(
          ctx, "behavior.anomaly.auth_failure_burst", normalized_user,
          "{\"scope\":\"username\",\"username\":\"" +
              json_escape(normalized_user) + "\",\"ip\":\"" +
              json_escape(client_ip) + "\",\"signalCount\":" +
              std::to_string(signal_count) + ",\"windowSeconds\":" +
              std::to_string(window_seconds) + ",\"trigger\":\"" +
              json_escape(trigger_type) + "\"}");
    }
  }

  const std::string normalized_ip = trim_copy(client_ip);
  if (!normalized_ip.empty()) {
    const std::string ip_key = auth_ip_anomaly_key(normalized_ip);
    const int signal_count =
        ctx.record_anomaly_signal(ip_key, std::chrono::seconds(window_seconds));
    if (signal_count >= ip_threshold &&
        ctx.should_emit_anomaly_signal(ip_key + ":emit",
                                       std::chrono::seconds(cooldown_seconds))) {
      append_behavior_anomaly_event(
          ctx, "behavior.anomaly.auth_failure_burst", normalized_user,
          "{\"scope\":\"ip\",\"username\":\"" +
              json_escape(normalized_user) + "\",\"ip\":\"" +
              json_escape(normalized_ip) + "\",\"signalCount\":" +
              std::to_string(signal_count) + ",\"windowSeconds\":" +
              std::to_string(window_seconds) + ",\"trigger\":\"" +
              json_escape(trigger_type) + "\"}");
    }
  }
}

void maybe_emit_stale_session_anomalies(AppContext &ctx) {
  const int stale_threshold_seconds = env_int_value(
      "ENDORIUMFORT_ALERT_STALE_SESSION_SECONDS", 7200, 300, 604800);
  const int cooldown_seconds = env_int_value(
      "ENDORIUMFORT_ALERT_STALE_SESSION_COOLDOWN_SECONDS", 900, 30, 86400);

  std::vector<Session> active_sessions;
  {
    std::lock_guard<std::mutex> lock(ctx.session_mutex);
    active_sessions.reserve(ctx.sessions.size());
    for (const auto &entry : ctx.sessions) {
      if (entry.second.status == "active") {
        active_sessions.push_back(entry.second);
      }
    }
  }

  const int64_t now_seconds = now_epoch_seconds();
  for (const auto &session : active_sessions) {
    const auto created_epoch = parse_utc_epoch_seconds(session.createdAt);
    if (!created_epoch.has_value()) continue;

    const int64_t age_seconds = std::max<int64_t>(0, now_seconds - *created_epoch);
    if (age_seconds < stale_threshold_seconds) continue;

    const std::string signal_key =
        "anomaly:session:stale:" + std::to_string(session.id);
    if (!ctx.should_emit_anomaly_signal(signal_key,
                                        std::chrono::seconds(cooldown_seconds))) {
      continue;
    }

    append_behavior_anomaly_event(
        ctx, "behavior.anomaly.stale_session",
        session.user.empty() ? "system" : session.user,
        "{\"sessionId\":" + std::to_string(session.id) +
            ",\"username\":\"" + json_escape(session.user) +
            "\",\"target\":\"" + json_escape(session.target) +
            "\",\"protocol\":\"" + json_escape(session.protocol) +
            "\",\"ageSeconds\":" + std::to_string(age_seconds) +
            ",\"thresholdSeconds\":" +
            std::to_string(stale_threshold_seconds) + "}");
  }
}

bool is_valid_fail_mode(const std::string &mode) {
  return mode == "fail-open" || mode == "fail-closed";
}

bool is_plausible_ticket_id(const std::string &ticket_id) {
  if (ticket_id.size() < 3 || ticket_id.size() > 80) return false;
  bool has_alpha = false;
  bool has_digit = false;
  for (char ch : ticket_id) {
    const unsigned char c = static_cast<unsigned char>(ch);
    if (std::isalnum(c)) {
      has_alpha = has_alpha || std::isalpha(c) != 0;
      has_digit = has_digit || std::isdigit(c) != 0;
      continue;
    }
    if (c == '-' || c == '_' || c == '/' || c == '.') continue;
    return false;
  }
  return has_alpha && has_digit;
}

struct SsoProviderDescriptor {
  const char *id;
  const char *label;
  const char *protocol;
  const char *enabledEnv;
};

const std::vector<SsoProviderDescriptor> &sso_provider_catalog() {
  static const std::vector<SsoProviderDescriptor> providers = {
      {"entra_id", "Microsoft Entra ID", "oidc",
       "ENDORIUMFORT_SSO_ENTRA_ID_ENABLED"},
      {"okta", "Okta", "oidc", "ENDORIUMFORT_SSO_OKTA_ENABLED"},
      {"google_workspace", "Google Workspace", "oidc",
       "ENDORIUMFORT_SSO_GOOGLE_WORKSPACE_ENABLED"},
      {"keycloak", "Keycloak", "oidc", "ENDORIUMFORT_SSO_KEYCLOAK_ENABLED"},
      {"saml_generic", "SAML 2.0", "saml", "ENDORIUMFORT_SSO_SAML_ENABLED"}};
  return providers;
}

struct IntegrationDescriptor {
  const char *id;
  const char *label;
  const char *enabledEnv;
};

const std::vector<IntegrationDescriptor> &itsm_provider_catalog() {
  static const std::vector<IntegrationDescriptor> providers = {
      {"servicenow", "ServiceNow", "ENDORIUMFORT_ITSM_SERVICENOW_ENABLED"},
      {"jira", "Jira", "ENDORIUMFORT_ITSM_JIRA_ENABLED"}};
  return providers;
}

const std::vector<IntegrationDescriptor> &siem_channel_catalog() {
  static const std::vector<IntegrationDescriptor> channels = {
      {"splunk", "Splunk", "ENDORIUMFORT_SIEM_SPLUNK_ENABLED"},
      {"sentinel", "Microsoft Sentinel", "ENDORIUMFORT_SIEM_SENTINEL_ENABLED"},
      {"syslog", "Syslog", "ENDORIUMFORT_SIEM_SYSLOG_ENABLED"},
      {"json_webhook", "JSON Webhook", "ENDORIUMFORT_SIEM_WEBHOOK_ENABLED"}};
  return channels;
}

struct LdapRuntimeConfig {
  bool enabled = false;
  std::string host;
  int port = 389;
  bool useTls = false;
  bool startTls = false;
  bool requireCert = true;
  std::string baseDn;
  std::string userAttribute = "sAMAccountName";
  std::string bindDnTemplate;
  std::string domain;
  std::string defaultRole = "operator";
  bool syncRole = false;
  std::string roleMap;
  std::string roleAdminMatchers;
  std::string roleAuditorMatchers;
};

struct LdapRoleResolution {
  std::string role = "operator";
  std::string strategy = "default";
  std::string matchedRule;
};

bool env_has_non_empty_value(const char *name) {
  if (!name || !*name) return false;
  const char *raw = std::getenv(name);
  if (!raw) return false;
  return !trim_copy(raw).empty();
}

void apply_ldap_host_overrides(LdapRuntimeConfig &cfg,
                               const std::string &host_value) {
  std::string host = trim_copy(host_value);
  if (host.empty()) {
    cfg.host = "";
    return;
  }

  const std::string lower = to_lower(host);
  if (lower.rfind("ldap://", 0) == 0) {
    cfg.useTls = false;
    host = trim_copy(host.substr(7));
  } else if (lower.rfind("ldaps://", 0) == 0) {
    cfg.useTls = true;
    host = trim_copy(host.substr(8));
  }

  const size_t slash_pos = host.find('/');
  if (slash_pos != std::string::npos) {
    host = trim_copy(host.substr(0, slash_pos));
  }

  std::string host_only = host;
  int parsed_port = 0;

  if (!host.empty() && host.front() == '[') {
    const size_t closing = host.find(']');
    if (closing != std::string::npos) {
      host_only = host.substr(1, closing - 1);
      if (closing + 1 < host.size() && host[closing + 1] == ':') {
        const std::string port_part = trim_copy(host.substr(closing + 2));
        if (!port_part.empty() &&
            std::all_of(port_part.begin(), port_part.end(),
                        [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
          parsed_port = std::stoi(port_part);
        }
      }
    }
  } else {
    const size_t first_colon = host.find(':');
    const size_t last_colon = host.rfind(':');
    if (first_colon != std::string::npos && first_colon == last_colon) {
      const std::string maybe_port = trim_copy(host.substr(last_colon + 1));
      if (!maybe_port.empty() &&
          std::all_of(maybe_port.begin(), maybe_port.end(),
                      [](unsigned char ch) { return std::isdigit(ch) != 0; })) {
        host_only = trim_copy(host.substr(0, last_colon));
        parsed_port = std::stoi(maybe_port);
      }
    }
  }

  cfg.host = trim_copy(host_only);
  if (parsed_port > 0 &&
      !env_has_non_empty_value("ENDORIUMFORT_LDAP_PORT")) {
    cfg.port = std::clamp(parsed_port, 1, 65535);
  }
}

std::vector<std::pair<std::string, std::string>> parse_ldap_role_map(
    const std::string &raw_map) {
  auto split_ldap_rules = [](const std::string &raw_rules) {
    std::vector<std::string> rules;
    const std::string trimmed = trim_copy(raw_rules);
    if (trimmed.empty()) return rules;

    const bool explicit_separator =
        trimmed.find(';') != std::string::npos ||
        trimmed.find('\n') != std::string::npos;
    if (!explicit_separator) {
      const std::string lowered = to_lower(trimmed);
      const bool dn_like = lowered.find(",ou=") != std::string::npos ||
                           lowered.find(",dc=") != std::string::npos ||
                           lowered.find(",cn=") != std::string::npos;
      if (dn_like) {
        rules.push_back(trimmed);
      } else {
        rules = split_csv_compact(trimmed);
      }
      return rules;
    }

    std::string current;
    for (char ch : trimmed) {
      if (ch == ';' || ch == '\n') {
        const std::string token = trim_copy(current);
        if (!token.empty()) rules.push_back(token);
        current.clear();
        continue;
      }
      current.push_back(ch);
    }
    const std::string trailing = trim_copy(current);
    if (!trailing.empty()) rules.push_back(trailing);
    return rules;
  };

  std::vector<std::pair<std::string, std::string>> role_map;
  for (const auto &entry_raw : split_ldap_rules(raw_map)) {
    const std::string entry = trim_copy(entry_raw);
    if (entry.empty()) continue;
    size_t separator = entry.rfind('=');
    if (separator == std::string::npos) separator = entry.rfind(':');
    if (separator == std::string::npos) continue;

    std::string key = to_lower(trim_copy(entry.substr(0, separator)));
    std::string role = normalize_user_role(trim_copy(entry.substr(separator + 1)));
    if (key.empty() ||
        !is_allowed_user_role(role, {"operator", "admin", "auditor"})) {
      continue;
    }
    role_map.emplace_back(key, role);
  }
  return role_map;
}

std::optional<std::string> first_matching_csv_token(
    const std::string &raw_csv, const std::string &haystack) {
  if (haystack.empty()) return std::nullopt;
  std::vector<std::string> tokens;
  const std::string trimmed = trim_copy(raw_csv);
  if (trimmed.find(';') != std::string::npos ||
      trimmed.find('\n') != std::string::npos) {
    std::string current;
    for (char ch : trimmed) {
      if (ch == ';' || ch == '\n') {
        const std::string token = trim_copy(current);
        if (!token.empty()) tokens.push_back(token);
        current.clear();
        continue;
      }
      current.push_back(ch);
    }
    const std::string trailing = trim_copy(current);
    if (!trailing.empty()) tokens.push_back(trailing);
  } else {
    const std::string lowered = to_lower(trimmed);
    const bool dn_like = lowered.find(",ou=") != std::string::npos ||
                         lowered.find(",dc=") != std::string::npos ||
                         lowered.find(",cn=") != std::string::npos;
    if (dn_like) {
      if (!trimmed.empty()) tokens.push_back(trimmed);
    } else {
      tokens = split_csv_compact(trimmed);
    }
  }

  for (const auto &token_raw : tokens) {
    const std::string token = to_lower(trim_copy(token_raw));
    if (token.empty()) continue;
    if (haystack.find(token) != std::string::npos) {
      return token;
    }
  }
  return std::nullopt;
}

LdapRoleResolution resolve_ldap_role(const LdapRuntimeConfig &cfg,
                                     const std::string &username,
                                     const std::string &directory_identity) {
  LdapRoleResolution resolution;
  resolution.role =
      is_allowed_user_role(cfg.defaultRole, {"operator", "admin", "auditor"})
          ? normalize_user_role(cfg.defaultRole)
          : "operator";

  const std::string normalized_username = to_lower(trim_copy(username));
  const std::string normalized_identity = to_lower(trim_copy(directory_identity));

  const auto role_map = parse_ldap_role_map(cfg.roleMap);
  for (const auto &entry : role_map) {
    if (!normalized_username.empty() && entry.first == normalized_username) {
      resolution.role = entry.second;
      resolution.strategy = "role_map_user";
      resolution.matchedRule = entry.first;
      return resolution;
    }
    if (!normalized_identity.empty() && entry.first == normalized_identity) {
      resolution.role = entry.second;
      resolution.strategy = "role_map_identity";
      resolution.matchedRule = entry.first;
      return resolution;
    }
  }

  const std::string haystack = normalized_username + " " + normalized_identity;
  if (auto token = first_matching_csv_token(cfg.roleAdminMatchers, haystack)) {
    resolution.role = "admin";
    resolution.strategy = "matcher_admin";
    resolution.matchedRule = *token;
    return resolution;
  }
  if (auto token = first_matching_csv_token(cfg.roleAuditorMatchers, haystack)) {
    resolution.role = "auditor";
    resolution.strategy = "matcher_auditor";
    resolution.matchedRule = *token;
    return resolution;
  }

  return resolution;
}

bool ldap_command_available() {
#ifdef _WIN32
  return false;
#else
  return std::system("command -v ldapwhoami >/dev/null 2>&1") == 0;
#endif
}

std::string shell_quote(const std::string &value) {
  std::string quoted = "'";
  for (char ch : value) {
    if (ch == '\'') {
      quoted += "'\"'\"'";
    } else {
      quoted.push_back(ch);
    }
  }
  quoted.push_back('\'');
  return quoted;
}

std::string replace_all_copy(std::string input, const std::string &from,
                             const std::string &to) {
  if (from.empty()) return input;
  size_t start = 0;
  while (true) {
    const size_t pos = input.find(from, start);
    if (pos == std::string::npos) break;
    input.replace(pos, from.size(), to);
    start = pos + to.size();
  }
  return input;
}

LdapRuntimeConfig load_ldap_runtime_config() {
  LdapRuntimeConfig cfg;
  cfg.enabled = env_flag_enabled("ENDORIUMFORT_LDAP_ENABLED", false);
  cfg.useTls = env_flag_enabled("ENDORIUMFORT_LDAP_USE_TLS", false);
  cfg.startTls = env_flag_enabled("ENDORIUMFORT_LDAP_STARTTLS", false);
  cfg.requireCert = env_flag_enabled("ENDORIUMFORT_LDAP_REQUIRE_CERT", true);
  cfg.host = env_string_value("ENDORIUMFORT_LDAP_HOST", "");
  cfg.port = env_int_value("ENDORIUMFORT_LDAP_PORT", cfg.useTls ? 636 : 389,
                           1, 65535);
  apply_ldap_host_overrides(cfg, cfg.host);
  cfg.baseDn = env_string_value("ENDORIUMFORT_LDAP_BASE_DN", "");
  cfg.userAttribute = env_string_value("ENDORIUMFORT_LDAP_USER_ATTRIBUTE",
                                       "sAMAccountName");
  cfg.bindDnTemplate =
      env_string_value("ENDORIUMFORT_LDAP_BIND_DN_TEMPLATE", "");
  if (cfg.bindDnTemplate.empty()) {
    cfg.bindDnTemplate = env_string_value("ENDORIUMFORT_LDAP_USER_TEMPLATE", "");
  }
  cfg.domain = env_string_value("ENDORIUMFORT_LDAP_AD_DOMAIN", "");
  cfg.defaultRole = normalize_user_role(
      env_string_value("ENDORIUMFORT_LDAP_DEFAULT_ROLE", "operator"));
  if (!is_allowed_user_role(cfg.defaultRole,
                            {"operator", "admin", "auditor"})) {
    cfg.defaultRole = "operator";
  }
  cfg.syncRole = env_flag_enabled("ENDORIUMFORT_LDAP_SYNC_ROLE", false);
  cfg.roleMap = env_string_value("ENDORIUMFORT_LDAP_ROLE_MAP", "");
  cfg.roleAdminMatchers =
      env_string_value("ENDORIUMFORT_LDAP_ROLE_ADMIN_MATCHERS", "");
  cfg.roleAuditorMatchers =
      env_string_value("ENDORIUMFORT_LDAP_ROLE_AUDITOR_MATCHERS", "");
  return cfg;
}

std::string ldap_bind_identity_for_user(const LdapRuntimeConfig &cfg,
                                        const std::string &username) {
  const std::string normalized_user = trim_copy(username);
  if (normalized_user.empty()) return "";

  if (!cfg.bindDnTemplate.empty()) {
    std::string identity = replace_all_copy(cfg.bindDnTemplate, "{user}",
                                            normalized_user);
    identity = replace_all_copy(identity, "{username}", normalized_user);
    return identity;
  }

  if (!cfg.domain.empty() && normalized_user.find('@') == std::string::npos &&
      normalized_user.find('\\') == std::string::npos) {
    return normalized_user + "@" + cfg.domain;
  }

  if (!cfg.baseDn.empty() && !cfg.userAttribute.empty()) {
    return cfg.userAttribute + "=" + normalized_user + "," + cfg.baseDn;
  }

  return normalized_user;
}

std::string ldap_endpoint_uri(const LdapRuntimeConfig &cfg) {
  const std::string scheme = cfg.useTls ? "ldaps" : "ldap";
  return scheme + "://" + cfg.host + ":" + std::to_string(cfg.port);
}

bool run_ldap_bind_command(const LdapRuntimeConfig &cfg,
                           const std::string &bind_identity,
                           const std::string &password,
                           std::string &directory_identity,
                           std::string &error_message) {
  std::vector<std::string> command = {
      "ldapwhoami", "-x", "-o", "nettimeout=5", "-H",
      ldap_endpoint_uri(cfg)};
  if (cfg.startTls && !cfg.useTls) {
    command.push_back("-ZZ");
  }
  command.push_back("-D");
  command.push_back(bind_identity);
  command.push_back("-w");
  command.push_back(password);

  std::ostringstream shell_command;
  if (!cfg.requireCert) {
    shell_command << "LDAPTLS_REQCERT=never ";
  }
  for (size_t i = 0; i < command.size(); ++i) {
    if (i > 0) shell_command << ' ';
    shell_command << shell_quote(command[i]);
  }
  shell_command << " 2>&1";

  FILE *pipe = popen(shell_command.str().c_str(), "r");
  if (!pipe) {
    error_message = "Failed to execute ldapwhoami";
    return false;
  }

  std::string output;
  char buffer[256];
  while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
    output.append(buffer);
  }
  const int rc = pclose(pipe);

  directory_identity = trim_copy(output);
  if (rc != 0) {
    error_message = directory_identity.empty() ? "LDAP bind failed"
                                               : directory_identity;
    return false;
  }

  if (directory_identity.empty()) {
    directory_identity = bind_identity;
  }
  return true;
}

bool ldap_authenticate_user(const LdapRuntimeConfig &cfg,
                            const std::string &username,
                            const std::string &password,
                            std::string &directory_identity,
                            std::string &error_message) {
  if (!cfg.enabled) {
    error_message = "LDAP integration is disabled";
    return false;
  }
  if (trim_copy(cfg.host).empty()) {
    error_message = "LDAP host is not configured";
    return false;
  }
  if (trim_copy(username).empty() || password.empty()) {
    error_message = "Missing LDAP username or password";
    return false;
  }
  if (!ldap_command_available()) {
    error_message = "ldapwhoami command is not available on this host";
    return false;
  }

  const std::string bind_identity = ldap_bind_identity_for_user(cfg, username);
  if (bind_identity.empty()) {
    error_message = "Unable to build LDAP bind identity";
    return false;
  }

  return run_ldap_bind_command(cfg, bind_identity, password, directory_identity,
                               error_message);
}

bool is_ldap_shadow_password(const std::string &password_hash) {
  return password_hash.rfind("ldap_external:", 0) == 0;
}

std::optional<UserAccount> provision_ldap_shadow_user(
  AppContext &ctx, const std::string &username, const LdapRuntimeConfig &cfg,
  const std::string &resolved_role, bool &created, bool &updated,
  std::string &error_message) {
  created = false;
  updated = false;

  std::string normalized_username = trim_copy(username);
  if (normalized_username.empty()) {
    error_message = "LDAP username is empty";
    return std::nullopt;
  }
  if (normalized_username.size() > 128) normalized_username.resize(128);

  const std::string wanted = to_lower(normalized_username);
  const std::string default_role =
      is_allowed_user_role(cfg.defaultRole, {"operator", "admin", "auditor"})
          ? normalize_user_role(cfg.defaultRole)
          : "operator";
  std::string provision_role = normalize_user_role(trim_copy(resolved_role));
  if (!is_allowed_user_role(provision_role, {"operator", "admin", "auditor"})) {
    provision_role = default_role;
  }

  UserAccount user;
  bool found_existing = false;
  bool persist_update = false;
  bool persist_insert = false;

  {
    std::lock_guard<std::mutex> lock(ctx.user_mutex);
    for (auto &entry : ctx.users) {
      if (to_lower(entry.second.username) != wanted) continue;
      found_existing = true;
      user = entry.second;
      if (is_ldap_shadow_password(user.password) && cfg.syncRole &&
          normalize_user_role(user.role) != provision_role) {
        user.role = provision_role;
        user.updatedAt = now_utc();
        entry.second = user;
        updated = true;
        persist_update = true;
      }
      break;
    }

    if (!found_existing) {
      created = true;
      persist_insert = true;
      user.id = ctx.next_user_id.fetch_add(1);
      user.username = normalized_username;
      user.password = "ldap_external:" + ctx.generate_token();
      user.role = provision_role;
      user.createdAt = now_utc();
      user.updatedAt = user.createdAt;
      user.bootstrapPasswordChangeRequired = false;
      user.bootstrapMfaRequired = false;
      ctx.users[user.id] = user;
    }
  }

  if (persist_insert && !ctx.insert_user(user)) {
    error_message = "Failed to persist LDAP user";
    return std::nullopt;
  }
  if (persist_update && !ctx.update_user_db(user)) {
    error_message = "Failed to update LDAP user role";
    return std::nullopt;
  }

  return user;
}

crow::json::wvalue ldap_config_to_json(const LdapRuntimeConfig &cfg) {
  crow::json::wvalue payload;
  const auto role_map = parse_ldap_role_map(cfg.roleMap);
  std::string auth_mode = "raw_username";
  std::string user_template = "{username}";
  if (!cfg.bindDnTemplate.empty()) {
    auth_mode = "bind_dn_template";
    user_template = cfg.bindDnTemplate;
  } else if (!cfg.domain.empty()) {
    auth_mode = "domain_upn";
    user_template = "{username}@" + cfg.domain;
  } else if (!cfg.baseDn.empty() && !cfg.userAttribute.empty()) {
    auth_mode = "attribute_dn";
    user_template = cfg.userAttribute + "={username}," + cfg.baseDn;
  }

  payload["provider"] = "ldap_ad";
  payload["enabled"] = cfg.enabled;
  payload["host"] = cfg.host;
  payload["port"] = cfg.port;
  payload["useTls"] = cfg.useTls;
  payload["startTls"] = cfg.startTls;
  payload["requireCert"] = cfg.requireCert;
  payload["baseDn"] = cfg.baseDn;
  payload["userAttribute"] = cfg.userAttribute;
  payload["bindDnTemplate"] = cfg.bindDnTemplate;
  payload["userTemplate"] = user_template;
  payload["authMode"] = auth_mode;
  payload["domain"] = cfg.domain;
  payload["defaultRole"] = cfg.defaultRole;
  payload["syncRole"] = cfg.syncRole;
  payload["roleMapConfigured"] = !cfg.roleMap.empty();
  payload["roleMapEntries"] = static_cast<int>(role_map.size());
  payload["roleAdminMatchers"] = cfg.roleAdminMatchers;
  payload["roleAuditorMatchers"] = cfg.roleAuditorMatchers;
  payload["roleMappingEnabled"] =
      !role_map.empty() || !cfg.roleAdminMatchers.empty() ||
      !cfg.roleAuditorMatchers.empty();
  payload["commandAvailable"] = ldap_command_available();
  payload["authPath"] = "/api/auth/directory/ldap/test-bind";
  payload["jitProvisioning"] = true;
  return payload;
}

constexpr int kOidcStateTtlSeconds = 300;

struct ParsedEndpointUrl {
  std::string scheme;
  std::string host;
  int port = 0;
  std::string target;
};

struct OidcProviderConfig {
  std::string provider;
  std::string clientId;
  std::string clientSecret;
  std::string authorizationEndpoint;
  std::string tokenEndpoint;
  std::string userinfoEndpoint;
  std::string scope;
  std::string redirectUri;
  std::string roleClaim;
  std::string defaultRole;
  bool syncRole = true;
};

struct OidcAuthStateRecord {
  std::string state;
  std::string provider;
  std::string nonce;
  std::string codeVerifier;
  std::string redirectAfterLogin;
  std::string createdAt;
  std::string expiresAt;
};

struct OidcProvisionResult {
  UserAccount user;
  bool created = false;
  bool updated = false;
};

std::string dynamic_env_string(const std::string &name,
                               const std::string &fallback = "") {
  if (name.empty()) return fallback;
  const char *raw = std::getenv(name.c_str());
  if (!raw) return fallback;
  const std::string value = trim_copy(raw);
  return value.empty() ? fallback : value;
}

bool dynamic_env_flag(const std::string &name, bool fallback) {
  if (name.empty()) return fallback;
  const char *raw = std::getenv(name.c_str());
  if (!raw) return fallback;
  const std::string normalized = to_lower(trim_copy(raw));
  if (normalized == "1" || normalized == "true" || normalized == "yes" ||
      normalized == "on") {
    return true;
  }
  if (normalized == "0" || normalized == "false" || normalized == "no" ||
      normalized == "off") {
    return false;
  }
  return fallback;
}

std::string normalize_for_env_key(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) -> char {
                   if (std::isalnum(c)) return static_cast<char>(std::toupper(c));
                   return '_';
                 });
  return value;
}

const SsoProviderDescriptor *find_sso_provider_descriptor(
    const std::string &provider) {
  const auto &providers = sso_provider_catalog();
  auto it = std::find_if(providers.begin(), providers.end(),
                         [&](const SsoProviderDescriptor &entry) {
                           return to_lower(entry.id) == provider;
                         });
  if (it == providers.end()) return nullptr;
  return &(*it);
}

std::string oidc_provider_env_value(const std::string &provider,
                                    const std::string &suffix,
                                    const std::string &fallback = "") {
  const std::string normalized_suffix = normalize_for_env_key(suffix);
  if (!provider.empty()) {
    const std::string provider_specific =
        "ENDORIUMFORT_SSO_OIDC_" + normalize_for_env_key(provider) + "_" +
        normalized_suffix;
    const std::string provider_value = dynamic_env_string(provider_specific, "");
    if (!provider_value.empty()) return provider_value;
  }
  return dynamic_env_string("ENDORIUMFORT_SSO_OIDC_" + normalized_suffix,
                            fallback);
}

bool oidc_provider_env_flag(const std::string &provider,
                            const std::string &suffix, bool fallback) {
  const std::string normalized_suffix = normalize_for_env_key(suffix);
  if (!provider.empty()) {
    const std::string provider_specific =
        "ENDORIUMFORT_SSO_OIDC_" + normalize_for_env_key(provider) + "_" +
        normalized_suffix;
    if (std::getenv(provider_specific.c_str())) {
      return dynamic_env_flag(provider_specific, fallback);
    }
  }
  return dynamic_env_flag("ENDORIUMFORT_SSO_OIDC_" + normalized_suffix,
                          fallback);
}

std::string request_base_url(const crow::request &request) {
  std::string explicit_base =
      dynamic_env_string("ENDORIUMFORT_EXTERNAL_BASE_URL", "");
  if (!explicit_base.empty()) {
    while (!explicit_base.empty() && explicit_base.back() == '/') {
      explicit_base.pop_back();
    }
    return explicit_base;
  }

  std::string host = request.get_header_value("X-Forwarded-Host");
  if (host.empty()) host = request.get_header_value("Host");
  if (host.empty()) {
    host = "localhost";
  }
  const size_t comma = host.find(',');
  if (comma != std::string::npos) {
    host = trim_copy(host.substr(0, comma));
  } else {
    host = trim_copy(host);
  }
  std::string base = std::string(request_uses_https(request) ? "https://"
                                                            : "http://") +
                     host;
  while (!base.empty() && base.back() == '/') {
    base.pop_back();
  }
  return base;
}

std::string sanitize_post_login_redirect(const std::string &raw) {
  std::string value = trim_copy(raw);
  if (value.empty()) return "/";
  if (value[0] != '/') return "/";
  if (value.rfind("//", 0) == 0) return "/";
  if (value.find("://") != std::string::npos) return "/";
  if (value.size() > 240) value.resize(240);
  return value;
}

std::string url_encode(const std::string &value) {
  static const char kHex[] = "0123456789ABCDEF";
  std::string encoded;
  encoded.reserve(value.size() * 3);
  for (unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      encoded.push_back(static_cast<char>(c));
      continue;
    }
    encoded.push_back('%');
    encoded.push_back(kHex[(c >> 4) & 0x0F]);
    encoded.push_back(kHex[c & 0x0F]);
  }
  return encoded;
}

std::string append_query_params(
    const std::string &base,
    const std::vector<std::pair<std::string, std::string>> &params) {
  if (params.empty()) return base;
  std::ostringstream oss;
  oss << base;
  char separator = base.find('?') == std::string::npos ? '?' : '&';
  for (const auto &param : params) {
    oss << separator << url_encode(param.first) << '='
        << url_encode(param.second);
    separator = '&';
  }
  return oss.str();
}

std::optional<ParsedEndpointUrl> parse_endpoint_url(const std::string &raw_url) {
  const std::string url = trim_copy(raw_url);
  if (url.empty()) return std::nullopt;

  const size_t scheme_sep = url.find("://");
  if (scheme_sep == std::string::npos) return std::nullopt;

  ParsedEndpointUrl parsed;
  parsed.scheme = to_lower(url.substr(0, scheme_sep));
  if (parsed.scheme != "http" && parsed.scheme != "https") {
    return std::nullopt;
  }

  std::string remainder = url.substr(scheme_sep + 3);
  if (remainder.empty()) return std::nullopt;

  const size_t path_pos = remainder.find('/');
  const size_t query_pos = remainder.find('?');
  size_t authority_end = std::string::npos;
  if (path_pos == std::string::npos && query_pos == std::string::npos) {
    authority_end = remainder.size();
  } else if (path_pos == std::string::npos) {
    authority_end = query_pos;
  } else if (query_pos == std::string::npos) {
    authority_end = path_pos;
  } else {
    authority_end = std::min(path_pos, query_pos);
  }

  const std::string authority = remainder.substr(0, authority_end);
  if (authority.empty()) return std::nullopt;

  parsed.target = authority_end < remainder.size() ? remainder.substr(authority_end)
                                                    : "/";
  if (parsed.target.empty()) parsed.target = "/";
  if (!parsed.target.empty() && parsed.target[0] != '/') {
    parsed.target = "/" + parsed.target;
  }

  parsed.port = parsed.scheme == "https" ? 443 : 80;
  if (authority.front() == '[') {
    const size_t close = authority.find(']');
    if (close == std::string::npos || close <= 1) return std::nullopt;
    parsed.host = authority.substr(1, close - 1);
    if (close + 1 < authority.size()) {
      if (authority[close + 1] != ':') return std::nullopt;
      const std::string port_part = authority.substr(close + 2);
      if (port_part.empty() ||
          !std::all_of(port_part.begin(), port_part.end(),
                       [](unsigned char c) { return std::isdigit(c) != 0; })) {
        return std::nullopt;
      }
      try {
        parsed.port = std::stoi(port_part);
      } catch (...) {
        return std::nullopt;
      }
    }
  } else {
    parsed.host = authority;
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos && authority.find(':') == colon) {
      const std::string port_part = authority.substr(colon + 1);
      if (!port_part.empty() &&
          std::all_of(port_part.begin(), port_part.end(),
                      [](unsigned char c) { return std::isdigit(c) != 0; })) {
        try {
          parsed.port = std::stoi(port_part);
          parsed.host = authority.substr(0, colon);
        } catch (...) {
          return std::nullopt;
        }
      }
    }
  }

  if (parsed.host.empty()) return std::nullopt;
  return parsed;
}

std::string build_pkce_challenge(const std::string &verifier) {
  const auto digest =
      crypto::sha256(reinterpret_cast<const uint8_t *>(verifier.data()),
                     verifier.size());
  const std::string raw_digest(reinterpret_cast<const char *>(digest.data()),
                               digest.size());
  return webauthn::base64url_encode(raw_digest);
}

bool ensure_oidc_state_table(AppContext &ctx) {
  if (!ctx.sqlite.db) return false;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *schema =
      "CREATE TABLE IF NOT EXISTS oidc_auth_states ("
      "state TEXT PRIMARY KEY,"
      "provider TEXT NOT NULL,"
      "nonce TEXT NOT NULL,"
      "code_verifier TEXT NOT NULL,"
      "redirect_after_login TEXT NOT NULL,"
      "created_at TEXT NOT NULL,"
      "expires_at TEXT NOT NULL"
      ");";
  char *error_message = nullptr;
  const int rc = sqlite3_exec(ctx.sqlite.db, schema, nullptr, nullptr,
                              &error_message);
  if (error_message) sqlite3_free(error_message);
  return rc == SQLITE_OK;
}

bool store_oidc_auth_state(AppContext &ctx, const OidcAuthStateRecord &record) {
  if (!ensure_oidc_state_table(ctx)) return false;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);

  sqlite3_stmt *cleanup_stmt = nullptr;
  const char *cleanup_sql =
      "DELETE FROM oidc_auth_states WHERE expires_at < ?";
  if (sqlite3_prepare_v2(ctx.sqlite.db, cleanup_sql, -1, &cleanup_stmt,
                         nullptr) == SQLITE_OK) {
    const std::string now = now_utc();
    sqlite3_bind_text(cleanup_stmt, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(cleanup_stmt);
  }
  sqlite3_finalize(cleanup_stmt);

  sqlite3_stmt *insert_stmt = nullptr;
  const char *insert_sql =
      "INSERT OR REPLACE INTO oidc_auth_states("
      "state, provider, nonce, code_verifier, redirect_after_login, "
      "created_at, expires_at"
      ") VALUES(?, ?, ?, ?, ?, ?, ?)";
  if (sqlite3_prepare_v2(ctx.sqlite.db, insert_sql, -1, &insert_stmt,
                         nullptr) != SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(insert_stmt, 1, record.state.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 2, record.provider.c_str(), -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 3, record.nonce.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 4, record.codeVerifier.c_str(), -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 5, record.redirectAfterLogin.c_str(), -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 6, record.createdAt.c_str(), -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(insert_stmt, 7, record.expiresAt.c_str(), -1,
                    SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(insert_stmt) == SQLITE_DONE;
  sqlite3_finalize(insert_stmt);
  return ok;
}

std::optional<OidcAuthStateRecord> consume_oidc_auth_state(
    AppContext &ctx, const std::string &state) {
  if (state.empty()) return std::nullopt;
  if (!ensure_oidc_state_table(ctx)) return std::nullopt;

  OidcAuthStateRecord record;
  bool found = false;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);

  sqlite3_stmt *select_stmt = nullptr;
  const char *select_sql =
      "SELECT provider, nonce, code_verifier, redirect_after_login, "
      "created_at, expires_at "
      "FROM oidc_auth_states WHERE state=?";
  if (sqlite3_prepare_v2(ctx.sqlite.db, select_sql, -1, &select_stmt,
                         nullptr) == SQLITE_OK) {
    sqlite3_bind_text(select_stmt, 1, state.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(select_stmt) == SQLITE_ROW) {
      found = true;
      record.state = state;
      if (auto value = sqlite3_column_text(select_stmt, 0)) {
        record.provider = reinterpret_cast<const char *>(value);
      }
      if (auto value = sqlite3_column_text(select_stmt, 1)) {
        record.nonce = reinterpret_cast<const char *>(value);
      }
      if (auto value = sqlite3_column_text(select_stmt, 2)) {
        record.codeVerifier = reinterpret_cast<const char *>(value);
      }
      if (auto value = sqlite3_column_text(select_stmt, 3)) {
        record.redirectAfterLogin = reinterpret_cast<const char *>(value);
      }
      if (auto value = sqlite3_column_text(select_stmt, 4)) {
        record.createdAt = reinterpret_cast<const char *>(value);
      }
      if (auto value = sqlite3_column_text(select_stmt, 5)) {
        record.expiresAt = reinterpret_cast<const char *>(value);
      }
    }
  }
  sqlite3_finalize(select_stmt);

  sqlite3_stmt *delete_stmt = nullptr;
  const char *delete_sql = "DELETE FROM oidc_auth_states WHERE state=?";
  if (sqlite3_prepare_v2(ctx.sqlite.db, delete_sql, -1, &delete_stmt,
                         nullptr) == SQLITE_OK) {
    sqlite3_bind_text(delete_stmt, 1, state.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(delete_stmt);
  }
  sqlite3_finalize(delete_stmt);

  if (!found) return std::nullopt;
  if (!record.expiresAt.empty() && record.expiresAt < now_utc()) {
    return std::nullopt;
  }
  return record;
}

std::optional<std::string> json_string_field(const crow::json::rvalue &payload,
                                             const std::string &field) {
  if (!payload.has(field.c_str())) return std::nullopt;
  try {
    const std::string value = trim_copy(std::string(payload[field].s()));
    if (!value.empty()) return value;
  } catch (...) {
  }
  return std::nullopt;
}

std::optional<bool> json_bool_field(const crow::json::rvalue &payload,
                                    const std::string &field) {
  if (!payload.has(field.c_str())) return std::nullopt;
  try {
    return payload[field].b();
  } catch (...) {
  }
  return std::nullopt;
}

std::optional<std::string> json_first_string_field(
    const crow::json::rvalue &payload, const std::string &field) {
  if (!payload.has(field.c_str())) return std::nullopt;
  try {
    auto node = payload[field];
    if (node.size() <= 0) return std::nullopt;
    try {
      const std::string direct = trim_copy(std::string(node[0].s()));
      if (!direct.empty()) return direct;
    } catch (...) {
    }
    try {
      if (node[0].has("value")) {
        const std::string nested =
            trim_copy(std::string(node[0]["value"].s()));
        if (!nested.empty()) return nested;
      }
    } catch (...) {
    }
  } catch (...) {
  }
  return std::nullopt;
}

std::string extract_oidc_username_from_claims(const crow::json::rvalue &claims) {
  static const std::vector<std::string> preferred_claims = {
      "preferred_username", "email", "upn", "sub", "name"};
  for (const auto &claim : preferred_claims) {
    auto value = json_string_field(claims, claim);
    if (!value) continue;
    if (value->size() <= 128) return *value;
    return value->substr(0, 128);
  }
  return {};
}

std::string extract_oidc_role_from_claims(const crow::json::rvalue &claims,
                                          const std::string &claim_name,
                                          const std::string &fallback_role) {
  std::string role;
  if (auto value = json_string_field(claims, claim_name)) {
    role = *value;
  }
  if (role.empty()) {
    if (auto value = json_first_string_field(claims, claim_name)) {
      role = *value;
    }
  }
  if (role.empty() && claim_name != "roles") {
    if (auto value = json_string_field(claims, "roles")) {
      role = *value;
    } else if (auto value = json_first_string_field(claims, "roles")) {
      role = *value;
    }
  }

  const std::string default_role =
      is_allowed_user_role(fallback_role, {"operator", "admin", "auditor"})
          ? normalize_user_role(fallback_role)
          : "operator";
  if (role.empty()) return default_role;

  role = normalize_user_role(role);
  if (!is_allowed_user_role(role, {"operator", "admin", "auditor"})) {
    return default_role;
  }
  return role;
}

std::string scim_username_from_payload(const crow::json::rvalue &body) {
  if (auto value = json_string_field(body, "userName")) return *value;
  if (auto value = json_string_field(body, "username")) return *value;
  return {};
}

std::string scim_role_from_payload(const crow::json::rvalue &body,
                                   const std::string &fallback = "operator") {
  std::string role;
  if (auto value = json_string_field(body, "role")) {
    role = *value;
  }
  if (role.empty()) {
    if (auto value = json_first_string_field(body, "roles")) {
      role = *value;
    }
  }
  if (role.empty()) role = fallback;
  role = normalize_user_role(role);
  if (!is_allowed_user_role(role, {"operator", "admin", "auditor"})) {
    return normalize_user_role(
        is_allowed_user_role(fallback, {"operator", "admin", "auditor"})
            ? fallback
            : "operator");
  }
  return role;
}

std::optional<bool> json_bool_scalar(const crow::json::rvalue &node) {
  try {
    const auto type = node.t();
    if (type == crow::json::type::True) return true;
    if (type == crow::json::type::False) return false;
  } catch (...) {
  }
  return std::nullopt;
}

std::optional<std::string> json_string_scalar(const crow::json::rvalue &node) {
  try {
    const std::string value = trim_copy(std::string(node.s()));
    if (!value.empty()) return value;
  } catch (...) {
  }
  return std::nullopt;
}

std::optional<std::string> scim_role_from_patch_value(
    const crow::json::rvalue &value_node) {
  if (auto direct = json_string_scalar(value_node)) {
    const std::string normalized = normalize_user_role(*direct);
    if (is_allowed_user_role(normalized, {"operator", "admin", "auditor"})) {
      return normalized;
    }
  }

  try {
    if (value_node.has("value")) {
      const auto nested = json_string_scalar(value_node["value"]);
      if (nested) {
        const std::string normalized = normalize_user_role(*nested);
        if (is_allowed_user_role(normalized, {"operator", "admin", "auditor"})) {
          return normalized;
        }
      }
    }
  } catch (...) {
  }

  try {
    if (value_node.size() > 0) {
      if (auto list_first = json_string_scalar(value_node[0])) {
        const std::string normalized = normalize_user_role(*list_first);
        if (is_allowed_user_role(normalized, {"operator", "admin", "auditor"})) {
          return normalized;
        }
      }
      try {
        if (value_node[0].has("value")) {
          const auto nested_first = json_string_scalar(value_node[0]["value"]);
          if (nested_first) {
            const std::string normalized = normalize_user_role(*nested_first);
            if (is_allowed_user_role(normalized,
                                     {"operator", "admin", "auditor"})) {
              return normalized;
            }
          }
        }
      } catch (...) {
      }
    }
  } catch (...) {
  }

  return std::nullopt;
}

struct ScimUserMutation {
  std::optional<std::string> username;
  std::optional<std::string> role;
  std::optional<bool> active;
};

bool parse_scim_list_query(const crow::request &request, ScimListQuery &query,
                           std::string &error_message) {
  return parse_scim_list_query_params(request.url_params.get("startIndex"),
                                      request.url_params.get("count"),
                                      request.url_params.get("filter"), query,
                                      error_message);
}

bool scim_user_matches_filter(const UserAccount &user,
                              const ScimFilterExpression &expression) {
  if (expression.attribute == "id") {
    return scim_match_string_expr(std::to_string(user.id), expression);
  }
  if (expression.attribute == "username" || expression.attribute == "user.name") {
    return scim_match_string_expr(user.username, expression);
  }
  if (expression.attribute == "displayname") {
    return scim_match_string_expr(user.username, expression);
  }
  if (expression.attribute == "role" || expression.attribute == "roles") {
    return scim_match_string_expr(normalize_user_role(user.role), expression);
  }
  if (expression.attribute == "active") {
    return scim_match_string_expr("true", expression);
  }
  return false;
}

bool scim_group_matches_filter(const std::string &name,
                               const std::vector<int> &members,
                               const ScimFilterExpression &expression) {
  if (expression.attribute == "id") {
    return scim_match_string_expr("role:" + name, expression);
  }
  if (expression.attribute == "displayname") {
    return scim_match_string_expr(name, expression);
  }
  if (expression.attribute == "members" || expression.attribute == "member") {
    for (int member : members) {
      if (scim_match_string_expr(std::to_string(member), expression)) {
        return true;
      }
    }
    return false;
  }
  return false;
}

bool parse_scim_patch_mutation(const crow::json::rvalue &body,
                               ScimUserMutation &mutation,
                               std::string &error_message) {
  if (!body.has("Operations")) {
    error_message = "Missing Operations";
    return false;
  }

  auto operations = body["Operations"];
  if (operations.size() <= 0) {
    error_message = "Operations must contain at least one item";
    return false;
  }

  for (int i = 0; i < operations.size(); ++i) {
    const auto operation = operations[i];
    std::string op;
    try {
      op = to_lower(trim_copy(std::string(operation["op"].s())));
    } catch (...) {
    }
    if (op.empty()) {
      error_message = "Each SCIM operation must define op";
      return false;
    }
    if (op != "add" && op != "replace" && op != "remove") {
      error_message = "Unsupported SCIM op: " + op;
      return false;
    }

    std::string path;
    try {
      if (operation.has("path")) {
        path = to_lower(trim_copy(std::string(operation["path"].s())));
      }
    } catch (...) {
    }

    if (path.empty()) {
      if (op == "remove") {
        error_message = "SCIM remove requires an explicit path";
        return false;
      }
      if (!operation.has("value")) {
        error_message = "SCIM add/replace requires value";
        return false;
      }
      const auto value_node = operation["value"];
      bool any_supported = false;

      if (auto username = json_string_field(value_node, "userName")) {
        std::string normalized = trim_copy(*username);
        if (normalized.empty()) {
          error_message = "userName cannot be empty";
          return false;
        }
        if (normalized.size() > 128) normalized.resize(128);
        mutation.username = normalized;
        any_supported = true;
      }
      if (auto active = json_bool_field(value_node, "active")) {
        mutation.active = *active;
        any_supported = true;
      }
      try {
        if (value_node.has("role") || value_node.has("roles")) {
          mutation.role = scim_role_from_payload(value_node, "operator");
          any_supported = true;
        }
      } catch (...) {
      }
      if (!any_supported) {
        error_message = "SCIM operation does not include supported fields";
        return false;
      }
      continue;
    }

    const bool is_user_name_path =
        path == "username" || path == "user_name" || path == "user.name";
    const bool is_active_path = path == "active";
    const bool is_role_path = path == "role" || path.rfind("roles", 0) == 0;

    if (!is_user_name_path && !is_active_path && !is_role_path) {
      error_message = "Unsupported SCIM path: " + path;
      return false;
    }

    if (is_user_name_path) {
      if (op == "remove") {
        error_message = "Removing userName is not supported";
        return false;
      }
      if (!operation.has("value")) {
        error_message = "userName patch requires value";
        return false;
      }
      auto username = json_string_scalar(operation["value"]);
      if (!username) {
        try {
          if (operation["value"].has("userName")) {
            username = json_string_field(operation["value"], "userName");
          }
        } catch (...) {
        }
      }
      if (!username || trim_copy(*username).empty()) {
        error_message = "userName patch value must be a non-empty string";
        return false;
      }
      std::string normalized = trim_copy(*username);
      if (normalized.size() > 128) normalized.resize(128);
      mutation.username = normalized;
      continue;
    }

    if (is_active_path) {
      if (op == "remove") {
        mutation.active = false;
        continue;
      }
      if (!operation.has("value")) {
        error_message = "active patch requires value";
        return false;
      }
      auto active = json_bool_scalar(operation["value"]);
      if (!active) {
        try {
          if (operation["value"].has("active")) {
            active = json_bool_field(operation["value"], "active");
          }
        } catch (...) {
        }
      }
      if (!active) {
        error_message = "active patch value must be a boolean";
        return false;
      }
      mutation.active = *active;
      continue;
    }

    if (is_role_path) {
      if (op == "remove") {
        mutation.role = "operator";
        continue;
      }
      if (!operation.has("value")) {
        error_message = "role patch requires value";
        return false;
      }
      auto role = scim_role_from_patch_value(operation["value"]);
      if (!role) {
        error_message = "role patch value must resolve to operator/admin/auditor";
        return false;
      }
      mutation.role = *role;
      continue;
    }
  }

  return true;
}

bool scim_update_user_record(AppContext &ctx, int user_id,
                             const std::optional<std::string> &requested_username,
                             const std::optional<std::string> &requested_role,
                             UserAccount &updated_user,
                             int &status_code,
                             std::string &error_message) {
  status_code = 500;
  {
    std::lock_guard<std::mutex> lock(ctx.user_mutex);
    auto it = ctx.users.find(user_id);
    if (it == ctx.users.end()) {
      status_code = 404;
      error_message = "User not found";
      return false;
    }

    updated_user = it->second;
    if (requested_username) {
      std::string next_name = trim_copy(*requested_username);
      if (next_name.empty()) {
        status_code = 400;
        error_message = "userName cannot be empty";
        return false;
      }
      if (next_name.size() > 128) next_name.resize(128);
      const std::string lowered_new = to_lower(next_name);
      for (const auto &entry : ctx.users) {
        if (entry.first == user_id) continue;
        if (to_lower(entry.second.username) == lowered_new) {
          status_code = 409;
          error_message = "userName already exists";
          return false;
        }
      }
      updated_user.username = next_name;
    }

    if (requested_role) {
      const std::string normalized_role = normalize_user_role(*requested_role);
      if (!is_allowed_user_role(normalized_role,
                                {"operator", "admin", "auditor"})) {
        status_code = 400;
        error_message = "Invalid role";
        return false;
      }
      updated_user.role = normalized_role;
    }

    updated_user.updatedAt = now_utc();
    it->second = updated_user;
  }

  if (!ctx.update_user_db(updated_user)) {
    status_code = 500;
    error_message = "Failed to persist SCIM user update";
    return false;
  }
  status_code = 200;
  return true;
}

bool scim_deprovision_user_record(AppContext &ctx, int user_id,
                                  UserAccount &removed_user,
                                  int &status_code,
                                  std::string &error_message) {
  status_code = 500;
  {
    std::lock_guard<std::mutex> lock(ctx.user_mutex);
    auto it = ctx.users.find(user_id);
    if (it == ctx.users.end()) {
      status_code = 404;
      error_message = "User not found";
      return false;
    }
    removed_user = it->second;
    ctx.users.erase(it);
  }

  ctx.invalidate_user_tokens(user_id);
  if (!ctx.delete_user_db(user_id)) {
    status_code = 500;
    error_message = "Failed to deprovision user";
    return false;
  }

  status_code = 204;
  return true;
}

std::string scim_user_resource_location(int user_id) {
  return "/api/scim/v2/Users/" + std::to_string(user_id);
}

std::string scim_user_resource_version(const UserAccount &user) {
  const std::string fingerprint = user.updatedAt + "|" + user.username +
                                  "|" + normalize_user_role(user.role);
  const auto digest = static_cast<uint64_t>(
      std::hash<std::string>{}(fingerprint));
  return "W/\"" + std::to_string(user.id) + "-" +
         std::to_string(digest) + "\"";
}

crow::json::wvalue scim_user_resource_json(const UserAccount &user) {
  crow::json::wvalue payload;
  payload["schemas"] = crow::json::wvalue::list();
  payload["schemas"][0] = "urn:ietf:params:scim:schemas:core:2.0:User";
  payload["id"] = std::to_string(user.id);
  payload["userName"] = user.username;
  payload["displayName"] = user.username;
  payload["active"] = true;
  payload["roles"] = crow::json::wvalue::list();
  payload["roles"][0]["value"] = normalize_user_role(user.role);
  payload["roles"][0]["display"] = user.role;
  payload["meta"]["resourceType"] = "User";
  payload["meta"]["created"] = user.createdAt;
  payload["meta"]["lastModified"] = user.updatedAt;
  payload["meta"]["location"] = scim_user_resource_location(user.id);
  payload["meta"]["version"] = scim_user_resource_version(user);
  return payload;
}

void add_scim_security_headers(crow::response &response) {
  response.add_header("X-Content-Type-Options", "nosniff");
  response.add_header("X-Frame-Options", "SAMEORIGIN");
  response.add_header("X-XSS-Protection", "0");
  response.add_header("Referrer-Policy", "strict-origin-when-cross-origin");
  response.add_header("Cache-Control",
                      "no-store, no-cache, must-revalidate, private");
  response.add_header("Pragma", "no-cache");
  response.add_header("Cross-Origin-Opener-Policy", "same-origin");
  response.add_header("Cross-Origin-Resource-Policy", "same-origin");
  response.add_header("X-Permitted-Cross-Domain-Policies", "none");
  response.add_header("Content-Security-Policy",
                      "default-src 'self'; "
                      "base-uri 'self'; "
                      "object-src 'none'; "
                      "frame-ancestors 'self'; "
                      "script-src 'self' 'unsafe-inline'; "
                      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                      "font-src 'self' https://fonts.gstatic.com; "
                      "img-src 'self' data: https:; "
                      "connect-src 'self' ws: wss:; "
                      "frame-src 'self'; "
                      "form-action 'self'; "
                      "worker-src 'self' blob:");
  response.add_header(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
}

crow::response scim_user_resource_response(const UserAccount &user,
                                          int status_code = 200) {
  auto payload = scim_user_resource_json(user);
  crow::response response;
  response.code = status_code;
  response.body = payload.dump();
  response.add_header("Content-Type", "application/json");
  add_scim_security_headers(response);
  response.add_header("ETag", scim_user_resource_version(user));
  return response;
}

crow::response scim_json_response(crow::json::wvalue payload,
                                  int status_code = 200) {
  crow::response response;
  response.code = status_code;
  response.body = payload.dump();
  response.add_header("Content-Type", "application/json");
  add_scim_security_headers(response);
  return response;
}

crow::response scim_error_response(int status_code, const std::string &detail,
                                   const std::string &scim_type = "") {
  crow::json::wvalue payload;
  payload["schemas"] = crow::json::wvalue::list();
  payload["schemas"][0] = "urn:ietf:params:scim:api:messages:2.0:Error";
  payload["status"] = std::to_string(status_code);
  payload["detail"] = detail;
  if (!scim_type.empty()) payload["scimType"] = scim_type;

  return scim_json_response(payload, status_code);
}

std::string scim_error_type_for_status_code(int status_code) {
  switch (status_code) {
    case 400:
      return "invalidValue";
    case 404:
      return "noTarget";
    case 409:
      return "uniqueness";
    default:
      return "";
  }
}

std::string scim_error_type_for_detail(int status_code,
                                       const std::string &detail) {
  if (status_code == 400) {
    const std::string lowered = to_lower(detail);
    if (lowered.find("unsupported scim path") != std::string::npos) {
      return "invalidPath";
    }
    if (lowered.find("invalid json") != std::string::npos) {
      return "invalidSyntax";
    }
    if (lowered.find("filter") != std::string::npos) {
      return "invalidFilter";
    }
    return "invalidValue";
  }
  return scim_error_type_for_status_code(status_code);
}

std::optional<int> resolve_scim_user_id(AppContext &ctx,
                                        const std::string &identifier) {
  const std::string wanted = trim_copy(identifier);
  if (wanted.empty()) return std::nullopt;

  const bool numeric =
      std::all_of(wanted.begin(), wanted.end(),
                  [](unsigned char c) { return std::isdigit(c) != 0; });

  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  if (numeric) {
    try {
      const int user_id = std::stoi(wanted);
      if (ctx.users.find(user_id) != ctx.users.end()) return user_id;
    } catch (...) {
      return std::nullopt;
    }
    return std::nullopt;
  }

  const std::string lowered_wanted = to_lower(wanted);
  for (const auto &entry : ctx.users) {
    if (to_lower(entry.second.username) == lowered_wanted) {
      return entry.first;
    }
  }
  return std::nullopt;
}

std::optional<OidcProviderConfig> load_oidc_provider_config(
    const std::string &requested_provider, const crow::request &request,
    std::string &error_message) {
  OidcProviderConfig config;
  config.provider = to_lower(trim_copy(requested_provider));
  if (config.provider.empty()) {
    config.provider =
        to_lower(trim_copy(env_string_value("ENDORIUMFORT_SSO_DEFAULT_PROVIDER",
                                            "keycloak")));
  }
  if (config.provider.empty()) config.provider = "keycloak";

  const auto *provider_descriptor = find_sso_provider_descriptor(config.provider);
  if (!provider_descriptor ||
      to_lower(provider_descriptor->protocol) != "oidc") {
    error_message = "Unsupported OIDC provider";
    return std::nullopt;
  }

  if (!env_flag_enabled("ENDORIUMFORT_SSO_OIDC_ENABLED", true)) {
    error_message = "OIDC SSO is disabled";
    return std::nullopt;
  }
  if (!env_flag_enabled(provider_descriptor->enabledEnv, true)) {
    error_message = "Requested OIDC provider is disabled";
    return std::nullopt;
  }

  config.clientId = oidc_provider_env_value(config.provider, "CLIENT_ID", "");
  config.clientSecret =
      oidc_provider_env_value(config.provider, "CLIENT_SECRET", "");
  config.authorizationEndpoint =
      oidc_provider_env_value(config.provider, "AUTHORIZATION_ENDPOINT", "");
  config.tokenEndpoint =
      oidc_provider_env_value(config.provider, "TOKEN_ENDPOINT", "");
  config.userinfoEndpoint =
      oidc_provider_env_value(config.provider, "USERINFO_ENDPOINT", "");
  config.scope =
      oidc_provider_env_value(config.provider, "SCOPE", "openid profile email");
  config.redirectUri =
      oidc_provider_env_value(config.provider, "REDIRECT_URI", "");
  config.roleClaim =
      oidc_provider_env_value(config.provider, "ROLE_CLAIM", "role");
  config.defaultRole = normalize_user_role(
      oidc_provider_env_value(config.provider, "DEFAULT_ROLE", "operator"));
  if (!is_allowed_user_role(config.defaultRole,
                            {"operator", "admin", "auditor"})) {
    config.defaultRole = "operator";
  }
  config.syncRole = oidc_provider_env_flag(config.provider, "SYNC_ROLE", true);

  if (config.clientId.empty()) {
    error_message = "Missing OIDC client identifier configuration";
    return std::nullopt;
  }
  if (config.authorizationEndpoint.empty()) {
    error_message = "Missing OIDC authorization endpoint configuration";
    return std::nullopt;
  }
  if (config.tokenEndpoint.empty()) {
    error_message = "Missing OIDC token endpoint configuration";
    return std::nullopt;
  }

  if (config.redirectUri.empty()) {
    config.redirectUri = request_base_url(request) + "/api/auth/sso/oidc/callback";
  } else if (!config.redirectUri.empty() && config.redirectUri[0] == '/') {
    config.redirectUri = request_base_url(request) + config.redirectUri;
  }

  return config;
}

std::optional<OidcProvisionResult> provision_oidc_user(
    AppContext &ctx, const std::string &username, const std::string &resolved_role,
    bool sync_role, std::string &error_message) {
  const std::string canonical_username = trim_copy(username);
  if (canonical_username.empty()) {
    error_message = "OIDC identity is empty";
    return std::nullopt;
  }

  const std::string final_role =
      is_allowed_user_role(resolved_role, {"operator", "admin", "auditor"})
          ? normalize_user_role(resolved_role)
          : "operator";

  OidcProvisionResult result;
  const std::string wanted = to_lower(canonical_username);
  bool update_db = false;
  {
    std::lock_guard<std::mutex> lock(ctx.user_mutex);
    for (auto &entry : ctx.users) {
      if (to_lower(entry.second.username) != wanted) continue;
      result.user = entry.second;
      if (sync_role && normalize_user_role(result.user.role) != final_role) {
        result.user.role = final_role;
        result.user.updatedAt = now_utc();
        entry.second = result.user;
        result.updated = true;
        update_db = true;
      }
      return result;
    }

    result.created = true;
    result.user.id = ctx.next_user_id.fetch_add(1);
    result.user.username = canonical_username;
    result.user.password = crypto::hash_password(ctx.generate_token());
    result.user.role = final_role;
    result.user.createdAt = now_utc();
    result.user.updatedAt = result.user.createdAt;
    result.user.bootstrapPasswordChangeRequired = false;
    result.user.bootstrapMfaRequired = false;
    ctx.users[result.user.id] = result.user;
  }

  if (result.created) {
    if (!ctx.insert_user(result.user)) {
      error_message = "Failed to persist provisioned SSO user";
      return std::nullopt;
    }
    return result;
  }
  if (update_db && !ctx.update_user_db(result.user)) {
    error_message = "Failed to update SSO user role mapping";
    return std::nullopt;
  }
  return result;
}

void append_sso_failure_audit(AppContext &ctx, const std::string &provider,
                              const std::string &reason,
                              const std::string &detail) {
  AuditEvent event;
  event.id = ctx.next_audit_id.fetch_add(1);
  event.type = "auth.login.sso.failure";
  event.actor = "anonymous";
  event.role = "anonymous";
  event.createdAt = now_utc();
  std::ostringstream payload;
  payload << "{\"provider\":\"" << json_escape(provider)
          << "\",\"reason\":\"" << json_escape(reason) << "\"";
  if (!detail.empty()) {
    payload << ",\"detail\":\"" << json_escape(detail) << "\"";
  }
  payload << '}';
  event.payloadJson = payload.str();
  event.payloadIsJson = true;
  ctx.append_audit(event);
}

bool has_permission(AppContext &ctx, const AuthSession &auth,
                    const std::string &permission) {
  return ctx.has_permission(auth.userId, auth.role, permission);
}

bool has_any_permission(AppContext &ctx, const AuthSession &auth,
                        const std::vector<std::string> &permissions) {
  for (const auto &permission : permissions) {
    if (has_permission(ctx, auth, permission)) return true;
  }
  return false;
}

bool can_access_any_resource(AppContext &ctx, const AuthSession &auth) {
  if (has_permission(ctx, auth, "resources.manage")) return true;
  if (has_permission(ctx, auth, "resources.read")) return true;
  return false;
}

crow::json::wvalue build_webauthn_assertion_options(
    const WebAuthnChallenge &challenge,
    const std::vector<WebAuthnCredential> &credentials) {
  crow::json::wvalue payload;
  payload["requestId"] = challenge.requestId;
  payload["challenge"] = webauthn::base64url_encode(challenge.challenge);
  payload["rpId"] = challenge.rpId;
  payload["timeout"] = challenge.expiresAtEpoch > now_epoch_seconds()
                           ? static_cast<int>((challenge.expiresAtEpoch -
                                               now_epoch_seconds()) *
                                              1000)
                           : 0;
  payload["userVerification"] = "preferred";
  payload["allowCredentials"] = crow::json::wvalue::list();
  int index = 0;
  for (const auto &credential : credentials) {
    crow::json::wvalue item;
    item["type"] = "public-key";
    item["id"] = credential.credentialId;
    payload["allowCredentials"][index++] = std::move(item);
  }
  return payload;
}

std::string build_webauthn_audit_payload(const WebAuthnCredential &credential) {
  std::ostringstream oss;
  oss << "{\"userId\":" << credential.userId
      << ",\"credentialRecordId\":" << credential.id
      << ",\"label\":\"" << json_escape(credential.label) << "\"";
  if (!credential.transportsCsv.empty()) {
    oss << ",\"transports\":\"" << json_escape(credential.transportsCsv) << "\"";
  }
  oss << '}';
  return oss.str();
}

struct SecurityAlertTemplate {
  std::string severity;
  std::string title;
  std::string hint;
};

std::optional<SecurityAlertTemplate> classify_security_alert_type(
    const std::string &event_type_raw) {
  const std::string event_type = to_lower(event_type_raw);
  if (event_type.find("security.incident.opened") != std::string::npos) {
    return SecurityAlertTemplate{"warning", "Incident Case Opened",
                                 "An active incident case has been declared for coordination."};
  }
  if (event_type.find("security.incident.closed") != std::string::npos) {
    return SecurityAlertTemplate{"ok", "Incident Case Closed",
                                 "Incident coordination case has been closed."};
  }
  if (event_type.find("security.containment.enabled") != std::string::npos) {
    return SecurityAlertTemplate{"warning", "Containment Mode Enabled",
                                 "Session opens now require explicit justification."};
  }
  if (event_type.find("auth.login.failure") != std::string::npos ||
      event_type.find("auth.login.rate_limited") != std::string::npos ||
      event_type.find("auth.rate_limit") != std::string::npos) {
    return SecurityAlertTemplate{"critical", "Authentication Anomaly",
                                 "Repeated login failures or throttling detected."};
  }
  if (event_type.find("behavior.anomaly.auth_failure_burst") !=
      std::string::npos) {
    return SecurityAlertTemplate{"critical", "Brute-Force Burst Detected",
                                 "Correlated authentication failures exceed the baseline."};
  }
  if (event_type.find("behavior.anomaly.stale_session") !=
      std::string::npos) {
    return SecurityAlertTemplate{"warning", "Stale Active Session",
                                 "An active session exceeded its expected duration."};
  }
  if (event_type.find("behavior.anomaly") != std::string::npos) {
    return SecurityAlertTemplate{"warning", "Behavioral Anomaly",
                                 "Unusual activity pattern detected in session telemetry."};
  }
  if (event_type.find("session.create.unjustified") != std::string::npos) {
    return SecurityAlertTemplate{"warning", "Unjustified Session Opened",
                                 "Session opened without explicit justification."};
  }
  if (event_type.find("session.dna") != std::string::npos &&
      event_type.find("mismatch") != std::string::npos) {
    return SecurityAlertTemplate{"critical", "Session DNA Integrity Mismatch",
                                 "Audit chain verification issue detected."};
  }
  return std::nullopt;
}

std::optional<int> extract_session_id_from_audit_event(const AuditEvent &event) {
  if (!event.payloadIsJson || event.payloadJson.empty()) return std::nullopt;
  auto payload = crow::json::load(event.payloadJson);
  if (!payload) return std::nullopt;
  if (!payload.has("sessionId")) return std::nullopt;
  int session_id = payload["sessionId"].i();
  if (session_id <= 0) return std::nullopt;
  return session_id;
}

bool is_valid_approval_mode(const std::string &value) {
  return is_allowed_role(to_lower(value), {"inherit", "none", "required"});
}

bool is_valid_mfa_requirement(const std::string &value) {
  return is_allowed_role(to_lower(value), {"any", "required", "totp", "webauthn"});
}

bool is_valid_routing_constraint(const std::string &value) {
  return is_allowed_role(to_lower(value), {"any", "direct", "relay"});
}

bool is_valid_credential_source(const std::string &value) {
  return is_allowed_role(
      to_lower(value), {"vaulted", "brokered", "ephemeral_account"});
}

bool is_valid_time_window_format(const std::string &value) {
  const std::string normalized = to_lower(trim_copy(value));
  if (normalized.empty() || normalized == "any") return true;
  if (normalized.size() != 11 || normalized[5] != '-') return false;
  auto parse_segment = [](const std::string &segment) -> bool {
    if (segment.size() != 5 || segment[2] != ':') return false;
    if (!std::isdigit(static_cast<unsigned char>(segment[0])) ||
        !std::isdigit(static_cast<unsigned char>(segment[1])) ||
        !std::isdigit(static_cast<unsigned char>(segment[3])) ||
        !std::isdigit(static_cast<unsigned char>(segment[4]))) {
      return false;
    }
    const int hours = std::stoi(segment.substr(0, 2));
    const int minutes = std::stoi(segment.substr(3, 2));
    return hours >= 0 && hours <= 23 && minutes >= 0 && minutes <= 59;
  };
  return parse_segment(normalized.substr(0, 5)) &&
         parse_segment(normalized.substr(6));
}

int next_table_numeric_id(AppContext &ctx, const char *table_name) {
  if (!ctx.sqlite.db || !table_name || !*table_name) return 1;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const std::string sql =
      std::string("SELECT COALESCE(MAX(id), 0) + 1 FROM ") + table_name;
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql.c_str(), -1, &stmt, nullptr) !=
      SQLITE_OK) {
    return 1;
  }
  int next_id = 1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    next_id = std::max(1, sqlite3_column_int(stmt, 0));
  }
  sqlite3_finalize(stmt);
  return next_id;
}

std::optional<UserAccount> find_user_account_snapshot(AppContext &ctx, int user_id) {
  std::lock_guard<std::mutex> lock(ctx.user_mutex);
  auto it = ctx.users.find(user_id);
  if (it == ctx.users.end()) return std::nullopt;
  return it->second;
}

bool user_meets_mfa_requirement(const UserAccount &user,
                                const std::string &requirement) {
  const std::string normalized = to_lower(trim_copy(requirement));
  if (normalized.empty() || normalized == "any") return true;
  if (normalized == "required") {
    return user.totpEnabled || user.webauthnCredentialCount > 0;
  }
  if (normalized == "totp") return user.totpEnabled;
  if (normalized == "webauthn") return user.webauthnCredentialCount > 0;
  return true;
}

std::vector<AccessPolicy> query_access_policies(AppContext &ctx) {
  std::vector<AccessPolicy> items;
  if (!ctx.sqlite.db) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT id, name, description, identity_pattern, group_name, role, "
      "resource_tags_csv, risk_level, ticket_required, "
      "require_justification, approval_mode, mfa_requirement, time_window, "
      "max_duration_seconds, routing_constraint, enabled, created_at, "
      "updated_at FROM access_policies ORDER BY id ASC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return items;
  }
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    AccessPolicy policy;
    policy.id = sqlite3_column_int(stmt, 0);
    if (auto value = sqlite3_column_text(stmt, 1))
      policy.name = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 2))
      policy.description = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 3))
      policy.identityPattern = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 4))
      policy.groupName = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 5))
      policy.role = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 6))
      policy.resourceTagsCsv = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 7))
      policy.riskLevel = reinterpret_cast<const char *>(value);
    policy.ticketRequired = sqlite3_column_int(stmt, 8) != 0;
    policy.requireJustification = sqlite3_column_int(stmt, 9) != 0;
    if (auto value = sqlite3_column_text(stmt, 10))
      policy.approvalMode = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 11))
      policy.mfaRequirement = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 12))
      policy.timeWindow = reinterpret_cast<const char *>(value);
    policy.maxDurationSeconds = sqlite3_column_int(stmt, 13);
    if (auto value = sqlite3_column_text(stmt, 14))
      policy.routingConstraint = reinterpret_cast<const char *>(value);
    policy.enabled = sqlite3_column_int(stmt, 15) != 0;
    if (auto value = sqlite3_column_text(stmt, 16))
      policy.createdAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 17))
      policy.updatedAt = reinterpret_cast<const char *>(value);
    items.push_back(policy);
  }
  sqlite3_finalize(stmt);
  return items;
}

std::optional<AccessPolicy> query_access_policy_by_id(AppContext &ctx, int policy_id) {
  if (policy_id <= 0) return std::nullopt;
  for (const auto &policy : query_access_policies(ctx)) {
    if (policy.id == policy_id) return policy;
  }
  return std::nullopt;
}

bool insert_access_policy_db(AppContext &ctx, const AccessPolicy &policy) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "INSERT INTO access_policies "
      "(id, name, description, identity_pattern, group_name, role, "
      "resource_tags_csv, risk_level, ticket_required, "
      "require_justification, approval_mode, mfa_requirement, time_window, "
      "max_duration_seconds, routing_constraint, enabled, created_at, "
      "updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, policy.id);
  sqlite3_bind_text(stmt, 2, policy.name.c_str(), -1, SQLITE_TRANSIENT);
  policy.description.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, policy.description.c_str(), -1,
                          SQLITE_TRANSIENT);
  policy.identityPattern.empty()
      ? sqlite3_bind_null(stmt, 4)
      : sqlite3_bind_text(stmt, 4, policy.identityPattern.c_str(), -1,
                          SQLITE_TRANSIENT);
  policy.groupName.empty()
      ? sqlite3_bind_null(stmt, 5)
      : sqlite3_bind_text(stmt, 5, policy.groupName.c_str(), -1,
                          SQLITE_TRANSIENT);
  policy.role.empty()
      ? sqlite3_bind_null(stmt, 6)
      : sqlite3_bind_text(stmt, 6, policy.role.c_str(), -1, SQLITE_TRANSIENT);
  policy.resourceTagsCsv.empty()
      ? sqlite3_bind_null(stmt, 7)
      : sqlite3_bind_text(stmt, 7, policy.resourceTagsCsv.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, policy.riskLevel.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 9, policy.ticketRequired ? 1 : 0);
  sqlite3_bind_int(stmt, 10, policy.requireJustification ? 1 : 0);
  sqlite3_bind_text(stmt, 11, policy.approvalMode.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 12, policy.mfaRequirement.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 13, policy.timeWindow.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 14, policy.maxDurationSeconds);
  sqlite3_bind_text(stmt, 15, policy.routingConstraint.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 16, policy.enabled ? 1 : 0);
  sqlite3_bind_text(stmt, 17, policy.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 18, policy.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool update_access_policy_db(AppContext &ctx, const AccessPolicy &policy) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "UPDATE access_policies SET name=?, description=?, identity_pattern=?, "
      "group_name=?, role=?, resource_tags_csv=?, risk_level=?, "
      "ticket_required=?, require_justification=?, approval_mode=?, "
      "mfa_requirement=?, time_window=?, max_duration_seconds=?, "
      "routing_constraint=?, enabled=?, updated_at=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_text(stmt, 1, policy.name.c_str(), -1, SQLITE_TRANSIENT);
  policy.description.empty()
      ? sqlite3_bind_null(stmt, 2)
      : sqlite3_bind_text(stmt, 2, policy.description.c_str(), -1,
                          SQLITE_TRANSIENT);
  policy.identityPattern.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, policy.identityPattern.c_str(), -1,
                          SQLITE_TRANSIENT);
  policy.groupName.empty()
      ? sqlite3_bind_null(stmt, 4)
      : sqlite3_bind_text(stmt, 4, policy.groupName.c_str(), -1,
                          SQLITE_TRANSIENT);
  policy.role.empty()
      ? sqlite3_bind_null(stmt, 5)
      : sqlite3_bind_text(stmt, 5, policy.role.c_str(), -1, SQLITE_TRANSIENT);
  policy.resourceTagsCsv.empty()
      ? sqlite3_bind_null(stmt, 6)
      : sqlite3_bind_text(stmt, 6, policy.resourceTagsCsv.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 7, policy.riskLevel.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 8, policy.ticketRequired ? 1 : 0);
  sqlite3_bind_int(stmt, 9, policy.requireJustification ? 1 : 0);
  sqlite3_bind_text(stmt, 10, policy.approvalMode.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 11, policy.mfaRequirement.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 12, policy.timeWindow.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 13, policy.maxDurationSeconds);
  sqlite3_bind_text(stmt, 14, policy.routingConstraint.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 15, policy.enabled ? 1 : 0);
  sqlite3_bind_text(stmt, 16, policy.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 17, policy.id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool delete_access_policy_db(AppContext &ctx, int policy_id) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql = "DELETE FROM access_policies WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, policy_id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<AccessProfile> query_access_profiles(AppContext &ctx) {
  std::vector<AccessProfile> items;
  if (!ctx.sqlite.db) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT id, name, description, resource_tags_csv, resource_ids_csv, "
      "policy_id, created_at, updated_at FROM access_profiles ORDER BY id ASC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return items;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    AccessProfile profile;
    profile.id = sqlite3_column_int(stmt, 0);
    if (auto value = sqlite3_column_text(stmt, 1))
      profile.name = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 2))
      profile.description = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 3))
      profile.resourceTagsCsv = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 4))
      profile.resourceIdsCsv = reinterpret_cast<const char *>(value);
    profile.policyId = sqlite3_column_int(stmt, 5);
    if (auto value = sqlite3_column_text(stmt, 6))
      profile.createdAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 7))
      profile.updatedAt = reinterpret_cast<const char *>(value);
    items.push_back(profile);
  }
  sqlite3_finalize(stmt);
  return items;
}

std::vector<AccessProfile> query_user_access_profiles(AppContext &ctx, int user_id) {
  std::vector<AccessProfile> items;
  if (!ctx.sqlite.db || user_id <= 0) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT p.id, p.name, p.description, p.resource_tags_csv, "
      "p.resource_ids_csv, p.policy_id, p.created_at, p.updated_at "
      "FROM access_profiles p "
      "INNER JOIN user_access_profiles up ON up.profile_id = p.id "
      "WHERE up.user_id = ? ORDER BY p.id ASC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return items;
  sqlite3_bind_int(stmt, 1, user_id);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    AccessProfile profile;
    profile.id = sqlite3_column_int(stmt, 0);
    if (auto value = sqlite3_column_text(stmt, 1))
      profile.name = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 2))
      profile.description = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 3))
      profile.resourceTagsCsv = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 4))
      profile.resourceIdsCsv = reinterpret_cast<const char *>(value);
    profile.policyId = sqlite3_column_int(stmt, 5);
    if (auto value = sqlite3_column_text(stmt, 6))
      profile.createdAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 7))
      profile.updatedAt = reinterpret_cast<const char *>(value);
    items.push_back(profile);
  }
  sqlite3_finalize(stmt);
  return items;
}

std::vector<int> query_user_access_profile_ids(AppContext &ctx, int user_id) {
  std::vector<int> ids;
  if (!ctx.sqlite.db || user_id <= 0) return ids;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT profile_id FROM user_access_profiles WHERE user_id=? ORDER BY profile_id ASC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return ids;
  sqlite3_bind_int(stmt, 1, user_id);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ids.push_back(sqlite3_column_int(stmt, 0));
  }
  sqlite3_finalize(stmt);
  return ids;
}

bool insert_access_profile_db(AppContext &ctx, const AccessProfile &profile) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "INSERT INTO access_profiles "
      "(id, name, description, resource_tags_csv, resource_ids_csv, policy_id, "
      "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, profile.id);
  sqlite3_bind_text(stmt, 2, profile.name.c_str(), -1, SQLITE_TRANSIENT);
  profile.description.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, profile.description.c_str(), -1,
                          SQLITE_TRANSIENT);
  profile.resourceTagsCsv.empty()
      ? sqlite3_bind_null(stmt, 4)
      : sqlite3_bind_text(stmt, 4, profile.resourceTagsCsv.c_str(), -1,
                          SQLITE_TRANSIENT);
  profile.resourceIdsCsv.empty()
      ? sqlite3_bind_null(stmt, 5)
      : sqlite3_bind_text(stmt, 5, profile.resourceIdsCsv.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 6, profile.policyId);
  sqlite3_bind_text(stmt, 7, profile.createdAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, profile.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool update_access_profile_db(AppContext &ctx, const AccessProfile &profile) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "UPDATE access_profiles SET name=?, description=?, resource_tags_csv=?, "
      "resource_ids_csv=?, policy_id=?, updated_at=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_text(stmt, 1, profile.name.c_str(), -1, SQLITE_TRANSIENT);
  profile.description.empty()
      ? sqlite3_bind_null(stmt, 2)
      : sqlite3_bind_text(stmt, 2, profile.description.c_str(), -1,
                          SQLITE_TRANSIENT);
  profile.resourceTagsCsv.empty()
      ? sqlite3_bind_null(stmt, 3)
      : sqlite3_bind_text(stmt, 3, profile.resourceTagsCsv.c_str(), -1,
                          SQLITE_TRANSIENT);
  profile.resourceIdsCsv.empty()
      ? sqlite3_bind_null(stmt, 4)
      : sqlite3_bind_text(stmt, 4, profile.resourceIdsCsv.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 5, profile.policyId);
  sqlite3_bind_text(stmt, 6, profile.updatedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 7, profile.id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool delete_access_profile_db(AppContext &ctx, int profile_id) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(
          ctx.sqlite.db, "DELETE FROM user_access_profiles WHERE profile_id=?",
          -1, &stmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_int(stmt, 1, profile_id);
    sqlite3_step(stmt);
  }
  sqlite3_finalize(stmt);
  if (sqlite3_prepare_v2(ctx.sqlite.db, "DELETE FROM access_profiles WHERE id=?",
                         -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }
  sqlite3_bind_int(stmt, 1, profile_id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool assign_access_profile_to_user(AppContext &ctx, int user_id, int profile_id) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "INSERT OR IGNORE INTO user_access_profiles (user_id, profile_id, created_at) "
      "VALUES (?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_int(stmt, 2, profile_id);
  const std::string created_at = now_utc();
  sqlite3_bind_text(stmt, 3, created_at.c_str(), -1, SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool revoke_access_profile_from_user(AppContext &ctx, int user_id, int profile_id) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "DELETE FROM user_access_profiles WHERE user_id=? AND profile_id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, user_id);
  sqlite3_bind_int(stmt, 2, profile_id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<AccessGrant> query_access_grants(AppContext &ctx) {
  std::vector<AccessGrant> items;
  if (!ctx.sqlite.db) return items;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "SELECT id, policy_id, profile_id, resource_id, session_id, approval_ref, "
      "subject, resource_scope, granted_at, expires_at, used_at, mission_ref, "
      "elevation_scope, status, credential_source, routing_constraint, "
      "ticket_id, purpose, justification, mfa_requirement "
      "FROM access_grants ORDER BY id DESC";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return items;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    AccessGrant grant;
    grant.id = sqlite3_column_int(stmt, 0);
    grant.policyId = sqlite3_column_int(stmt, 1);
    grant.profileId = sqlite3_column_int(stmt, 2);
    grant.resourceId = sqlite3_column_int(stmt, 3);
    grant.sessionId = sqlite3_column_int(stmt, 4);
    grant.approvalRef = sqlite3_column_int(stmt, 5);
    if (auto value = sqlite3_column_text(stmt, 6))
      grant.subject = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 7))
      grant.resourceScope = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 8))
      grant.grantedAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 9))
      grant.expiresAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 10))
      grant.usedAt = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 11))
      grant.missionRef = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 12))
      grant.elevationScope = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 13))
      grant.status = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 14))
      grant.credentialSource = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 15))
      grant.routingConstraint = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 16))
      grant.ticketId = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 17))
      grant.purpose = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 18))
      grant.justification = reinterpret_cast<const char *>(value);
    if (auto value = sqlite3_column_text(stmt, 19))
      grant.mfaRequirement = reinterpret_cast<const char *>(value);
    items.push_back(grant);
  }
  sqlite3_finalize(stmt);
  return items;
}

std::optional<AccessGrant> query_access_grant_by_id(AppContext &ctx, int grant_id) {
  if (grant_id <= 0) return std::nullopt;
  for (const auto &grant : query_access_grants(ctx)) {
    if (grant.id == grant_id) return grant;
  }
  return std::nullopt;
}

bool insert_access_grant_db(AppContext &ctx, const AccessGrant &grant) {
  if (!ctx.sqlite.db) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql =
      "INSERT INTO access_grants "
      "(id, policy_id, profile_id, resource_id, session_id, approval_ref, "
      "subject, resource_scope, granted_at, expires_at, used_at, mission_ref, "
      "elevation_scope, status, credential_source, routing_constraint, "
      "ticket_id, purpose, justification, mfa_requirement) "
      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, grant.id);
  sqlite3_bind_int(stmt, 2, grant.policyId);
  sqlite3_bind_int(stmt, 3, grant.profileId);
  sqlite3_bind_int(stmt, 4, grant.resourceId);
  sqlite3_bind_int(stmt, 5, grant.sessionId);
  sqlite3_bind_int(stmt, 6, grant.approvalRef);
  sqlite3_bind_text(stmt, 7, grant.subject.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, grant.resourceScope.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, grant.grantedAt.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 10, grant.expiresAt.c_str(), -1, SQLITE_TRANSIENT);
  grant.usedAt.empty()
      ? sqlite3_bind_null(stmt, 11)
      : sqlite3_bind_text(stmt, 11, grant.usedAt.c_str(), -1, SQLITE_TRANSIENT);
  grant.missionRef.empty()
      ? sqlite3_bind_null(stmt, 12)
      : sqlite3_bind_text(stmt, 12, grant.missionRef.c_str(), -1, SQLITE_TRANSIENT);
  grant.elevationScope.empty()
      ? sqlite3_bind_null(stmt, 13)
      : sqlite3_bind_text(stmt, 13, grant.elevationScope.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 14, grant.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 15, grant.credentialSource.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 16, grant.routingConstraint.c_str(), -1, SQLITE_TRANSIENT);
  grant.ticketId.empty()
      ? sqlite3_bind_null(stmt, 17)
      : sqlite3_bind_text(stmt, 17, grant.ticketId.c_str(), -1, SQLITE_TRANSIENT);
  grant.purpose.empty()
      ? sqlite3_bind_null(stmt, 18)
      : sqlite3_bind_text(stmt, 18, grant.purpose.c_str(), -1, SQLITE_TRANSIENT);
  grant.justification.empty()
      ? sqlite3_bind_null(stmt, 19)
      : sqlite3_bind_text(stmt, 19, grant.justification.c_str(), -1,
                          SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 20, grant.mfaRequirement.c_str(), -1, SQLITE_TRANSIENT);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool update_access_grant_session_binding(AppContext &ctx, int grant_id, int session_id) {
  if (!ctx.sqlite.db || grant_id <= 0) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql = "UPDATE access_grants SET session_id=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  sqlite3_bind_int(stmt, 1, session_id);
  sqlite3_bind_int(stmt, 2, grant_id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool update_access_grant_elevation_scope_db(AppContext &ctx, int grant_id,
                                            const std::string &scope) {
  if (!ctx.sqlite.db || grant_id <= 0) return true;
  std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
  const char *sql = "UPDATE access_grants SET elevation_scope=? WHERE id=?";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(ctx.sqlite.db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;
  if (scope.empty()) {
    sqlite3_bind_null(stmt, 1);
  } else {
    sqlite3_bind_text(stmt, 1, scope.c_str(), -1, SQLITE_TRANSIENT);
  }
  sqlite3_bind_int(stmt, 2, grant_id);
  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

void expire_old_access_grants(AppContext &ctx) {
  if (!ctx.sqlite.db) return;
  const std::string now = now_utc();
  struct ExpiredGrantInfo {
    int id = 0;
    int resourceId = 0;
    int sessionId = 0;
    std::string subject;
  };
  std::vector<ExpiredGrantInfo> expired;
  {
    std::lock_guard<std::mutex> lock(ctx.sqlite.mutex);
    const char *select_sql =
        "SELECT id, resource_id, session_id, subject FROM access_grants "
        "WHERE status='issued' AND expires_at < ?";
    sqlite3_stmt *select_stmt = nullptr;
    if (sqlite3_prepare_v2(ctx.sqlite.db, select_sql, -1, &select_stmt,
                           nullptr) != SQLITE_OK) {
      return;
    }
    sqlite3_bind_text(select_stmt, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    while (sqlite3_step(select_stmt) == SQLITE_ROW) {
      ExpiredGrantInfo item;
      item.id = sqlite3_column_int(select_stmt, 0);
      item.resourceId = sqlite3_column_int(select_stmt, 1);
      item.sessionId = sqlite3_column_int(select_stmt, 2);
      if (auto value = sqlite3_column_text(select_stmt, 3)) {
        item.subject = reinterpret_cast<const char *>(value);
      }
      expired.push_back(std::move(item));
    }
    sqlite3_finalize(select_stmt);

    if (expired.empty()) return;

    const char *update_sql =
        "UPDATE access_grants SET status='expired' WHERE id=?";
    sqlite3_stmt *update_stmt = nullptr;
    if (sqlite3_prepare_v2(ctx.sqlite.db, update_sql, -1, &update_stmt,
                           nullptr) != SQLITE_OK) {
      return;
    }
    for (const auto &item : expired) {
      sqlite3_bind_int(update_stmt, 1, item.id);
      sqlite3_step(update_stmt);
      sqlite3_reset(update_stmt);
      sqlite3_clear_bindings(update_stmt);
    }
    sqlite3_finalize(update_stmt);
  }

  for (const auto &item : expired) {
    AuditEvent event;
    event.id = ctx.next_audit_id.fetch_add(1);
    event.type = "access.grant.expired";
    event.actor = "system";
    event.role = "system";
    event.createdAt = now;
    std::ostringstream payload;
    payload << "{\"id\":" << item.id
            << ",\"resourceId\":" << item.resourceId
            << ",\"sessionId\":" << item.sessionId;
    if (!item.subject.empty()) {
      payload << ",\"subject\":\"" << json_escape(item.subject) << "\"";
    }
    payload << '}';
    event.payloadJson = payload.str();
    event.payloadIsJson = true;
    ctx.append_audit(event);
  }
}

bool profile_matches_resource(const AccessProfile &profile,
                              const Resource &resource) {
  if (csv_contains_token(profile.resourceIdsCsv, std::to_string(resource.id))) {
    return true;
  }
  if (!profile.resourceTagsCsv.empty() &&
      csv_intersects(profile.resourceTagsCsv, resource.tagsCsv)) {
    return true;
  }
  return profile.resourceIdsCsv.empty() && profile.resourceTagsCsv.empty();
}

bool policy_matches_subject_and_resource(const AccessPolicy &policy,
                                         const AuthSession &auth,
                                         const Resource &resource) {
  if (!policy.enabled) return false;
  const std::string identity_pattern = to_lower(trim_copy(policy.identityPattern));
  if (!identity_pattern.empty() && identity_pattern != "*" &&
      identity_pattern != to_lower(auth.user)) {
    return false;
  }
  const std::string role = to_lower(trim_copy(policy.role));
  if (!role.empty() && role != "any" && role != normalize_user_role(auth.role)) {
    return false;
  }
  const std::string group = to_lower(trim_copy(policy.groupName));
  if (!group.empty() && group != "*" && group != normalize_user_role(auth.role)) {
    return false;
  }
  const std::string risk = to_lower(trim_copy(policy.riskLevel));
  if (!risk.empty() && risk != "any" && risk != to_lower(resource.riskLevel)) {
    return false;
  }
  if (!policy.resourceTagsCsv.empty() &&
      !csv_intersects(policy.resourceTagsCsv, resource.tagsCsv)) {
    return false;
  }
  return true;
}

struct AccessDecision {
  bool requireJustification = false;
  bool ticketRequired = false;
  bool approvalRequired = false;
  bool purposeRequired = false;
  std::string mfaRequirement = "any";
  std::string routingConstraint = "any";
  int maxDurationSeconds = 3600;
  int selectedPolicyId = 0;
  int selectedProfileId = 0;
  std::vector<int> matchedPolicyIds;
  std::vector<std::string> matchedPolicyNames;
  std::vector<std::string> factors;
};

AccessDecision build_access_decision(
    AppContext &ctx, const AuthSession &auth, const UserAccount &account,
    const Resource &resource, const std::vector<AccessPolicy> &all_policies,
    const std::vector<AccessProfile> &user_profiles) {
  AccessDecision decision;
  decision.requireJustification = resource.requireAccessJustification;
  decision.approvalRequired = resource.requireDualApproval;
  decision.purposeRequired =
      to_lower(resource.riskLevel) == "high" ||
      to_lower(resource.riskLevel) == "critical";
  if (resource.adaptiveAccessPolicy && decision.purposeRequired) {
    decision.ticketRequired = true;
    decision.factors.push_back("resource.adaptive.ticket_required");
  }

  std::unordered_set<int> applied_policy_ids;
  std::unordered_map<int, int> policy_profile_map;
  for (const auto &profile : user_profiles) {
    if (!profile_matches_resource(profile, resource) || profile.policyId <= 0) continue;
    policy_profile_map[profile.policyId] = profile.id;
  }

  const std::time_t now = std::time(nullptr);
  std::tm utc_tm{};
#ifdef _WIN32
  gmtime_s(&utc_tm, &now);
#else
  gmtime_r(&now, &utc_tm);
#endif

  for (const auto &policy : all_policies) {
    const bool global_match =
        policy_matches_subject_and_resource(policy, auth, resource);
    const auto profile_it = policy_profile_map.find(policy.id);
    if (!global_match && profile_it == policy_profile_map.end()) continue;
    if (!applied_policy_ids.insert(policy.id).second) continue;
    if (!is_time_window_match_utc(policy.timeWindow, utc_tm.tm_hour,
                                  utc_tm.tm_min)) {
      decision.factors.push_back("policy.time_window.denied:" + policy.name);
      continue;
    }

    decision.matchedPolicyIds.push_back(policy.id);
    decision.matchedPolicyNames.push_back(policy.name);
    if (decision.selectedPolicyId == 0) decision.selectedPolicyId = policy.id;
    if (profile_it != policy_profile_map.end() && decision.selectedProfileId == 0) {
      decision.selectedProfileId = profile_it->second;
    }
    if (policy.requireJustification) decision.requireJustification = true;
    if (policy.ticketRequired) decision.ticketRequired = true;
    if (to_lower(policy.approvalMode) == "required") {
      decision.approvalRequired = true;
    }
    decision.mfaRequirement =
        stronger_mfa_requirement(decision.mfaRequirement, policy.mfaRequirement);
    if (policy.maxDurationSeconds > 0 &&
        (decision.maxDurationSeconds <= 0 ||
         policy.maxDurationSeconds < decision.maxDurationSeconds)) {
      decision.maxDurationSeconds = policy.maxDurationSeconds;
      decision.selectedPolicyId = policy.id;
      if (profile_it != policy_profile_map.end()) {
        decision.selectedProfileId = profile_it->second;
      }
    }
    const std::string routing = to_lower(policy.routingConstraint);
    if (!routing.empty() && routing != "any") {
      if (decision.routingConstraint == "any" ||
          decision.routingConstraint == routing) {
        decision.routingConstraint = routing;
      } else {
        decision.factors.push_back("policy.routing.conflict");
      }
    }
  }

  if (!user_meets_mfa_requirement(account, decision.mfaRequirement)) {
    decision.factors.push_back("policy.mfa.missing:" + decision.mfaRequirement);
  }

  if (decision.routingConstraint == "relay") {
    std::lock_guard<std::mutex> lock(ctx.relay_mutex);
    if (!ctx.resource_relay_bindings.count(resource.id) ||
        ctx.resource_relay_bindings[resource.id].empty()) {
      decision.factors.push_back("policy.routing.relay_required");
    }
  }

  return decision;
}

std::string ensure_evidence_signing_secret(AppContext &ctx) {
  std::lock_guard<std::mutex> lock(ctx.tunnel_signing_key_mutex);
  if (ctx.tunnel_signing_key_current_secret.empty()) {
    ctx.tunnel_signing_key_current_secret = ctx.generate_token();
    ctx.tunnel_signing_key_current_id = "evidence-" + ctx.generate_token();
    ctx.tunnel_signing_key_current_epoch = now_epoch_seconds();
  }
  return ctx.tunnel_signing_key_current_secret;
}
}

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
  // GET /api/auth/sso/oidc/start
  CROW_ROUTE(app, "/api/auth/sso/oidc/start").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        const std::string provider = request.url_params.get("provider")
                                         ? to_lower(trim_copy(
                                               request.url_params.get("provider")))
                                         : "";
        std::string config_error;
        auto config = load_oidc_provider_config(provider, request, config_error);
        if (!config) {
          append_sso_failure_audit(ctx, provider.empty() ? "unknown" : provider,
                                   "config_error", config_error);
          return crow::response(400, config_error);
        }
        if (!parse_endpoint_url(config->authorizationEndpoint)) {
          append_sso_failure_audit(
              ctx, config->provider, "invalid_authorization_endpoint",
              "authorization endpoint URL is malformed");
          return crow::response(500, "Invalid OIDC authorization endpoint");
        }

        OidcAuthStateRecord state;
        state.state = ctx.generate_token();
        state.provider = config->provider;
        state.nonce = ctx.generate_token();
        state.codeVerifier = ctx.generate_token() + ctx.generate_token();
        if (state.codeVerifier.size() > 120) state.codeVerifier.resize(120);
        state.redirectAfterLogin = sanitize_post_login_redirect(
            request.url_params.get("postLoginRedirect")
                ? request.url_params.get("postLoginRedirect")
                : "/");
        state.createdAt = now_utc();
        const auto state_expires_at = checked_epoch_seconds_after(
            now_epoch_seconds(), kOidcStateTtlSeconds);
        if (!state_expires_at) {
          return crow::response(500, "Invalid OIDC state TTL");
        }
        state.expiresAt = utc_from_epoch_seconds(*state_expires_at);

        if (!store_oidc_auth_state(ctx, state)) {
          append_sso_failure_audit(ctx, config->provider, "state_persist_error",
                                   "failed to persist OIDC state");
          return crow::response(500, "Failed to initialize OIDC login state");
        }

        const std::string authorization_url = append_query_params(
            config->authorizationEndpoint,
            {{"response_type", "code"},
             {"client_id", config->clientId},
             {"redirect_uri", config->redirectUri},
             {"scope", config->scope},
             {"state", state.state},
             {"nonce", state.nonce},
             {"code_challenge", build_pkce_challenge(state.codeVerifier)},
             {"code_challenge_method", "S256"}});

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "auth.login.sso.start";
        event.actor = "anonymous";
        event.role = "anonymous";
        event.createdAt = now_utc();
        event.payloadJson = "{\"provider\":\"" +
                            json_escape(config->provider) +
                            "\",\"redirect\":\"" +
                            json_escape(state.redirectAfterLogin) + "\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::response response;
        response.code = 302;
        response.add_header("Location", authorization_url);
        response.add_header("Cache-Control", "no-store");
        return response;
      });

  // GET /api/auth/sso/oidc/callback
  CROW_ROUTE(app, "/api/auth/sso/oidc/callback").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        std::string provider_hint = request.url_params.get("provider")
                                        ? to_lower(trim_copy(
                                              request.url_params.get("provider")))
                                        : "unknown";

        const std::string provider_error =
            request.url_params.get("error")
                ? trim_copy(request.url_params.get("error"))
                : "";
        if (!provider_error.empty()) {
          append_sso_failure_audit(
              ctx, provider_hint, "provider_error",
              request.url_params.get("error_description")
                  ? request.url_params.get("error_description")
                  : "");
          return crow::response(401, "OIDC provider rejected authentication");
        }

        const std::string code = request.url_params.get("code")
                                     ? trim_copy(request.url_params.get("code"))
                                     : "";
        const std::string state_value =
            request.url_params.get("state")
                ? trim_copy(request.url_params.get("state"))
                : "";
        if (code.empty() || state_value.empty()) {
          append_sso_failure_audit(ctx, provider_hint, "missing_code_or_state",
                                   "callback parameters are incomplete");
          return crow::response(400, "Missing authorization code or state");
        }

        auto state = consume_oidc_auth_state(ctx, state_value);
        if (!state) {
          append_sso_failure_audit(ctx, provider_hint, "invalid_state",
                                   "OIDC state is missing or expired");
          return crow::response(400, "OIDC state is invalid or expired");
        }
        provider_hint = state->provider;

        std::string config_error;
        auto config =
            load_oidc_provider_config(state->provider, request, config_error);
        if (!config) {
          append_sso_failure_audit(ctx, state->provider, "config_error",
                                   config_error);
          return crow::response(400, config_error);
        }

        const auto token_endpoint = parse_endpoint_url(config->tokenEndpoint);
        if (!token_endpoint) {
          append_sso_failure_audit(
              ctx, config->provider, "invalid_token_endpoint",
              "token endpoint URL is malformed");
          return crow::response(500, "Invalid OIDC token endpoint");
        }
        const bool token_use_tls = token_endpoint->scheme == "https";

        std::ostringstream token_form;
        bool first = true;
        auto append_form_field = [&token_form, &first](const std::string &key,
                                                        const std::string &value) {
          if (!first) token_form << '&';
          first = false;
          token_form << url_encode(key) << '=' << url_encode(value);
        };
        append_form_field("grant_type", "authorization_code");
        append_form_field("code", code);
        append_form_field("redirect_uri", config->redirectUri);
        append_form_field("client_id", config->clientId);
        append_form_field("code_verifier", state->codeVerifier);
        if (!config->clientSecret.empty()) {
          append_form_field("client_secret", config->clientSecret);
        }

        std::unordered_map<std::string, std::string> token_headers;
        token_headers["Content-Type"] = "application/x-www-form-urlencoded";
        token_headers["Accept"] = "application/json";
        std::string token_error;
        const auto token_response =
            http_proxy_request("POST", token_endpoint->host, token_endpoint->port,
                               token_endpoint->target, token_form.str(),
                     token_headers, token_error, token_use_tls);
        if (!token_error.empty()) {
          append_sso_failure_audit(ctx, config->provider, "token_exchange_error",
                                   token_error);
          return crow::response(502, "OIDC token exchange failed");
        }
        if (token_response.status_code < 200 || token_response.status_code >= 300) {
          append_sso_failure_audit(ctx, config->provider,
                                   "token_exchange_rejected",
                                   "HTTP " +
                                       std::to_string(token_response.status_code));
          return crow::response(502, "OIDC token endpoint rejected authorization");
        }

        const auto token_payload = crow::json::load(token_response.body);
        if (!token_payload) {
          append_sso_failure_audit(
              ctx, config->provider, "invalid_token_response",
              "token endpoint returned non-JSON payload");
          return crow::response(502,
                                "OIDC token response is not valid JSON payload");
        }

        const std::string access_token =
            json_string_field(token_payload, "access_token").value_or("");
        if (access_token.empty()) {
          append_sso_failure_audit(ctx, config->provider, "missing_access_token",
                                   "access_token field was not provided");
          return crow::response(502,
                                "OIDC token response does not include access token");
        }

        std::string username = extract_oidc_username_from_claims(token_payload);
        std::string role = extract_oidc_role_from_claims(
            token_payload, config->roleClaim, config->defaultRole);

        if (!config->userinfoEndpoint.empty()) {
          const auto userinfo_endpoint = parse_endpoint_url(config->userinfoEndpoint);
          if (!userinfo_endpoint) {
            append_sso_failure_audit(ctx, config->provider,
                                     "invalid_userinfo_endpoint",
                                     "userinfo endpoint URL is malformed");
            return crow::response(500, "Invalid OIDC userinfo endpoint");
          }
          const bool userinfo_use_tls = userinfo_endpoint->scheme == "https";
          std::unordered_map<std::string, std::string> userinfo_headers;
          userinfo_headers["Authorization"] = "Bearer " + access_token;
          userinfo_headers["Accept"] = "application/json";
          std::string userinfo_error;
          const auto userinfo_response =
              http_proxy_request("GET", userinfo_endpoint->host,
                                 userinfo_endpoint->port, userinfo_endpoint->target,
                                 "", userinfo_headers, userinfo_error,
                                 userinfo_use_tls);
          if (!userinfo_error.empty()) {
            if (username.empty()) {
              append_sso_failure_audit(ctx, config->provider,
                                       "userinfo_request_error", userinfo_error);
              return crow::response(502, "OIDC userinfo request failed");
            }
          } else if (userinfo_response.status_code >= 200 &&
                     userinfo_response.status_code < 300) {
            const auto userinfo_payload = crow::json::load(userinfo_response.body);
            if (userinfo_payload) {
              const std::string claimed_username =
                  extract_oidc_username_from_claims(userinfo_payload);
              if (!claimed_username.empty()) username = claimed_username;
              role = extract_oidc_role_from_claims(
                  userinfo_payload, config->roleClaim, role);
            }
          }
        }

        if (username.empty()) {
          append_sso_failure_audit(ctx, config->provider, "missing_identity",
                                   "OIDC claims do not expose a usable username");
          return crow::response(502,
                                "OIDC claims do not expose a usable identity");
        }

        std::string provision_error;
        auto provisioned = provision_oidc_user(ctx, username, role, config->syncRole,
                                               provision_error);
        if (!provisioned) {
          append_sso_failure_audit(ctx, config->provider, "provisioning_error",
                                   provision_error);
          return crow::response(500, "Failed to provision SSO user");
        }

        if (provisioned->created || provisioned->updated) {
          AuditEvent identity_event;
          identity_event.id = ctx.next_audit_id.fetch_add(1);
          identity_event.type = provisioned->created
                                    ? "identity.sso.provisioned"
                                    : "identity.sso.role_synced";
          identity_event.actor = provisioned->user.username;
          identity_event.role = provisioned->user.role;
          identity_event.createdAt = now_utc();
          identity_event.payloadJson = build_user_payload_json(provisioned->user);
          identity_event.payloadIsJson = true;
          ctx.append_audit(identity_event);
        }

        ctx.cleanup_expired_tokens();
        AuthSession auth;
        auth.userId = provisioned->user.id;
        auth.user = provisioned->user.username;
        auth.role = provisioned->user.role;
        auth.issuedAt = now_utc();
        auth.expiresAt = ctx.compute_expiry();
        auth.token = ctx.generate_token();
        {
          std::lock_guard<std::mutex> lock(ctx.auth_mutex);
          ctx.auth_sessions[auth.token] = auth;
        }

        AuditEvent success_event;
        success_event.id = ctx.next_audit_id.fetch_add(1);
        success_event.type = "auth.login.sso.success";
        success_event.actor = auth.user;
        success_event.role = auth.role;
        success_event.createdAt = now_utc();
        std::ostringstream success_payload;
        success_payload << "{\"provider\":\"" << json_escape(config->provider)
                        << "\",\"userId\":" << auth.userId
                        << ",\"username\":\"" << json_escape(auth.user)
                        << "\",\"role\":\"" << json_escape(auth.role)
                        << "\",\"jitProvisioned\":"
                        << (provisioned->created ? "true" : "false")
                        << ",\"roleSynced\":"
                        << (provisioned->updated ? "true" : "false") << '}';
        success_event.payloadJson = success_payload.str();
        success_event.payloadIsJson = true;
        ctx.append_audit(success_event);

        auto effective_permissions =
            ctx.get_effective_permissions(auth.userId, auth.role);
        std::vector<std::string> ordered_permissions(effective_permissions.begin(),
                                                     effective_permissions.end());
        std::sort(ordered_permissions.begin(), ordered_permissions.end());

        crow::json::wvalue auth_payload;
        auth_payload["token"] = auth.token;
        auth_payload["user"] = auth.user;
        auth_payload["role"] = auth.role;
        auth_payload["permissions"] = crow::json::wvalue::list();
        for (size_t i = 0; i < ordered_permissions.size(); ++i) {
          auth_payload["permissions"][static_cast<int>(i)] =
              ordered_permissions[i];
        }
        const std::string redirect_target =
            sanitize_post_login_redirect(state->redirectAfterLogin);
        const std::string payload_b64 = base64_encode(auth_payload.dump());
        const std::string redirect_b64 = base64_encode(redirect_target);

        std::ostringstream html;
        html << "<!doctype html><html><head><meta charset=\"utf-8\">"
             << "<title>EndoriumFort SSO</title></head><body>"
             << "<p>SSO login successful. Redirecting...</p><script>"
             << "try{const data=atob('" << payload_b64
             << "');window.localStorage.setItem('endoriumfort_auth',data);}"
             << "catch(_){ }"
             << "window.location.replace(atob('" << redirect_b64 << "'));"
             << "</script></body></html>";

        crow::response response;
        response.code = 200;
        response.body = html.str();
        response.set_header("Content-Type", "text/html; charset=utf-8");
        response.add_header(
            "Set-Cookie",
            build_auth_cookie(auth.token, request_uses_https(request),
                              ctx.token_ttl_seconds));
        response.add_header("Cache-Control", "no-store");
        return response;
      });

  // POST /api/auth/login
  CROW_ROUTE(app, "/api/auth/login").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");
        std::string user = body["user"].s();
        std::string password = body["password"].s();
        if (user.empty() || password.empty())
          return crow::response(400, "Missing user or password");

        // Extract client IP for IP-based rate limiting
        std::string client_ip = get_client_ip(request);

        // Check username-based rate limiting
        if (!ctx.check_rate_limit("login:" + user)) {
          AuditEvent rl_evt;
          rl_evt.id = ctx.next_audit_id.fetch_add(1);
          rl_evt.type = "auth.login.rate_limited";
          rl_evt.actor = user;
          rl_evt.role = "";
          rl_evt.createdAt = now_utc();
          rl_evt.payloadJson = "{\"username\":\"" + json_escape(user) + "\",\"reason\":\"username_rate_limit\",\"ip\":\"" + json_escape(client_ip) + "\"}";
          rl_evt.payloadIsJson = true;
          ctx.append_audit(rl_evt);
          maybe_emit_auth_failure_burst_anomaly(ctx, user, client_ip,
                                                rl_evt.type);
          return crow::response(429, "Too many login attempts. Try again later.");
        }

        // Check IP-based rate limiting (brute-force protection across different usernames)
        if (!ctx.check_rate_limit("login_ip:" + client_ip)) {
          AuditEvent rl_evt;
          rl_evt.id = ctx.next_audit_id.fetch_add(1);
          rl_evt.type = "auth.login.rate_limited";
          rl_evt.actor = user;
          rl_evt.role = "";
          rl_evt.createdAt = now_utc();
          rl_evt.payloadJson = "{\"username\":\"" + json_escape(user) + "\",\"reason\":\"ip_rate_limit\",\"ip\":\"" + json_escape(client_ip) + "\"}";
          rl_evt.payloadIsJson = true;
          ctx.append_audit(rl_evt);
          maybe_emit_auth_failure_burst_anomaly(ctx, user, client_ip,
                                                rl_evt.type);
          return crow::response(429, "Too many login attempts from this IP. Try again later.");
        }

        // Optional MFA payloads for 2FA
        std::string totp_code;
        if (body.has("totpCode"))
          totp_code = body["totpCode"].s();
        std::string webauthn_request_id;
        std::string webauthn_credential_id;
        std::string webauthn_client_data;
        std::string webauthn_authenticator_data;
        std::string webauthn_signature;
        if (body.has("webauthnRequestId"))
          webauthn_request_id = body["webauthnRequestId"].s();
        if (body.has("webauthnCredentialId"))
          webauthn_credential_id = body["webauthnCredentialId"].s();
        if (body.has("webauthnClientDataJSON"))
          webauthn_client_data = body["webauthnClientDataJSON"].s();
        if (body.has("webauthnAuthenticatorData"))
          webauthn_authenticator_data = body["webauthnAuthenticatorData"].s();
        if (body.has("webauthnSignature"))
          webauthn_signature = body["webauthnSignature"].s();

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

        const LdapRuntimeConfig ldap_cfg = load_ldap_runtime_config();
        bool ldap_authenticated = false;
        std::string ldap_directory_identity;
        LdapRoleResolution ldap_role_resolution;
        bool local_password_ok =
            matched && crypto::verify_password(password, matched->password);

        if (!local_password_ok) {
          const bool can_try_ldap =
              ldap_cfg.enabled &&
              (!matched || is_ldap_shadow_password(matched->password));
          if (can_try_ldap) {
            std::string ldap_error;
            if (ldap_authenticate_user(ldap_cfg, user, password,
                                       ldap_directory_identity, ldap_error)) {
              ldap_role_resolution =
                resolve_ldap_role(ldap_cfg, user, ldap_directory_identity);
              bool ldap_created = false;
              bool ldap_role_updated = false;
              std::string provision_error;
              auto ldap_user = provision_ldap_shadow_user(
                ctx, user, ldap_cfg, ldap_role_resolution.role, ldap_created,
                ldap_role_updated, provision_error);
              if (!ldap_user) {
                AuditEvent ldap_evt;
                ldap_evt.id = ctx.next_audit_id.fetch_add(1);
                ldap_evt.type = "auth.login.ldap.failure";
                ldap_evt.actor = user;
                ldap_evt.role = "";
                ldap_evt.createdAt = now_utc();
                ldap_evt.payloadJson =
                    "{\"reason\":\"provisioning_failed\",\"username\":\"" +
                    json_escape(user) + "\",\"ip\":\"" +
                    json_escape(client_ip) + "\",\"detail\":\"" +
                    json_escape(provision_error) + "\"}";
                ldap_evt.payloadIsJson = true;
                ctx.append_audit(ldap_evt);
                return crow::response(500, "Failed to provision LDAP user");
              }

              matched = *ldap_user;
              local_password_ok = true;
              ldap_authenticated = true;

              AuditEvent ldap_evt;
              ldap_evt.id = ctx.next_audit_id.fetch_add(1);
              ldap_evt.type = "auth.login.ldap.success";
              ldap_evt.actor = matched->username;
              ldap_evt.role = matched->role;
              ldap_evt.createdAt = now_utc();
              ldap_evt.payloadJson =
                  "{\"username\":\"" + json_escape(matched->username) +
                  "\",\"ip\":\"" + json_escape(client_ip) +
                  "\",\"directoryIdentity\":\"" +
                  json_escape(ldap_directory_identity) + "\",\"created\":" +
                  (ldap_created ? "true" : "false") +
                  ",\"roleUpdated\":" +
                  (ldap_role_updated ? "true" : "false") +
                  ",\"mappedRole\":\"" +
                  json_escape(ldap_role_resolution.role) +
                  "\",\"mappingStrategy\":\"" +
                  json_escape(ldap_role_resolution.strategy) +
                  "\",\"matchedRule\":\"" +
                  json_escape(ldap_role_resolution.matchedRule) + "\"}";
              ldap_evt.payloadIsJson = true;
              ctx.append_audit(ldap_evt);
            } else {
              AuditEvent ldap_evt;
              ldap_evt.id = ctx.next_audit_id.fetch_add(1);
              ldap_evt.type = "auth.login.ldap.failure";
              ldap_evt.actor = user;
              ldap_evt.role = "";
              ldap_evt.createdAt = now_utc();
              ldap_evt.payloadJson =
                  "{\"reason\":\"bind_failed\",\"username\":\"" +
                  json_escape(user) + "\",\"ip\":\"" +
                  json_escape(client_ip) + "\",\"detail\":\"" +
                  json_escape(ldap_error) + "\"}";
              ldap_evt.payloadIsJson = true;
              ctx.append_audit(ldap_evt);
            }
          }
        }

        // Verify password (supports hashed and legacy plaintext) with optional
        // LDAP fallback for directory-managed users.
        if (!local_password_ok) {
          // Record failed attempt for exponential backoff
          ctx.record_failed_login_attempt("login:" + user);
          ctx.record_failed_login_attempt("login_ip:" + client_ip);
          
          // Audit: login failure
          AuditEvent evt;
          evt.id = ctx.next_audit_id.fetch_add(1);
          evt.type = "auth.login.failure";
          evt.actor = user;
          evt.role = "";
          evt.createdAt = now_utc();
          evt.payloadJson = "{\"reason\":\"invalid_credentials\",\"username\":\"" +
                            json_escape(user) + "\",\"ip\":\"" + json_escape(client_ip) + "\"}";
          evt.payloadIsJson = true;
          ctx.append_audit(evt);
          maybe_emit_auth_failure_burst_anomaly(ctx, user, client_ip, evt.type);
          return crow::response(401, "Invalid credentials");
        }

        // Auto-migrate legacy password formats to the current scrypt scheme.
        if (!ldap_authenticated &&
            crypto::password_hash_needs_rehash(matched->password)) {
          std::string hashed = crypto::hash_password(password);
          ctx.update_user_password_hash(matched->id, hashed);
          matched->password = hashed;
        }

        const bool has_webauthn = user_has_webauthn_enabled(*matched);
        if (matched->totpEnabled || has_webauthn) {
          bool mfa_ok = false;

          if (matched->totpEnabled && !totp_code.empty() &&
              totp::verify_code(matched->totpSecret, totp_code)) {
            mfa_ok = true;
          }

          if (!mfa_ok && has_webauthn && !webauthn_request_id.empty() &&
              !webauthn_credential_id.empty() && !webauthn_client_data.empty() &&
              !webauthn_authenticator_data.empty() && !webauthn_signature.empty()) {
            const auto challenge = ctx.consume_webauthn_challenge(
                webauthn_request_id, matched->id, "login");
            const auto credential =
                ctx.find_webauthn_credential_by_external_id(webauthn_credential_id);
            const auto client_data =
                webauthn::parse_client_data(webauthn_client_data);
            const auto authenticator_data = challenge
                                                ? webauthn::parse_authenticator_data(
                                                      webauthn_authenticator_data,
                                                      challenge->rpId)
                                                : std::nullopt;

            if (challenge && credential && client_data && authenticator_data &&
                credential->userId == matched->id &&
                client_data->type == "webauthn.get" &&
                client_data->challenge ==
                    webauthn::base64url_encode(challenge->challenge) &&
                client_data->origin == challenge->origin &&
                (authenticator_data->flags & 0x01) != 0 &&
                webauthn::verify_assertion_signature(
                    credential->publicKeySpki, authenticator_data->raw,
                    client_data->rawJson, webauthn_signature)) {
              if (!(credential->signCount > 0 &&
                    authenticator_data->signCount <=
                        static_cast<uint32_t>(credential->signCount) &&
                    authenticator_data->signCount != 0)) {
                WebAuthnCredential updated = *credential;
                updated.signCount =
                    static_cast<int>(authenticator_data->signCount);
                updated.lastUsedAt = now_utc();
                ctx.update_webauthn_credential(updated);
                mfa_ok = true;
              }
            }
          }

          if (!mfa_ok) {
            if (matched->totpEnabled && !totp_code.empty() && !has_webauthn) {
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

            crow::json::wvalue payload;
            payload["status"] = "mfa_required";
            payload["message"] =
                "A second factor is required to complete this login";
            payload["user"] = matched->username;
            apply_auth_mfa_payload(payload, *matched);
            payload["mfaMethods"] = crow::json::wvalue::list();
            int method_index = 0;
            const auto ordered_methods = ordered_mfa_methods_for_login(*matched);
            bool needs_webauthn_options = false;
            for (const auto &method : ordered_methods) {
              payload["mfaMethods"][method_index++] = method;
              if (method == "webauthn") needs_webauthn_options = true;
            }
            if (needs_webauthn_options) {
              const std::string rp_id = webauthn::expected_rp_id(
                  request, ctx.webauthn_rp_id_override);
              const std::string origin = webauthn::expected_origin(
                  request, ctx.webauthn_origin_override);
              if (!webauthn::is_valid_rp_id(rp_id) ||
                  !webauthn::is_valid_origin(origin)) {
                return crow::response(
                    400,
                    "WebAuthn requires a valid domain. Configure "
                    "ENDORIUMFORT_WEBAUTHN_RP_ID and ENDORIUMFORT_WEBAUTHN_ORIGIN "
                    "(example: app.example.com / https://app.example.com), or use localhost in dev.");
              }
              const auto challenge = ctx.create_webauthn_challenge(
                  matched->id, matched->username, "login", rp_id, origin);
              payload["webauthn"] = build_webauthn_assertion_options(
                  challenge, ctx.get_user_webauthn_credentials(matched->id));
            }
            return crow::response{payload};
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

        // Clear rate limiting attempts on successful login
        ctx.clear_login_attempts("login:" + user);
        ctx.clear_login_attempts("login_ip:" + client_ip);
        ctx.clear_anomaly_signal(auth_user_anomaly_key(user));
        ctx.clear_anomaly_signal(auth_user_anomaly_key(user) + ":emit");
        ctx.clear_anomaly_signal(auth_ip_anomaly_key(client_ip));
        ctx.clear_anomaly_signal(auth_ip_anomaly_key(client_ip) + ":emit");

        // Audit: login success
        AuditEvent evt;
        evt.id = ctx.next_audit_id.fetch_add(1);
        evt.type = "auth.login.success";
        evt.actor = matched->username;
        evt.role = matched->role;
        evt.createdAt = now_utc();
        evt.payloadJson = "{\"userId\":" + std::to_string(matched->id) +
              ",\"username\":\"" +
              json_escape(matched->username) +
              "\",\"ip\":\"" + json_escape(client_ip) +
              "\",\"authSource\":\"" +
              std::string(ldap_authenticated ? "ldap" : "local") +
              "\",\"directoryRole\":\"" +
              json_escape(ldap_authenticated
                  ? ldap_role_resolution.role
                  : std::string("")) +
              "\",\"directoryRoleStrategy\":\"" +
              json_escape(ldap_authenticated
                  ? ldap_role_resolution.strategy
                  : std::string("")) + "\"}";
        evt.payloadIsJson = true;
        ctx.append_audit(evt);

        crow::json::wvalue payload;
        payload["token"] = auth.token;
        payload["user"] = auth.user;
        payload["role"] = auth.role;
        payload["permissions"] = crow::json::wvalue::list();
        int perm_index = 0;
        auto effective_permissions =
            ctx.get_effective_permissions(auth.userId, auth.role);
        for (const auto &permission : effective_permissions) {
          payload["permissions"][perm_index++] = permission;
        }
        payload["issuedAt"] = auth.issuedAt;
        payload["expiresAt"] = auth.expiresAt;
        payload["authSource"] = ldap_authenticated ? "ldap" : "local";
        if (ldap_authenticated) {
          payload["directoryRole"] = ldap_role_resolution.role;
          payload["directoryRoleStrategy"] = ldap_role_resolution.strategy;
          payload["directoryMatchedRule"] = ldap_role_resolution.matchedRule;
        }
        apply_auth_mfa_payload(payload, *matched);
        crow::response response{payload};
        response.add_header(
            "Set-Cookie",
            build_auth_cookie(auth.token, request_uses_https(request),
                              ctx.token_ttl_seconds));
        response.add_header("Cache-Control", "no-store");
        return response;
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
        crow::response response{payload};
        response.add_header("Set-Cookie",
                            build_cleared_auth_cookie(request_uses_https(request)));
        response.add_header("Cache-Control", "no-store");
        return response;
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
        bool keep_current_session = body.has("keepCurrentSession") &&
                                    body["keepCurrentSession"].b();
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
        bool mfa_required = false;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it == ctx.users.end())
            return crow::response(404, "User not found");
          mfa_required = it->second.bootstrapMfaRequired;
        }
        if (!ctx.update_user_bootstrap_flags(auth->userId, false, mfa_required))
          return crow::response(500, "Failed to update bootstrap security status");

        // Invalidate sessions, optionally preserving the current bootstrap flow.
        if (keep_current_session) {
          ctx.invalidate_user_tokens_except(auth->userId, auth->token);
        } else {
          ctx.invalidate_user_tokens(auth->userId);
        }

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
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it != ctx.users.end()) {
            apply_auth_mfa_payload(payload, it->second);
          }
        }
        payload["message"] = keep_current_session
                                 ? "Password changed successfully."
                                 : "Password changed. All sessions invalidated — please log in again.";
        crow::response response{payload};
        response.add_header(
            "Set-Cookie",
            keep_current_session
                ? build_auth_cookie(auth->token, request_uses_https(request),
                                    ctx.token_ttl_seconds)
                : build_cleared_auth_cookie(request_uses_https(request)));
        response.add_header("Cache-Control", "no-store");
        return response;
      });

  // GET /api/auth/bootstrap-status
  CROW_ROUTE(app, "/api/auth/bootstrap-status").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        std::lock_guard<std::mutex> lock(ctx.user_mutex);
        auto it = ctx.users.find(auth->userId);
        if (it == ctx.users.end())
          return crow::response(404, "User not found");

        crow::json::wvalue payload;
        payload["status"] = "ok";
        apply_auth_mfa_payload(payload, it->second);
        return scim_json_response(payload);
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
        if (!has_permission(ctx, *auth, "users.read"))
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
        return scim_json_response(payload);
      });

  // POST /api/users
  CROW_ROUTE(app, "/api/users").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.manage"))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string username = body["username"].s();
        std::string password = body["password"].s();
        std::string role = body["role"].s();
        bool force_password_rotation =
            body.has("forcePasswordRotation")
                ? body["forcePasswordRotation"].b()
                : normalize_user_role(role) == "admin";
        if (username.empty() || password.empty() || role.empty())
          return crow::response(400, "Missing username, password, or role");
        if (!is_allowed_user_role(role, {"operator", "admin", "auditor"}))
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
        user.role = normalize_user_role(role);
        user.createdAt = now_utc();
        user.updatedAt = user.createdAt;
        user.bootstrapPasswordChangeRequired = force_password_rotation;
        user.bootstrapMfaRequired = user.role == "admin";

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
        return scim_json_response(payload);
      });

  // PUT /api/users/<int>
  CROW_ROUTE(app, "/api/users/<int>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "users.manage"))
              return crow::response(403, "Forbidden");
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            std::string password = body["password"].s();
            std::string role = body["role"].s();
            std::string normalized_role = normalize_user_role(role);
            bool force_password_rotation =
                body.has("forcePasswordRotation")
                    ? body["forcePasswordRotation"].b()
                    : normalized_role == "admin";
            if (password.empty() || role.empty())
              return crow::response(400, "Missing password or role");
            if (!is_allowed_user_role(role, {"operator", "admin", "auditor"}))
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
              user.role = normalized_role;
              user.updatedAt = now_utc();
              user.bootstrapPasswordChangeRequired = force_password_rotation;
              user.bootstrapMfaRequired =
                  user.role == "admin" && !user.totpEnabled &&
                  user.webauthnCredentialCount == 0;
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
            if (!has_permission(ctx, *auth, "users.manage"))
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
            if (!has_permission(ctx, *auth, "resources.assign"))
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
            if (!has_permission(ctx, *auth, "resources.assign"))
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
            if (!has_permission(ctx, *auth, "resources.assign"))
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

  // GET /api/users/<int>/access-profiles
  CROW_ROUTE(app, "/api/users/<int>/access-profiles")
      .methods(crow::HTTPMethod::Get)(
          [&ctx](const crow::request &request, int user_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");

            const auto profile_ids = query_user_access_profile_ids(ctx, user_id);
            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["userId"] = user_id;
            payload["profileIds"] = crow::json::wvalue::list();
            for (size_t i = 0; i < profile_ids.size(); ++i) {
              payload["profileIds"][static_cast<int>(i)] = profile_ids[i];
            }
            return crow::response{payload};
          });

  // POST /api/users/<int>/access-profiles/<int>
  CROW_ROUTE(app, "/api/users/<int>/access-profiles/<int>")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int user_id, int profile_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");
            const auto profiles = query_access_profiles(ctx);
            if (std::none_of(profiles.begin(), profiles.end(),
                             [&](const AccessProfile &item) {
                               return item.id == profile_id;
                             })) {
              return crow::response(404, "Access profile not found");
            }
            if (!assign_access_profile_to_user(ctx, user_id, profile_id))
              return crow::response(500, "Failed to assign access profile");

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["userId"] = user_id;
            payload["profileId"] = profile_id;
            return crow::response{payload};
          });

  // DELETE /api/users/<int>/access-profiles/<int>
  CROW_ROUTE(app, "/api/users/<int>/access-profiles/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int user_id, int profile_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.assign"))
              return crow::response(403, "Forbidden");
            if (!revoke_access_profile_from_user(ctx, user_id, profile_id))
              return crow::response(500, "Failed to revoke access profile");

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["userId"] = user_id;
            payload["profileId"] = profile_id;
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
        if (!can_access_any_resource(ctx, *auth))
          return crow::response(403, "Forbidden");

        std::vector<int> allowed_resource_ids;
        if (has_permission(ctx, *auth, "resources.manage")) {
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
        return scim_json_response(payload);
      });

  // POST /api/resources
  CROW_ROUTE(app, "/api/resources").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string name = body["name"].s();
        std::string target = body["target"].s();
        std::string protocol = body["protocol"].s();
        int port = 22;
        if (body.has("port")) port = body["port"].i();
        int tunnel_ticket_rate_limit_max_attempts = 0;
        if (body.has("tunnelTicketRateLimitMaxAttempts")) {
          tunnel_ticket_rate_limit_max_attempts =
              body["tunnelTicketRateLimitMaxAttempts"].i();
        }
        std::string description;
        if (body.has("description")) description = body["description"].s();
        std::string image_url;
        if (body.has("imageUrl")) image_url = body["imageUrl"].s();
        std::string image_data;
        if (body.has("imageData")) image_data = body["imageData"].s();
        std::string tags_csv;
        if (body.has("tagsCsv")) tags_csv = join_csv_compact(split_csv_compact(body["tagsCsv"].s()));
        std::string credential_source = "vaulted";
        if (body.has("credentialSource")) {
          credential_source = to_lower(body["credentialSource"].s());
        }
        std::string http_username;
        if (body.has("httpUsername")) http_username = body["httpUsername"].s();
        std::string http_password;
        if (body.has("httpPassword")) http_password = body["httpPassword"].s();
        std::string ssh_username;
        if (body.has("sshUsername")) ssh_username = body["sshUsername"].s();
        std::string ssh_password;
        if (body.has("sshPassword")) ssh_password = body["sshPassword"].s();
        bool require_access_justification = false;
        if (body.has("requireAccessJustification")) {
          require_access_justification = body["requireAccessJustification"].b();
        }
        bool require_dual_approval = false;
        if (body.has("requireDualApproval")) {
          require_dual_approval = body["requireDualApproval"].b();
        }
        bool enable_command_guard = false;
        if (body.has("enableCommandGuard")) {
          enable_command_guard = body["enableCommandGuard"].b();
        }
        bool adaptive_access_policy = false;
        if (body.has("adaptiveAccessPolicy")) {
          adaptive_access_policy = body["adaptiveAccessPolicy"].b();
        }
        std::string risk_level = "low";
        if (body.has("riskLevel")) risk_level = to_lower(body["riskLevel"].s());
        if (!is_allowed_role(risk_level, {"low", "medium", "high", "critical"})) {
          return crow::response(400, "Invalid riskLevel");
        }
        if (!is_valid_credential_source(credential_source)) {
          return crow::response(400, "Invalid credentialSource");
        }

        if (name.empty() || target.empty() || protocol.empty())
          return crow::response(400, "Missing name, target, or protocol");
        if (port <= 0 || port > 65535)
          return crow::response(400, "Invalid port");
        if (tunnel_ticket_rate_limit_max_attempts < 0)
          return crow::response(400, "Invalid tunnelTicketRateLimitMaxAttempts");

        // Validate protocol whitelist
        if (!is_allowed_role(protocol, {"ssh", "rdp", "vnc", "http", "https", "agent"}))
          return crow::response(400, "Invalid protocol. Allowed: ssh, rdp, vnc, http, https, agent");

        // Input length limits
        if (name.size() > 255 || target.size() > 255 || description.size() > 1024 ||
            tags_csv.size() > 512)
          return crow::response(400, "Field too long");

        // SSRF protection: allow loopback only for SSH resources.
        if (!ctx.is_safe_target(target, protocol == "ssh"))
          return crow::response(400, "Target address is not allowed for this protocol");

        // Validate imageUrl scheme if provided
        if (!image_url.empty() && image_url.rfind("http", 0) != 0 && image_url.rfind("/", 0) != 0)
          return crow::response(400, "Invalid imageUrl: must be HTTP(S) or relative path");

        Resource resource;
        resource.id = ctx.next_resource_id.fetch_add(1);
        resource.name = name;
        resource.target = target;
        resource.protocol = protocol;
        resource.port = port;
        resource.tunnelTicketRateLimitMaxAttempts =
            tunnel_ticket_rate_limit_max_attempts;
        resource.description = description;
        resource.imageUrl = image_url;
        resource.imageData = image_data;
        resource.tagsCsv = tags_csv;
        resource.credentialSource = credential_source;
        resource.httpUsername = http_username;
        resource.httpPassword = http_password;
        resource.sshUsername = ssh_username;
        resource.sshPassword = ssh_password;
        resource.requireAccessJustification = require_access_justification;
        resource.requireDualApproval = require_dual_approval;
        resource.enableCommandGuard = enable_command_guard;
        resource.adaptiveAccessPolicy = adaptive_access_policy;
        resource.riskLevel = risk_level;
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
        return scim_json_response(payload);
      });

  // PUT /api/resources/<int>
  CROW_ROUTE(app, "/api/resources/<int>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            std::string name = body["name"].s();
            std::string target = body["target"].s();
            std::string protocol = body["protocol"].s();
            int port = 22;
            if (body.has("port")) port = body["port"].i();
            int tunnel_ticket_rate_limit_max_attempts = 0;
            if (body.has("tunnelTicketRateLimitMaxAttempts")) {
              tunnel_ticket_rate_limit_max_attempts =
                  body["tunnelTicketRateLimitMaxAttempts"].i();
            }
            std::string description;
            if (body.has("description")) description = body["description"].s();
            std::string image_url;
            if (body.has("imageUrl")) image_url = body["imageUrl"].s();
            std::string image_data;
            if (body.has("imageData")) image_data = body["imageData"].s();
            std::string tags_csv;
            if (body.has("tagsCsv")) {
              tags_csv = join_csv_compact(split_csv_compact(body["tagsCsv"].s()));
            }
            std::string credential_source = "vaulted";
            if (body.has("credentialSource")) {
              credential_source = to_lower(body["credentialSource"].s());
            }
            std::string http_username;
            if (body.has("httpUsername")) http_username = body["httpUsername"].s();
            std::string http_password;
            if (body.has("httpPassword")) http_password = body["httpPassword"].s();
            std::string ssh_username;
            if (body.has("sshUsername")) ssh_username = body["sshUsername"].s();
            std::string ssh_password;
            if (body.has("sshPassword")) ssh_password = body["sshPassword"].s();
            bool require_access_justification = false;
            if (body.has("requireAccessJustification")) {
              require_access_justification = body["requireAccessJustification"].b();
            }
            bool require_dual_approval = false;
            if (body.has("requireDualApproval")) {
              require_dual_approval = body["requireDualApproval"].b();
            }
            bool enable_command_guard = false;
            if (body.has("enableCommandGuard")) {
              enable_command_guard = body["enableCommandGuard"].b();
            }
            bool adaptive_access_policy = false;
            if (body.has("adaptiveAccessPolicy")) {
              adaptive_access_policy = body["adaptiveAccessPolicy"].b();
            }
            std::string risk_level = "low";
            if (body.has("riskLevel")) risk_level = to_lower(body["riskLevel"].s());
            if (!is_allowed_role(risk_level, {"low", "medium", "high", "critical"})) {
              return crow::response(400, "Invalid riskLevel");
            }
            if (!is_valid_credential_source(credential_source)) {
              return crow::response(400, "Invalid credentialSource");
            }

            if (name.empty() || target.empty() || protocol.empty())
              return crow::response(400, "Missing name, target, or protocol");
            if (port <= 0 || port > 65535)
              return crow::response(400, "Invalid port");
            if (tunnel_ticket_rate_limit_max_attempts < 0)
              return crow::response(400, "Invalid tunnelTicketRateLimitMaxAttempts");

            // Validate protocol whitelist
            if (!is_allowed_role(protocol, {"ssh", "rdp", "vnc", "http", "https", "agent"}))
              return crow::response(400, "Invalid protocol");

            // Input length limits
            if (name.size() > 255 || target.size() > 255 || description.size() > 1024 ||
                tags_csv.size() > 512)
              return crow::response(400, "Field too long");

            // SSRF protection: allow loopback only for SSH resources.
            if (!ctx.is_safe_target(target, protocol == "ssh"))
              return crow::response(400, "Target address is not allowed for this protocol");

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
              resource.tunnelTicketRateLimitMaxAttempts =
                  tunnel_ticket_rate_limit_max_attempts;
              resource.description = description;
              resource.imageUrl = image_url;
              resource.imageData = image_data;
              resource.tagsCsv = tags_csv;
              resource.credentialSource = credential_source;
              resource.httpUsername = http_username;
              resource.httpPassword = http_password;
              resource.sshUsername = ssh_username;
              // Only update sshPassword if provided (non-empty)
              if (!ssh_password.empty()) resource.sshPassword = ssh_password;
              resource.requireAccessJustification = require_access_justification;
              resource.requireDualApproval = require_dual_approval;
              resource.enableCommandGuard = enable_command_guard;
              resource.adaptiveAccessPolicy = adaptive_access_policy;
              resource.riskLevel = risk_level;
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
            if (!has_permission(ctx, *auth, "resources.manage"))
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

  // GET /api/access-policies
  CROW_ROUTE(app, "/api/access-policies").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");

        const auto items = query_access_policies(ctx);
        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < items.size(); ++i) {
          payload["items"][static_cast<int>(i)] = access_policy_to_json(items[i]);
        }
        return scim_json_response(payload);
      });

  // POST /api/access-policies
  CROW_ROUTE(app, "/api/access-policies").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        AccessPolicy policy;
        policy.id = next_table_numeric_id(ctx, "access_policies");
        policy.name = body.has("name") ? std::string(body["name"].s()) : "";
        policy.description =
            body.has("description") ? std::string(body["description"].s()) : "";
        policy.identityPattern =
            body.has("identityPattern") ? std::string(body["identityPattern"].s()) : "";
        policy.groupName =
            body.has("groupName") ? std::string(body["groupName"].s()) : "";
        policy.role = body.has("role") ? to_lower(body["role"].s()) : "";
        policy.resourceTagsCsv = body.has("resourceTagsCsv")
                                     ? join_csv_compact(split_csv_compact(body["resourceTagsCsv"].s()))
                                     : "";
        policy.riskLevel = body.has("riskLevel") ? to_lower(body["riskLevel"].s()) : "any";
        policy.ticketRequired =
            body.has("ticketRequired") && body["ticketRequired"].b();
        policy.requireJustification =
            body.has("requireJustification") && body["requireJustification"].b();
        policy.approvalMode =
            body.has("approvalMode") ? to_lower(body["approvalMode"].s()) : "inherit";
        policy.mfaRequirement = body.has("mfaRequirement")
                                    ? to_lower(body["mfaRequirement"].s())
                                    : "any";
        policy.timeWindow =
            body.has("timeWindow") ? to_lower(body["timeWindow"].s()) : "any";
        policy.maxDurationSeconds = body.has("maxDurationSeconds")
                                        ? body["maxDurationSeconds"].i()
                                        : 3600;
        policy.routingConstraint = body.has("routingConstraint")
                                       ? to_lower(body["routingConstraint"].s())
                                       : "any";
        policy.enabled = !body.has("enabled") || body["enabled"].b();
        if (policy.name.empty()) return crow::response(400, "Missing name");
        if (policy.name.size() > 255 || policy.description.size() > 1024 ||
            policy.resourceTagsCsv.size() > 512 || policy.timeWindow.size() > 32) {
          return crow::response(400, "Field too long");
        }
        if (!is_allowed_role(policy.riskLevel, {"any", "low", "medium", "high", "critical"}))
          return crow::response(400, "Invalid riskLevel");
        if (!is_valid_approval_mode(policy.approvalMode))
          return crow::response(400, "Invalid approvalMode");
        if (!is_valid_mfa_requirement(policy.mfaRequirement))
          return crow::response(400, "Invalid mfaRequirement");
        if (!is_valid_routing_constraint(policy.routingConstraint))
          return crow::response(400, "Invalid routingConstraint");
        if (policy.maxDurationSeconds <= 0 || policy.maxDurationSeconds > 86400)
          return crow::response(400, "Invalid maxDurationSeconds");
        if (!is_valid_time_window_format(policy.timeWindow)) {
          return crow::response(400, "Invalid timeWindow format");
        }
        policy.createdAt = now_utc();
        policy.updatedAt = policy.createdAt;
        if (!insert_access_policy_db(ctx, policy))
          return crow::response(500, "Failed to persist access policy");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "access_policy.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = access_policy_to_json(policy).dump();
        event.payloadIsJson = true;
        ctx.append_audit(event);
        return crow::response{access_policy_to_json(policy)};
      });

  // PUT /api/access-policies/<int>
  CROW_ROUTE(app, "/api/access-policies/<int>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, int policy_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");
            auto existing = query_access_policy_by_id(ctx, policy_id);
            if (!existing) return crow::response(404, "Access policy not found");
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            AccessPolicy policy = *existing;
            if (body.has("name")) policy.name = body["name"].s();
            if (body.has("description")) policy.description = body["description"].s();
            if (body.has("identityPattern")) policy.identityPattern = body["identityPattern"].s();
            if (body.has("groupName")) policy.groupName = body["groupName"].s();
            if (body.has("role")) policy.role = to_lower(body["role"].s());
            if (body.has("resourceTagsCsv")) {
              policy.resourceTagsCsv =
                  join_csv_compact(split_csv_compact(body["resourceTagsCsv"].s()));
            }
            if (body.has("riskLevel")) policy.riskLevel = to_lower(body["riskLevel"].s());
            if (body.has("ticketRequired")) policy.ticketRequired = body["ticketRequired"].b();
            if (body.has("requireJustification")) {
              policy.requireJustification = body["requireJustification"].b();
            }
            if (body.has("approvalMode")) policy.approvalMode = to_lower(body["approvalMode"].s());
            if (body.has("mfaRequirement")) {
              policy.mfaRequirement = to_lower(body["mfaRequirement"].s());
            }
            if (body.has("timeWindow")) policy.timeWindow = to_lower(body["timeWindow"].s());
            if (body.has("maxDurationSeconds")) {
              policy.maxDurationSeconds = body["maxDurationSeconds"].i();
            }
            if (body.has("routingConstraint")) {
              policy.routingConstraint = to_lower(body["routingConstraint"].s());
            }
            if (body.has("enabled")) policy.enabled = body["enabled"].b();
            if (policy.name.empty()) return crow::response(400, "Missing name");
            if (!is_allowed_role(policy.riskLevel, {"any", "low", "medium", "high", "critical"}) ||
                !is_valid_approval_mode(policy.approvalMode) ||
                !is_valid_mfa_requirement(policy.mfaRequirement) ||
                !is_valid_routing_constraint(policy.routingConstraint) ||
                policy.maxDurationSeconds <= 0 || policy.maxDurationSeconds > 86400) {
              return crow::response(400, "Invalid policy payload");
            }
            if (!is_valid_time_window_format(policy.timeWindow)) {
              return crow::response(400, "Invalid timeWindow format");
            }
            policy.updatedAt = now_utc();
            if (!update_access_policy_db(ctx, policy))
              return crow::response(500, "Failed to persist access policy");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "access_policy.update";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = access_policy_to_json(policy).dump();
            event.payloadIsJson = true;
            ctx.append_audit(event);
            return crow::response{access_policy_to_json(policy)};
          });

  // DELETE /api/access-policies/<int>
  CROW_ROUTE(app, "/api/access-policies/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int policy_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");
            auto existing = query_access_policy_by_id(ctx, policy_id);
            if (!existing) return crow::response(404, "Access policy not found");
            if (!delete_access_policy_db(ctx, policy_id))
              return crow::response(500, "Failed to delete access policy");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "access_policy.delete";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = access_policy_to_json(*existing).dump();
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "deleted";
            payload["id"] = policy_id;
            return crow::response{payload};
          });

  // GET /api/access-profiles
  CROW_ROUTE(app, "/api/access-profiles").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");
        const auto items = query_access_profiles(ctx);
        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < items.size(); ++i) {
          payload["items"][static_cast<int>(i)] = access_profile_to_json(items[i]);
        }
        return scim_json_response(payload);
      });

  // POST /api/access-profiles
  CROW_ROUTE(app, "/api/access-profiles").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        AccessProfile profile;
        profile.id = next_table_numeric_id(ctx, "access_profiles");
        profile.name = body.has("name") ? std::string(body["name"].s()) : "";
        profile.description =
            body.has("description") ? std::string(body["description"].s()) : "";
        profile.resourceTagsCsv = body.has("resourceTagsCsv")
                                      ? join_csv_compact(split_csv_compact(body["resourceTagsCsv"].s()))
                                      : "";
        profile.resourceIdsCsv = body.has("resourceIdsCsv")
                                     ? join_csv_compact(split_csv_compact(body["resourceIdsCsv"].s()))
                                     : "";
        profile.policyId = body.has("policyId") ? body["policyId"].i() : 0;
        if (profile.name.empty()) return crow::response(400, "Missing name");
        if (profile.name.size() > 255 || profile.description.size() > 1024 ||
            profile.resourceTagsCsv.size() > 512 || profile.resourceIdsCsv.size() > 512) {
          return crow::response(400, "Field too long");
        }
        if (profile.policyId > 0 && !query_access_policy_by_id(ctx, profile.policyId)) {
          return crow::response(404, "Referenced access policy not found");
        }
        profile.createdAt = now_utc();
        profile.updatedAt = profile.createdAt;
        if (!insert_access_profile_db(ctx, profile))
          return crow::response(500, "Failed to persist access profile");

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "access_profile.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = access_profile_to_json(profile).dump();
        event.payloadIsJson = true;
        ctx.append_audit(event);
        return crow::response{access_profile_to_json(profile)};
      });

  // PUT /api/access-profiles/<int>
  CROW_ROUTE(app, "/api/access-profiles/<int>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, int profile_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");
            auto items = query_access_profiles(ctx);
            auto it = std::find_if(items.begin(), items.end(),
                                   [&](const AccessProfile &item) {
                                     return item.id == profile_id;
                                   });
            if (it == items.end()) return crow::response(404, "Access profile not found");
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");
            AccessProfile profile = *it;
            if (body.has("name")) profile.name = body["name"].s();
            if (body.has("description")) profile.description = body["description"].s();
            if (body.has("resourceTagsCsv")) {
              profile.resourceTagsCsv =
                  join_csv_compact(split_csv_compact(body["resourceTagsCsv"].s()));
            }
            if (body.has("resourceIdsCsv")) {
              profile.resourceIdsCsv =
                  join_csv_compact(split_csv_compact(body["resourceIdsCsv"].s()));
            }
            if (body.has("policyId")) profile.policyId = body["policyId"].i();
            if (profile.name.empty()) return crow::response(400, "Missing name");
            if (profile.policyId > 0 && !query_access_policy_by_id(ctx, profile.policyId)) {
              return crow::response(404, "Referenced access policy not found");
            }
            profile.updatedAt = now_utc();
            if (!update_access_profile_db(ctx, profile))
              return crow::response(500, "Failed to persist access profile");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "access_profile.update";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = access_profile_to_json(profile).dump();
            event.payloadIsJson = true;
            ctx.append_audit(event);
            return crow::response{access_profile_to_json(profile)};
          });

  // DELETE /api/access-profiles/<int>
  CROW_ROUTE(app, "/api/access-profiles/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int profile_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "resources.manage"))
              return crow::response(403, "Forbidden");
            auto items = query_access_profiles(ctx);
            auto it = std::find_if(items.begin(), items.end(),
                                   [&](const AccessProfile &item) {
                                     return item.id == profile_id;
                                   });
            if (it == items.end()) return crow::response(404, "Access profile not found");
            if (!delete_access_profile_db(ctx, profile_id))
              return crow::response(500, "Failed to delete access profile");

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "access_profile.delete";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = access_profile_to_json(*it).dump();
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "deleted";
            payload["id"] = profile_id;
            return crow::response{payload};
          });
}

// ══════════════════════════════════════════════════════════════════════
//  Access Requests
// ══════════════════════════════════════════════════════════════════════

void register_access_request_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/access-requests
  CROW_ROUTE(app, "/api/access-requests").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "access_requests.read")) {
          return crow::response(403, "Forbidden");
        }

        std::vector<AccessRequest> items;
        std::vector<AccessRequest> expired_to_persist;
        {
          std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
          items.reserve(ctx.access_requests.size());
          const int64_t now_epoch = now_epoch_seconds();
          for (auto &entry : ctx.access_requests) {
            auto &request_item = entry.second;
            if (request_item.status == "approved") {
              const auto approved_at =
                  parse_utc_epoch_seconds(request_item.reviewedAt);
              if (approved_at && (now_epoch - *approved_at) >
                                     kApprovedAccessTtlSeconds) {
                request_item.status = "expired";
                expired_to_persist.push_back(request_item);
              }
            }
            if (!has_permission(ctx, *auth, "access_requests.review") &&
                !has_permission(ctx, *auth, "audit.read") &&
                request_item.requester != auth->user) {
              continue;
            }
            items.push_back(request_item);
          }
        }

        for (const auto &expired : expired_to_persist) {
          ctx.update_access_request(expired);
          AuditEvent event;
          event.id = ctx.next_audit_id.fetch_add(1);
          event.type = "access_request.expire";
          event.actor = "system";
          event.role = "system";
          event.createdAt = now_utc();
          event.payloadJson = "{\"id\":" + std::to_string(expired.id) +
                              ",\"resourceId\":" +
                              std::to_string(expired.resourceId) + "}";
          event.payloadIsJson = true;
          ctx.append_audit(event);
        }
        std::sort(items.begin(), items.end(),
                  [](const AccessRequest &a, const AccessRequest &b) {
                    return a.id > b.id;
                  });

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < items.size(); ++i) {
          payload["items"][static_cast<int>(i)] = access_request_to_json(items[i]);
        }
        return scim_json_response(payload);
      });

  // POST /api/access-requests
  CROW_ROUTE(app, "/api/access-requests").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "access_requests.create")) {
          return crow::response(403, "Forbidden");
        }

        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");
        if (!body.has("resourceId")) return crow::response(400, "Missing resourceId");

        const int resource_id = body["resourceId"].i();
        std::string justification =
            body.has("justification") ? std::string(body["justification"].s()) : "";
        std::string ticket_id =
            body.has("ticketId") ? std::string(body["ticketId"].s()) : "";

        if (justification.empty()) {
          return crow::response(400, "justification is required for access requests");
        }
        if (justification.size() > 280)
          return crow::response(400, "justification is too long (max 280 chars)");
        if (ticket_id.size() > 80)
          return crow::response(400, "ticketId is too long (max 80 chars)");

        Resource resource;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          auto it = ctx.resources.find(resource_id);
          if (it == ctx.resources.end()) return crow::response(404, "Resource not found");
          resource = it->second;
        }

        if (!has_permission(ctx, *auth, "resources.manage")) {
          auto allowed = ctx.get_resource_permissions(auth->userId);
          if (std::find(allowed.begin(), allowed.end(), resource_id) == allowed.end()) {
            return crow::response(403, "Forbidden");
          }
        }

        AccessRequest req;
        req.id = ctx.next_access_request_id.fetch_add(1);
        req.resourceId = resource.id;
        req.resourceName = resource.name;
        req.requester = auth->user;
        req.requesterRole = auth->role;
        req.status = "pending";
        req.justification = justification;
        req.ticketId = ticket_id;
        req.createdAt = now_utc();

        {
          std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
          ctx.access_requests[req.id] = req;
        }
        if (!ctx.insert_access_request(req)) {
          return crow::response(500, "Failed to persist access request");
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "access_request.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = "{\"id\":" + std::to_string(req.id) +
                            ",\"resourceId\":" + std::to_string(req.resourceId) +
                            ",\"status\":\"pending\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload = access_request_to_json(req);
        return crow::response{payload};
      });

  // POST /api/access-requests/<int>/approve
  CROW_ROUTE(app, "/api/access-requests/<int>/approve")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int req_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "access_requests.review")) {
              return crow::response(403, "Forbidden");
            }

            AccessRequest req;
            {
              std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
              auto it = ctx.access_requests.find(req_id);
              if (it == ctx.access_requests.end()) {
                return crow::response(404, "Access request not found");
              }
              req = it->second;
              req.status = "approved";
              req.reviewedAt = now_utc();
              req.reviewedBy = auth->user;
              it->second = req;
            }
            if (!ctx.update_access_request(req)) {
              return crow::response(500, "Failed to persist decision");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "access_request.approve";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = "{\"id\":" + std::to_string(req.id) +
                                ",\"resourceId\":" + std::to_string(req.resourceId) +
                                ",\"requester\":\"" + json_escape(req.requester) + "\"}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload = access_request_to_json(req);
            return crow::response{payload};
          });

  // POST /api/access-requests/<int>/deny
  CROW_ROUTE(app, "/api/access-requests/<int>/deny")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int req_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "access_requests.review")) {
              return crow::response(403, "Forbidden");
            }

            AccessRequest req;
            {
              std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
              auto it = ctx.access_requests.find(req_id);
              if (it == ctx.access_requests.end()) {
                return crow::response(404, "Access request not found");
              }
              req = it->second;
              req.status = "denied";
              req.reviewedAt = now_utc();
              req.reviewedBy = auth->user;
              it->second = req;
            }
            if (!ctx.update_access_request(req)) {
              return crow::response(500, "Failed to persist decision");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "access_request.deny";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = "{\"id\":" + std::to_string(req.id) +
                                ",\"resourceId\":" + std::to_string(req.resourceId) +
                                ",\"requester\":\"" + json_escape(req.requester) + "\"}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload = access_request_to_json(req);
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
    if (!has_permission(ctx, *auth, "sessions.read"))
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
    if (limit && *limit > 0) {
      // Compute the upper bound in a wider type: start_index and *limit are
      // both client-controlled and can each reach INT_MAX, so start_index +
      // *limit would overflow a signed int (undefined behaviour).
      long long bound = static_cast<long long>(start_index) + *limit;
      end_index = static_cast<int>(std::min<long long>(end_index, bound));
    }
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

  // GET /api/access-grants
  CROW_ROUTE(app, "/api/access-grants").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_any_permission(ctx, *auth, {"sessions.read", "resources.manage"}))
          return crow::response(403, "Forbidden");

        expire_old_access_grants(ctx);
        auto grants = query_access_grants(ctx);
        if (!has_permission(ctx, *auth, "resources.manage")) {
          grants.erase(
              std::remove_if(grants.begin(), grants.end(),
                             [&](const AccessGrant &grant) {
                               return grant.subject != auth->user;
                             }),
              grants.end());
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < grants.size(); ++i) {
          payload["items"][static_cast<int>(i)] = access_grant_to_json(grants[i]);
        }
        return crow::response{payload};
      });

  // POST /api/sessions/risk-preview
  CROW_ROUTE(app, "/api/sessions/risk-preview").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.create"))
          return crow::response(403, "Forbidden");

        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        int resource_id = body.has("resourceId") ? body["resourceId"].i() : 0;
        if (resource_id <= 0) return crow::response(400, "Missing resourceId");
        Resource resource;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          auto it = ctx.resources.find(resource_id);
          if (it == ctx.resources.end())
            return crow::response(404, "Resource not found");
          resource = it->second;
        }
        std::string justification =
            body.has("justification") ? std::string(body["justification"].s()) : "";
        std::string ticket_id =
            body.has("ticketId") ? std::string(body["ticketId"].s()) : "";
        std::string purpose =
            body.has("purpose") ? std::string(body["purpose"].s()) : "";
        const auto account = find_user_account_snapshot(ctx, auth->userId)
                                 .value_or(UserAccount{});
        const auto decision = build_access_decision(
            ctx, *auth, account, resource, query_access_policies(ctx),
            query_user_access_profiles(ctx, auth->userId));
        const std::string risk_level = to_lower(resource.riskLevel);
        const bool purpose_required = decision.purposeRequired;
        int score = base_risk_score_for_level(risk_level);
        std::vector<std::string> factors;
        factors.push_back("base:" + risk_level);

        if (decision.requireJustification && justification.empty()) {
          score += 10;
          factors.push_back("missing_justification:+10");
        }
        if (decision.ticketRequired && ticket_id.empty()) {
          score += 10;
          factors.push_back("missing_ticket_required:+10");
        }
        if (purpose_required && purpose.empty()) {
          score += 15;
          factors.push_back("missing_purpose_bound:+15");
        }
        if (!user_meets_mfa_requirement(account, decision.mfaRequirement)) {
          score += 15;
          factors.push_back("mfa_requirement_unmet:+15");
        }
        if (decision.routingConstraint == "relay") {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          if (!ctx.resource_relay_bindings.count(resource.id) ||
              ctx.resource_relay_bindings[resource.id].empty()) {
            score += 12;
            factors.push_back("relay_required_unavailable:+12");
          }
        }
        if (is_off_hours_utc()) {
          score += 10;
          factors.push_back("off_hours_utc:+10");
        }
        for (const auto &factor : decision.factors) {
          factors.push_back(factor);
        }
        if (score < 0) score = 0;
        if (score > 100) score = 100;

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["score"] = score;
        payload["effectiveRiskLevel"] = risk_level_for_score(score);
        payload["resourceRiskLevel"] = risk_level;
        payload["adaptivePolicyEnabled"] = resource.adaptiveAccessPolicy;
        payload["purposeRequired"] = purpose_required;
        payload["ticketRequired"] = decision.ticketRequired;
        payload["justificationRequired"] = decision.requireJustification;
        payload["approvalRequired"] = decision.approvalRequired;
        payload["mfaRequirement"] = decision.mfaRequirement;
        payload["routingConstraint"] = decision.routingConstraint;
        payload["maxDurationSeconds"] = decision.maxDurationSeconds;
        payload["matchedPolicyIds"] = crow::json::wvalue::list();
        for (size_t i = 0; i < decision.matchedPolicyIds.size(); ++i) {
          payload["matchedPolicyIds"][static_cast<int>(i)] =
              decision.matchedPolicyIds[i];
        }
        payload["factors"] = crow::json::wvalue::list();
        for (size_t i = 0; i < factors.size(); ++i) {
          payload["factors"][static_cast<int>(i)] = factors[i];
        }
        return crow::response{payload};
      });

  // POST /api/sessions
  CROW_ROUTE(app, "/api/sessions").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.create"))
          return crow::response(403, "Forbidden");
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        std::string target = body["target"].s();
        std::string user = body["user"].s();
        std::string protocol = body["protocol"].s();
        std::string justification = body.has("justification")
                                        ? std::string(body["justification"].s())
                                        : "";
        std::string ticket_id = body.has("ticketId")
                                    ? std::string(body["ticketId"].s())
                                    : "";
        std::string purpose = body.has("purpose")
                ? std::string(body["purpose"].s())
                : "";
        std::string purpose_evidence = body.has("purposeEvidence")
                   ? std::string(body["purposeEvidence"].s())
                   : "";
        std::string mission_ref = body.has("missionRef")
                                      ? std::string(body["missionRef"].s())
                                      : "";
        int resource_id = 0;
        if (body.has("resourceId")) resource_id = body["resourceId"].i();
        int access_request_id = 0;
        if (body.has("accessRequestId")) access_request_id = body["accessRequestId"].i();
        int port = 22;
        if (body.has("port")) port = body["port"].i();
        if (target.empty() || user.empty() || protocol.empty())
          return crow::response(400, "Missing target, user, or protocol");
        if (port <= 0 || port > 65535)
          return crow::response(400, "Invalid port");
        if (justification.size() > 280)
          return crow::response(400, "justification is too long (max 280 chars)");
        if (ticket_id.size() > 80)
          return crow::response(400, "ticketId is too long (max 80 chars)");
        if (purpose.size() > 120)
          return crow::response(400, "purpose is too long (max 120 chars)");
        if (purpose_evidence.size() > 280)
          return crow::response(400, "purposeEvidence is too long (max 280 chars)");

        Resource resource;
        bool has_resource = false;
        AccessDecision decision;
        UserAccount account;
        std::string risk_level = "low";
        if (resource_id > 0) {
          {
            std::lock_guard<std::mutex> lock(ctx.resource_mutex);
            auto it = ctx.resources.find(resource_id);
            if (it == ctx.resources.end()) {
              return crow::response(404, "Resource not found");
            }
            resource = it->second;
            has_resource = true;
          }

          // Non-admin users can only open sessions on assigned resources.
          if (!has_permission(ctx, *auth, "resources.manage")) {
            auto allowed = ctx.get_resource_permissions(auth->userId);
            if (std::find(allowed.begin(), allowed.end(), resource_id) ==
                allowed.end()) {
              return crow::response(403, "Forbidden");
            }
          }

          if (resource.target != target || resource.protocol != protocol ||
              resource.port != port) {
            return crow::response(
                400,
                "resourceId does not match target/protocol/port payload");
          }
          const auto maybe_account = find_user_account_snapshot(ctx, auth->userId);
          if (maybe_account) account = *maybe_account;
          decision = build_access_decision(
              ctx, *auth, account, resource, query_access_policies(ctx),
              query_user_access_profiles(ctx, auth->userId));
          risk_level = to_lower(resource.riskLevel);
        } else {
          account = find_user_account_snapshot(ctx, auth->userId).value_or(UserAccount{});
          decision.maxDurationSeconds = 3600;
          decision.mfaRequirement = "any";
        }
        if (mission_ref.empty() && !purpose.empty()) {
          mission_ref = purpose;
        }

        auto emit_policy_decision = [&](const std::string &type,
                                        const std::string &reason) {
          AuditEvent decision_event;
          decision_event.id = ctx.next_audit_id.fetch_add(1);
          decision_event.type = type;
          decision_event.actor = auth->user;
          decision_event.role = auth->role;
          decision_event.createdAt = now_utc();
          std::ostringstream oss;
          oss << "{\"resourceId\":" << resource_id
              << ",\"reason\":\"" << json_escape(reason) << "\"";
          if (!decision.matchedPolicyIds.empty()) {
            oss << ",\"policyIds\":[";
            for (size_t i = 0; i < decision.matchedPolicyIds.size(); ++i) {
              if (i) oss << ',';
              oss << decision.matchedPolicyIds[i];
            }
            oss << "]";
          }
          oss << '}';
          decision_event.payloadJson = oss.str();
          decision_event.payloadIsJson = true;
          ctx.append_audit(decision_event);
        };

        if (decision.requireJustification && justification.empty()) {
          emit_policy_decision("policy.decision.deny", "missing_justification");
          return crow::response(
              400,
              "This resource requires an access justification before connect");
        }

        if (decision.approvalRequired &&
            !has_permission(ctx, *auth, "access_requests.review")) {
          if (access_request_id <= 0) {
            emit_policy_decision("policy.decision.deny", "approval_required");
            return crow::response(
                400,
                "This resource requires dual approval: provide an approved accessRequestId");
          }
          AccessRequest req;
          {
            std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
            auto it = ctx.access_requests.find(access_request_id);
            if (it == ctx.access_requests.end()) {
              return crow::response(404, "Access request not found");
            }
            req = it->second;
          }

          if (req.status == "approved") {
            const int64_t now_epoch = now_epoch_seconds();
            const auto approved_at =
                parse_utc_epoch_seconds(req.reviewedAt);
            if (approved_at && (now_epoch - *approved_at) >
                                   kApprovedAccessTtlSeconds) {
              req.status = "expired";
              {
                std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
                auto it = ctx.access_requests.find(access_request_id);
                if (it != ctx.access_requests.end()) {
                  it->second = req;
                }
              }
              ctx.update_access_request(req);

              AuditEvent expire_event;
              expire_event.id = ctx.next_audit_id.fetch_add(1);
              expire_event.type = "access_request.expire";
              expire_event.actor = "system";
              expire_event.role = "system";
              expire_event.createdAt = now_utc();
              expire_event.payloadJson =
                  "{\"id\":" + std::to_string(req.id) +
                  ",\"resourceId\":" + std::to_string(req.resourceId) +
                  "}";
              expire_event.payloadIsJson = true;
              ctx.append_audit(expire_event);
            }
          }

          if (req.status != "approved") {
            emit_policy_decision("policy.decision.deny", "approval_not_approved");
            return crow::response(403, "Access request is not approved");
          }
          if (req.requester != auth->user || req.resourceId != resource_id) {
            emit_policy_decision("policy.decision.deny", "approval_scope_mismatch");
            return crow::response(403, "Access request does not match requester/resource");
          }
        }

        if (decision.ticketRequired && ticket_id.empty()) {
          emit_policy_decision("policy.decision.deny", "ticket_required");
          return crow::response(
              400,
              "This access path requires a ticketId under JIT policy");
        }
        if (decision.purposeRequired && purpose.empty()) {
          emit_policy_decision("policy.decision.deny", "purpose_required");
          return crow::response(
              400,
              "High-risk resources require a purpose (purpose-bound session)");
        }
        if (!user_meets_mfa_requirement(account, decision.mfaRequirement)) {
          emit_policy_decision("policy.decision.deny", "mfa_requirement_unmet");
          return crow::response(403, "Additional MFA posture is required for this access");
        }
        if (decision.routingConstraint == "relay") {
          std::lock_guard<std::mutex> lock(ctx.relay_mutex);
          if (!ctx.resource_relay_bindings.count(resource_id) ||
              ctx.resource_relay_bindings[resource_id].empty()) {
            emit_policy_decision("policy.decision.deny", "relay_required");
            return crow::response(403, "This access policy requires a relay route");
          }
        }

        bool containment_enabled = false;
        std::string containment_reason;
        {
          std::lock_guard<std::mutex> lock(ctx.containment_mutex);
          containment_enabled = ctx.containment_mode_enabled;
          containment_reason = ctx.containment_reason;
        }
        if (containment_enabled && justification.empty()) {
          AuditEvent blocked_event;
          blocked_event.id = ctx.next_audit_id.fetch_add(1);
          blocked_event.type = "session.create.blocked.containment";
          blocked_event.actor = auth->user;
          blocked_event.role = auth->role;
          blocked_event.createdAt = now_utc();
          blocked_event.payloadJson =
              "{\"resourceId\":" + std::to_string(resource_id) +
              ",\"target\":\"" + json_escape(target) + "\"" +
              ",\"reason\":\"missing_justification\"" +
              ",\"containmentReason\":\"" +
              json_escape(containment_reason) + "\"}";
          blocked_event.payloadIsJson = true;
          ctx.append_audit(blocked_event);
          emit_policy_decision("policy.decision.deny", "containment_justification_required");
          return crow::response(
              400,
              "Containment mode is enabled: provide a justification to open this session");
        }

        emit_policy_decision("policy.decision.allow", "granted");

        AccessGrant grant;
        if (has_resource) {
          grant.id = next_table_numeric_id(ctx, "access_grants");
          grant.policyId = decision.selectedPolicyId;
          grant.profileId = decision.selectedProfileId;
          grant.resourceId = resource.id;
          grant.approvalRef = access_request_id;
          grant.subject = auth->user;
          grant.resourceScope = resource.name.empty()
                                    ? std::to_string(resource.id)
                                    : resource.name;
          grant.grantedAt = now_utc();
          const auto grant_expires_at = checked_epoch_seconds_after(
              now_epoch_seconds(),
              std::max<int64_t>(300, decision.maxDurationSeconds));
          if (!grant_expires_at) {
            return crow::response(500, "Invalid access grant TTL");
          }
          grant.expiresAt = utc_from_epoch_seconds(*grant_expires_at);
          grant.missionRef = mission_ref;
          grant.status = "issued";
          grant.credentialSource = resource.credentialSource;
          grant.routingConstraint = decision.routingConstraint;
          grant.ticketId = ticket_id;
          grant.purpose = purpose;
          grant.justification = justification;
          grant.mfaRequirement = decision.mfaRequirement;
          if (!insert_access_grant_db(ctx, grant)) {
            return crow::response(500, "Failed to persist access grant");
          }

          AuditEvent grant_event;
          grant_event.id = ctx.next_audit_id.fetch_add(1);
          grant_event.type = "access.grant.issued";
          grant_event.actor = auth->user;
          grant_event.role = auth->role;
          grant_event.createdAt = now_utc();
          grant_event.payloadJson = access_grant_to_json(grant).dump();
          grant_event.payloadIsJson = true;
          ctx.append_audit(grant_event);
        }

        Session session;
        session.id = ctx.next_session_id.fetch_add(1);
        session.resourceId = resource_id;
        session.accessGrantId = grant.id;
        session.target = target;
        session.user = user;
        session.protocol = protocol;
        session.port = port;
        session.status = "active";
        session.missionRef = mission_ref;
        session.credentialSource =
            has_resource ? resource.credentialSource : std::string("vaulted");
        session.maxDurationSeconds = decision.maxDurationSeconds;
        session.createdAt = now_utc();

        {
          std::lock_guard<std::mutex> lock(ctx.session_mutex);
          ctx.sessions.emplace(session.id, session);
        }
        if (!ctx.insert_session(session))
          return crow::response(500, "Failed to persist session");
        if (grant.id > 0) {
          update_access_grant_session_binding(ctx, grant.id, session.id);
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "session.create";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_session_payload_json(session);
        if (!justification.empty() || !ticket_id.empty() || !purpose.empty() ||
            !purpose_evidence.empty()) {
          if (!event.payloadJson.empty() && event.payloadJson.back() == '}') {
            event.payloadJson.pop_back();
          }
          if (!justification.empty()) {
            event.payloadJson += ",\"justification\":\"" +
                                 json_escape(justification) + "\"";
          }
          if (!ticket_id.empty()) {
            event.payloadJson +=
                ",\"ticketId\":\"" + json_escape(ticket_id) + "\"";
          }
          if (!purpose.empty()) {
            event.payloadJson +=
                ",\"purpose\":\"" + json_escape(purpose) + "\"";
          }
          if (!purpose_evidence.empty()) {
            event.payloadJson += ",\"purposeEvidence\":\"" +
                                 json_escape(purpose_evidence) + "\"";
          }
          event.payloadJson += "}";
        }
        if (access_request_id > 0) {
          if (!event.payloadJson.empty() && event.payloadJson.back() == '}') {
            event.payloadJson.pop_back();
          }
          event.payloadJson += ",\"accessRequestId\":" +
                               std::to_string(access_request_id) + "}";
        }
        event.payloadIsJson = true;
        ctx.append_audit(event);
        ctx.append_session_dna_entry(session.id, event.id, event.type,
                                     event.payloadJson, event.createdAt);
        ctx.append_session_event("session.create", session);

        if (!purpose.empty()) {
          AuditEvent purpose_event;
          purpose_event.id = ctx.next_audit_id.fetch_add(1);
          purpose_event.type = "session.purpose.bound";
          purpose_event.actor = auth->user;
          purpose_event.role = auth->role;
          purpose_event.createdAt = now_utc();
          purpose_event.payloadJson =
              "{\"sessionId\":" + std::to_string(session.id) +
              ",\"purpose\":\"" + json_escape(purpose) + "\"}";
          purpose_event.payloadIsJson = true;
          ctx.append_audit(purpose_event);
          ctx.append_session_dna_entry(session.id, purpose_event.id,
                                       purpose_event.type,
                                       purpose_event.payloadJson,
                                       purpose_event.createdAt);
        }

        // Compliance signal: track sessions opened without explicit reason.
        if (justification.empty()) {
          AuditEvent reason_event;
          reason_event.id = ctx.next_audit_id.fetch_add(1);
          reason_event.type = "session.create.unjustified";
          reason_event.actor = auth->user;
          reason_event.role = auth->role;
          reason_event.createdAt = now_utc();
          reason_event.payloadJson = "{\"sessionId\":" +
                                     std::to_string(session.id) + "}";
          reason_event.payloadIsJson = true;
          ctx.append_audit(reason_event);
          ctx.append_session_dna_entry(session.id, reason_event.id,
                                       reason_event.type,
                                       reason_event.payloadJson,
                                       reason_event.createdAt);
        }

        crow::json::wvalue payload = session_to_json(session);
        return crow::response{payload};
      });

  // GET /api/sessions/<int>
  CROW_ROUTE(app, "/api/sessions/<int>")(
      [&ctx](const crow::request &request, int session_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.read"))
          return crow::response(403, "Forbidden");
        std::lock_guard<std::mutex> lock(ctx.session_mutex);
        auto it = ctx.sessions.find(session_id);
        if (it == ctx.sessions.end())
          return crow::response(404, "Session not found");
        crow::json::wvalue payload = session_to_json(it->second);
        return crow::response{payload};
      });

  // GET /api/sessions/<int>/dna
  CROW_ROUTE(app, "/api/sessions/<int>/dna")(
      [&ctx](const crow::request &request, int session_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.read"))
          return crow::response(403, "Forbidden");

        auto entries = ctx.get_session_dna_chain(session_id);
        if (entries.empty()) {
          crow::json::wvalue payload;
          payload["status"] = "ok";
          payload["sessionId"] = session_id;
          payload["entries"] = crow::json::wvalue::list();
          payload["verified"] = true;
          payload["message"] = "No session DNA entries";
          return crow::response{payload};
        }

        bool verified = true;
        std::string reason;
        std::string prev = "GENESIS";
        for (const auto &entry : entries) {
          if (entry.prevHash != prev) {
            verified = false;
            reason = "prev_hash_mismatch_at_entry_" + std::to_string(entry.id);
            break;
          }
          const std::string expected = crypto::sha256_hex(
              entry.prevHash + "|" + entry.eventType + "|" +
              entry.payloadHash + "|" + entry.createdAt);
          if (expected != entry.chainHash) {
            verified = false;
            reason = "chain_hash_mismatch_at_entry_" +
                     std::to_string(entry.id);
            break;
          }
          prev = entry.chainHash;
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["sessionId"] = session_id;
        payload["verified"] = verified;
        payload["entries"] = crow::json::wvalue::list();
        for (size_t i = 0; i < entries.size(); ++i) {
          crow::json::wvalue row;
          row["id"] = entries[i].id;
          row["auditEventId"] = entries[i].auditEventId;
          row["eventType"] = entries[i].eventType;
          row["createdAt"] = entries[i].createdAt;
          row["prevHash"] = entries[i].prevHash;
          row["payloadHash"] = entries[i].payloadHash;
          row["chainHash"] = entries[i].chainHash;
          payload["entries"][static_cast<int>(i)] = std::move(row);
        }
        if (!verified) payload["reason"] = reason;
        return crow::response{payload};
      });

  // GET /api/evidence-packs/sessions/<int>
  CROW_ROUTE(app, "/api/evidence-packs/sessions/<int>")
      .methods(crow::HTTPMethod::Get)(
          [&ctx](const crow::request &request, int session_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "sessions.read"))
              return crow::response(403, "Forbidden");

            Session session;
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              auto it = ctx.sessions.find(session_id);
              if (it == ctx.sessions.end()) {
                return crow::response(404, "Session not found");
              }
              session = it->second;
            }

            Resource resource;
            bool has_resource = false;
            if (session.resourceId > 0) {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(session.resourceId);
              if (it != ctx.resources.end()) {
                resource = it->second;
                has_resource = true;
              }
            }

            const auto grant = query_access_grant_by_id(ctx, session.accessGrantId);
            AccessRequest approval;
            bool has_approval = false;
            if (grant && grant->approvalRef > 0) {
              std::lock_guard<std::mutex> lock(ctx.access_request_mutex);
              auto it = ctx.access_requests.find(grant->approvalRef);
              if (it != ctx.access_requests.end()) {
                approval = it->second;
                has_approval = true;
              }
            }

            const auto dna = ctx.get_session_dna_chain(session_id);
            std::vector<AuditEvent> related_audit;
            {
              std::lock_guard<std::mutex> lock(ctx.audit_mutex);
              for (const auto &event : ctx.audit_events) {
                bool include = false;
                if (event.payloadIsJson && !event.payloadJson.empty()) {
                  auto payload = crow::json::load(event.payloadJson);
                  if (payload) {
                    if (payload.has("sessionId") && payload["sessionId"].i() == session_id) {
                      include = true;
                    }
                    if (!include && grant && payload.has("id") &&
                        event.type == "access.grant.issued" &&
                        payload["id"].i() == grant->id) {
                      include = true;
                    }
                    if (!include && has_resource && payload.has("resourceId") &&
                        payload["resourceId"].i() == resource.id &&
                        (event.type.find("policy.decision") != std::string::npos ||
                         event.type.find("access_request.") != std::string::npos)) {
                      include = true;
                    }
                  }
                }
                if (include) related_audit.push_back(event);
              }
            }

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["session"] = session_to_json(session);
            if (has_resource) payload["resource"] = resource_to_json(resource);
            if (grant) payload["accessGrant"] = access_grant_to_json(*grant);
            if (has_approval) payload["approval"] = access_request_to_json(approval);
            payload["sessionDna"] = crow::json::wvalue::list();
            for (size_t i = 0; i < dna.size(); ++i) {
              crow::json::wvalue item;
              item["id"] = dna[i].id;
              item["auditEventId"] = dna[i].auditEventId;
              item["eventType"] = dna[i].eventType;
              item["createdAt"] = dna[i].createdAt;
              item["prevHash"] = dna[i].prevHash;
              item["payloadHash"] = dna[i].payloadHash;
              item["chainHash"] = dna[i].chainHash;
              payload["sessionDna"][static_cast<int>(i)] = std::move(item);
            }
            payload["auditTrail"] = crow::json::wvalue::list();
            for (size_t i = 0; i < related_audit.size(); ++i) {
              crow::json::wvalue item;
              item["id"] = related_audit[i].id;
              item["type"] = related_audit[i].type;
              item["actor"] = related_audit[i].actor;
              item["role"] = related_audit[i].role;
              item["createdAt"] = related_audit[i].createdAt;
              item["payloadRaw"] = related_audit[i].payloadJson;
              item["payloadIsJson"] = related_audit[i].payloadIsJson;
              payload["auditTrail"][static_cast<int>(i)] = std::move(item);
            }

            const std::string secret = ensure_evidence_signing_secret(ctx);
            const std::string canonical = payload.dump();
            payload["digest"] = crypto::sha256_hex(canonical);
            payload["signature"] = crypto::hmac_sha256_hex(secret, canonical);
            payload["signatureMethod"] = "hmac-sha256/server";
            payload["signedAt"] = now_utc();
            return crow::response{payload};
          });

  // POST /api/sessions/<int>/terminate
  CROW_ROUTE(app, "/api/sessions/<int>/terminate")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int session_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "sessions.terminate"))
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

  // POST /api/sessions/<int>/elevation/start
  CROW_ROUTE(app, "/api/sessions/<int>/elevation/start")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int session_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "sessions.create")) {
              return crow::response(403, "Forbidden");
            }
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            Session session;
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              auto it = ctx.sessions.find(session_id);
              if (it == ctx.sessions.end()) {
                return crow::response(404, "Session not found");
              }
              session = it->second;
            }

            std::string scope =
                body.has("scope") ? trim_copy(body["scope"].s()) : "sudo";
            std::string ticket_id =
                body.has("ticketId") ? trim_copy(body["ticketId"].s()) : "";
            std::string justification = body.has("justification")
                                            ? trim_copy(body["justification"].s())
                                            : "";
            if (scope.empty()) scope = "sudo";
            if (scope.size() > 120 || ticket_id.size() > 80 ||
                justification.size() > 280) {
              return crow::response(400, "Field too long");
            }

            if (session.accessGrantId > 0 &&
                !update_access_grant_elevation_scope_db(ctx, session.accessGrantId,
                                                        scope)) {
              return crow::response(500, "Failed to persist elevation scope");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "access.elevation.started";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            std::ostringstream payload;
            payload << "{\"sessionId\":" << session.id
                    << ",\"accessGrantId\":" << session.accessGrantId
                    << ",\"scope\":\"" << json_escape(scope) << "\"";
            if (!ticket_id.empty()) {
              payload << ",\"ticketId\":\"" << json_escape(ticket_id)
                      << "\"";
            }
            if (!justification.empty()) {
              payload << ",\"justification\":\""
                      << json_escape(justification) << "\"";
            }
            if (!session.missionRef.empty()) {
              payload << ",\"missionRef\":\""
                      << json_escape(session.missionRef) << "\"";
            }
            payload << '}';
            event.payloadJson = payload.str();
            event.payloadIsJson = true;
            ctx.append_audit(event);
            ctx.append_session_dna_entry(session.id, event.id, event.type,
                                         event.payloadJson, event.createdAt);

            crow::json::wvalue response;
            response["status"] = "ok";
            response["sessionId"] = session.id;
            response["accessGrantId"] = session.accessGrantId;
            response["scope"] = scope;
            return crow::response{response};
          });

  // POST /api/sessions/<int>/elevation/end
  CROW_ROUTE(app, "/api/sessions/<int>/elevation/end")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int session_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "sessions.terminate")) {
              return crow::response(403, "Forbidden");
            }
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            Session session;
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              auto it = ctx.sessions.find(session_id);
              if (it == ctx.sessions.end()) {
                return crow::response(404, "Session not found");
              }
              session = it->second;
            }

            std::string scope =
                body.has("scope") ? trim_copy(body["scope"].s()) : "";
            std::string reason =
                body.has("reason") ? trim_copy(body["reason"].s()) : "";
            if (scope.size() > 120 || reason.size() > 280) {
              return crow::response(400, "Field too long");
            }
            if (scope.empty() && session.accessGrantId > 0) {
              const auto grant =
                  query_access_grant_by_id(ctx, session.accessGrantId);
              if (grant) scope = grant->elevationScope;
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "access.elevation.ended";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            std::ostringstream payload;
            payload << "{\"sessionId\":" << session.id
                    << ",\"accessGrantId\":" << session.accessGrantId;
            if (!scope.empty()) {
              payload << ",\"scope\":\"" << json_escape(scope) << "\"";
            }
            if (!reason.empty()) {
              payload << ",\"reason\":\"" << json_escape(reason) << "\"";
            }
            payload << '}';
            event.payloadJson = payload.str();
            event.payloadIsJson = true;
            ctx.append_audit(event);
            ctx.append_session_dna_entry(session.id, event.id, event.type,
                                         event.payloadJson, event.createdAt);

            crow::json::wvalue response;
            response["status"] = "ok";
            response["sessionId"] = session.id;
            response["scope"] = scope;
            return crow::response{response};
          });

  // POST /api/sessions/<int>/goal-review
  CROW_ROUTE(app, "/api/sessions/<int>/goal-review")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int session_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "audit.read")) {
              return crow::response(403, "Forbidden");
            }
            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            Session session;
            {
              std::lock_guard<std::mutex> lock(ctx.session_mutex);
              auto it = ctx.sessions.find(session_id);
              if (it == ctx.sessions.end()) {
                return crow::response(404, "Session not found");
              }
              session = it->second;
            }

            const bool goal_matched =
                !body.has("goalMatched") || body["goalMatched"].b();
            std::string summary =
                body.has("summary") ? trim_copy(body["summary"].s()) : "";
            std::string mismatch_reason =
                body.has("mismatchReason") ? trim_copy(body["mismatchReason"].s())
                                           : "";
            if (summary.size() > 280 || mismatch_reason.size() > 280) {
              return crow::response(400, "Field too long");
            }
            if (!goal_matched && mismatch_reason.empty()) {
              return crow::response(400,
                                    "mismatchReason is required when goalMatched is false");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = goal_matched ? "session.goal.match" : "session.goal.mismatch";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            std::ostringstream payload;
            payload << "{\"sessionId\":" << session.id
                    << ",\"goalMatched\":"
                    << (goal_matched ? "true" : "false");
            if (!session.missionRef.empty()) {
              payload << ",\"missionRef\":\""
                      << json_escape(session.missionRef) << "\"";
            }
            if (!summary.empty()) {
              payload << ",\"summary\":\"" << json_escape(summary) << "\"";
            }
            if (!mismatch_reason.empty()) {
              payload << ",\"mismatchReason\":\""
                      << json_escape(mismatch_reason) << "\"";
            }
            payload << '}';
            event.payloadJson = payload.str();
            event.payloadIsJson = true;
            ctx.append_audit(event);
            ctx.append_session_dna_entry(session.id, event.id, event.type,
                                         event.payloadJson, event.createdAt);

            crow::json::wvalue response;
            response["status"] = "ok";
            response["eventType"] = event.type;
            response["sessionId"] = session.id;
            response["goalMatched"] = goal_matched;
            return crow::response{response};
          });

  // GET /api/sessions/stream (SSE)
  CROW_ROUTE(app, "/api/sessions/stream")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.read"))
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
//  Enterprise Foundations (SSO / SCIM / Integrations)
// ══════════════════════════════════════════════════════════════════════

void register_enterprise_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/auth/sso/providers
  CROW_ROUTE(app, "/api/auth/sso/providers").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.manage")) {
          return crow::response(403, "Forbidden");
        }

        const bool oidc_enabled =
            env_flag_enabled("ENDORIUMFORT_SSO_OIDC_ENABLED", true);
        const bool saml_enabled =
            env_flag_enabled("ENDORIUMFORT_SSO_SAML_ENABLED", false);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["singleTenant"] = true;
        payload["items"] = crow::json::wvalue::list();
        const auto &providers = sso_provider_catalog();
        for (size_t i = 0; i < providers.size(); ++i) {
          const auto &provider = providers[i];
          const bool protocol_default =
              std::string(provider.protocol) == "saml" ? saml_enabled : oidc_enabled;
          payload["items"][static_cast<int>(i)]["id"] = provider.id;
          payload["items"][static_cast<int>(i)]["name"] = provider.label;
          payload["items"][static_cast<int>(i)]["protocol"] = provider.protocol;
          payload["items"][static_cast<int>(i)]["enabled"] =
              env_flag_enabled(provider.enabledEnv, protocol_default);
          payload["items"][static_cast<int>(i)]["jitProvisioning"] = true;
        }
        return crow::response{payload};
      });

  // GET /api/auth/sso/config
  CROW_ROUTE(app, "/api/auth/sso/config").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.manage")) {
          return crow::response(403, "Forbidden");
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["singleTenant"] = true;
        payload["oidcEnabled"] =
            env_flag_enabled("ENDORIUMFORT_SSO_OIDC_ENABLED", true);
        payload["samlEnabled"] =
            env_flag_enabled("ENDORIUMFORT_SSO_SAML_ENABLED", false);
        payload["defaultProvider"] =
            env_string_value("ENDORIUMFORT_SSO_DEFAULT_PROVIDER", "keycloak");
        payload["jitProvisioning"] = true;
        payload["scimPreferred"] = true;
        payload["ldapEnabled"] =
            env_flag_enabled("ENDORIUMFORT_LDAP_ENABLED", false);
        payload["oidcStartPath"] = "/api/auth/sso/oidc/start";
        payload["oidcCallbackPath"] = "/api/auth/sso/oidc/callback";
        payload["scimProvisioning"] = true;
        payload["ldapConfigPath"] = "/api/auth/directory/ldap/config";
        payload["ldapTestBindPath"] = "/api/auth/directory/ldap/test-bind";
        return crow::response{payload};
      });

  // GET /api/auth/directory/providers
  CROW_ROUTE(app, "/api/auth/directory/providers")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.manage")) {
          return crow::response(403, "Forbidden");
        }

        const LdapRuntimeConfig ldap_cfg = load_ldap_runtime_config();

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        payload["items"][0]["id"] = "ldap_ad";
        payload["items"][0]["name"] = "LDAP / Active Directory";
        payload["items"][0]["enabled"] = ldap_cfg.enabled;
        payload["items"][0]["supportsBindTest"] = true;
        payload["items"][0]["jitProvisioning"] = true;
        payload["items"][0]["supportsRoleMapping"] = true;
        payload["items"][0]["configPath"] = "/api/auth/directory/ldap/config";
        payload["items"][0]["testBindPath"] =
            "/api/auth/directory/ldap/test-bind";
        return crow::response{payload};
      });

  // GET /api/auth/directory/ldap/config
  CROW_ROUTE(app, "/api/auth/directory/ldap/config")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.manage")) {
          return crow::response(403, "Forbidden");
        }

        const LdapRuntimeConfig ldap_cfg = load_ldap_runtime_config();
        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["config"] = ldap_config_to_json(ldap_cfg);
        return crow::response{payload};
      });

  // POST /api/auth/directory/ldap/test-bind
  CROW_ROUTE(app, "/api/auth/directory/ldap/test-bind")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.manage")) {
          return crow::response(403, "Forbidden");
        }

        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        const std::string username =
            body.has("username") ? trim_copy(std::string(body["username"].s()))
                                 : "";
        const std::string password =
            body.has("password") ? std::string(body["password"].s()) : "";

        if (username.empty() || password.empty()) {
          return crow::response(400, "Missing username or password");
        }

        const LdapRuntimeConfig ldap_cfg = load_ldap_runtime_config();
        std::string directory_identity;
        std::string ldap_error;

        const bool authenticated = ldap_authenticate_user(
            ldap_cfg, username, password, directory_identity, ldap_error);
        const LdapRoleResolution role_resolution =
          resolve_ldap_role(ldap_cfg, username, directory_identity);

        crow::json::wvalue payload;
        payload["provider"] = "ldap_ad";
        payload["username"] = username;
        payload["authenticated"] = authenticated;
        payload["directoryIdentity"] = directory_identity;
        payload["mappedRole"] = role_resolution.role;
        payload["mappingStrategy"] = role_resolution.strategy;
        payload["matchedRule"] = role_resolution.matchedRule;

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();

        if (authenticated) {
          payload["status"] = "ok";
          event.type = "integration.directory.ldap.bind_test.success";
          event.payloadJson = payload.dump();
          event.payloadIsJson = true;
          ctx.append_audit(event);
          return crow::response{payload};
        }

        payload["status"] = "error";
        payload["message"] = ldap_error;
        const bool infrastructure_error =
            ldap_error.find("disabled") != std::string::npos ||
            ldap_error.find("not configured") != std::string::npos ||
            ldap_error.find("not available") != std::string::npos;

        event.type = "integration.directory.ldap.bind_test.failure";
        event.payloadJson = payload.dump();
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::response response{payload};
        response.code = infrastructure_error ? 503 : 401;
        return response;
      });

  // GET /api/scim/v2/ServiceProviderConfig
  CROW_ROUTE(app, "/api/scim/v2/ServiceProviderConfig")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return scim_error_response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.read")) {
          return scim_error_response(403, "Forbidden");
        }

        crow::json::wvalue payload;
        payload["schemas"] = crow::json::wvalue::list();
        payload["schemas"][0] =
            "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig";
        payload["patch"]["supported"] = true;
        payload["bulk"]["supported"] = false;
        payload["filter"]["supported"] = true;
        payload["filter"]["maxResults"] = 200;
        payload["changePassword"]["supported"] = false;
        payload["sort"]["supported"] = false;
        payload["etag"]["supported"] = true;
        payload["authenticationSchemes"] = crow::json::wvalue::list();
        payload["authenticationSchemes"][0]["type"] = "oauthbearertoken";
        payload["authenticationSchemes"][0]["name"] = "Bearer Token";
        payload["authenticationSchemes"][0]["description"] =
            "EndoriumFort API bearer token";
        payload["authenticationSchemes"][0]["primary"] = true;
        return crow::response{payload};
      });

  // GET /api/scim/v2/Users
  CROW_ROUTE(app, "/api/scim/v2/Users").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return scim_error_response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.read")) {
          return scim_error_response(403, "Forbidden");
        }

        ScimListQuery query;
        std::string query_error;
        if (!parse_scim_list_query(request, query, query_error)) {
          return scim_error_response(400, query_error, "invalidValue");
        }
        const auto filter_expression =
            parse_scim_filter_expression(query.filter, query_error);
        if (!query.filter.empty() && !filter_expression) {
          return scim_error_response(400, query_error, "invalidFilter");
        }
        if (filter_expression &&
            !scim_user_filter_supported_attribute(filter_expression->attribute)) {
          return scim_error_response(400,
                                     "Unsupported SCIM filter attribute for Users",
                                     "invalidFilter");
        }

        std::vector<UserAccount> users;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          users.reserve(ctx.users.size());
          for (const auto &entry : ctx.users) users.push_back(entry.second);
        }
        std::sort(users.begin(), users.end(),
                  [](const UserAccount &a, const UserAccount &b) {
                    return a.id < b.id;
                  });

        std::vector<UserAccount> filtered_users;
        filtered_users.reserve(users.size());
        for (const auto &user : users) {
          if (filter_expression &&
              !scim_user_matches_filter(user, *filter_expression)) {
            continue;
          }
          filtered_users.push_back(user);
        }

        const auto page = scim_page_window(query, filtered_users.size());

        crow::json::wvalue payload;
        payload["schemas"] = crow::json::wvalue::list();
        payload["schemas"][0] =
            "urn:ietf:params:scim:api:messages:2.0:ListResponse";
        payload["totalResults"] = static_cast<uint64_t>(filtered_users.size());
        payload["startIndex"] = query.startIndex;
        payload["itemsPerPage"] = static_cast<uint64_t>(page.end - page.start);
        payload["Resources"] = crow::json::wvalue::list();
        unsigned out_index = 0;
        for (std::size_t i = page.start; i < page.end; ++i) {
          payload["Resources"][out_index++] =
              scim_user_resource_json(filtered_users[i]);
        }
        return crow::response{payload};
      });

  // GET /api/scim/v2/Users/<string>
  CROW_ROUTE(app, "/api/scim/v2/Users/<string>")
      .methods(crow::HTTPMethod::Get)(
          [&ctx](const crow::request &request, const std::string &identifier) {
            auto auth = ctx.find_auth(request);
            if (!auth) return scim_error_response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "users.read")) {
              return scim_error_response(403, "Forbidden");
            }

            const auto user_id = resolve_scim_user_id(ctx, identifier);
            if (!user_id)
              return scim_error_response(404, "User not found", "noTarget");

            UserAccount user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(*user_id);
              if (it == ctx.users.end()) {
                return scim_error_response(404, "User not found", "noTarget");
              }
              user = it->second;
            }
            return scim_user_resource_response(user);
          });

  // POST /api/scim/v2/Users
  CROW_ROUTE(app, "/api/scim/v2/Users").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return scim_error_response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.manage")) {
          return scim_error_response(403, "Forbidden");
        }

        auto body = crow::json::load(request.body);
        if (!body)
          return scim_error_response(400, "Invalid JSON body", "invalidSyntax");

        std::string username = scim_username_from_payload(body);
        if (username.empty())
          return scim_error_response(400, "Missing userName", "invalidValue");
        if (username.size() > 128) {
          username.resize(128);
        }
        const std::string normalized_name = to_lower(username);

        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          for (const auto &entry : ctx.users) {
            if (to_lower(entry.second.username) == normalized_name) {
              return scim_error_response(409, "User already exists", "uniqueness");
            }
          }
        }

        UserAccount user;
        user.id = ctx.next_user_id.fetch_add(1);
        user.username = username;
        user.password = crypto::hash_password(ctx.generate_token());
        user.role = scim_role_from_payload(body, "operator");
        user.createdAt = now_utc();
        user.updatedAt = user.createdAt;
        user.bootstrapPasswordChangeRequired = false;
        user.bootstrapMfaRequired = false;

        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          ctx.users[user.id] = user;
        }
        if (!ctx.insert_user(user)) {
          return scim_error_response(500, "Failed to persist SCIM user");
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "user.scim.provisioned";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = build_user_payload_json(user);
        event.payloadIsJson = true;
        ctx.append_audit(event);

        return scim_user_resource_response(user, 201);
      });

  // PUT /api/scim/v2/Users/<string>
  CROW_ROUTE(app, "/api/scim/v2/Users/<string>")
      .methods(crow::HTTPMethod::Put)(
          [&ctx](const crow::request &request, const std::string &identifier) {
            auto auth = ctx.find_auth(request);
            if (!auth) return scim_error_response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "users.manage")) {
              return scim_error_response(403, "Forbidden");
            }

            auto body = crow::json::load(request.body);
            if (!body)
              return scim_error_response(400, "Invalid JSON body", "invalidSyntax");

            auto user_id = resolve_scim_user_id(ctx, identifier);
            if (!user_id)
              return scim_error_response(404, "User not found", "noTarget");

            const auto active = json_bool_field(body, "active");
            if (active && !*active) {
              UserAccount removed;
              int status_code = 500;
              std::string error_message;
              if (!scim_deprovision_user_record(ctx, *user_id, removed, status_code,
                                                error_message)) {
                return scim_error_response(
                    status_code, error_message,
                    scim_error_type_for_status_code(status_code));
              }

              AuditEvent event;
              event.id = ctx.next_audit_id.fetch_add(1);
              event.type = "user.scim.deprovisioned";
              event.actor = auth->user;
              event.role = auth->role;
              event.createdAt = now_utc();
              event.payloadJson = build_user_payload_json(removed);
              event.payloadIsJson = true;
              ctx.append_audit(event);

              crow::response response;
              response.code = 204;
              return response;
            }

            const std::string requested_username = scim_username_from_payload(body);
            const bool role_provided = body.has("role") || body.has("roles");
            const std::optional<std::string> requested_username_opt =
                requested_username.empty()
                    ? std::nullopt
                    : std::optional<std::string>(requested_username);
            const std::optional<std::string> requested_role_opt =
                role_provided ? std::optional<std::string>(
                                    scim_role_from_payload(body, "operator"))
                              : std::nullopt;

            UserAccount user;
            int status_code = 500;
            std::string error_message;
            if (!scim_update_user_record(ctx, *user_id, requested_username_opt,
                                         requested_role_opt, user, status_code,
                                         error_message)) {
              return scim_error_response(
                  status_code, error_message,
                  scim_error_type_for_status_code(status_code));
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.scim.updated";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_user_payload_json(user);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            return scim_user_resource_response(user);
          });

  // PATCH /api/scim/v2/Users/<string>
  CROW_ROUTE(app, "/api/scim/v2/Users/<string>")
      .methods(crow::HTTPMethod::Patch)(
          [&ctx](const crow::request &request, const std::string &identifier) {
            auto auth = ctx.find_auth(request);
            if (!auth) return scim_error_response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "users.manage")) {
              return scim_error_response(403, "Forbidden");
            }

            auto body = crow::json::load(request.body);
            if (!body)
              return scim_error_response(400, "Invalid JSON body", "invalidSyntax");

            auto user_id = resolve_scim_user_id(ctx, identifier);
            if (!user_id)
              return scim_error_response(404, "User not found", "noTarget");

            ScimUserMutation mutation;
            std::string parse_error;
            if (!parse_scim_patch_mutation(body, mutation, parse_error)) {
              return scim_error_response(
                  400, parse_error, scim_error_type_for_detail(400, parse_error));
            }

            if (mutation.active && !*mutation.active) {
              UserAccount removed;
              int status_code = 500;
              std::string error_message;
              if (!scim_deprovision_user_record(ctx, *user_id, removed, status_code,
                                                error_message)) {
                return scim_error_response(
                    status_code, error_message,
                    scim_error_type_for_status_code(status_code));
              }

              AuditEvent event;
              event.id = ctx.next_audit_id.fetch_add(1);
              event.type = "user.scim.deprovisioned";
              event.actor = auth->user;
              event.role = auth->role;
              event.createdAt = now_utc();
              event.payloadJson = build_user_payload_json(removed);
              event.payloadIsJson = true;
              ctx.append_audit(event);

              crow::response response;
              response.code = 204;
              return response;
            }

            UserAccount user;
            if (mutation.username || mutation.role) {
              int status_code = 500;
              std::string error_message;
              if (!scim_update_user_record(ctx, *user_id, mutation.username,
                                           mutation.role, user, status_code,
                                           error_message)) {
                return scim_error_response(
                    status_code, error_message,
                    scim_error_type_for_status_code(status_code));
              }

              AuditEvent event;
              event.id = ctx.next_audit_id.fetch_add(1);
              event.type = "user.scim.patched";
              event.actor = auth->user;
              event.role = auth->role;
              event.createdAt = now_utc();
              event.payloadJson = build_user_payload_json(user);
              event.payloadIsJson = true;
              ctx.append_audit(event);

              return scim_user_resource_response(user);
            }

            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(*user_id);
              if (it == ctx.users.end()) {
                return scim_error_response(404, "User not found", "noTarget");
              }
              user = it->second;
            }
            return scim_user_resource_response(user);
          });

  // DELETE /api/scim/v2/Users/<string>
  CROW_ROUTE(app, "/api/scim/v2/Users/<string>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, const std::string &identifier) {
            auto auth = ctx.find_auth(request);
            if (!auth) return scim_error_response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "users.manage")) {
              return scim_error_response(403, "Forbidden");
            }

            auto user_id = resolve_scim_user_id(ctx, identifier);
            if (!user_id)
              return scim_error_response(404, "User not found", "noTarget");

            UserAccount removed;
            int status_code = 500;
            std::string error_message;
            if (!scim_deprovision_user_record(ctx, *user_id, removed, status_code,
                                              error_message)) {
              return scim_error_response(
                  status_code, error_message,
                  scim_error_type_for_status_code(status_code));
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.scim.deprovisioned";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_user_payload_json(removed);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::response response;
            response.code = 204;
            return response;
          });

  // GET /api/scim/v2/Groups
  CROW_ROUTE(app, "/api/scim/v2/Groups").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return scim_error_response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "users.read")) {
          return scim_error_response(403, "Forbidden");
        }

        ScimListQuery query;
        std::string query_error;
        if (!parse_scim_list_query(request, query, query_error)) {
          return scim_error_response(400, query_error, "invalidValue");
        }
        const auto filter_expression =
            parse_scim_filter_expression(query.filter, query_error);
        if (!query.filter.empty() && !filter_expression) {
          return scim_error_response(400, query_error, "invalidFilter");
        }
        if (filter_expression &&
            !scim_group_filter_supported_attribute(filter_expression->attribute)) {
          return scim_error_response(400,
                                     "Unsupported SCIM filter attribute for Groups",
                                     "invalidFilter");
        }

        std::unordered_map<std::string, std::vector<int>> groups;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          for (const auto &entry : ctx.users) {
            groups[normalize_user_role(entry.second.role)].push_back(entry.first);
          }
        }

        std::vector<std::string> names;
        names.reserve(groups.size());
        for (const auto &entry : groups) names.push_back(entry.first);
        std::sort(names.begin(), names.end());

        std::vector<std::string> filtered_names;
        filtered_names.reserve(names.size());
        for (const auto &name : names) {
          if (filter_expression &&
              !scim_group_matches_filter(name, groups[name], *filter_expression)) {
            continue;
          }
          filtered_names.push_back(name);
        }

        const auto page = scim_page_window(query, filtered_names.size());

        crow::json::wvalue payload;
        payload["schemas"] = crow::json::wvalue::list();
        payload["schemas"][0] =
            "urn:ietf:params:scim:api:messages:2.0:ListResponse";
        payload["totalResults"] = static_cast<uint64_t>(filtered_names.size());
        payload["startIndex"] = query.startIndex;
        payload["itemsPerPage"] = static_cast<uint64_t>(page.end - page.start);
        payload["Resources"] = crow::json::wvalue::list();
        unsigned out_index = 0;
        for (std::size_t i = page.start; i < page.end; ++i) {
          const auto &name = filtered_names[i];
          payload["Resources"][out_index]["schemas"] =
              crow::json::wvalue::list();
          payload["Resources"][out_index]["schemas"][0] =
              "urn:ietf:params:scim:schemas:core:2.0:Group";
          payload["Resources"][out_index]["id"] = "role:" + name;
          payload["Resources"][out_index]["displayName"] = name;
          payload["Resources"][out_index]["members"] =
              crow::json::wvalue::list();
          for (size_t member_index = 0; member_index < groups[name].size();
               ++member_index) {
            payload["Resources"][out_index]["members"]
                   [static_cast<int>(member_index)]["value"] =
                std::to_string(groups[name][member_index]);
          }
          payload["Resources"][out_index]["meta"]["resourceType"] =
              "Group";
          ++out_index;
        }
        return crow::response{payload};
      });

  // GET /api/integrations/itsm/providers
  CROW_ROUTE(app, "/api/integrations/itsm/providers")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage")) {
          return crow::response(403, "Forbidden");
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        const auto &providers = itsm_provider_catalog();
        for (size_t i = 0; i < providers.size(); ++i) {
          payload["items"][static_cast<int>(i)]["id"] = providers[i].id;
          payload["items"][static_cast<int>(i)]["name"] = providers[i].label;
          payload["items"][static_cast<int>(i)]["enabled"] =
              env_flag_enabled(providers[i].enabledEnv, false);
          payload["items"][static_cast<int>(i)]["mode"] = "ticket-verification";
        }
        return crow::response{payload};
      });

  // POST /api/integrations/itsm/verify-ticket
  CROW_ROUTE(app, "/api/integrations/itsm/verify-ticket")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "sessions.create")) {
          return crow::response(403, "Forbidden");
        }
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        const std::string provider =
            body.has("provider") ? to_lower(trim_copy(body["provider"].s())) : "";
        const std::string ticket_id =
            body.has("ticketId") ? trim_copy(body["ticketId"].s()) : "";
        const std::string fail_mode = body.has("failMode")
                                          ? to_lower(trim_copy(body["failMode"].s()))
                                          : "fail-closed";
        const bool simulate_unavailable =
            body.has("simulateUnavailable") && body["simulateUnavailable"].b();

        if (!is_allowed_role(provider, {"servicenow", "jira"})) {
          return crow::response(400, "Unsupported provider");
        }
        if (!is_valid_fail_mode(fail_mode)) {
          return crow::response(400, "Invalid failMode");
        }
        if (ticket_id.empty()) return crow::response(400, "Missing ticketId");
        if (ticket_id.size() > 80) return crow::response(400, "ticketId is too long");

        const char *provider_env =
            provider == "servicenow" ? "ENDORIUMFORT_ITSM_SERVICENOW_ENABLED"
                                      : "ENDORIUMFORT_ITSM_JIRA_ENABLED";
        const bool provider_enabled = env_flag_enabled(provider_env, false);
        const bool unavailable = simulate_unavailable || !provider_enabled;

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["provider"] = provider;
        payload["ticketId"] = ticket_id;
        payload["failMode"] = fail_mode;

        if (unavailable) {
          payload["verified"] = false;
          payload["reason"] = "provider_unavailable";
          payload["policyDecision"] =
              fail_mode == "fail-open" ? "allow" : "deny";

          AuditEvent event;
          event.id = ctx.next_audit_id.fetch_add(1);
          event.type = "integration.ticket.unavailable";
          event.actor = auth->user;
          event.role = auth->role;
          event.createdAt = now_utc();
          event.payloadJson = payload.dump();
          event.payloadIsJson = true;
          ctx.append_audit(event);

          crow::response response{payload};
          response.code = fail_mode == "fail-open" ? 200 : 503;
          return response;
        }

        const bool verified = is_plausible_ticket_id(ticket_id);
        payload["verified"] = verified;
        payload["policyDecision"] = verified ? "allow" : "deny";

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = verified ? "integration.ticket.verified"
                              : "integration.ticket.rejected";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = payload.dump();
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::response response{payload};
        response.code = verified ? 200 : 400;
        return response;
      });

  // GET /api/integrations/siem/channels
  CROW_ROUTE(app, "/api/integrations/siem/channels")
      .methods(crow::HTTPMethod::Get)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage")) {
          return crow::response(403, "Forbidden");
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["defaultDeliveryMode"] =
            env_string_value("ENDORIUMFORT_INTEGRATIONS_DELIVERY_MODE", "fail-open");
        payload["items"] = crow::json::wvalue::list();
        const auto &channels = siem_channel_catalog();
        for (size_t i = 0; i < channels.size(); ++i) {
          payload["items"][static_cast<int>(i)]["id"] = channels[i].id;
          payload["items"][static_cast<int>(i)]["name"] = channels[i].label;
          payload["items"][static_cast<int>(i)]["enabled"] =
              env_flag_enabled(channels[i].enabledEnv, false);
        }
        return crow::response{payload};
      });

  // POST /api/integrations/siem/events
  CROW_ROUTE(app, "/api/integrations/siem/events")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_any_permission(ctx, *auth, {"audit.read", "resources.manage"})) {
          return crow::response(403, "Forbidden");
        }
        auto body = crow::json::load(request.body);
        if (!body) return crow::response(400, "Invalid JSON body");

        const std::string event_type =
            body.has("eventType") ? trim_copy(body["eventType"].s()) : "";
        const std::string channel =
            body.has("channel") ? to_lower(trim_copy(body["channel"].s()))
                                : "json_webhook";
        const std::string delivery_mode = body.has("deliveryMode")
                                              ? to_lower(trim_copy(body["deliveryMode"].s()))
                                              : to_lower(env_string_value(
                                                    "ENDORIUMFORT_INTEGRATIONS_DELIVERY_MODE",
                                                    "fail-open"));
        const bool simulate_failure =
            body.has("simulateFailure") && body["simulateFailure"].b();

        if (event_type.empty()) return crow::response(400, "Missing eventType");
        if (event_type.size() > 120) return crow::response(400, "eventType is too long");
        if (!is_valid_fail_mode(delivery_mode)) {
          return crow::response(400, "Invalid deliveryMode");
        }

        const auto &channels = siem_channel_catalog();
        auto channel_it =
            std::find_if(channels.begin(), channels.end(),
                         [&](const IntegrationDescriptor &item) {
                           return channel == item.id;
                         });
        if (channel_it == channels.end()) {
          return crow::response(400, "Unsupported SIEM channel");
        }

        const bool channel_enabled =
            env_flag_enabled(channel_it->enabledEnv, false);
        const bool delivery_failed = simulate_failure || !channel_enabled;

        crow::json::wvalue payload;
        payload["status"] = delivery_failed ? "degraded" : "ok";
        payload["eventType"] = event_type;
        payload["channel"] = channel;
        payload["deliveryMode"] = delivery_mode;
        payload["delivered"] = !delivery_failed;
        payload["policyDecision"] =
            (!delivery_failed || delivery_mode == "fail-open") ? "allow" : "deny";

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = delivery_failed ? "integration.siem.delivery_failed"
                                     : "integration.siem.forwarded";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson = payload.dump();
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::response response{payload};
        if (!delivery_failed) {
          response.code = 200;
        } else if (delivery_mode == "fail-open") {
          response.code = 202;
        } else {
          response.code = 502;
        }
        return response;
      });
}

// ══════════════════════════════════════════════════════════════════════
//  Audit
// ══════════════════════════════════════════════════════════════════════

void register_audit_routes(CrowApp &app, AppContext &ctx) {
  // GET /api/security/alerts
  CROW_ROUTE(app, "/api/security/alerts")([&ctx](const crow::request &request) {
    auto auth = ctx.find_auth(request);
    if (!auth) return crow::response(401, "Unauthorized");
    if (!has_permission(ctx, *auth, "audit.read"))
      return crow::response(403, "Forbidden");

    const char *since_param = request.url_params.get("sinceId");
    const int since_id = parse_int_param(since_param).value_or(0);

    // Generate derived behavioral anomalies before returning live alerts.
    maybe_emit_stale_session_anomalies(ctx);

    std::vector<AuditEvent> snapshot;
    int max_event_id = since_id;
    {
      std::lock_guard<std::mutex> lock(ctx.audit_mutex);
      snapshot.reserve(ctx.audit_events.size());
      for (const auto &event : ctx.audit_events) {
        if (event.id > max_event_id) max_event_id = event.id;
        if (event.id > since_id) snapshot.push_back(event);
      }
    }

    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["sinceId"] = since_id;
    payload["maxEventId"] = max_event_id;
    payload["items"] = crow::json::wvalue::list();

    int index = 0;
    for (const auto &event : snapshot) {
      const auto classification = classify_security_alert_type(event.type);
      if (!classification) continue;
      payload["items"][index]["id"] = event.id;
      payload["items"][index]["eventType"] = event.type;
      payload["items"][index]["createdAt"] = event.createdAt;
      payload["items"][index]["actor"] = event.actor;
      payload["items"][index]["severity"] = classification->severity;
      payload["items"][index]["title"] = classification->title;
      payload["items"][index]["hint"] = classification->hint;
      auto session_id = extract_session_id_from_audit_event(event);
      if (session_id) {
        payload["items"][index]["sessionId"] = *session_id;
      }
      ++index;
      if (index >= 100) break;
    }

    return crow::response{payload};
  });

  // POST /api/security/incidents/escalate
  CROW_ROUTE(app, "/api/security/incidents/escalate")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "audit.read"))
          return crow::response(403, "Forbidden");

        auto body = crow::json::load(request.body);
        int critical_count = 0;
        int window_seconds = 0;
        std::string profile = "normal";
        if (body) {
          if (body.has("criticalCount")) critical_count = body["criticalCount"].i();
          if (body.has("windowSeconds")) window_seconds = body["windowSeconds"].i();
          if (body.has("profile")) profile = body["profile"].s();
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "security.incident.escalated";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = now_utc();
        event.payloadJson =
            "{\"criticalCount\":" + std::to_string(std::max(0, critical_count)) +
            ",\"windowSeconds\":" + std::to_string(std::max(0, window_seconds)) +
            ",\"profile\":\"" + json_escape(profile) +
            "\",\"source\":\"frontend.live_alert\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "accepted";
        payload["id"] = event.id;
        return crow::response{payload};
      });

  // GET /api/security/containment
  CROW_ROUTE(app, "/api/security/containment")([&ctx](const crow::request &request) {
    auto auth = ctx.find_auth(request);
    if (!auth) return crow::response(401, "Unauthorized");
    if (!has_permission(ctx, *auth, "audit.read"))
      return crow::response(403, "Forbidden");

    bool enabled = false;
    std::string updated_at;
    std::string updated_by;
    std::string reason;
    {
      std::lock_guard<std::mutex> lock(ctx.containment_mutex);
      enabled = ctx.containment_mode_enabled;
      updated_at = ctx.containment_updated_at;
      updated_by = ctx.containment_updated_by;
      reason = ctx.containment_reason;
    }

    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["enabled"] = enabled;
    payload["updatedAt"] = updated_at;
    payload["updatedBy"] = updated_by;
    payload["reason"] = reason;
    return crow::response{payload};
  });

  // POST /api/security/containment
  CROW_ROUTE(app, "/api/security/containment")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");

        auto body = crow::json::load(request.body);
        if (!body || !body.has("enabled"))
          return crow::response(400, "Missing enabled field");

        const bool enabled = body["enabled"].b();
        std::string reason = body.has("reason") ? std::string(body["reason"].s()) : "";
        if (reason.size() > 280)
          return crow::response(400, "reason is too long (max 280 chars)");

        const std::string updated_at = now_utc();
        {
          std::lock_guard<std::mutex> lock(ctx.containment_mutex);
          ctx.containment_mode_enabled = enabled;
          ctx.containment_updated_at = updated_at;
          ctx.containment_updated_by = auth->user;
          ctx.containment_reason = reason;
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = enabled ? "security.containment.enabled"
                             : "security.containment.disabled";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = updated_at;
        event.payloadJson =
            "{\"enabled\":" + std::string(enabled ? "true" : "false") +
            ",\"reason\":\"" + json_escape(reason) +
            "\",\"source\":\"frontend.incident_banner\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["enabled"] = enabled;
        payload["updatedAt"] = updated_at;
        payload["updatedBy"] = auth->user;
        payload["reason"] = reason;
        payload["auditId"] = event.id;
        return crow::response{payload};
      });

  // GET /api/security/incidents/active
  CROW_ROUTE(app, "/api/security/incidents/active")([&ctx](const crow::request &request) {
    auto auth = ctx.find_auth(request);
    if (!auth) return crow::response(401, "Unauthorized");
    if (!has_permission(ctx, *auth, "audit.read"))
      return crow::response(403, "Forbidden");

    bool active = false;
    int incident_id = 0;
    int critical_count = 0;
    int window_seconds = 0;
    std::string profile;
    std::string title;
    std::string summary;
    std::string opened_at;
    std::string opened_by;
    std::string closed_at;
    std::string closed_by;
    std::string close_reason;
    {
      std::lock_guard<std::mutex> lock(ctx.incident_mutex);
      active = ctx.incident_active;
      incident_id = ctx.incident_id;
      critical_count = ctx.incident_critical_count;
      window_seconds = ctx.incident_window_seconds;
      profile = ctx.incident_profile;
      title = ctx.incident_title;
      summary = ctx.incident_summary;
      opened_at = ctx.incident_opened_at;
      opened_by = ctx.incident_opened_by;
      closed_at = ctx.incident_closed_at;
      closed_by = ctx.incident_closed_by;
      close_reason = ctx.incident_close_reason;
    }

    crow::json::wvalue payload;
    payload["status"] = "ok";
    payload["active"] = active;
    payload["incident"]["id"] = incident_id;
    payload["incident"]["criticalCount"] = critical_count;
    payload["incident"]["windowSeconds"] = window_seconds;
    payload["incident"]["profile"] = profile;
    payload["incident"]["title"] = title;
    payload["incident"]["summary"] = summary;
    payload["incident"]["openedAt"] = opened_at;
    payload["incident"]["openedBy"] = opened_by;
    payload["incident"]["closedAt"] = closed_at;
    payload["incident"]["closedBy"] = closed_by;
    payload["incident"]["closeReason"] = close_reason;
    return crow::response{payload};
  });

  // POST /api/security/incidents/open
  CROW_ROUTE(app, "/api/security/incidents/open")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "audit.read"))
          return crow::response(403, "Forbidden");

        auto body = crow::json::load(request.body);
        int critical_count = 0;
        int window_seconds = 0;
        std::string profile = "normal";
        std::string title = "Potential Security Incident";
        std::string summary = "Escalated from live security signals.";
        if (body) {
          if (body.has("criticalCount")) critical_count = body["criticalCount"].i();
          if (body.has("windowSeconds")) window_seconds = body["windowSeconds"].i();
          if (body.has("profile")) profile = body["profile"].s();
          if (body.has("title")) title = body["title"].s();
          if (body.has("summary")) summary = body["summary"].s();
        }
        if (title.size() > 140)
          return crow::response(400, "title is too long (max 140 chars)");
        if (summary.size() > 280)
          return crow::response(400, "summary is too long (max 280 chars)");

        int incident_id = 0;
        std::string opened_at;
        {
          std::lock_guard<std::mutex> lock(ctx.incident_mutex);
          if (ctx.incident_active) {
            return crow::response(409, "An incident case is already active");
          }
          incident_id = ctx.next_incident_id.fetch_add(1);
          opened_at = now_utc();
          ctx.incident_active = true;
          ctx.incident_id = incident_id;
          ctx.incident_critical_count = std::max(0, critical_count);
          ctx.incident_window_seconds = std::max(0, window_seconds);
          ctx.incident_profile = profile;
          ctx.incident_title = title;
          ctx.incident_summary = summary;
          ctx.incident_opened_at = opened_at;
          ctx.incident_opened_by = auth->user;
          ctx.incident_closed_at.clear();
          ctx.incident_closed_by.clear();
          ctx.incident_close_reason.clear();
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "security.incident.opened";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = opened_at;
        event.payloadJson =
            "{\"incidentId\":" + std::to_string(incident_id) +
            ",\"criticalCount\":" + std::to_string(std::max(0, critical_count)) +
            ",\"windowSeconds\":" + std::to_string(std::max(0, window_seconds)) +
            ",\"profile\":\"" + json_escape(profile) +
            "\",\"title\":\"" + json_escape(title) +
            "\",\"source\":\"frontend.incident_banner\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["active"] = true;
        payload["incident"]["id"] = incident_id;
        payload["incident"]["criticalCount"] = std::max(0, critical_count);
        payload["incident"]["windowSeconds"] = std::max(0, window_seconds);
        payload["incident"]["profile"] = profile;
        payload["incident"]["title"] = title;
        payload["incident"]["summary"] = summary;
        payload["incident"]["openedAt"] = opened_at;
        payload["incident"]["openedBy"] = auth->user;
        payload["auditId"] = event.id;
        return crow::response{payload};
      });

  // POST /api/security/incidents/close
  CROW_ROUTE(app, "/api/security/incidents/close")
      .methods(crow::HTTPMethod::Post)([&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "resources.manage"))
          return crow::response(403, "Forbidden");

        auto body = crow::json::load(request.body);
        std::string reason = body && body.has("reason") ? std::string(body["reason"].s()) : "";
        if (reason.size() > 280)
          return crow::response(400, "reason is too long (max 280 chars)");

        int incident_id = 0;
        std::string incident_title;
        std::string closed_at;
        {
          std::lock_guard<std::mutex> lock(ctx.incident_mutex);
          if (!ctx.incident_active) {
            return crow::response(404, "No active incident case");
          }
          incident_id = ctx.incident_id;
          incident_title = ctx.incident_title;
          closed_at = now_utc();
          ctx.incident_active = false;
          ctx.incident_closed_at = closed_at;
          ctx.incident_closed_by = auth->user;
          ctx.incident_close_reason = reason;
        }

        AuditEvent event;
        event.id = ctx.next_audit_id.fetch_add(1);
        event.type = "security.incident.closed";
        event.actor = auth->user;
        event.role = auth->role;
        event.createdAt = closed_at;
        event.payloadJson =
            "{\"incidentId\":" + std::to_string(incident_id) +
            ",\"title\":\"" + json_escape(incident_title) +
            "\",\"reason\":\"" + json_escape(reason) +
            "\",\"source\":\"frontend.incident_banner\"}";
        event.payloadIsJson = true;
        ctx.append_audit(event);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["active"] = false;
        payload["incidentId"] = incident_id;
        payload["closedAt"] = closed_at;
        payload["closedBy"] = auth->user;
        payload["reason"] = reason;
        payload["auditId"] = event.id;
        return crow::response{payload};
      });

  // POST /api/audit
  CROW_ROUTE(app, "/api/audit").methods(crow::HTTPMethod::Post)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_permission(ctx, *auth, "audit.read"))
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
    if (!has_permission(ctx, *auth, "audit.read"))
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
            payload["webauthnCompatible"] = true;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              }
            }
            payload["message"] =
                "Import the secret or otpauth URI into your authenticator app, "
                "then call /api/auth/verify-2fa with a code to enable.";
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
            bool password_required = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                password_required = it->second.bootstrapPasswordChangeRequired;
              }
            }
            ctx.update_user_bootstrap_flags(auth->userId, password_required, false);

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
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              }
            }
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
            std::string role;
            bool has_webauthn = false;
            UserAccount current_user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it == ctx.users.end())
                return crow::response(404, "User not found");
              current_user = it->second;
              secret = it->second.totpSecret;
              enabled = it->second.totpEnabled;
              role = it->second.role;
              has_webauthn = user_has_webauthn_enabled(it->second);
            }
            if (!enabled)
              return crow::response(400, "2FA is not enabled");
            if (normalize_user_role(role) == "admin" &&
                !admin_can_disable_totp(current_user))
              return crow::response(
                  403,
                  "Admin accounts need at least one MFA method before TOTP can be disabled");

            if (!totp::verify_code(secret, code))
              return crow::response(401, "Invalid TOTP code");

            ctx.update_user_totp(auth->userId, false, "");
            bool prefer_totp = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              prefer_totp = it != ctx.users.end() &&
                            it->second.preferredMfaMethod == "totp";
            }
            if (prefer_totp) {
              ctx.update_user_mfa_preference(auth->userId,
                                             has_webauthn ? "webauthn" : "any");
            }

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
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              }
            }
            return crow::response{payload};
          });

  // GET /api/auth/2fa-status — Check the current 2FA status
  CROW_ROUTE(app, "/api/auth/2fa-status")(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        bool enabled = false;
        bool webauthn_enabled = false;
        std::string preferred_mfa_method = "any";
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it != ctx.users.end()) {
            enabled = it->second.totpEnabled;
            webauthn_enabled = it->second.webauthnCredentialCount > 0;
            preferred_mfa_method = it->second.preferredMfaMethod;
          }
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          auto it = ctx.users.find(auth->userId);
          if (it != ctx.users.end()) {
            apply_auth_mfa_payload(payload, it->second);
          } else {
            payload["totpEnabled"] = enabled;
            payload["webauthnEnabled"] = webauthn_enabled;
            payload["preferredMfaMethod"] = normalize_mfa_preference(preferred_mfa_method);
          }
        }
        payload["credentials"] = crow::json::wvalue::list();
        int idx = 0;
        for (const auto &credential : ctx.get_user_webauthn_credentials(auth->userId)) {
          payload["credentials"][idx++] = webauthn::credential_to_json(credential);
        }
        return crow::response{payload};
      });

  // POST /api/auth/mfa-preference
  CROW_ROUTE(app, "/api/auth/mfa-preference")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            const std::string method =
                body.has("method") ? std::string(body["method"].s()) : std::string();
            const std::string normalized_method = normalize_mfa_preference(method);
            if (normalized_method != method && method != "ANY" && method != "TOTP" &&
                method != "WEBAUTHN") {
              return crow::response(400, "Invalid MFA preference");
            }

            bool totp_enabled = false;
            bool webauthn_enabled = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it == ctx.users.end()) return crow::response(404, "User not found");
              totp_enabled = it->second.totpEnabled;
              webauthn_enabled = it->second.webauthnCredentialCount > 0;
            }
            if (normalized_method == "totp" && !totp_enabled) {
              return crow::response(400, "TOTP is not enabled for this account");
            }
            if (normalized_method == "webauthn" && !webauthn_enabled) {
              return crow::response(400, "No passkey is registered for this account");
            }
            if (!ctx.update_user_mfa_preference(auth->userId, normalized_method)) {
              return crow::response(500, "Failed to save MFA preference");
            }

            crow::json::wvalue payload;
            payload["status"] = "ok";
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              } else {
                payload["totpEnabled"] = totp_enabled;
                payload["webauthnEnabled"] = webauthn_enabled;
                payload["preferredMfaMethod"] = normalized_method;
              }
            }
            return crow::response{payload};
          });

  // POST /api/auth/webauthn/register/options
  CROW_ROUTE(app, "/api/auth/webauthn/register/options")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            std::string label =
                body && body.has("label") ? std::string(body["label"].s()) : std::string();

            const std::string rp_id = webauthn::expected_rp_id(
                request, ctx.webauthn_rp_id_override);
            const std::string origin = webauthn::expected_origin(
                request, ctx.webauthn_origin_override);
            if (!webauthn::is_valid_rp_id(rp_id) ||
                !webauthn::is_valid_origin(origin)) {
              return crow::response(
                  400,
                  "WebAuthn requires a valid domain. Configure "
                  "ENDORIUMFORT_WEBAUTHN_RP_ID and ENDORIUMFORT_WEBAUTHN_ORIGIN "
                  "(example: app.example.com / https://app.example.com), or use localhost in dev.");
            }

            auto challenge = ctx.create_webauthn_challenge(
                auth->userId, auth->user, "register", rp_id, origin);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["requestId"] = challenge.requestId;
            payload["publicKey"]["rp"]["name"] = "EndoriumFort";
            payload["publicKey"]["rp"]["id"] = challenge.rpId;
            payload["publicKey"]["user"]["id"] =
                webauthn::base64url_encode(std::to_string(auth->userId));
            payload["publicKey"]["user"]["name"] = auth->user;
            payload["publicKey"]["user"]["displayName"] = auth->user;
            payload["publicKey"]["challenge"] =
                webauthn::base64url_encode(challenge.challenge);
            payload["publicKey"]["timeout"] = ctx.webauthn_challenge_ttl_seconds * 1000;
            payload["publicKey"]["attestation"] = "none";
            payload["publicKey"]["userVerification"] = "preferred";
            payload["publicKey"]["authenticatorSelection"]["userVerification"] =
                "preferred";
            payload["publicKey"]["pubKeyCredParams"] = crow::json::wvalue::list();
            payload["publicKey"]["pubKeyCredParams"][0]["type"] = "public-key";
            payload["publicKey"]["pubKeyCredParams"][0]["alg"] = -7;
            payload["publicKey"]["pubKeyCredParams"][1]["type"] = "public-key";
            payload["publicKey"]["pubKeyCredParams"][1]["alg"] = -257;
            payload["publicKey"]["excludeCredentials"] = crow::json::wvalue::list();
            int index = 0;
            for (const auto &credential :
                 ctx.get_user_webauthn_credentials(auth->userId)) {
              payload["publicKey"]["excludeCredentials"][index]["type"] =
                  "public-key";
              payload["publicKey"]["excludeCredentials"][index]["id"] =
                  credential.credentialId;
              ++index;
            }
            payload["labelHint"] = label;
            return crow::response{payload};
          });

  // POST /api/auth/webauthn/register/verify
  CROW_ROUTE(app, "/api/auth/webauthn/register/verify")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto body = crow::json::load(request.body);
            if (!body) return crow::response(400, "Invalid JSON body");

            const std::string request_id = body.has("requestId")
                                               ? std::string(body["requestId"].s())
                                               : std::string();
            const std::string credential_id = body.has("credentialId")
                                                  ? std::string(body["credentialId"].s())
                                                  : std::string();
            const std::string public_key = body.has("publicKey")
                                               ? std::string(body["publicKey"].s())
                                               : std::string();
            const std::string client_data_json = body.has("clientDataJSON")
                                                     ? std::string(body["clientDataJSON"].s())
                                                     : std::string();
            const std::string authenticator_data =
                body.has("authenticatorData")
                    ? std::string(body["authenticatorData"].s())
                    : std::string();
            const std::string label =
                body.has("label") ? std::string(body["label"].s()) : std::string();
            const int algorithm = body.has("algorithm") ? body["algorithm"].i() : 0;
            if (request_id.empty() || credential_id.empty() || public_key.empty() ||
                client_data_json.empty() || authenticator_data.empty()) {
              return crow::response(400, "Missing WebAuthn registration payload");
            }
            if (algorithm != -7 && algorithm != -257)
              return crow::response(400, "Only ES256 and RS256 passkeys are supported currently");

            const auto challenge =
                ctx.consume_webauthn_challenge(request_id, auth->userId, "register");
            const auto client_data = webauthn::parse_client_data(client_data_json);
            const auto parsed_auth_data = challenge
                                              ? webauthn::parse_authenticator_data(
                                                    authenticator_data,
                                                    challenge->rpId)
                                              : std::nullopt;
            if (!challenge || !client_data || !parsed_auth_data ||
                client_data->type != "webauthn.create" ||
                client_data->challenge !=
                    webauthn::base64url_encode(challenge->challenge) ||
                client_data->origin != challenge->origin ||
                (parsed_auth_data->flags & 0x01) == 0) {
              return crow::response(401, "WebAuthn registration validation failed");
            }

            WebAuthnCredential credential;
            credential.id = ctx.next_webauthn_credential_id.fetch_add(1);
            credential.userId = auth->userId;
            credential.credentialId = credential_id;
            credential.publicKeySpki = public_key;
            credential.signCount = static_cast<int>(parsed_auth_data->signCount);
            credential.label = label.empty() ? "Security key" : label;
            credential.transportsCsv =
                body.has("transports")
                    ? webauthn::transports_to_csv(body["transports"])
                    : "";
            credential.createdAt = now_utc();

            if (!ctx.insert_webauthn_credential(credential))
              return crow::response(409, "This passkey is already registered");

            bool password_required = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                password_required = it->second.bootstrapPasswordChangeRequired;
              }
            }
            ctx.update_user_bootstrap_flags(auth->userId, password_required, false);

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.webauthn.register";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_webauthn_audit_payload(credential);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "Passkey registered successfully";
            payload["credential"] = webauthn::credential_to_json(credential);
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto it = ctx.users.find(auth->userId);
              if (it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, it->second);
              }
            }
            return crow::response{payload};
          });

  // DELETE /api/auth/webauthn/credentials/<int>
  CROW_ROUTE(app, "/api/auth/webauthn/credentials/<int>")
      .methods(crow::HTTPMethod::Delete)(
          [&ctx](const crow::request &request, int credential_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");

            auto credentials = ctx.get_user_webauthn_credentials(auth->userId);
            auto it = std::find_if(credentials.begin(), credentials.end(),
                                   [credential_id](const WebAuthnCredential &item) {
                                     return item.id == credential_id;
                                   });
            if (it == credentials.end())
              return crow::response(404, "Passkey not found");

            bool totp_enabled = false;
            std::string role;
            UserAccount current_user;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto user_it = ctx.users.find(auth->userId);
              if (user_it == ctx.users.end())
                return crow::response(404, "User not found");
              current_user = user_it->second;
              totp_enabled = user_it->second.totpEnabled;
              role = user_it->second.role;
            }
            if (normalize_user_role(role) == "admin" &&
                !admin_can_remove_webauthn_credential(
                    current_user, static_cast<int>(credentials.size()) - 1)) {
              return crow::response(
                  403,
                  "Admin accounts must keep at least one MFA method enabled");
            }
            if (!ctx.delete_webauthn_credential(credential_id))
              return crow::response(500, "Failed to remove passkey");

            const bool has_webauthn = ctx.user_has_webauthn(auth->userId);
            if (!totp_enabled) {
              ctx.update_user_bootstrap_flags(auth->userId, false, !has_webauthn);
            }
            bool prefer_webauthn = false;
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto user_it = ctx.users.find(auth->userId);
              prefer_webauthn = user_it != ctx.users.end() &&
                                user_it->second.preferredMfaMethod == "webauthn" &&
                                !has_webauthn;
            }
            if (prefer_webauthn) {
              ctx.update_user_mfa_preference(auth->userId,
                                             totp_enabled ? "totp" : "any");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "user.webauthn.delete";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson = build_webauthn_audit_payload(*it);
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["message"] = "Passkey removed";
            {
              std::lock_guard<std::mutex> lock(ctx.user_mutex);
              auto user_it = ctx.users.find(auth->userId);
              if (user_it != ctx.users.end()) {
                apply_auth_mfa_payload(payload, user_it->second);
              }
            }
            payload["credentials"] = crow::json::wvalue::list();
            int idx = 0;
            for (const auto &credential : ctx.get_user_webauthn_credentials(auth->userId)) {
              payload["credentials"][idx++] = webauthn::credential_to_json(credential);
            }
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
        if (!has_permission(ctx, *auth, "recordings.read"))
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
        if (!has_permission(ctx, *auth, "recordings.read"))
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
        if (!has_permission(ctx, *auth, "recordings.read"))
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
        if (!has_permission(ctx, *auth, "stats.read"))
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

        int total_resources = 0, ssh_resources = 0, http_resources = 0,
            rdp_resources = 0, vnc_resources = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          total_resources = static_cast<int>(ctx.resources.size());
          for (const auto &entry : ctx.resources) {
            if (entry.second.protocol == "ssh") ++ssh_resources;
            else if (entry.second.protocol == "http" || entry.second.protocol == "https") ++http_resources;
            else if (entry.second.protocol == "rdp") ++rdp_resources;
            else if (entry.second.protocol == "vnc") ++vnc_resources;
          }
        }

        int total_users = 0, admin_users = 0, admins_without_mfa = 0,
            admins_pending_bootstrap = 0;
        {
          std::lock_guard<std::mutex> lock(ctx.user_mutex);
          total_users = static_cast<int>(ctx.users.size());
          for (const auto &entry : ctx.users) {
            if (!is_user_role(entry.second.role, "admin")) continue;
            ++admin_users;
            if (!user_has_any_mfa_enabled(entry.second)) ++admins_without_mfa;
            if (entry.second.bootstrapPasswordChangeRequired ||
                entry.second.bootstrapMfaRequired) {
              ++admins_pending_bootstrap;
            }
          }
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

        const std::string effective_rp_id =
            webauthn::expected_rp_id(request, ctx.webauthn_rp_id_override);
        const std::string effective_origin =
            webauthn::expected_origin(request, ctx.webauthn_origin_override);
        const bool rp_id_valid = webauthn::is_valid_rp_id(effective_rp_id);
        const bool origin_valid = webauthn::is_valid_origin(effective_origin);

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["sessions"]["total"] = total_sessions;
        payload["sessions"]["active"] = active_sessions;
        payload["sessions"]["terminated"] = terminated_sessions;
        payload["resources"]["total"] = total_resources;
        payload["resources"]["ssh"] = ssh_resources;
        payload["resources"]["http"] = http_resources;
        payload["resources"]["rdp"] = rdp_resources;
        payload["resources"]["vnc"] = vnc_resources;
        payload["users"]["total"] = total_users;
        payload["users"]["admins"] = admin_users;
        payload["users"]["adminsWithoutMfa"] = admins_without_mfa;
        payload["users"]["adminsPendingBootstrap"] = admins_pending_bootstrap;
        payload["recordings"]["total"] = total_recordings;
        payload["audit"]["total"] = total_audit;
        payload["auth"]["activeTokens"] = active_tokens;
        payload["auth"]["runtime"]["port"] = ctx.listen_port;
        payload["auth"]["runtime"]["tokenTtlSeconds"] = ctx.token_ttl_seconds;
        payload["auth"]["runtime"]["webauthnChallengeTtlSeconds"] =
            ctx.webauthn_challenge_ttl_seconds;
        payload["auth"]["runtime"]["webauthnRpIdOverrideConfigured"] =
            !ctx.webauthn_rp_id_override.empty();
        payload["auth"]["runtime"]["webauthnOriginOverrideConfigured"] =
            !ctx.webauthn_origin_override.empty();
        payload["auth"]["webauthn"]["rpId"] = effective_rp_id;
        payload["auth"]["webauthn"]["origin"] = effective_origin;
        payload["auth"]["webauthn"]["rpIdValid"] = rp_id_valid;
        payload["auth"]["webauthn"]["originValid"] = origin_valid;
        payload["auth"]["webauthn"]["configured"] = rp_id_valid && origin_valid;
        payload["relay"]["runtime"]["enrollmentEnabled"] =
            !ctx.relay_enroll_secret.empty();
        payload["relay"]["runtime"]["certificateRequired"] =
            ctx.relay_certificate_required;
        payload["relay"]["runtime"]["certificateTtlSeconds"] =
            ctx.relay_certificate_ttl_seconds;
        payload["relay"]["runtime"]["enrollmentTokenTtlSeconds"] =
            ctx.relay_enrollment_token_ttl_seconds;
        payload["relay"]["runtime"]["tokenTtlSeconds"] =
            ctx.relay_token_ttl_seconds;
        payload["relay"]["runtime"]["heartbeatStaleSeconds"] =
            ctx.relay_heartbeat_stale_seconds;
        return crow::response{payload};
      });

  // GET /api/resources/<int>/credentials — Fetch stored SSH creds for auto-inject
  CROW_ROUTE(app, "/api/resources/<int>/credentials")(
      [&ctx](const crow::request &request, int resource_id) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");
        if (!has_any_permission(ctx, *auth, {"credentials.ephemeral.consume",
                                             "credentials.ephemeral.issue"}))
          return crow::response(403, "Forbidden");

        // Permission check
        std::vector<int> allowed_ids;
        if (has_permission(ctx, *auth, "resources.manage")) {
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

  // POST /api/resources/<int>/ephemeral-credentials — issue one-time lease
  CROW_ROUTE(app, "/api/resources/<int>/ephemeral-credentials")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int resource_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "credentials.ephemeral.issue")) {
              return crow::response(403, "Forbidden");
            }

            if (!has_permission(ctx, *auth, "resources.manage")) {
              auto allowed_ids = ctx.get_resource_permissions(auth->userId);
              if (std::find(allowed_ids.begin(), allowed_ids.end(),
                            resource_id) == allowed_ids.end()) {
                return crow::response(403, "No access to this resource");
              }
            }

            Resource target_resource;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(resource_id);
              if (it == ctx.resources.end()) {
                return crow::response(404, "Resource not found");
              }
              target_resource = it->second;
            }

            if (to_lower(target_resource.protocol) != "ssh") {
              return crow::response(
                  400,
                  "Ephemeral credential lease is only available for SSH resources");
            }
            if (target_resource.sshUsername.empty() ||
                target_resource.sshPassword.empty()) {
              return crow::response(
                  400,
                  "Resource has no vaulted SSH credentials to lease");
            }

            const int64_t now_epoch = now_epoch_seconds();
            EphemeralCredentialLease lease;
            lease.id = ctx.next_ephemeral_credential_id.fetch_add(1);
            lease.resourceId = resource_id;
            lease.requester = auth->user;
            lease.username = target_resource.sshUsername;
            lease.status = "issued";
            lease.issuedAt = now_utc();
            const auto lease_expires_at =
                checked_epoch_seconds_after(now_epoch, kEphemeralLeaseTtlSeconds);
            if (!lease_expires_at) {
              return crow::response(500, "Invalid ephemeral lease TTL");
            }
            lease.expiresAt = utc_from_epoch_seconds(*lease_expires_at);

            {
              std::lock_guard<std::mutex> lock(ctx.ephemeral_credential_mutex);
              ctx.ephemeral_credentials[lease.id] = lease;
            }
            if (!ctx.insert_ephemeral_credential(lease)) {
              return crow::response(500, "Failed to persist lease");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "credential.ephemeral.issue";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson =
                "{\"leaseId\":" + std::to_string(lease.id) +
                ",\"resourceId\":" + std::to_string(resource_id) +
                ",\"expiresAt\":\"" + json_escape(lease.expiresAt) +
                "\"}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["leaseId"] = lease.id;
            payload["resourceId"] = resource_id;
            payload["username"] = lease.username;
            payload["expiresAt"] = lease.expiresAt;
            payload["ttlSeconds"] = static_cast<int>(kEphemeralLeaseTtlSeconds);
            return crow::response{payload};
          });

  // POST /api/ephemeral-credentials/<int>/consume — one-time secret reveal
  CROW_ROUTE(app, "/api/ephemeral-credentials/<int>/consume")
      .methods(crow::HTTPMethod::Post)(
          [&ctx](const crow::request &request, int lease_id) {
            auto auth = ctx.find_auth(request);
            if (!auth) return crow::response(401, "Unauthorized");
            if (!has_permission(ctx, *auth, "credentials.ephemeral.consume")) {
              return crow::response(403, "Forbidden");
            }

            EphemeralCredentialLease lease;
            {
              std::lock_guard<std::mutex> lock(ctx.ephemeral_credential_mutex);
              auto it = ctx.ephemeral_credentials.find(lease_id);
              if (it == ctx.ephemeral_credentials.end()) {
                return crow::response(404, "Lease not found");
              }
              lease = it->second;
            }

            if (!has_permission(ctx, *auth, "resources.manage") &&
                lease.requester != auth->user) {
              return crow::response(403, "Lease requester mismatch");
            }
            if (lease.status != "issued") {
              return crow::response(403, "Lease is not consumable");
            }

            const int64_t now_epoch = now_epoch_seconds();
            const auto expiry_epoch = parse_utc_epoch_seconds(lease.expiresAt);
            if (expiry_epoch && now_epoch > *expiry_epoch) {
              lease.status = "expired";
              {
                std::lock_guard<std::mutex> lock(ctx.ephemeral_credential_mutex);
                auto it = ctx.ephemeral_credentials.find(lease_id);
                if (it != ctx.ephemeral_credentials.end()) it->second = lease;
              }
              ctx.update_ephemeral_credential(lease);
              return crow::response(403, "Lease has expired");
            }

            Resource target_resource;
            {
              std::lock_guard<std::mutex> lock(ctx.resource_mutex);
              auto it = ctx.resources.find(lease.resourceId);
              if (it == ctx.resources.end()) {
                return crow::response(404, "Resource not found");
              }
              target_resource = it->second;
            }

            if (target_resource.sshUsername.empty() ||
                target_resource.sshPassword.empty()) {
              return crow::response(
                  400,
                  "Resource has no vaulted SSH credentials to consume");
            }

            lease.status = "consumed";
            lease.usedAt = now_utc();
            {
              std::lock_guard<std::mutex> lock(ctx.ephemeral_credential_mutex);
              auto it = ctx.ephemeral_credentials.find(lease_id);
              if (it != ctx.ephemeral_credentials.end()) it->second = lease;
            }
            if (!ctx.update_ephemeral_credential(lease)) {
              return crow::response(500, "Failed to persist lease state");
            }

            AuditEvent event;
            event.id = ctx.next_audit_id.fetch_add(1);
            event.type = "credential.ephemeral.consume";
            event.actor = auth->user;
            event.role = auth->role;
            event.createdAt = now_utc();
            event.payloadJson =
                "{\"leaseId\":" + std::to_string(lease.id) +
                ",\"resourceId\":" + std::to_string(lease.resourceId) +
                "}";
            event.payloadIsJson = true;
            ctx.append_audit(event);

            crow::json::wvalue payload;
            payload["status"] = "ok";
            payload["leaseId"] = lease.id;
            payload["resourceId"] = lease.resourceId;
            payload["sshUsername"] = target_resource.sshUsername;
            payload["sshPassword"] = target_resource.sshPassword;
            payload["expiresAt"] = lease.expiresAt;
            return crow::response{payload};
          });
}
