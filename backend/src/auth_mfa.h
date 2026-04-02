#pragma once

#include "models.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

inline std::string normalize_mfa_preference(std::string method) {
  std::transform(method.begin(), method.end(), method.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (method == "totp" || method == "webauthn" || method == "any") {
    return method;
  }
  return "any";
}

inline bool user_has_webauthn_enabled(const UserAccount &user) {
  return user.webauthnCredentialCount > 0;
}

inline bool user_has_any_mfa_enabled(const UserAccount &user) {
  return user.totpEnabled || user_has_webauthn_enabled(user);
}

inline std::string effective_mfa_preference(const UserAccount &user) {
  const std::string preferred = normalize_mfa_preference(user.preferredMfaMethod);
  if (preferred == "totp" && !user.totpEnabled) {
    return user_has_webauthn_enabled(user) ? "webauthn" : "any";
  }
  if (preferred == "webauthn" && !user_has_webauthn_enabled(user)) {
    return user.totpEnabled ? "totp" : "any";
  }
  return preferred;
}

inline std::vector<std::string> ordered_mfa_methods_for_login(
    const UserAccount &user) {
  std::vector<std::string> methods;
  const std::string preferred = effective_mfa_preference(user);
  auto append_once = [&methods](const std::string &value) {
    if (std::find(methods.begin(), methods.end(), value) == methods.end()) {
      methods.push_back(value);
    }
  };
  if (preferred == "webauthn" && user_has_webauthn_enabled(user)) {
    append_once("webauthn");
  }
  if (preferred == "totp" && user.totpEnabled) {
    append_once("totp");
  }
  if (user.totpEnabled) append_once("totp");
  if (user_has_webauthn_enabled(user)) append_once("webauthn");
  return methods;
}

inline bool admin_can_disable_totp(const UserAccount &user) {
  return !user.role.empty() &&
         (user.role == "admin" ? user_has_webauthn_enabled(user) : true);
}

inline bool admin_can_remove_webauthn_credential(const UserAccount &user,
                                                 int remaining_credentials) {
  if (user.role != "admin") return true;
  if (remaining_credentials > 0) return true;
  return user.totpEnabled;
}
