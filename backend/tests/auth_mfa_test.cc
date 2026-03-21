#include "auth_mfa.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

bool expect_methods(const std::vector<std::string> &actual,
                    const std::vector<std::string> &expected,
                    const std::string &message) {
  if (actual != expected) {
    std::cerr << "[FAIL] " << message << " expected=[";
    for (size_t i = 0; i < expected.size(); ++i) {
      if (i) std::cerr << ',';
      std::cerr << expected[i];
    }
    std::cerr << "] actual=[";
    for (size_t i = 0; i < actual.size(); ++i) {
      if (i) std::cerr << ',';
      std::cerr << actual[i];
    }
    std::cerr << "]" << std::endl;
    return false;
  }
  return true;
}

}  // namespace

int main() {
  bool ok = true;

  UserAccount admin;
  admin.role = "admin";
  admin.totpEnabled = true;
  admin.webauthnCredentialCount = 1;
  admin.preferredMfaMethod = "webauthn";

  ok &= expect(effective_mfa_preference(admin) == "webauthn",
               "effective_mfa_preference should keep an available preferred passkey");
  ok &= expect_methods(ordered_mfa_methods_for_login(admin),
                       {"webauthn", "totp"},
                       "ordered_mfa_methods_for_login should prioritize passkeys");

  admin.webauthnCredentialCount = 0;
  ok &= expect(effective_mfa_preference(admin) == "totp",
               "effective_mfa_preference should fall back to TOTP");
  ok &= expect(admin_can_disable_totp(admin) == false,
               "admin cannot disable TOTP without passkeys");

  admin.totpEnabled = false;
  admin.webauthnCredentialCount = 2;
  admin.preferredMfaMethod = "totp";
  ok &= expect(effective_mfa_preference(admin) == "webauthn",
               "effective_mfa_preference should fall back to passkey");
  ok &= expect(admin_can_remove_webauthn_credential(admin, 1),
               "admin can remove a passkey if another remains");
  ok &= expect(!admin_can_remove_webauthn_credential(admin, 0),
               "admin cannot remove the last passkey without TOTP");

  UserAccount operator_user;
  operator_user.role = "operator";
  operator_user.totpEnabled = false;
  operator_user.webauthnCredentialCount = 1;
  operator_user.preferredMfaMethod = "banana";
  ok &= expect(normalize_mfa_preference("banana") == "any",
               "normalize_mfa_preference should normalize unknown values");
  ok &= expect(effective_mfa_preference(operator_user) == "any",
               "invalid stored preference should degrade to any");
  ok &= expect_methods(ordered_mfa_methods_for_login(operator_user),
                       {"webauthn"},
                       "ordered_mfa_methods_for_login should expose only available factors");
  ok &= expect(admin_can_disable_totp(operator_user),
               "non-admins are not blocked by admin TOTP rule");

  if (!ok) {
    return 1;
  }

  std::cout << "All auth MFA tests passed." << std::endl;
  return 0;
}
