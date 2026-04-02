#pragma once

#include "crypto.h"
#include "crow.h"
#include "models.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace webauthn {

inline std::string base64url_encode(const std::string &input) {
  static const char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string output;
  int val = 0;
  int valb = -6;
  for (unsigned char c : input) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      output.push_back(table[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) output.push_back(table[((val << 8) >> (valb + 8)) & 0x3F]);
  return output;
}

inline std::optional<std::string> base64url_decode(std::string input) {
  static const std::string chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::vector<int> lookup(256, -1);
  for (size_t i = 0; i < chars.size(); ++i) {
    lookup[static_cast<unsigned char>(chars[i])] = static_cast<int>(i);
  }
  std::string output;
  int val = 0;
  int valb = -8;
  for (unsigned char c : input) {
    if (c == '=') break;
    const int decoded = lookup[c];
    if (decoded < 0) return std::nullopt;
    val = (val << 6) + decoded;
    valb += 6;
    if (valb >= 0) {
      output.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return output;
}

inline std::string trim_port(const std::string &host) {
  if (host.empty()) return host;
  if (host.front() == '[') {
    const size_t end = host.find(']');
    return end == std::string::npos ? host : host.substr(0, end + 1);
  }
  const size_t colon = host.find(':');
  return colon == std::string::npos ? host : host.substr(0, colon);
}

inline bool is_ipv4_address(const std::string &value) {
  if (value.empty()) return false;
  int dots = 0;
  for (char ch : value) {
    if (ch == '.') {
      ++dots;
      continue;
    }
    if (!std::isdigit(static_cast<unsigned char>(ch))) return false;
  }
  return dots == 3;
}

inline bool is_loopback_ipv4(const std::string &value) {
  return value == "127.0.0.1";
}

inline bool is_valid_rp_id(const std::string &value) {
  if (value.empty()) return false;
  if (value == "localhost" || is_loopback_ipv4(value)) return true;
  if (is_ipv4_address(value)) return false;
  if (value.front() == '.' || value.back() == '.' || value.find('.') == std::string::npos) {
    return false;
  }
  for (char ch : value) {
    const unsigned char uch = static_cast<unsigned char>(ch);
    if (!(std::isalnum(uch) || ch == '-' || ch == '.')) return false;
  }
  return true;
}

inline std::string request_scheme(const crow::request &request) {
  std::string proto = request.get_header_value("X-Forwarded-Proto");
  std::transform(proto.begin(), proto.end(), proto.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  if (proto == "https" || proto == "http") return proto;
  return request.get_header_value("Origin").rfind("https://", 0) == 0 ? "https"
                                                                       : "http";
}

inline std::string request_host(const crow::request &request) {
  std::string host = request.get_header_value("X-Forwarded-Host");
  if (host.empty()) host = request.get_header_value("Host");
  const size_t comma = host.find(',');
  if (comma != std::string::npos) host = host.substr(0, comma);
  while (!host.empty() && std::isspace(static_cast<unsigned char>(host.front()))) {
    host.erase(host.begin());
  }
  while (!host.empty() && std::isspace(static_cast<unsigned char>(host.back()))) {
    host.pop_back();
  }
  return host;
}

inline bool is_valid_origin(const std::string &origin) {
  return origin.rfind("https://", 0) == 0 ||
         origin.rfind("http://localhost", 0) == 0 ||
         origin.rfind("http://127.0.0.1", 0) == 0;
}

inline std::string expected_origin(const crow::request &request,
                                   const std::string &override_origin = {}) {
  if (!override_origin.empty()) return override_origin;
  const std::string host = request_host(request);
  if (host.empty()) return {};
  return request_scheme(request) + "://" + host;
}

inline std::string expected_rp_id(const crow::request &request,
                                  const std::string &override_rp_id = {}) {
  if (!override_rp_id.empty()) return override_rp_id;
  return trim_port(request_host(request));
}

inline uint32_t read_u32_be(const unsigned char *data) {
  return (static_cast<uint32_t>(data[0]) << 24) |
         (static_cast<uint32_t>(data[1]) << 16) |
         (static_cast<uint32_t>(data[2]) << 8) |
         static_cast<uint32_t>(data[3]);
}

struct ParsedClientData {
  std::string type;
  std::string challenge;
  std::string origin;
  std::string rawJson;
};

inline std::optional<ParsedClientData> parse_client_data(
    const std::string &client_data_b64url) {
  const auto decoded = base64url_decode(client_data_b64url);
  if (!decoded) return std::nullopt;
  auto json = crow::json::load(*decoded);
  if (!json) return std::nullopt;
  ParsedClientData result;
  result.rawJson = *decoded;
  result.type = json.has("type") ? std::string(json["type"].s()) : "";
  result.challenge = json.has("challenge") ? std::string(json["challenge"].s()) : "";
  result.origin = json.has("origin") ? std::string(json["origin"].s()) : "";
  if (result.type.empty() || result.challenge.empty() || result.origin.empty()) {
    return std::nullopt;
  }
  return result;
}

struct ParsedAuthenticatorData {
  std::string raw;
  uint8_t flags = 0;
  uint32_t signCount = 0;
};

inline std::optional<ParsedAuthenticatorData> parse_authenticator_data(
    const std::string &authenticator_data_b64url, const std::string &rp_id) {
  const auto decoded = base64url_decode(authenticator_data_b64url);
  if (!decoded || decoded->size() < 37) return std::nullopt;

  const auto expected_hash =
      crypto::sha256(reinterpret_cast<const uint8_t *>(rp_id.data()), rp_id.size());
  if (!std::equal(expected_hash.begin(), expected_hash.end(), decoded->begin())) {
    return std::nullopt;
  }

  ParsedAuthenticatorData result;
  result.raw = *decoded;
  result.flags = static_cast<uint8_t>((*decoded)[32]);
  result.signCount =
      read_u32_be(reinterpret_cast<const unsigned char *>(decoded->data() + 33));
  return result;
}

inline bool verify_assertion_signature(const std::string &public_key_spki_b64url,
                                       const std::string &authenticator_data_raw,
                                       const std::string &client_data_json_raw,
                                       const std::string &signature_b64url) {
  const auto public_key_der = base64url_decode(public_key_spki_b64url);
  const auto signature = base64url_decode(signature_b64url);
  if (!public_key_der || !signature) return false;

  const auto client_hash = crypto::sha256(
      reinterpret_cast<const uint8_t *>(client_data_json_raw.data()),
      client_data_json_raw.size());
  std::string signed_payload = authenticator_data_raw;
  signed_payload.append(reinterpret_cast<const char *>(client_hash.data()),
                        client_hash.size());

  const unsigned char *der_ptr =
      reinterpret_cast<const unsigned char *>(public_key_der->data());
  EVP_PKEY *raw_pkey =
      d2i_PUBKEY(nullptr, &der_ptr, static_cast<long>(public_key_der->size()));
  if (!raw_pkey) return false;
  std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(raw_pkey,
                                                           &EVP_PKEY_free);

  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(),
                                                              &EVP_MD_CTX_free);
  if (!ctx) return false;
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr,
                           pkey.get()) != 1) {
    return false;
  }
  if (EVP_DigestVerifyUpdate(ctx.get(), signed_payload.data(),
                             signed_payload.size()) != 1) {
    return false;
  }
  return EVP_DigestVerifyFinal(
             ctx.get(),
             reinterpret_cast<const unsigned char *>(signature->data()),
             signature->size()) == 1;
}

inline std::string transports_to_csv(const crow::json::rvalue &value) {
  if (!value || value.t() != crow::json::type::List) return {};
  std::ostringstream oss;
  bool first = true;
  for (const auto &item : value) {
    const std::string transport = item.s();
    if (transport.empty()) continue;
    if (!first) oss << ',';
    first = false;
    oss << transport;
  }
  return oss.str();
}

inline crow::json::wvalue credential_to_json(const WebAuthnCredential &credential) {
  crow::json::wvalue payload;
  payload["id"] = credential.id;
  payload["label"] = credential.label;
  payload["createdAt"] = credential.createdAt;
  payload["lastUsedAt"] = credential.lastUsedAt;
  payload["transports"] = credential.transportsCsv;
  return payload;
}

}  // namespace webauthn
