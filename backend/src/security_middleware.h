#pragma once
// ─── EndoriumFort — Security headers middleware ─────────────────────────
// Global Crow middleware that injects security headers on every response.
// All route files should use CrowApp (= crow::App<SecurityHeadersMiddleware>)
// instead of crow::SimpleApp.

#include "crow.h"

#include <algorithm>
#include <cctype>
#include <string>

namespace security_headers {

inline std::string trim_copy(std::string value) {
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.front())) != 0) {
    value.erase(value.begin());
  }
  while (!value.empty() &&
         std::isspace(static_cast<unsigned char>(value.back())) != 0) {
    value.pop_back();
  }
  return value;
}

inline std::string to_lower(std::string value) {
  std::transform(
      value.begin(), value.end(), value.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

inline std::string first_csv_token(const std::string &value) {
  const size_t comma = value.find(',');
  if (comma == std::string::npos) return trim_copy(value);
  return trim_copy(value.substr(0, comma));
}

inline bool request_uses_https(const crow::request &req) {
  const std::string proto =
      to_lower(first_csv_token(req.get_header_value("X-Forwarded-Proto")));
  if (proto == "https") return true;

  const std::string scheme =
      to_lower(first_csv_token(req.get_header_value("X-Forwarded-Scheme")));
  if (scheme == "https") return true;

  const std::string forwarded_ssl =
      to_lower(trim_copy(req.get_header_value("X-Forwarded-Ssl")));
  return forwarded_ssl == "on" || forwarded_ssl == "1" ||
         forwarded_ssl == "true";
}

inline std::string host_without_port(const crow::request &req) {
  std::string host = req.get_header_value("X-Forwarded-Host");
  if (host.empty()) host = req.get_header_value("Host");
  host = first_csv_token(host);
  if (host.empty()) return host;

  if (host.front() == '[') {
    const size_t close_bracket = host.find(']');
    if (close_bracket != std::string::npos && close_bracket > 1) {
      return to_lower(host.substr(1, close_bracket - 1));
    }
  }

  const size_t colon = host.rfind(':');
  if (colon != std::string::npos && host.find(':') == colon) {
    host = host.substr(0, colon);
  }
  return to_lower(host);
}

inline bool is_local_host(const std::string &host) {
  return host == "localhost" || host == "127.0.0.1" || host == "::1";
}

}  // namespace security_headers

struct SecurityHeadersMiddleware {
  struct context {};

  void before_handle(crow::request & /*req*/, crow::response & /*res*/,
                     context & /*ctx*/) {}

  void after_handle(crow::request &req, crow::response &res,
                    context & /*ctx*/) {
    res.add_header("X-Content-Type-Options", "nosniff");
    res.add_header("X-Frame-Options", "SAMEORIGIN");
    // X-XSS-Protection is deprecated in modern browsers; disable legacy mode.
    res.add_header("X-XSS-Protection", "0");
    res.add_header("Referrer-Policy", "strict-origin-when-cross-origin");
    res.add_header("Cache-Control",
                   "no-store, no-cache, must-revalidate, private");
    res.add_header("Pragma", "no-cache");
    res.add_header("Cross-Origin-Opener-Policy", "same-origin");
    res.add_header("Cross-Origin-Resource-Policy", "same-origin");
    res.add_header("X-Permitted-Cross-Domain-Policies", "none");
    res.add_header("Content-Security-Policy",
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
    res.add_header("Permissions-Policy",
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=()");

    const bool https = security_headers::request_uses_https(req);
    const std::string host = security_headers::host_without_port(req);
    if (https && !security_headers::is_local_host(host)) {
      // One year HSTS with subdomains and preload eligibility.
      res.add_header("Strict-Transport-Security",
                     "max-age=31536000; includeSubDomains; preload");
    }
  }
};

// Every route file should use this alias instead of crow::SimpleApp.
using CrowApp = crow::App<SecurityHeadersMiddleware>;
