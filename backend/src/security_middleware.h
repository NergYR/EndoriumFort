#pragma once
// ─── EndoriumFort — Security headers middleware ─────────────────────────
// Global Crow middleware that injects security headers on every response.
// All route files should use CrowApp (= crow::App<SecurityHeadersMiddleware>)
// instead of crow::SimpleApp.

#include "crow.h"

struct SecurityHeadersMiddleware {
  struct context {};

  void before_handle(crow::request & /*req*/, crow::response & /*res*/,
                     context & /*ctx*/) {}

  void after_handle(crow::request & /*req*/, crow::response &res,
                    context & /*ctx*/) {
    res.add_header("X-Content-Type-Options", "nosniff");
    res.add_header("X-Frame-Options", "SAMEORIGIN");
    res.add_header("X-XSS-Protection", "1; mode=block");
    res.add_header("Referrer-Policy", "strict-origin-when-cross-origin");
    res.add_header("Cache-Control", "no-store, no-cache, must-revalidate");
    res.add_header("Pragma", "no-cache");
    res.add_header("Content-Security-Policy",
                    "default-src 'self'; "
                    "script-src 'self' 'unsafe-inline'; "
                    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                    "font-src 'self' https://fonts.gstatic.com; "
                    "img-src 'self' data: https:; "
                    "connect-src 'self' ws: wss:; "
                    "frame-src 'self'");
    res.add_header("Permissions-Policy",
                    "camera=(), microphone=(), geolocation=()");
  }
};

// Every route file should use this alias instead of crow::SimpleApp.
using CrowApp = crow::App<SecurityHeadersMiddleware>;
