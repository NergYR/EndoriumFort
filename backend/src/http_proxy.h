#pragma once
// ─── EndoriumFort — HTTP reverse-proxy logic ────────────────────────────
// Contains the raw HTTP client (http_proxy_request) and the Crow handler
// that implements /proxy/<id>/<path>.

#include "crow.h"
#include "models.h"

#include <string>
#include <unordered_map>

// Forward declaration
struct AppContext;

// Low-level HTTP client: opens a TCP socket, sends one request, returns the
// response.  On error the `error` string is set and the response is empty.
HttpProxyResponse http_proxy_request(
    const std::string &method,
    const std::string &host, int port,
    const std::string &path,
    const std::string &request_body,
    const std::unordered_map<std::string, std::string> &request_headers,
    std::string &error);

// High-level handler: authenticates, resolves the target resource, proxies
// the request and rewrites HTML/cookies/headers.  Used by the two
// CROW_ROUTE entries for /proxy/<int> and /proxy/<int>/<path>.
crow::response handle_proxy_request(
    AppContext &ctx,
    const crow::request &request,
    int resource_id,
    const std::string &path);

// Registers /proxy/<int> and /proxy/<int>/<path> routes.
void register_proxy_routes(crow::SimpleApp &app, AppContext &ctx);

// Registers /api/web/resources/<int>/url and /api/web/resources routes.
void register_web_resource_routes(crow::SimpleApp &app, AppContext &ctx);
