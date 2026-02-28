// ─── EndoriumFort — HTTP reverse-proxy implementation ───────────────────

#include "http_proxy.h"
#include "app_context.h"
#include "utils.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <optional>
#include <sstream>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

// ═══════════════════════════════════════════════════════════════════════
// Low-level raw HTTP client
// ═══════════════════════════════════════════════════════════════════════

HttpProxyResponse http_proxy_request(
    const std::string &method,
    const std::string &host, int port,
    const std::string &path,
    const std::string &request_body,
    const std::unordered_map<std::string, std::string> &request_headers,
    std::string &error) {

  HttpProxyResponse response;

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    error = "Failed to create socket";
    return response;
  }

  struct hostent *server_entry = gethostbyname(host.c_str());
  if (!server_entry) {
    error = "Failed to resolve hostname";
    close(sock);
    return response;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  memcpy(&server_addr.sin_addr.s_addr, server_entry->h_addr,
         server_entry->h_length);

  struct timeval connect_tv;
  connect_tv.tv_sec = 10;
  connect_tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &connect_tv, sizeof(connect_tv));

  if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    error = "Failed to connect to server";
    close(sock);
    return response;
  }

  struct timeval recv_tv;
  recv_tv.tv_sec = 30;
  recv_tv.tv_usec = 0;
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &recv_tv, sizeof(recv_tv));

  // Build HTTP request
  std::ostringstream request;
  request << method << " " << path << " HTTP/1.1\r\n";
  if ((port == 80) || (port == 443)) {
    request << "Host: " << host << "\r\n";
  } else {
    request << "Host: " << host << ":" << port << "\r\n";
  }
  request << "Connection: close\r\n";

  for (const auto &kv : request_headers) {
    if (kv.first != "Host" && kv.first != "Connection") {
      request << kv.first << ": " << kv.second << "\r\n";
    }
  }

  if (!request_body.empty()) {
    request << "Content-Length: " << request_body.length() << "\r\n";
  }

  request << "\r\n";
  if (!request_body.empty()) {
    request << request_body;
  }

  std::string request_str = request.str();

  ssize_t sent = send(sock, request_str.c_str(), request_str.length(), 0);
  if (sent < 0) {
    error = "Failed to send request";
    close(sock);
    return response;
  }

  // ── Receive response ──
  std::string full_response;
  char buffer[8192];
  ssize_t received;

  // Phase 1: Read until headers complete
  bool headers_complete = false;
  size_t header_end_pos = std::string::npos;
  while (!headers_complete) {
    received = recv(sock, buffer, sizeof(buffer), 0);
    if (received <= 0) break;
    full_response.append(buffer, received);
    header_end_pos = full_response.find("\r\n\r\n");
    if (header_end_pos != std::string::npos) {
      headers_complete = true;
    }
  }

  if (!headers_complete) {
    close(sock);
    if (full_response.empty()) {
      error = "No response from upstream";
    } else {
      error = "Incomplete HTTP response headers";
    }
    return response;
  }

  size_t body_start = header_end_pos + 4;
  std::string header_block = full_response.substr(0, header_end_pos);
  std::string header_block_lower = to_lower(header_block);

  long expected_content_length = -1;
  bool is_chunked = false;
  {
    size_t cl_pos = header_block_lower.find("content-length:");
    if (cl_pos != std::string::npos) {
      size_t val_start = cl_pos + 15;
      while (val_start < header_block_lower.size() &&
             header_block_lower[val_start] == ' ') {
        val_start++;
      }
      size_t val_end = header_block_lower.find("\r\n", val_start);
      if (val_end == std::string::npos) val_end = header_block_lower.size();
      try {
        expected_content_length = std::stol(
            header_block_lower.substr(val_start, val_end - val_start));
      } catch (...) {}
    }
    if (header_block_lower.find("transfer-encoding: chunked") != std::string::npos ||
        header_block_lower.find("transfer-encoding:chunked") != std::string::npos) {
      is_chunked = true;
    }
  }

  // Phase 2: Read body
  if (expected_content_length >= 0) {
    size_t body_so_far = full_response.size() - body_start;
    while ((long)body_so_far < expected_content_length) {
      received = recv(sock, buffer, sizeof(buffer), 0);
      if (received <= 0) break;
      full_response.append(buffer, received);
      body_so_far = full_response.size() - body_start;
    }
  } else if (is_chunked) {
    auto has_final_chunk = [&]() -> bool {
      if (full_response.size() < body_start + 5) return false;
      if (full_response.size() >= body_start + 3 &&
          full_response[body_start] == '0' &&
          full_response[body_start + 1] == '\r' &&
          full_response[body_start + 2] == '\n') {
        return true;
      }
      return full_response.find("\r\n0\r\n", body_start) != std::string::npos;
    };
    while (!has_final_chunk()) {
      received = recv(sock, buffer, sizeof(buffer), 0);
      if (received <= 0) break;
      full_response.append(buffer, received);
    }
  } else {
    while ((received = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
      full_response.append(buffer, received);
    }
  }
  close(sock);

  // ── Parse HTTP response ──
  size_t header_end = full_response.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    header_end = full_response.find("\n\n");
    if (header_end == std::string::npos) {
      error = "Invalid HTTP response";
      return response;
    }
    response.body = full_response.substr(header_end + 2);
  } else {
    response.body = full_response.substr(header_end + 4);
  }

  // Parse status line
  size_t status_line_end = full_response.find("\r\n");
  if (status_line_end == std::string::npos) {
    status_line_end = full_response.find("\n");
  }
  std::string status_line = full_response.substr(0, status_line_end);
  size_t code_start = status_line.find(" ") + 1;
  size_t code_end = status_line.find(" ", code_start);
  try {
    response.status_code = std::stoi(
        status_line.substr(code_start, code_end - code_start));
  } catch (const std::exception &) {
    error = "Failed to parse status code";
    return response;
  }

  // Parse response headers
  size_t header_start = status_line_end + 2;
  if (full_response[header_start] == '\r') header_start += 2;

  while (header_start < header_end) {
    size_t header_line_end = full_response.find("\r\n", header_start);
    if (header_line_end == std::string::npos) {
      header_line_end = full_response.find("\n", header_start);
    }

    std::string header_line =
        full_response.substr(header_start, header_line_end - header_start);
    size_t colon_pos = header_line.find(": ");
    if (colon_pos != std::string::npos) {
      std::string header_name = header_line.substr(0, colon_pos);
      std::string header_value = header_line.substr(colon_pos + 2);
      std::string header_name_lower = to_lower(header_name);
      if (header_name_lower == "set-cookie") {
        response.set_cookie_headers.push_back(header_value);
      } else {
        response.headers[header_name_lower] = header_value;
      }
    }
    header_start = header_line_end + 2;
  }

  // De-chunk if needed
  auto encoding_it = response.headers.find("transfer-encoding");
  if (encoding_it != response.headers.end() &&
      encoding_it->second.find("chunked") != std::string::npos) {
    std::string dechunked;
    size_t pos = 0;
    bool dechunk_success = true;

    while (pos < response.body.size() && dechunk_success) {
      size_t line_end = response.body.find("\r\n", pos);
      size_t line_len = 2;
      if (line_end == std::string::npos) {
        line_end = response.body.find('\n', pos);
        line_len = 1;
      }
      if (line_end == std::string::npos) {
        dechunk_success = false;
        break;
      }
      std::string len_text = response.body.substr(pos, line_end - pos);
      size_t ext_pos = len_text.find(';');
      if (ext_pos != std::string::npos) {
        len_text = len_text.substr(0, ext_pos);
      }

      size_t chunk_len = 0;
      try {
        chunk_len = std::stoul(len_text, nullptr, 16);
      } catch (...) {
        dechunk_success = false;
        break;
      }

      pos = line_end + line_len;
      if (chunk_len == 0) break;
      if (pos + chunk_len > response.body.size()) {
        dechunk_success = false;
        break;
      }
      dechunked.append(response.body.substr(pos, chunk_len));
      pos += chunk_len;
      if (pos + 1 < response.body.size() && response.body[pos] == '\r' &&
          response.body[pos + 1] == '\n') {
        pos += 2;
      } else if (pos < response.body.size() && response.body[pos] == '\n') {
        pos += 1;
      }
    }

    if (dechunk_success) {
      response.body = dechunked;
      response.headers.erase("transfer-encoding");
      response.headers["content-length"] = std::to_string(response.body.size());
    }
  }

  return response;
}

// ═══════════════════════════════════════════════════════════════════════
//  Helper lambdas used inside handle_proxy_request (file-local)
// ═══════════════════════════════════════════════════════════════════════

namespace {

auto get_query_param_value(const std::string &query, const std::string &key)
    -> std::optional<std::string> {
  if (query.empty() || key.empty()) return std::nullopt;
  size_t pos = 0;
  while (pos <= query.size()) {
    size_t amp = query.find('&', pos);
    if (amp == std::string::npos) amp = query.size();
    std::string part = query.substr(pos, amp - pos);
    size_t eq = part.find('=');
    std::string name = (eq == std::string::npos) ? part : part.substr(0, eq);
    if (name == key) {
      if (eq == std::string::npos) return std::string();
      return part.substr(eq + 1);
    }
    if (amp == query.size()) break;
    pos = amp + 1;
  }
  return std::nullopt;
}

bool is_bastion_token(const std::string &value) {
  return value.rfind("eft_", 0) == 0 || value.rfind("tok-", 0) == 0;
}

std::string strip_bastion_query_params(const std::string &query,
                                       const std::string &bastion_token) {
  if (query.empty()) return query;
  std::ostringstream out;
  bool first = true;
  size_t pos = 0;
  while (pos <= query.size()) {
    size_t amp = query.find('&', pos);
    if (amp == std::string::npos) amp = query.size();
    std::string part = query.substr(pos, amp - pos);
    bool keep = true;
    if (!part.empty()) {
      size_t eq = part.find('=');
      std::string name = (eq == std::string::npos) ? part : part.substr(0, eq);
      std::string value = (eq == std::string::npos) ? std::string() : part.substr(eq + 1);
      if (name == "ef_token") keep = false;
      if (keep && name == "token" && !bastion_token.empty() &&
          value == bastion_token) {
        keep = false;
      }
    }
    if (keep && !part.empty()) {
      if (!first) out << '&';
      out << part;
      first = false;
    }
    if (amp == query.size()) break;
    pos = amp + 1;
  }
  return out.str();
}

std::vector<std::pair<std::string, std::string>>
parse_cookie_pairs(const std::string &cookie_header) {
  std::vector<std::pair<std::string, std::string>> result;
  size_t pos = 0;
  while (pos < cookie_header.size()) {
    while (pos < cookie_header.size() &&
           std::isspace(static_cast<unsigned char>(cookie_header[pos]))) {
      ++pos;
    }
    size_t sep = cookie_header.find(';', pos);
    if (sep == std::string::npos) sep = cookie_header.size();
    std::string part = cookie_header.substr(pos, sep - pos);
    size_t eq = part.find('=');
    if (eq != std::string::npos) {
      std::string name = part.substr(0, eq);
      std::string value = part.substr(eq + 1);
      while (!name.empty() && std::isspace(static_cast<unsigned char>(name.front()))) name.erase(name.begin());
      while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back()))) name.pop_back();
      while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
      while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
      if (!name.empty()) result.push_back({name, value});
    }
    if (sep == cookie_header.size()) break;
    pos = sep + 1;
  }
  return result;
}

std::string build_cookie_header(
    const std::vector<std::pair<std::string, std::string>> &pairs) {
  std::ostringstream out;
  bool first = true;
  for (const auto &kv : pairs) {
    if (kv.first.empty()) continue;
    if (!first) out << "; ";
    out << kv.first << "=" << kv.second;
    first = false;
  }
  return out.str();
}

std::vector<std::pair<std::string, std::string>>
dedupe_cookie_pairs_keep_first(
    const std::vector<std::pair<std::string, std::string>> &pairs) {
  std::vector<std::pair<std::string, std::string>> dedup;
  std::unordered_map<std::string, bool> seen;
  dedup.reserve(pairs.size());
  for (const auto &kv : pairs) {
    if (kv.first.empty()) continue;
    if (seen.find(kv.first) != seen.end()) continue;
    seen[kv.first] = true;
    dedup.push_back(kv);
  }
  return dedup;
}

std::optional<std::pair<std::string, std::string>>
parse_set_cookie_name_value(const std::string &set_cookie_value) {
  if (set_cookie_value.empty()) return std::nullopt;
  size_t end = set_cookie_value.find(';');
  std::string first_part = set_cookie_value.substr(
      0, end == std::string::npos ? set_cookie_value.size() : end);
  size_t eq = first_part.find('=');
  if (eq == std::string::npos) return std::nullopt;
  std::string name = first_part.substr(0, eq);
  std::string value = first_part.substr(eq + 1);
  while (!name.empty() && std::isspace(static_cast<unsigned char>(name.front()))) name.erase(name.begin());
  while (!name.empty() && std::isspace(static_cast<unsigned char>(name.back()))) name.pop_back();
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
  while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
  if (name.empty()) return std::nullopt;
  return std::make_pair(name, value);
}

std::string trim_copy(const std::string &value) {
  size_t start = 0;
  while (start < value.size() &&
         std::isspace(static_cast<unsigned char>(value[start]))) ++start;
  size_t e = value.size();
  while (e > start &&
         std::isspace(static_cast<unsigned char>(value[e - 1]))) --e;
  return value.substr(start, e - start);
}

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════════
//  High-level proxy handler
// ═══════════════════════════════════════════════════════════════════════

crow::response handle_proxy_request(
    AppContext &ctx,
    const crow::request &request,
    int resource_id,
    const std::string &path) {

  bool is_ajax_request = false;
  const char *ajax_param = request.url_params.get("ajax_request");
  if (ajax_param && (std::string(ajax_param) == "true" ||
                     std::string(ajax_param) == "1")) {
    is_ajax_request = true;
  }
  auto requested_with = to_lower(request.get_header_value("X-Requested-With"));
  if (requested_with == "xmlhttprequest") is_ajax_request = true;
  if (!is_ajax_request && !request.body.empty()) {
    if (request.body.find("ajax_request=true") != std::string::npos ||
        request.body.find("ajax_request=1") != std::string::npos) {
      is_ajax_request = true;
    }
  }

  // ── Extract auth token ──
  auto auth_header = request.get_header_value("Authorization");
  std::string token;

  if (auth_header.find("Bearer ") != std::string::npos) {
    token = auth_header.substr(7);
  } else {
    const char *ef_token_param = request.url_params.get("ef_token");
    if (ef_token_param && is_bastion_token(ef_token_param)) {
      token = ef_token_param;
    }
    if (token.empty()) {
      const char *token_param = request.url_params.get("token");
      if (token_param && is_bastion_token(token_param)) {
        token = token_param;
      }
    }
    if (token.empty()) {
      auto cookie = request.get_header_value("Cookie");
      if (!cookie.empty()) {
        size_t pos = cookie.find("endoriumfort_token=");
        if (pos != std::string::npos) {
          size_t start = pos + 19;
          size_t end = cookie.find(';', start);
          if (end == std::string::npos) end = cookie.length();
          token = cookie.substr(start, end - start);
        }
      }
    }
    if (token.empty()) {
      auto referer = request.get_header_value("Referer");
      if (!referer.empty()) {
        size_t qpos = referer.find('?');
        if (qpos != std::string::npos && qpos + 1 < referer.size()) {
          std::string query = referer.substr(qpos + 1);
          auto referer_token = get_query_param_value(query, "ef_token");
          if (!referer_token) {
            auto legacy_token = get_query_param_value(query, "token");
            if (legacy_token && is_bastion_token(*legacy_token)) {
              referer_token = legacy_token;
            }
          }
          if (referer_token) token = *referer_token;
        }
      }
    }
  }

  auto auth = ctx.find_auth_by_token(token);
  if (!auth) return crow::response(401, "Unauthorized");

  const std::string proxy_cookie_key = token + ":" + std::to_string(resource_id);
  const bool use_proxy_cookie_jar = false;

  // ── Check resource permissions ──
  std::vector<int> allowed_resource_ids;
  if (auth->role == "admin") {
    std::lock_guard<std::mutex> lock(ctx.resource_mutex);
    for (const auto &entry : ctx.resources) {
      allowed_resource_ids.push_back(entry.first);
    }
  } else {
    allowed_resource_ids = ctx.get_resource_permissions(auth->userId);
  }

  Resource target_resource;
  {
    std::lock_guard<std::mutex> lock(ctx.resource_mutex);
    auto it = ctx.resources.find(resource_id);
    if (it == ctx.resources.end()) {
      return crow::response(404, "Resource not found");
    }
    if (it->second.protocol != "http" && it->second.protocol != "https") {
      return crow::response(400, "Resource is not a web resource");
    }
    bool has_permission = false;
    for (int id : allowed_resource_ids) {
      if (id == resource_id) { has_permission = true; break; }
    }
    if (!has_permission) {
      return crow::response(403, "Access denied to this resource");
    }
    target_resource = it->second;
  }

  std::string target_host = target_resource.target;
  int target_port = target_resource.port;
  size_t port_sep = target_host.rfind(':');
  if (port_sep != std::string::npos && target_host.find(']') == std::string::npos) {
    std::string port_text = target_host.substr(port_sep + 1);
    if (!port_text.empty() &&
        std::all_of(port_text.begin(), port_text.end(),
                    [](unsigned char ch) { return std::isdigit(ch); })) {
      target_port = std::stoi(port_text);
      target_host = target_host.substr(0, port_sep);
    }
  }
  if (target_host.empty()) return crow::response(400, "Invalid target host");

  // Build target URL
  std::string target_url = "/" + path;
  if (!request.url.empty() && request.url.find('?') != std::string::npos) {
    std::string raw_query = request.url.substr(request.url.find('?') + 1);
    std::string sanitized_query = strip_bastion_query_params(raw_query, token);
    if (!sanitized_query.empty()) target_url += "?" + sanitized_query;
  }

  std::string upstream_origin = target_resource.protocol + "://" + target_host;
  const bool is_http_default_port =
      target_resource.protocol == "http" && target_port == 80;
  const bool is_https_default_port =
      target_resource.protocol == "https" && target_port == 443;
  if (!is_http_default_port && !is_https_default_port) {
    upstream_origin += ":" + std::to_string(target_port);
  }

  const bool is_config_get_request =
      target_url.find("route=/config/get") != std::string::npos;

  // HTTP method name
  std::string method_name;
  if (request.method == crow::HTTPMethod::Get) method_name = "GET";
  else if (request.method == crow::HTTPMethod::Post) method_name = "POST";
  else if (request.method == crow::HTTPMethod::Put) method_name = "PUT";
  else if (request.method == crow::HTTPMethod::Delete) method_name = "DELETE";
  else if (request.method == crow::HTTPMethod::Head) method_name = "HEAD";
  else if (request.method == crow::HTTPMethod::Patch) method_name = "PATCH";
  else if (request.method == crow::HTTPMethod::Options) method_name = "OPTIONS";
  else method_name = "GET";

  // ── Prepare request headers ──
  std::unordered_map<std::string, std::string> proxy_headers;
  proxy_headers["User-Agent"] = "EndoriumFort-Proxy/1.0";
  proxy_headers["X-Forwarded-For"] = request.remote_ip_address;
  proxy_headers["X-Forwarded-Proto"] = target_resource.protocol;
  proxy_headers["Accept-Encoding"] = "identity";

  if (!target_resource.httpUsername.empty()) {
    std::string credentials =
        target_resource.httpUsername + ":" + target_resource.httpPassword;
    proxy_headers["Authorization"] = "Basic " + base64_encode(credentials);
  }

  for (const auto &header : request.headers) {
    const std::string header_name_lower = to_lower(header.first);

    bool skip_auth = false;
    if (header_name_lower == "authorization") {
      if (!target_resource.httpUsername.empty()) skip_auth = true;
      else if (header.second.find("Bearer ") != std::string::npos) skip_auth = true;
    }

    if (!skip_auth &&
        header_name_lower != "host" &&
        header_name_lower != "connection" &&
        header_name_lower != "transfer-encoding" &&
        header_name_lower != "accept-encoding" &&
        header_name_lower != "content-length" &&
        header_name_lower != "expect") {
      if (header_name_lower == "origin") {
        proxy_headers["Origin"] = upstream_origin;
        continue;
      }
      if (header_name_lower == "referer") {
        std::string rewritten_referer = header.second;
        std::string proxy_prefix = "/proxy/" + std::to_string(resource_id) + "/";
        std::string proxy_prefix_noslash = "/proxy/" + std::to_string(resource_id);

        size_t path_start = std::string::npos;
        size_t proto_end = rewritten_referer.find("://");
        if (proto_end != std::string::npos) {
          path_start = rewritten_referer.find('/', proto_end + 3);
        }

        if (path_start != std::string::npos) {
          std::string ref_path = rewritten_referer.substr(path_start);
          if (ref_path.find(proxy_prefix) == 0) {
            ref_path = "/" + ref_path.substr(proxy_prefix.size());
          } else if (ref_path.find(proxy_prefix_noslash) == 0 &&
                     (ref_path.size() == proxy_prefix_noslash.size() ||
                      ref_path[proxy_prefix_noslash.size()] == '?')) {
            ref_path = "/" + ref_path.substr(proxy_prefix_noslash.size());
          }
          size_t qpos = ref_path.find('?');
          if (qpos != std::string::npos) {
            std::string ref_query = ref_path.substr(qpos + 1);
            std::string clean_query = strip_bastion_query_params(ref_query, token);
            ref_path = ref_path.substr(0, qpos);
            if (!clean_query.empty()) ref_path += "?" + clean_query;
          }
          rewritten_referer = upstream_origin + ref_path;
        } else {
          rewritten_referer = upstream_origin + "/";
        }
        proxy_headers["Referer"] = rewritten_referer;
        continue;
      }
      if (header_name_lower == "cookie") {
        auto cookie_pairs = parse_cookie_pairs(header.second);
        std::vector<std::pair<std::string, std::string>> sanitized;
        sanitized.reserve(cookie_pairs.size());
        for (const auto &kv : cookie_pairs) {
          if (kv.first == "endoriumfort_token") continue;
          sanitized.push_back(kv);
        }
        sanitized = dedupe_cookie_pairs_keep_first(sanitized);
        std::string rebuilt = build_cookie_header(sanitized);
        if (!rebuilt.empty()) proxy_headers["Cookie"] = rebuilt;
      } else {
        proxy_headers[header.first] = header.second;
      }
    }
  }

  if (is_ajax_request) {
    proxy_headers["X-Requested-With"] = "XMLHttpRequest";
  }

  if (use_proxy_cookie_jar) {
    std::lock_guard<std::mutex> lock(ctx.proxy_cookie_mutex);
    auto jar_it = ctx.proxy_cookie_jar.find(proxy_cookie_key);
    if (jar_it != ctx.proxy_cookie_jar.end() && !jar_it->second.empty()) {
      std::vector<std::pair<std::string, std::string>> merged;
      auto existing_it = proxy_headers.find("Cookie");
      if (existing_it != proxy_headers.end() && !existing_it->second.empty()) {
        merged = parse_cookie_pairs(existing_it->second);
      }
      for (const auto &jar_cookie : jar_it->second) {
        bool found = false;
        for (auto &item : merged) {
          if (item.first == jar_cookie.first) { found = true; break; }
        }
        if (!found) merged.push_back({jar_cookie.first, jar_cookie.second});
      }
      merged = dedupe_cookie_pairs_keep_first(merged);
      std::string rebuilt = build_cookie_header(merged);
      if (!rebuilt.empty()) proxy_headers["Cookie"] = rebuilt;
    }
  }

  // ── Execute proxy request ──
  std::string error;
  HttpProxyResponse proxy_response = http_proxy_request(
      method_name, target_host, target_port, target_url,
      request.body, proxy_headers, error);

  if (!error.empty()) {
    AuditEvent event;
    event.id = ctx.next_audit_id.fetch_add(1);
    event.type = "web.proxy_error";
    event.actor = auth->user;
    event.role = auth->role;
    event.createdAt = now_utc();
    event.payloadJson = "{\"resourceId\":" + std::to_string(resource_id) +
                        ",\"error\":\"" + error + "\"}";
    event.payloadIsJson = true;
    ctx.append_audit(event);
    return crow::response(502, error);
  }

  // Audit success
  AuditEvent audit_event;
  audit_event.id = ctx.next_audit_id.fetch_add(1);
  audit_event.type = "web.proxy_access";
  audit_event.actor = auth->user;
  audit_event.role = auth->role;
  audit_event.createdAt = now_utc();
  {
    std::ostringstream oss;
    oss << "{"
        << "\"resourceId\":" << resource_id
        << ",\"resourceName\":\"" << target_resource.name << "\""
        << ",\"path\":\"" << path << "\""
        << ",\"method\":\"" << method_name
        << "\",\"status\":" << proxy_response.status_code
        << ",\"responseSize\":" << proxy_response.body.length()
        << "}";
    audit_event.payloadJson = oss.str();
  }
  audit_event.payloadIsJson = true;
  ctx.append_audit(audit_event);

  // ── Rewrite helpers (lambdas capturing local state) ──

  auto rewrite_location = [&](const std::string &location) -> std::string {
    if (location.empty()) return location;
    const std::string prefix = "/proxy/" + std::to_string(resource_id);
    std::string rewritten_url;

    if (location[0] == '/') {
      rewritten_url = prefix + location;
    } else {
      const std::string http_prefix = "http://";
      const std::string https_prefix = "https://";
      if (location.rfind(http_prefix, 0) == 0 ||
          location.rfind(https_prefix, 0) == 0) {
        std::string without_scheme = location;
        size_t scheme_end = without_scheme.find("//");
        if (scheme_end != std::string::npos) {
          without_scheme = without_scheme.substr(scheme_end + 2);
        }
        size_t slash_pos = without_scheme.find('/');
        std::string host_port = slash_pos == std::string::npos
                                    ? without_scheme
                                    : without_scheme.substr(0, slash_pos);
        std::string rest = slash_pos == std::string::npos
                               ? std::string()
                               : without_scheme.substr(slash_pos);
        if (host_port == target_host || host_port == target_resource.target) {
          if (rest.empty()) rest = "/";
          rewritten_url = prefix + rest;
        } else {
          return location;
        }
      } else {
        return location;
      }
    }
    return rewritten_url;
  };

  auto rewrite_html_body = [&](const std::string &html) -> std::string {
    if (html.empty()) return html;
    std::string rewritten = html;
    const std::string prefix = "/proxy/" + std::to_string(resource_id) + "/";
    const std::string prefix_escaped =
        "\\/proxy\\/" + std::to_string(resource_id) + "\\/";

    const std::array<std::string, 7> tokens = {
        "href=\"/", "href=\'/", "src=\"/", "src=\'/",
        "action=\"/", "action=\'/", "url(/"};
    for (const auto &tok : tokens) {
      size_t pos = 0;
      while ((pos = rewritten.find(tok, pos)) != std::string::npos) {
        if (pos + tok.size() + 8 < rewritten.size() &&
            rewritten.substr(pos + tok.size(), 6) == "proxy/") {
          pos += tok.size() + 1;
          continue;
        }
        std::string replacement = tok.substr(0, tok.size() - 1) + prefix;
        rewritten.replace(pos, tok.size(), replacement);
        pos += replacement.size();
      }
    }

    // LuCI-specific escaped slashes
    {
      const std::array<std::string, 2> luci_tokens = {
          "\"\\/cgi-bin\\/luci", "\"\\/luci-static"};
      for (const auto &escaped_token : luci_tokens) {
        size_t pos = 0;
        std::string escaped_replacement =
            "\"" + prefix_escaped + escaped_token.substr(3);
        while ((pos = rewritten.find(escaped_token, pos)) != std::string::npos) {
          if (pos + escaped_token.size() + 14 < rewritten.size() &&
              rewritten.substr(pos + 3, 6) == "proxy") {
            pos += escaped_token.size();
            continue;
          }
          rewritten.replace(pos, escaped_token.size(), escaped_replacement);
          pos += escaped_replacement.size();
        }
      }
    }

    // Inject <base> tag
    const std::string base_tag =
        "<base href=\"/proxy/" + std::to_string(resource_id) + "/\">";
    size_t head_pos = rewritten.find("<head>");
    if (head_pos != std::string::npos) {
      rewritten.insert(head_pos + 6, base_tag);
    } else {
      size_t head_pos2 = rewritten.find("<head ");
      if (head_pos2 != std::string::npos) {
        size_t head_close = rewritten.find('>', head_pos2);
        if (head_close != std::string::npos) {
          rewritten.insert(head_close + 1, base_tag);
        }
      } else {
        size_t html_pos = rewritten.find("<html");
        if (html_pos != std::string::npos) {
          size_t html_end = rewritten.find('>', html_pos);
          if (html_end != std::string::npos) {
            rewritten.insert(html_end + 1, base_tag);
          }
        }
      }
    }
    return rewritten;
  };

  auto rewrite_set_cookie_for_proxy = [&](const std::string &cookie_value)
      -> std::string {
    if (cookie_value.empty()) return cookie_value;

    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos <= cookie_value.size()) {
      size_t sep = cookie_value.find(';', pos);
      if (sep == std::string::npos) sep = cookie_value.size();
      parts.push_back(trim_copy(cookie_value.substr(pos, sep - pos)));
      if (sep == cookie_value.size()) break;
      pos = sep + 1;
    }
    if (parts.empty() || parts[0].empty()) return cookie_value;

    const std::string scoped_path =
        "Path=/proxy/" + std::to_string(resource_id) + "/";
    std::string rewritten = parts[0];
    bool has_path = false;

    for (size_t i = 1; i < parts.size(); ++i) {
      if (parts[i].empty()) continue;
      std::string lower = to_lower(parts[i]);
      if (lower == "secure") continue;
      if (lower.rfind("domain=", 0) == 0) continue;
      if (lower == "samesite=none") {
        rewritten += "; SameSite=Lax";
        continue;
      }
      if (lower.rfind("path=", 0) == 0) {
        rewritten += "; " + scoped_path;
        has_path = true;
        continue;
      }
      rewritten += "; " + parts[i];
    }
    if (!has_path) rewritten += "; " + scoped_path;
    return rewritten;
  };

  // ── Determine if HTML rewriting is needed ──
  auto content_type_it = proxy_response.headers.find("content-type");
  bool should_rewrite_html = false;
  if (content_type_it != proxy_response.headers.end()) {
    const std::string &content_type = content_type_it->second;
    if (content_type.find("text/html") != std::string::npos) {
      should_rewrite_html = true;
    }
    if (is_config_get_request &&
        content_type.find("application/json") != std::string::npos) {
      std::string trimmed_body = trim_copy(proxy_response.body);
      if (!trimmed_body.empty() && trimmed_body.front() == '{' &&
          trimmed_body.back() == '}' &&
          trimmed_body.find("\"success\":true") != std::string::npos &&
          trimmed_body.find("\"value\"") == std::string::npos) {
        size_t close_brace = trimmed_body.rfind('}');
        if (close_brace != std::string::npos) {
          if (close_brace > 0 && trimmed_body[close_brace - 1] != '{') {
            trimmed_body.insert(close_brace, ",\"value\":null");
          } else {
            trimmed_body.insert(close_brace, "\"value\":null");
          }
          proxy_response.body = trimmed_body;
        }
      }
    }
  }

  // ── Build response ──
  crow::response resp;
  resp.code = proxy_response.status_code;
  resp.body = proxy_response.body;

  if (should_rewrite_html) {
    resp.body = rewrite_html_body(proxy_response.body);
  }

  resp.set_header("X-Proxied-By", "EndoriumFort");
  resp.set_header("X-Resource-Id", std::to_string(resource_id));

  if (!token.empty()) {
    std::string cookie_value = "endoriumfort_token=" + token +
                               "; Path=/proxy/" + std::to_string(resource_id) +
                               "/; HttpOnly; SameSite=Lax";
    resp.add_header("Set-Cookie", cookie_value);
  }

  for (const auto &header : proxy_response.headers) {
    if (header.first == "connection" ||
        header.first == "transfer-encoding" ||
        header.first == "set-cookie" ||
        header.first == "x-frame-options" ||
        header.first == "frame-options" ||
        header.first == "content-security-policy" ||
        header.first == "x-content-security-policy" ||
        header.first == "x-webkit-csp" ||
        header.first == "content-length" ||
        (should_rewrite_html && header.first == "content-encoding")) {
      continue;
    }
    if (header.first == "location") {
      resp.set_header("Location", rewrite_location(header.second));
    } else {
      resp.set_header(header.first, header.second);
    }
  }

  // Rewrite Set-Cookie headers
  std::vector<std::string> cookie_name_order;
  std::unordered_map<std::string, std::string> dedup_cookies;
  cookie_name_order.reserve(proxy_response.set_cookie_headers.size());

  for (const auto &cookie_value : proxy_response.set_cookie_headers) {
    if (cookie_value.empty()) continue;
    std::string rewritten_cookie = rewrite_set_cookie_for_proxy(cookie_value);
    auto parsed_cookie = parse_set_cookie_name_value(rewritten_cookie);
    if (!parsed_cookie) continue;
    if (dedup_cookies.find(parsed_cookie->first) == dedup_cookies.end()) {
      cookie_name_order.push_back(parsed_cookie->first);
    }
    dedup_cookies[parsed_cookie->first] = rewritten_cookie;
  }

  for (const auto &cookie_name : cookie_name_order) {
    auto it = dedup_cookies.find(cookie_name);
    if (it == dedup_cookies.end()) continue;
    resp.add_header("Set-Cookie", it->second);

    if (use_proxy_cookie_jar) {
      auto parsed_cookie = parse_set_cookie_name_value(it->second);
      if (!parsed_cookie) continue;
      std::lock_guard<std::mutex> lock(ctx.proxy_cookie_mutex);
      if (parsed_cookie->second.empty()) {
        ctx.proxy_cookie_jar[proxy_cookie_key].erase(parsed_cookie->first);
      } else {
        ctx.proxy_cookie_jar[proxy_cookie_key][parsed_cookie->first] =
            parsed_cookie->second;
      }
    }
  }

  resp.set_header("Content-Length", std::to_string(resp.body.size()));
  return resp;
}

// ═══════════════════════════════════════════════════════════════════════
//  Route registration
// ═══════════════════════════════════════════════════════════════════════

void register_proxy_routes(crow::SimpleApp &app, AppContext &ctx) {
  CROW_ROUTE(app, "/proxy/<int>")
      .methods(crow::HTTPMethod::Get, crow::HTTPMethod::Post,
               crow::HTTPMethod::Put, crow::HTTPMethod::Delete,
               crow::HTTPMethod::Head, crow::HTTPMethod::Patch)
      ([&ctx](const crow::request &request, int resource_id) {
        return handle_proxy_request(ctx, request, resource_id, "");
      });

  CROW_ROUTE(app, "/proxy/<int>/<path>")
      .methods(crow::HTTPMethod::Get, crow::HTTPMethod::Post,
               crow::HTTPMethod::Put, crow::HTTPMethod::Delete,
               crow::HTTPMethod::Head, crow::HTTPMethod::Patch)
      ([&ctx](const crow::request &request, int resource_id, std::string path) {
        return handle_proxy_request(ctx, request, resource_id, path);
      });
}

void register_web_resource_routes(crow::SimpleApp &app, AppContext &ctx) {
  CROW_ROUTE(app, "/api/web/resources/<int>/url")
      .methods(crow::HTTPMethod::Get)
      ([&ctx](const crow::request &request, int resource_id) {
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

        bool has_permission = false;
        for (int id : allowed_resource_ids) {
          if (id == resource_id) { has_permission = true; break; }
        }
        if (!has_permission) return crow::response(403, "Access denied");

        Resource target_resource;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          auto it = ctx.resources.find(resource_id);
          if (it == ctx.resources.end())
            return crow::response(404, "Resource not found");
          target_resource = it->second;
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["resourceId"] = resource_id;
        payload["resourceName"] = target_resource.name;
        payload["proxyUrl"] =
            "/proxy/" + std::to_string(resource_id) + "?ef_token=" + auth->token;
        payload["token"] = auth->token;
        return crow::response{payload};
      });

  CROW_ROUTE(app, "/api/web/resources").methods(crow::HTTPMethod::Get)(
      [&ctx](const crow::request &request) {
        auto auth = ctx.find_auth(request);
        if (!auth) return crow::response(401, "Unauthorized");

        std::vector<Resource> web_resources;
        {
          std::lock_guard<std::mutex> lock(ctx.resource_mutex);
          for (const auto &entry : ctx.resources) {
            if (entry.second.protocol == "http" ||
                entry.second.protocol == "https") {
              web_resources.push_back(entry.second);
            }
          }
        }

        crow::json::wvalue payload;
        payload["status"] = "ok";
        payload["items"] = crow::json::wvalue::list();
        for (size_t i = 0; i < web_resources.size(); ++i) {
          payload["items"][static_cast<int>(i)] =
              resource_to_json(web_resources[i]);
        }
        return crow::response{payload};
      });
}
