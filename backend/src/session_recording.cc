// ─── EndoriumFort — Session Recording implementation ────────────────────

#include "session_recording.h"

#include <iomanip>
#include <sstream>

bool SessionRecorder::open(const std::string &path, int session_id,
                            int cols, int rows,
                            const std::string &title) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (file_.is_open()) return false;

  path_ = path;
  file_.open(path_, std::ios::out | std::ios::trunc);
  if (!file_.is_open()) return false;

  // Write Asciinema v2 header (first line = JSON object)
  auto now = std::chrono::system_clock::now();
  auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
                   now.time_since_epoch())
                   .count();

  std::ostringstream header;
  header << "{\"version\":2"
         << ",\"width\":" << cols
         << ",\"height\":" << rows
         << ",\"timestamp\":" << epoch;
  if (!title.empty()) {
    header << ",\"title\":\"";
    for (char c : title) {
      if (c == '"') header << "\\\"";
      else if (c == '\\') header << "\\\\";
      else header << c;
    }
    header << "\"";
  }
  header << ",\"env\":{\"TERM\":\"xterm-256color\",\"SHELL\":\"/bin/bash\"}"
         << ",\"meta\":{\"sessionId\":" << session_id << "}"
         << "}\n";

  std::string h = header.str();
  file_.write(h.c_str(), static_cast<std::streamsize>(h.size()));
  bytes_written_ = h.size();

  start_time_ = std::chrono::steady_clock::now();
  started_ = true;
  return true;
}

void SessionRecorder::append_output(const char *data, size_t len) {
  append_event("o", data, len);
}

void SessionRecorder::append_input(const char *data, size_t len) {
  append_event("i", data, len);
}

void SessionRecorder::append_event(const char *event_type,
                                    const char *data, size_t len) {
  if (len == 0) return;
  std::lock_guard<std::mutex> lock(mutex_);
  if (!started_ || !file_.is_open()) return;

  auto now = std::chrono::steady_clock::now();
  double elapsed =
      std::chrono::duration<double>(now - start_time_).count();

  std::ostringstream line;
  line << std::fixed << std::setprecision(6)
       << "[" << elapsed << ",\"" << event_type << "\",\""
       << json_escape_cast(data, len) << "\"]\n";

  std::string s = line.str();
  file_.write(s.c_str(), static_cast<std::streamsize>(s.size()));
  file_.flush();
  bytes_written_ += s.size();
}

void SessionRecorder::close() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (file_.is_open()) {
    file_.flush();
    file_.close();
  }
  started_ = false;
}

int64_t SessionRecorder::duration_ms() const {
  if (!started_) return 0;
  auto now = std::chrono::steady_clock::now();
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             now - start_time_)
      .count();
}

std::string SessionRecorder::json_escape_cast(const char *data, size_t len) {
  std::string result;
  result.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    unsigned char c = static_cast<unsigned char>(data[i]);
    switch (c) {
    case '\\': result += "\\\\"; break;
    case '"':  result += "\\\""; break;
    case '\n': result += "\\n"; break;
    case '\r': result += "\\r"; break;
    case '\t': result += "\\t"; break;
    case '\b': result += "\\b"; break;
    case '\f': result += "\\f"; break;
    default:
      if (c < 0x20) {
        char buf[8];
        snprintf(buf, sizeof(buf), "\\u%04x", c);
        result += buf;
      } else {
        result += static_cast<char>(c);
      }
      break;
    }
  }
  return result;
}
