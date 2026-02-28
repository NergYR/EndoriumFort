#pragma once
// ─── EndoriumFort — Session Recording ───────────────────────────────────
// Records SSH sessions in Asciinema v2 (.cast) format for audit replay.

#include <chrono>
#include <fstream>
#include <mutex>
#include <string>

class SessionRecorder {
public:
  // Open a recording file in Asciinema v2 format.
  bool open(const std::string &path, int session_id, int cols, int rows,
            const std::string &title = "");

  // Append an output event (data sent TO the terminal).
  void append_output(const char *data, size_t len);

  // Append an input event (data typed BY the user).
  void append_input(const char *data, size_t len);

  // Close the recording file.
  void close();

  bool is_open() const { return file_.is_open(); }
  const std::string &path() const { return path_; }
  int64_t duration_ms() const;
  size_t file_size() const { return bytes_written_; }

private:
  void append_event(const char *event_type, const char *data, size_t len);
  std::string json_escape_cast(const char *data, size_t len);

  std::mutex mutex_;
  std::ofstream file_;
  std::string path_;
  size_t bytes_written_ = 0;
  std::chrono::steady_clock::time_point start_time_;
  bool started_ = false;
};
