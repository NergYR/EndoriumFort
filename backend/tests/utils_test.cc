#include "utils.h"

#include <iostream>
#include <string>

namespace {

bool expect(bool condition, const std::string &message) {
  if (!condition) {
    std::cerr << "[FAIL] " << message << std::endl;
    return false;
  }
  return true;
}

}  // namespace

int main() {
  bool ok = true;

  const std::string now = now_utc();
  ok &= expect(now.size() == 20, "now_utc format length should be 20");
  ok &= expect(now[4] == '-' && now[7] == '-' && now[10] == 'T',
               "now_utc should be RFC3339-like UTC format");

  const auto epoch = parse_utc_epoch_seconds("2026-03-10T12:34:56Z");
  ok &= expect(epoch.has_value(), "parse_utc_epoch_seconds should parse valid UTC");

  const auto invalid = parse_utc_epoch_seconds("2026/03/10 12:34:56");
  ok &= expect(!invalid.has_value(), "parse_utc_epoch_seconds should reject invalid format");

  const std::string escaped = json_escape("a\"b\\c\n");
  ok &= expect(escaped == "a\\\"b\\\\c\\n", "json_escape should escape quote, slash, newline");

  const std::string from_epoch = utc_from_epoch_seconds(0);
  ok &= expect(from_epoch == "1970-01-01T00:00:00Z", "utc_from_epoch_seconds should format epoch zero");

  if (!ok) {
    return 1;
  }

  std::cout << "All backend utility tests passed." << std::endl;
  return 0;
}
