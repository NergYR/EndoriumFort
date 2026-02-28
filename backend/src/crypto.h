#pragma once
// ─── EndoriumFort — Cryptographic utilities ─────────────────────────────
// Self-contained SHA-256, password hashing with salt, and password policy.
// No external crypto dependency required.

#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace crypto {

// ═══════════════════════════════════════════════════════════════════════
//  SHA-256 (FIPS 180-4) – minimal implementation
// ═══════════════════════════════════════════════════════════════════════

namespace detail {

inline uint32_t rotr(uint32_t x, unsigned int n) {
  return (x >> n) | (x << (32 - n));
}

inline uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (~x & z);
}

inline uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sigma0(uint32_t x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t sigma1(uint32_t x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t gamma0(uint32_t x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t gamma1(uint32_t x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

static constexpr uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

}  // namespace detail

/// Compute SHA-256 hash of arbitrary data.
inline std::array<uint8_t, 32> sha256(const uint8_t *data, size_t len) {
  uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372,
           h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c,
           h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  uint64_t bit_len = static_cast<uint64_t>(len) * 8;

  // Pad message
  std::vector<uint8_t> msg(data, data + len);
  msg.push_back(0x80);
  while ((msg.size() % 64) != 56) msg.push_back(0x00);
  for (int i = 7; i >= 0; --i)
    msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

  // Process 512-bit blocks
  for (size_t offset = 0; offset < msg.size(); offset += 64) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
      w[i] = (static_cast<uint32_t>(msg[offset + i * 4]) << 24) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 2]) << 8) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i)
      w[i] = detail::gamma1(w[i - 2]) + w[i - 7] +
             detail::gamma0(w[i - 15]) + w[i - 16];

    uint32_t a = h0, b = h1, c = h2, d = h3;
    uint32_t e = h4, f = h5, g = h6, h = h7;

    for (int i = 0; i < 64; ++i) {
      uint32_t t1 =
          h + detail::sigma1(e) + detail::ch(e, f, g) + detail::K[i] + w[i];
      uint32_t t2 = detail::sigma0(a) + detail::maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    h0 += a; h1 += b; h2 += c; h3 += d;
    h4 += e; h5 += f; h6 += g; h7 += h;
  }

  std::array<uint8_t, 32> digest;
  auto put = [&](int off, uint32_t val) {
    for (int i = 0; i < 4; ++i)
      digest[off + i] = static_cast<uint8_t>((val >> (24 - i * 8)) & 0xFF);
  };
  put(0, h0);  put(4, h1);  put(8, h2);   put(12, h3);
  put(16, h4); put(20, h5); put(24, h6);  put(28, h7);
  return digest;
}

inline std::string sha256_hex(const std::string &input) {
  auto digest =
      sha256(reinterpret_cast<const uint8_t *>(input.data()), input.size());
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (auto byte : digest) {
    out += hex[byte >> 4];
    out += hex[byte & 0x0F];
  }
  return out;
}

// ═══════════════════════════════════════════════════════════════════════
//  Salt generation
// ═══════════════════════════════════════════════════════════════════════

/// Generate a random 16-byte hex salt (32 hex chars).
inline std::string generate_salt() {
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist;
  uint64_t a = dist(gen);
  uint64_t b = dist(gen);
  char buf[33];
  snprintf(buf, sizeof(buf), "%016llx%016llx",
           (unsigned long long)a, (unsigned long long)b);
  return std::string(buf);
}

// ═══════════════════════════════════════════════════════════════════════
//  Password hashing: SHA-256 with salt, 10000 iterations (PBKDF2-like)
// ═══════════════════════════════════════════════════════════════════════

/// Hash a password with the given salt using iterated SHA-256.
/// Returns: "sha256:10000:<salt>:<hex_hash>"
inline std::string hash_password(const std::string &password,
                                 const std::string &salt) {
  const int iterations = 10000;
  std::string current = salt + ":" + password;
  for (int i = 0; i < iterations; ++i) {
    current = sha256_hex(current);
  }
  return "sha256:10000:" + salt + ":" + current;
}

/// Hash a password with a new random salt.
inline std::string hash_password(const std::string &password) {
  return hash_password(password, generate_salt());
}

/// Verify a password against a stored hash string.
/// Supports both new format "sha256:10000:<salt>:<hash>" and legacy plaintext.
inline bool verify_password(const std::string &password,
                            const std::string &stored) {
  // New format: sha256:iterations:salt:hash
  if (stored.rfind("sha256:", 0) == 0) {
    // Parse: sha256:10000:salt:hash
    size_t p1 = stored.find(':', 7);   // after "sha256:"
    if (p1 == std::string::npos) return false;
    size_t p2 = stored.find(':', p1 + 1);
    if (p2 == std::string::npos) return false;
    std::string salt = stored.substr(p1 + 1, p2 - p1 - 1);
    std::string expected_hash = stored.substr(p2 + 1);
    int iterations = 10000;
    try {
      iterations = std::stoi(stored.substr(7, p1 - 7));
    } catch (...) {}

    std::string current = salt + ":" + password;
    for (int i = 0; i < iterations; ++i) {
      current = sha256_hex(current);
    }
    return current == expected_hash;
  }

  // Legacy: plaintext comparison (for migration)
  return stored == password;
}

// ═══════════════════════════════════════════════════════════════════════
//  Password policy validation
// ═══════════════════════════════════════════════════════════════════════

struct PasswordPolicyResult {
  bool valid = false;
  std::string message;
};

/// Validate password strength.
/// Requirements: min 8 chars, at least 1 uppercase, 1 lowercase, 1 digit.
inline PasswordPolicyResult validate_password(const std::string &password) {
  if (password.size() < 8)
    return {false, "Password must be at least 8 characters long"};

  bool has_upper = false, has_lower = false, has_digit = false;
  for (char c : password) {
    if (c >= 'A' && c <= 'Z') has_upper = true;
    if (c >= 'a' && c <= 'z') has_lower = true;
    if (c >= '0' && c <= '9') has_digit = true;
  }

  if (!has_upper)
    return {false, "Password must contain at least one uppercase letter"};
  if (!has_lower)
    return {false, "Password must contain at least one lowercase letter"};
  if (!has_digit)
    return {false, "Password must contain at least one digit"};

  return {true, "ok"};
}

}  // namespace crypto
