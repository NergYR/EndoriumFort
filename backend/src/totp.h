#pragma once
// ─── EndoriumFort — TOTP / 2FA implementation ──────────────────────────
// Self-contained TOTP (RFC 6238) with built-in SHA1 and HMAC-SHA1.
// No external crypto dependency required.

#include <array>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace totp {

// ═══════════════════════════════════════════════════════════════════════
//  SHA-1 (FIPS 180-4) – minimal implementation
// ═══════════════════════════════════════════════════════════════════════

namespace detail {

inline uint32_t left_rotate(uint32_t value, unsigned int count) {
  return (value << count) | (value >> (32 - count));
}

inline std::array<uint8_t, 20> sha1(const uint8_t *data, size_t len) {
  uint32_t h0 = 0x67452301;
  uint32_t h1 = 0xEFCDAB89;
  uint32_t h2 = 0x98BADCFE;
  uint32_t h3 = 0x10325476;
  uint32_t h4 = 0xC3D2E1F0;

  uint64_t bit_len = static_cast<uint64_t>(len) * 8;

  // Pad message
  std::vector<uint8_t> msg(data, data + len);
  msg.push_back(0x80);
  while ((msg.size() % 64) != 56)
    msg.push_back(0x00);
  for (int i = 7; i >= 0; --i)
    msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

  // Process blocks
  for (size_t offset = 0; offset < msg.size(); offset += 64) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
      w[i] = (static_cast<uint32_t>(msg[offset + i * 4]) << 24) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 1]) << 16) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 2]) << 8) |
             (static_cast<uint32_t>(msg[offset + i * 4 + 3]));
    }
    for (int i = 16; i < 80; ++i)
      w[i] = left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = h0, b = h1, c = h2, d = h3, e = h4;
    for (int i = 0; i < 80; ++i) {
      uint32_t f, k;
      if (i < 20) {
        f = (b & c) | ((~b) & d);
        k = 0x5A827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b ^ c ^ d;
        k = 0xCA62C1D6;
      }
      uint32_t temp = left_rotate(a, 5) + f + e + k + w[i];
      e = d;
      d = c;
      c = left_rotate(b, 30);
      b = a;
      a = temp;
    }
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
  }

  std::array<uint8_t, 20> digest;
  for (int i = 0; i < 4; ++i) {
    digest[i] = static_cast<uint8_t>((h0 >> (24 - i * 8)) & 0xFF);
    digest[i + 4] = static_cast<uint8_t>((h1 >> (24 - i * 8)) & 0xFF);
    digest[i + 8] = static_cast<uint8_t>((h2 >> (24 - i * 8)) & 0xFF);
    digest[i + 12] = static_cast<uint8_t>((h3 >> (24 - i * 8)) & 0xFF);
    digest[i + 16] = static_cast<uint8_t>((h4 >> (24 - i * 8)) & 0xFF);
  }
  return digest;
}

// ═══════════════════════════════════════════════════════════════════════
//  HMAC-SHA1 (RFC 2104)
// ═══════════════════════════════════════════════════════════════════════

inline std::array<uint8_t, 20> hmac_sha1(const uint8_t *key, size_t key_len,
                                          const uint8_t *msg, size_t msg_len) {
  const size_t block_size = 64;
  std::vector<uint8_t> k(block_size, 0);

  if (key_len > block_size) {
    auto hashed = sha1(key, key_len);
    std::memcpy(k.data(), hashed.data(), 20);
  } else {
    std::memcpy(k.data(), key, key_len);
  }

  std::vector<uint8_t> i_pad(block_size + msg_len);
  std::vector<uint8_t> o_pad(block_size + 20);

  for (size_t i = 0; i < block_size; ++i) {
    i_pad[i] = k[i] ^ 0x36;
    o_pad[i] = k[i] ^ 0x5C;
  }
  std::memcpy(i_pad.data() + block_size, msg, msg_len);

  auto inner = sha1(i_pad.data(), i_pad.size());
  std::memcpy(o_pad.data() + block_size, inner.data(), 20);

  return sha1(o_pad.data(), o_pad.size());
}

} // namespace detail

// ═══════════════════════════════════════════════════════════════════════
//  Base32 encode / decode (RFC 4648)
// ═══════════════════════════════════════════════════════════════════════

inline std::string base32_encode(const uint8_t *data, size_t len) {
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  std::string result;
  result.reserve((len * 8 + 4) / 5);

  uint32_t buffer = 0;
  int bits_left = 0;
  for (size_t i = 0; i < len; ++i) {
    buffer = (buffer << 8) | data[i];
    bits_left += 8;
    while (bits_left >= 5) {
      result += alphabet[(buffer >> (bits_left - 5)) & 0x1F];
      bits_left -= 5;
    }
  }
  if (bits_left > 0)
    result += alphabet[(buffer << (5 - bits_left)) & 0x1F];

  // Pad to multiple of 8
  while (result.size() % 8 != 0)
    result += '=';

  return result;
}

inline std::vector<uint8_t> base32_decode(const std::string &input) {
  auto b32val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
  };

  std::vector<uint8_t> result;
  uint32_t buffer = 0;
  int bits_left = 0;
  for (char c : input) {
    if (c == '=' || c == ' ') continue;
    int val = b32val(c);
    if (val < 0) continue;
    buffer = (buffer << 5) | static_cast<uint32_t>(val);
    bits_left += 5;
    if (bits_left >= 8) {
      result.push_back(static_cast<uint8_t>((buffer >> (bits_left - 8)) & 0xFF));
      bits_left -= 8;
    }
  }
  return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  TOTP (RFC 6238) — 6-digit, 30-second period, SHA1
// ═══════════════════════════════════════════════════════════════════════

inline std::string generate_secret(int byte_count = 20) {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(0, 255);
  std::vector<uint8_t> secret(byte_count);
  for (auto &b : secret)
    b = static_cast<uint8_t>(dist(gen));
  return base32_encode(secret.data(), secret.size());
}

inline uint32_t compute_totp(const std::string &base32_secret, uint64_t time_step) {
  auto key = base32_decode(base32_secret);

  uint8_t msg[8];
  for (int i = 7; i >= 0; --i) {
    msg[i] = static_cast<uint8_t>(time_step & 0xFF);
    time_step >>= 8;
  }

  auto hmac = detail::hmac_sha1(key.data(), key.size(), msg, 8);

  int offset = hmac[19] & 0x0F;
  uint32_t code = ((static_cast<uint32_t>(hmac[offset]) & 0x7F) << 24) |
                  ((static_cast<uint32_t>(hmac[offset + 1]) & 0xFF) << 16) |
                  ((static_cast<uint32_t>(hmac[offset + 2]) & 0xFF) << 8) |
                  ((static_cast<uint32_t>(hmac[offset + 3]) & 0xFF));

  return code % 1000000;
}

inline std::string generate_code(const std::string &base32_secret,
                                  int period = 30) {
  uint64_t time_step = static_cast<uint64_t>(std::time(nullptr)) / period;
  uint32_t code = compute_totp(base32_secret, time_step);
  char buf[8];
  snprintf(buf, sizeof(buf), "%06u", code);
  return std::string(buf);
}

inline bool verify_code(const std::string &base32_secret,
                        const std::string &user_code,
                        int period = 30, int window = 1) {
  uint64_t current = static_cast<uint64_t>(std::time(nullptr)) / period;
  for (int i = -window; i <= window; ++i) {
    uint32_t expected = compute_totp(base32_secret, current + i);
    char buf[8];
    snprintf(buf, sizeof(buf), "%06u", expected);
    if (user_code == std::string(buf))
      return true;
  }
  return false;
}

inline std::string build_otpauth_uri(const std::string &issuer,
                                      const std::string &account,
                                      const std::string &base32_secret) {
  // otpauth://totp/Issuer:account?secret=XXX&issuer=Issuer&digits=6&period=30
  std::ostringstream oss;
  oss << "otpauth://totp/" << issuer << ":" << account
      << "?secret=" << base32_secret
      << "&issuer=" << issuer
      << "&digits=6&period=30&algorithm=SHA1";
  return oss.str();
}

} // namespace totp
