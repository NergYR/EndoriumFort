#pragma once
// ─── EndoriumFort — Cryptographic utilities ─────────────────────────────
// SHA-256 helpers, password hashing with migration support, and password policy.

#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
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

inline std::string hmac_sha256_hex(const std::string &key,
                                   const std::string &message) {
  constexpr size_t block_size = 64;
  std::string normalized_key = key;
  if (normalized_key.size() > block_size) {
    auto key_hash = sha256(reinterpret_cast<const uint8_t *>(normalized_key.data()),
                           normalized_key.size());
    normalized_key.assign(reinterpret_cast<const char *>(key_hash.data()),
                          key_hash.size());
  }
  if (normalized_key.size() < block_size) {
    normalized_key.append(block_size - normalized_key.size(), '\0');
  }

  std::string o_key_pad(block_size, '\0');
  std::string i_key_pad(block_size, '\0');
  for (size_t i = 0; i < block_size; ++i) {
    const unsigned char b = static_cast<unsigned char>(normalized_key[i]);
    o_key_pad[i] = static_cast<char>(b ^ 0x5c);
    i_key_pad[i] = static_cast<char>(b ^ 0x36);
  }

  std::string inner = i_key_pad + message;
  auto inner_hash = sha256(reinterpret_cast<const uint8_t *>(inner.data()),
                           inner.size());

  std::string outer = o_key_pad +
                      std::string(reinterpret_cast<const char *>(inner_hash.data()),
                                  inner_hash.size());
  auto hmac = sha256(reinterpret_cast<const uint8_t *>(outer.data()),
                     outer.size());

  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(64);
  for (auto byte : hmac) {
    out += hex[byte >> 4];
    out += hex[byte & 0x0F];
  }
  return out;
}

inline bool constant_time_equals(const std::string &a, const std::string &b) {
  if (a.size() != b.size()) return false;
  unsigned char diff = 0;
  for (size_t i = 0; i < a.size(); ++i) {
    diff |= static_cast<unsigned char>(a[i] ^ b[i]);
  }
  return diff == 0;
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
  std::ostringstream oss;
  oss << std::hex << std::setfill('0')
      << std::setw(16) << static_cast<unsigned long long>(a)
      << std::setw(16) << static_cast<unsigned long long>(b);
  return oss.str();
}

// ═══════════════════════════════════════════════════════════════════════
//  Password hashing: scrypt (primary), legacy SHA-256 migration support
// ═══════════════════════════════════════════════════════════════════════

inline std::string hex_encode(const unsigned char *data, size_t len) {
  static const char hex[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; ++i) {
    const unsigned char byte = data[i];
    out += hex[byte >> 4];
    out += hex[byte & 0x0F];
  }
  return out;
}

inline bool hex_decode(const std::string &hex_value, std::string &out) {
  if (hex_value.size() % 2 != 0) return false;
  auto decode_nibble = [](char ch) -> int {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F') return 10 + (ch - 'A');
    return -1;
  };
  out.clear();
  out.reserve(hex_value.size() / 2);
  for (size_t i = 0; i < hex_value.size(); i += 2) {
    const int hi = decode_nibble(hex_value[i]);
    const int lo = decode_nibble(hex_value[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<char>((hi << 4) | lo));
  }
  return true;
}

inline std::string hash_password_legacy_sha256(const std::string &password,
                                               const std::string &salt) {
  const int iterations = 10000;
  std::string current = salt + ":" + password;
  for (int i = 0; i < iterations; ++i) {
    current = sha256_hex(current);
  }
  return "sha256:10000:" + salt + ":" + current;
}

inline std::string hash_password_legacy_sha256(const std::string &password) {
  return hash_password_legacy_sha256(password, generate_salt());
}

inline std::string hash_password_scrypt(const std::string &password,
                                        const std::string &salt_hex) {
  constexpr uint64_t n = 1ULL << 15;
  constexpr uint64_t r = 8;
  constexpr uint64_t p = 1;
  constexpr size_t derived_key_len = 32;
  constexpr uint64_t maxmem = 64ULL * 1024ULL * 1024ULL;
  std::string salt_bytes;
  if (!hex_decode(salt_hex, salt_bytes)) return {};
  unsigned char derived_key[derived_key_len];
  if (EVP_PBE_scrypt(password.c_str(), password.size(),
                     reinterpret_cast<const unsigned char *>(salt_bytes.data()),
                     salt_bytes.size(), n, r, p, maxmem, derived_key,
                     sizeof(derived_key)) != 1) {
    return {};
  }
  return "scrypt:32768:8:1:" + salt_hex + ":" +
         hex_encode(derived_key, sizeof(derived_key));
}

inline std::string hash_password(const std::string &password,
                                 const std::string &salt_hex) {
  return hash_password_scrypt(password, salt_hex);
}

inline std::string hash_password(const std::string &password) {
  return hash_password(password, generate_salt());
}

inline bool verify_password_legacy_sha256(const std::string &password,
                                          const std::string &stored) {
  size_t p1 = stored.find(':', 7);
  if (p1 == std::string::npos) return false;
  size_t p2 = stored.find(':', p1 + 1);
  if (p2 == std::string::npos) return false;
  const std::string salt = stored.substr(p1 + 1, p2 - p1 - 1);
  const std::string expected_hash = stored.substr(p2 + 1);
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

inline bool verify_password_scrypt(const std::string &password,
                                   const std::string &stored) {
  const std::string prefix = "scrypt:";
  constexpr uint64_t maxmem = 64ULL * 1024ULL * 1024ULL;
  if (stored.rfind(prefix, 0) != 0) return false;
  const size_t p1 = stored.find(':', prefix.size());
  const size_t p2 = stored.find(':', p1 == std::string::npos ? p1 : p1 + 1);
  const size_t p3 = stored.find(':', p2 == std::string::npos ? p2 : p2 + 1);
  const size_t p4 = stored.find(':', p3 == std::string::npos ? p3 : p3 + 1);
  if (p1 == std::string::npos || p2 == std::string::npos ||
      p3 == std::string::npos || p4 == std::string::npos) {
    return false;
  }

  uint64_t n = 0;
  uint64_t r = 0;
  uint64_t p = 0;
  try {
    n = static_cast<uint64_t>(std::stoull(stored.substr(prefix.size(), p1 - prefix.size())));
    r = static_cast<uint64_t>(std::stoull(stored.substr(p1 + 1, p2 - p1 - 1)));
    p = static_cast<uint64_t>(std::stoull(stored.substr(p2 + 1, p3 - p2 - 1)));
  } catch (...) {
    return false;
  }
  const std::string salt_hex = stored.substr(p3 + 1, p4 - p3 - 1);
  const std::string expected_hex = stored.substr(p4 + 1);
  std::string salt_bytes;
  if (!hex_decode(salt_hex, salt_bytes)) return false;
  std::string expected_bytes;
  if (!hex_decode(expected_hex, expected_bytes)) return false;
  std::vector<unsigned char> derived_key(expected_bytes.size(), 0);
  if (EVP_PBE_scrypt(password.c_str(), password.size(),
                     reinterpret_cast<const unsigned char *>(salt_bytes.data()),
                     salt_bytes.size(), n, r, p, maxmem, derived_key.data(),
                     derived_key.size()) != 1) {
    return false;
  }
  return constant_time_equals(
      std::string(reinterpret_cast<const char *>(derived_key.data()),
                  derived_key.size()),
      expected_bytes);
}

inline bool password_hash_needs_rehash(const std::string &stored) {
  return stored.rfind("scrypt:", 0) != 0;
}

/// Verify a password against a stored hash string.
/// Supports scrypt, legacy SHA-256, and legacy plaintext.
inline bool verify_password(const std::string &password,
                            const std::string &stored) {
  if (stored.rfind("scrypt:", 0) == 0) {
    return verify_password_scrypt(password, stored);
  }

  if (stored.rfind("sha256:", 0) == 0) {
    return verify_password_legacy_sha256(password, stored);
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

// ═══════════════════════════════════════════════════════════════════════
//  AES-256-GCM vault encryption/decryption
// ═══════════════════════════════════════════════════════════════════════

inline std::optional<std::string> get_vault_encryption_key() {
  const char *env_key = std::getenv("ENDORIUMFORT_VAULT_KEY");
  if (!env_key || std::string(env_key).empty()) {
    return std::nullopt;
  }
  // Key should be 64 hex chars (32 bytes)
  std::string key_hex(env_key);
  if (key_hex.size() != 64) {
    return std::nullopt;
  }
  std::string key_bytes;
  if (!hex_decode(key_hex, key_bytes) || key_bytes.size() != 32) {
    return std::nullopt;
  }
  return key_bytes;
}

/// Encrypt plaintext using AES-256-GCM; returns format "aes256:v1:iv:tag:ciphertext" (all hex).
/// Returns empty string on error.
inline std::string aes256_encrypt(const std::string &plaintext) {
  auto key_opt = get_vault_encryption_key();
  if (!key_opt) {
    return {};  // No key configured, return plaintext as-is (unencrypted)
  }
  const std::string &key = *key_opt;

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return {};

  unsigned char iv[12];  // 96-bit IV for GCM
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<uint64_t> dist;
  uint64_t a = dist(gen), b = dist(gen);
  std::memcpy(iv, &a, 8);
  std::memcpy(iv + 8, &b, 4);

  unsigned char tag[16];
  std::vector<unsigned char> ciphertext(plaintext.size() + 16);

  int len = 0;
  int ciphertext_len = 0;

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                         reinterpret_cast<const unsigned char *>(key.data()),
                         iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  if (EVP_EncryptUpdate(
          ctx, ciphertext.data(), &len,
          reinterpret_cast<const unsigned char *>(plaintext.data()),
          plaintext.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  ciphertext_len = len;

  if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  ciphertext_len += len;

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  EVP_CIPHER_CTX_free(ctx);

  // Format: "aes256:v1:{iv_hex}:{tag_hex}:{ciphertext_hex}"
  std::string iv_hex = hex_encode(iv, 12);
  std::string tag_hex = hex_encode(tag, 16);
  std::string ciphertext_hex = hex_encode(ciphertext.data(), ciphertext_len);

  return "aes256:v1:" + iv_hex + ":" + tag_hex + ":" + ciphertext_hex;
}

/// Decrypt ciphertext (format "aes256:v1:iv:tag:ciphertext") using AES-256-GCM.
/// Returns plaintext on success, empty string on error.
inline std::string aes256_decrypt(const std::string &ciphertext_packed) {
  auto key_opt = get_vault_encryption_key();
  if (!key_opt) {
    // No key, assume plaintext (for backward compatibility)
    return ciphertext_packed;
  }
  const std::string &key = *key_opt;

  // Parse format: "aes256:v1:iv:tag:ciphertext"
  const std::string prefix = "aes256:v1:";
  if (ciphertext_packed.rfind(prefix, 0) != 0) {
    // Not encrypted or wrong format, return as-is
    return ciphertext_packed;
  }

  size_t pos = prefix.size();
  size_t iv_end = ciphertext_packed.find(':', pos);
  if (iv_end == std::string::npos) return {};

  size_t tag_end = ciphertext_packed.find(':', iv_end + 1);
  if (tag_end == std::string::npos) return {};

  std::string iv_hex = ciphertext_packed.substr(pos, iv_end - pos);
  std::string tag_hex = ciphertext_packed.substr(iv_end + 1, tag_end - iv_end - 1);
  std::string ciphertext_hex = ciphertext_packed.substr(tag_end + 1);

  std::string iv_bytes, tag_bytes, ciphertext_bytes;
  if (!hex_decode(iv_hex, iv_bytes) || iv_bytes.size() != 12) return {};
  if (!hex_decode(tag_hex, tag_bytes) || tag_bytes.size() != 16) return {};
  if (!hex_decode(ciphertext_hex, ciphertext_bytes)) return {};

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return {};

  std::vector<unsigned char> plaintext(ciphertext_bytes.size() + 1);
  int len = 0;
  int plaintext_len = 0;

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                         reinterpret_cast<const unsigned char *>(key.data()),
                         reinterpret_cast<const unsigned char *>(iv_bytes.data())) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                          reinterpret_cast<unsigned char *>(
                              const_cast<char *>(tag_bytes.data()))) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }

  if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                        reinterpret_cast<const unsigned char *>(ciphertext_bytes.data()),
                        ciphertext_bytes.size()) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  plaintext_len = len;

  if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return {};
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);

  return std::string(reinterpret_cast<char *>(plaintext.data()), plaintext_len);
}

}  // namespace crypto
