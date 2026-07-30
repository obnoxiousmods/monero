// Copyright (c) 2024-2026, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "thp_crypto.hpp"
#include "exceptions.hpp"
#include "misc_log_ex.h"

#include <cstring>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace hw {
namespace trezor {
namespace thp {

// "Noise_XX_25519_AESGCM_SHA256" is 28 bytes; THP pads it to 32 with four zero
// bytes, and the padded form is what feeds the initial chaining key and h.
const char THP_PROTOCOL_NAME[] = "Noise_XX_25519_AESGCM_SHA256\0\0\0\0";

namespace {
struct EvpMdCtx {
  EVP_MD_CTX *ctx;
  EvpMdCtx() : ctx(EVP_MD_CTX_new()) {
    CHECK_AND_ASSERT_THROW_MES(ctx != nullptr, "THP: EVP_MD_CTX_new failed");
  }
  ~EvpMdCtx() { if (ctx) EVP_MD_CTX_free(ctx); }
  EvpMdCtx(const EvpMdCtx &) = delete;
  EvpMdCtx &operator=(const EvpMdCtx &) = delete;
};

struct EvpCipherCtx {
  EVP_CIPHER_CTX *ctx;
  EvpCipherCtx() : ctx(EVP_CIPHER_CTX_new()) {
    CHECK_AND_ASSERT_THROW_MES(ctx != nullptr, "THP: EVP_CIPHER_CTX_new failed");
  }
  ~EvpCipherCtx() { if (ctx) EVP_CIPHER_CTX_free(ctx); }
  EvpCipherCtx(const EvpCipherCtx &) = delete;
  EvpCipherCtx &operator=(const EvpCipherCtx &) = delete;
};

/** Build the 96-bit Noise AESGCM IV: 32 zero bits || big-endian uint64. */
void make_iv(uint8_t iv[12], uint64_t nonce) {
  memset(iv, 0, 4);
  for (int i = 0; i < 8; ++i) {
    iv[4 + i] = static_cast<uint8_t>((nonce >> (8 * (7 - i))) & 0xFF);
  }
}
} // namespace

hash256 sha256(const uint8_t *data, size_t len) {
  hash256 out{};
  EvpMdCtx c;
  CHECK_AND_ASSERT_THROW_MES(EVP_DigestInit_ex(c.ctx, EVP_sha256(), nullptr) == 1,
                             "THP: SHA-256 init failed");
  CHECK_AND_ASSERT_THROW_MES(EVP_DigestUpdate(c.ctx, data, len) == 1,
                             "THP: SHA-256 update failed");
  unsigned int outlen = 0;
  CHECK_AND_ASSERT_THROW_MES(EVP_DigestFinal_ex(c.ctx, out.data(), &outlen) == 1,
                             "THP: SHA-256 final failed");
  CHECK_AND_ASSERT_THROW_MES(outlen == out.size(), "THP: SHA-256 length mismatch");
  return out;
}

hash256 sha256(const bytes &data) {
  return sha256(data.data(), data.size());
}

hash256 sha256_cat(const std::vector<bytes> &chunks) {
  hash256 out{};
  EvpMdCtx c;
  CHECK_AND_ASSERT_THROW_MES(EVP_DigestInit_ex(c.ctx, EVP_sha256(), nullptr) == 1,
                             "THP: SHA-256 init failed");
  for (const auto &chunk : chunks) {
    if (chunk.empty()) continue;
    CHECK_AND_ASSERT_THROW_MES(EVP_DigestUpdate(c.ctx, chunk.data(), chunk.size()) == 1,
                               "THP: SHA-256 update failed");
  }
  unsigned int outlen = 0;
  CHECK_AND_ASSERT_THROW_MES(EVP_DigestFinal_ex(c.ctx, out.data(), &outlen) == 1,
                             "THP: SHA-256 final failed");
  return out;
}

std::array<uint8_t, 64> sha512(const uint8_t *data, size_t len) {
  std::array<uint8_t, 64> out{};
  EvpMdCtx c;
  CHECK_AND_ASSERT_THROW_MES(EVP_DigestInit_ex(c.ctx, EVP_sha512(), nullptr) == 1,
                             "THP: SHA-512 init failed");
  CHECK_AND_ASSERT_THROW_MES(EVP_DigestUpdate(c.ctx, data, len) == 1,
                             "THP: SHA-512 update failed");
  unsigned int outlen = 0;
  CHECK_AND_ASSERT_THROW_MES(EVP_DigestFinal_ex(c.ctx, out.data(), &outlen) == 1,
                             "THP: SHA-512 final failed");
  return out;
}

hash256 hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len) {
  hash256 out{};
  unsigned int outlen = 0;
  const uint8_t *res = HMAC(EVP_sha256(), key, static_cast<int>(key_len),
                            data, data_len, out.data(), &outlen);
  CHECK_AND_ASSERT_THROW_MES(res != nullptr && outlen == out.size(),
                             "THP: HMAC-SHA-256 failed");
  return out;
}

void hkdf(const uint8_t *ck, size_t ck_len,
          const uint8_t *input, size_t input_len,
          hash256 &out1, hash256 &out2) {
  const hash256 temp_key = hmac_sha256(ck, ck_len, input, input_len);

  const uint8_t one = 0x01;
  out1 = hmac_sha256(temp_key.data(), temp_key.size(), &one, 1);

  uint8_t buf[33];
  memcpy(buf, out1.data(), 32);
  buf[32] = 0x02;
  out2 = hmac_sha256(temp_key.data(), temp_key.size(), buf, sizeof(buf));
}

bytes aes_gcm_encrypt(const key256 &key, uint64_t nonce,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *plaintext, size_t pt_len) {
  uint8_t iv[12];
  make_iv(iv, nonce);

  EvpCipherCtx c;
  CHECK_AND_ASSERT_THROW_MES(
      EVP_EncryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1,
      "THP: AES-GCM init failed");
  CHECK_AND_ASSERT_THROW_MES(
      EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr) == 1,
      "THP: AES-GCM IV length not accepted");
  CHECK_AND_ASSERT_THROW_MES(
      EVP_EncryptInit_ex(c.ctx, nullptr, nullptr, key.data(), iv) == 1,
      "THP: AES-GCM key/IV init failed");

  // The AAD pass reports its own consumed length; keep it out of `len` so the
  // ciphertext offset below is not skewed by the size of the associated data.
  int aad_out = 0;
  if (ad_len > 0) {
    CHECK_AND_ASSERT_THROW_MES(
        EVP_EncryptUpdate(c.ctx, nullptr, &aad_out, ad, static_cast<int>(ad_len)) == 1,
        "THP: AES-GCM AAD failed");
  }

  int len = 0;
  bytes out(pt_len + AES_GCM_TAG_SIZE);
  if (pt_len > 0) {
    CHECK_AND_ASSERT_THROW_MES(
        EVP_EncryptUpdate(c.ctx, out.data(), &len, plaintext, static_cast<int>(pt_len)) == 1,
        "THP: AES-GCM encrypt failed");
  }
  int final_len = 0;
  CHECK_AND_ASSERT_THROW_MES(
      EVP_EncryptFinal_ex(c.ctx, out.data() + len, &final_len) == 1,
      "THP: AES-GCM finalisation failed");
  CHECK_AND_ASSERT_THROW_MES(static_cast<size_t>(len + final_len) == pt_len,
                             "THP: AES-GCM produced unexpected ciphertext length");
  CHECK_AND_ASSERT_THROW_MES(
      EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE,
                          out.data() + pt_len) == 1,
      "THP: AES-GCM tag extraction failed");
  return out;
}

bool aes_gcm_decrypt(const key256 &key, uint64_t nonce,
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *ciphertext, size_t ct_len,
                     bytes &out) {
  if (ct_len < AES_GCM_TAG_SIZE) return false;
  const size_t pt_len = ct_len - AES_GCM_TAG_SIZE;

  uint8_t iv[12];
  make_iv(iv, nonce);

  EvpCipherCtx c;
  if (EVP_DecryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) return false;
  if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), nullptr) != 1) return false;
  if (EVP_DecryptInit_ex(c.ctx, nullptr, nullptr, key.data(), iv) != 1) return false;

  int aad_out = 0;
  if (ad_len > 0) {
    if (EVP_DecryptUpdate(c.ctx, nullptr, &aad_out, ad, static_cast<int>(ad_len)) != 1) return false;
  }

  int len = 0;
  bytes plain(pt_len);
  if (pt_len > 0) {
    if (EVP_DecryptUpdate(c.ctx, plain.data(), &len, ciphertext, static_cast<int>(pt_len)) != 1)
      return false;
  }

  // The tag is supplied as a non-const buffer by OpenSSL's API contract.
  uint8_t tag[AES_GCM_TAG_SIZE];
  memcpy(tag, ciphertext + pt_len, AES_GCM_TAG_SIZE);
  if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag) != 1)
    return false;

  int final_len = 0;
  if (EVP_DecryptFinal_ex(c.ctx, plain.data() + len, &final_len) != 1) {
    // Authentication failed; leave `out` untouched.
    return false;
  }

  out = std::move(plain);
  return true;
}

bytes random_bytes(size_t n) {
  bytes out(n);
  if (n == 0) return out;
  CHECK_AND_ASSERT_THROW_MES(RAND_bytes(out.data(), static_cast<int>(n)) == 1,
                             "THP: RAND_bytes failed");
  return out;
}

bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; ++i) diff |= static_cast<uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

key256 cpace_generator(const std::string &code, const hash256 &handshake_hash) {
  // See the header for the derivation of these constants from the CPace
  // generator string; they are fixed because THP fixes the DSI ("CPace255"),
  // the code length (6) and the channel identifier length (32).
  static const uint8_t kPrefix[10] = {
      0x08, 'C', 'P', 'a', 'c', 'e', '2', '5', '5', 0x06};

  CHECK_AND_ASSERT_THROW_MES(code.size() == 6,
                             "THP: CPace pairing code must be exactly six digits");

  bytes buf;
  buf.reserve(10 + 6 + 113 + 32 + 1);
  buf.insert(buf.end(), kPrefix, kPrefix + sizeof(kPrefix));
  buf.insert(buf.end(), code.begin(), code.end());
  buf.push_back(0x6F);                      // length prefix of the zero padding
  buf.insert(buf.end(), 111, 0x00);         // zero padding
  buf.push_back(0x20);                      // length prefix of the channel identifier
  buf.insert(buf.end(), handshake_hash.begin(), handshake_hash.end());
  buf.push_back(0x00);                      // empty session identifier

  const auto pregen = sha512(buf.data(), buf.size());

  key256 generator{};
  elligator2(generator.data(), pregen.data());
  return generator;
}

} // namespace thp
} // namespace trezor
} // namespace hw
