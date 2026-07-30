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

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "thp_curve25519.hpp"

namespace hw {
namespace trezor {
namespace thp {

using bytes = std::vector<uint8_t>;
using hash256 = std::array<uint8_t, 32>;
using key256 = std::array<uint8_t, 32>;

/** Size of an AES-GCM authentication tag. */
constexpr size_t AES_GCM_TAG_SIZE = 16;

/** The Noise protocol name THP uses, including its four-byte zero padding. */
extern const char THP_PROTOCOL_NAME[];
constexpr size_t THP_PROTOCOL_NAME_SIZE = 32;

// --------------------------------------------------------------------------
// Hashes
// --------------------------------------------------------------------------

hash256 sha256(const uint8_t *data, size_t len);
hash256 sha256(const bytes &data);

/** SHA-256 over the concatenation of the supplied chunks. */
hash256 sha256_cat(const std::vector<bytes> &chunks);

/** SHA-512, returning all 64 bytes. */
std::array<uint8_t, 64> sha512(const uint8_t *data, size_t len);

hash256 hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len);

/**
 * The two-output HKDF defined by the Noise framework and used throughout THP:
 *
 *   temp_key = HMAC-SHA-256(ck, input)
 *   output_1 = HMAC-SHA-256(temp_key, 0x01)
 *   output_2 = HMAC-SHA-256(temp_key, output_1 || 0x02)
 */
void hkdf(const uint8_t *ck, size_t ck_len,
          const uint8_t *input, size_t input_len,
          hash256 &out1, hash256 &out2);

// --------------------------------------------------------------------------
// AEAD
// --------------------------------------------------------------------------

/**
 * AES-256-GCM encryption with a Noise-style nonce.
 *
 * The 96-bit IV is formed as 32 zero bits followed by the big-endian encoding
 * of `nonce`, per the Noise specification's AESGCM cipher. Returns
 * ciphertext || tag.
 */
bytes aes_gcm_encrypt(const key256 &key, uint64_t nonce,
                      const uint8_t *ad, size_t ad_len,
                      const uint8_t *plaintext, size_t pt_len);

/**
 * AES-256-GCM decryption, the inverse of aes_gcm_encrypt. `ciphertext` must
 * include the trailing tag. Returns false if authentication fails, in which
 * case `out` is left untouched.
 */
bool aes_gcm_decrypt(const key256 &key, uint64_t nonce,
                     const uint8_t *ad, size_t ad_len,
                     const uint8_t *ciphertext, size_t ct_len,
                     bytes &out);

// --------------------------------------------------------------------------
// Misc
// --------------------------------------------------------------------------

/** Cryptographically secure random bytes. Throws on failure. */
bytes random_bytes(size_t n);

/** Constant-time comparison. */
bool ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

// --------------------------------------------------------------------------
// CPace
// --------------------------------------------------------------------------

/**
 * Derive the CPace255 generator for the CodeEntry pairing method.
 *
 * This implements the CPACE-X25519-SHA512 generator string of
 * draft-irtf-cfrg-cpace-10 in the symmetric setting, which the THP
 * specification pins down as:
 *
 *   pregenerator = SHA-512(prefix || code || padding || handshake_hash || 0x00)[:32]
 *   generator    = ELLIGATOR2(pregenerator)
 *
 * where prefix is 0x08 || "CPace255" || 0x06 (the length-prefixed domain
 * separator followed by the length prefix of the six-digit code), and padding
 * is 0x6F || 0x00 * 111 || 0x20 (the zero-padding that aligns the hash block,
 * followed by the length prefix of the 32-byte channel identifier).
 *
 * `code` must be the six-digit pairing code in ASCII, zero padded.
 */
key256 cpace_generator(const std::string &code, const hash256 &handshake_hash);

} // namespace thp
} // namespace trezor
} // namespace hw
