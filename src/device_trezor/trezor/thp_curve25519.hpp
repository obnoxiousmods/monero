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

#include <cstdint>
#include <cstddef>

namespace hw {
namespace trezor {
namespace thp {

/**
 * Curve25519 primitives required by the Trezor-Host Protocol.
 *
 * These are deliberately self-contained rather than delegating to OpenSSL or
 * libsodium, because THP needs two operations that neither library exposes:
 *
 *  - scalar multiplication against an *arbitrary* base point (OpenSSL's EVP
 *    X25519 interface only derives against a peer public key, and the THP
 *    static-key masking step multiplies by a hash-derived scalar), and
 *  - the Elligator2 map to Curve25519, which CPace uses to turn the pairing
 *    code into a group generator. libsodium only offers the Edwards variant
 *    with cofactor clearing (crypto_core_ed25519_from_uniform), which is not
 *    the map THP specifies.
 *
 * The underlying field arithmetic is the public-domain ref10 implementation
 * already vendored in this repository (src/crypto/crypto-ops.c); it is
 * reproduced here with internal linkage so that this module does not depend on
 * cncrypto internals and does not clash with its exported symbols.
 */

/** Length of a scalar / field element / point in bytes. */
constexpr size_t X25519_KEY_SIZE = 32;

/**
 * X25519 scalar multiplication, as specified in RFC 7748 section 5.
 *
 * The scalar is clamped per decodeScalar25519 and the u-coordinate has its
 * most significant bit masked off per decodeUCoordinate, matching the
 * reference host implementation in trezorlib.thp.curve25519.multiply().
 *
 * Unlike libsodium's crypto_scalarmult_curve25519 this does not reject
 * all-zero output; THP's masking step legitimately operates on points whose
 * order is not checked by the protocol, and the caller validates where the
 * specification requires it.
 *
 * out, scalar and point are each X25519_KEY_SIZE bytes. out may alias neither
 * input.
 */
void x25519_scalarmult(uint8_t out[X25519_KEY_SIZE],
                       const uint8_t scalar[X25519_KEY_SIZE],
                       const uint8_t point[X25519_KEY_SIZE]);

/**
 * X25519 scalar multiplication against the canonical base point (u = 9),
 * i.e. derivation of a public key from a private scalar.
 */
void x25519_base(uint8_t out[X25519_KEY_SIZE],
                 const uint8_t scalar[X25519_KEY_SIZE]);

/**
 * map_to_curve_elligator2_curve25519 from RFC 9380 appendix G.2.1, returning
 * the u-coordinate of the resulting Curve25519 point.
 *
 * The input is interpreted as a field element with the most significant bit
 * masked off, matching trezorlib.thp.curve25519.elligator2().
 */
void elligator2(uint8_t out[X25519_KEY_SIZE],
                const uint8_t input[X25519_KEY_SIZE]);

} // namespace thp
} // namespace trezor
} // namespace hw
