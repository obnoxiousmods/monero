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

#include "thp_curve25519.hpp"

#include <cstring>
#include <cassert>

namespace hw {
namespace trezor {
namespace thp {

// Everything in this anonymous namespace has internal linkage. That is
// deliberate: the ref10 field arithmetic below is reproduced verbatim from
// src/crypto/crypto-ops.c, which exports some of these symbols (fe_add,
// fe_invert, fe_tobytes, load_3, load_4) with external linkage. Keeping our
// copies internal avoids duplicate-symbol errors when device_trezor is linked
// against cncrypto.
namespace {

typedef int32_t fe[10];

// Forward declarations: the extracted bodies below are emitted in the order
// they appear in crypto-ops.c, where fe_invert precedes fe_mul and fe_sq.
static void fe_mul(fe, const fe, const fe);
static void fe_sq(fe, const fe);
static void fe_copy(fe, const fe);
static void fe_tobytes(unsigned char *, const fe);

// ---------------------------------------------------------------------------
// Begin verbatim ref10 field arithmetic from src/crypto/crypto-ops.c
// (public domain, by Daniel J. Bernstein et al.)
// ---------------------------------------------------------------------------
uint64_t load_3(const unsigned char *in) {
  uint64_t result;
  result = (uint64_t) in[0];
  result |= ((uint64_t) in[1]) << 8;
  result |= ((uint64_t) in[2]) << 16;
  return result;
}

uint64_t load_4(const unsigned char *in)
{
  uint64_t result;
  result = (uint64_t) in[0];
  result |= ((uint64_t) in[1]) << 8;
  result |= ((uint64_t) in[2]) << 16;
  result |= ((uint64_t) in[3]) << 24;
  return result;
}

static void fe_0(fe h) {
  h[0] = 0;
  h[1] = 0;
  h[2] = 0;
  h[3] = 0;
  h[4] = 0;
  h[5] = 0;
  h[6] = 0;
  h[7] = 0;
  h[8] = 0;
  h[9] = 0;
}

static void fe_1(fe h) {
  h[0] = 1;
  h[1] = 0;
  h[2] = 0;
  h[3] = 0;
  h[4] = 0;
  h[5] = 0;
  h[6] = 0;
  h[7] = 0;
  h[8] = 0;
  h[9] = 0;
}

void fe_add(fe h, const fe f, const fe g) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t g0 = g[0];
  int32_t g1 = g[1];
  int32_t g2 = g[2];
  int32_t g3 = g[3];
  int32_t g4 = g[4];
  int32_t g5 = g[5];
  int32_t g6 = g[6];
  int32_t g7 = g[7];
  int32_t g8 = g[8];
  int32_t g9 = g[9];
  int32_t h0 = f0 + g0;
  int32_t h1 = f1 + g1;
  int32_t h2 = f2 + g2;
  int32_t h3 = f3 + g3;
  int32_t h4 = f4 + g4;
  int32_t h5 = f5 + g5;
  int32_t h6 = f6 + g6;
  int32_t h7 = f7 + g7;
  int32_t h8 = f8 + g8;
  int32_t h9 = f9 + g9;
  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

static void fe_cmov(fe f, const fe g, unsigned int b) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t g0 = g[0];
  int32_t g1 = g[1];
  int32_t g2 = g[2];
  int32_t g3 = g[3];
  int32_t g4 = g[4];
  int32_t g5 = g[5];
  int32_t g6 = g[6];
  int32_t g7 = g[7];
  int32_t g8 = g[8];
  int32_t g9 = g[9];
  int32_t x0 = f0 ^ g0;
  int32_t x1 = f1 ^ g1;
  int32_t x2 = f2 ^ g2;
  int32_t x3 = f3 ^ g3;
  int32_t x4 = f4 ^ g4;
  int32_t x5 = f5 ^ g5;
  int32_t x6 = f6 ^ g6;
  int32_t x7 = f7 ^ g7;
  int32_t x8 = f8 ^ g8;
  int32_t x9 = f9 ^ g9;
  assert((((b - 1) & ~b) | ((b - 2) & ~(b - 1))) == (unsigned int) -1);
  b = -b;
  x0 &= b;
  x1 &= b;
  x2 &= b;
  x3 &= b;
  x4 &= b;
  x5 &= b;
  x6 &= b;
  x7 &= b;
  x8 &= b;
  x9 &= b;
  f[0] = f0 ^ x0;
  f[1] = f1 ^ x1;
  f[2] = f2 ^ x2;
  f[3] = f3 ^ x3;
  f[4] = f4 ^ x4;
  f[5] = f5 ^ x5;
  f[6] = f6 ^ x6;
  f[7] = f7 ^ x7;
  f[8] = f8 ^ x8;
  f[9] = f9 ^ x9;
}

static void fe_copy(fe h, const fe f) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  h[0] = f0;
  h[1] = f1;
  h[2] = f2;
  h[3] = f3;
  h[4] = f4;
  h[5] = f5;
  h[6] = f6;
  h[7] = f7;
  h[8] = f8;
  h[9] = f9;
}

void fe_invert(fe out, const fe z) {
  fe t0;
  fe t1;
  fe t2;
  fe t3;
  int i;

  fe_sq(t0, z);
  fe_sq(t1, t0);
  fe_sq(t1, t1);
  fe_mul(t1, z, t1);
  fe_mul(t0, t0, t1);
  fe_sq(t2, t0);
  fe_mul(t1, t1, t2);
  fe_sq(t2, t1);
  for (i = 0; i < 4; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t1, t2, t1);
  fe_sq(t2, t1);
  for (i = 0; i < 9; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t2, t2, t1);
  fe_sq(t3, t2);
  for (i = 0; i < 19; ++i) {
    fe_sq(t3, t3);
  }
  fe_mul(t2, t3, t2);
  fe_sq(t2, t2);
  for (i = 0; i < 9; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t1, t2, t1);
  fe_sq(t2, t1);
  for (i = 0; i < 49; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t2, t2, t1);
  fe_sq(t3, t2);
  for (i = 0; i < 99; ++i) {
    fe_sq(t3, t3);
  }
  fe_mul(t2, t3, t2);
  fe_sq(t2, t2);
  for (i = 0; i < 49; ++i) {
    fe_sq(t2, t2);
  }
  fe_mul(t1, t2, t1);
  fe_sq(t1, t1);
  for (i = 0; i < 4; ++i) {
    fe_sq(t1, t1);
  }
  fe_mul(out, t1, t0);

  return;
}

static int fe_isnonzero(const fe f) {
  unsigned char s[32];
  fe_tobytes(s, f);
  return (((int) (s[0] | s[1] | s[2] | s[3] | s[4] | s[5] | s[6] | s[7] | s[8] |
    s[9] | s[10] | s[11] | s[12] | s[13] | s[14] | s[15] | s[16] | s[17] |
    s[18] | s[19] | s[20] | s[21] | s[22] | s[23] | s[24] | s[25] | s[26] |
    s[27] | s[28] | s[29] | s[30] | s[31]) - 1) >> 8) + 1;
}

static void fe_mul(fe h, const fe f, const fe g) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t g0 = g[0];
  int32_t g1 = g[1];
  int32_t g2 = g[2];
  int32_t g3 = g[3];
  int32_t g4 = g[4];
  int32_t g5 = g[5];
  int32_t g6 = g[6];
  int32_t g7 = g[7];
  int32_t g8 = g[8];
  int32_t g9 = g[9];
  int32_t g1_19 = 19 * g1; /* 1.959375*2^29 */
  int32_t g2_19 = 19 * g2; /* 1.959375*2^30; still ok */
  int32_t g3_19 = 19 * g3;
  int32_t g4_19 = 19 * g4;
  int32_t g5_19 = 19 * g5;
  int32_t g6_19 = 19 * g6;
  int32_t g7_19 = 19 * g7;
  int32_t g8_19 = 19 * g8;
  int32_t g9_19 = 19 * g9;
  int32_t f1_2 = 2 * f1;
  int32_t f3_2 = 2 * f3;
  int32_t f5_2 = 2 * f5;
  int32_t f7_2 = 2 * f7;
  int32_t f9_2 = 2 * f9;
  int64_t f0g0    = f0   * (int64_t) g0;
  int64_t f0g1    = f0   * (int64_t) g1;
  int64_t f0g2    = f0   * (int64_t) g2;
  int64_t f0g3    = f0   * (int64_t) g3;
  int64_t f0g4    = f0   * (int64_t) g4;
  int64_t f0g5    = f0   * (int64_t) g5;
  int64_t f0g6    = f0   * (int64_t) g6;
  int64_t f0g7    = f0   * (int64_t) g7;
  int64_t f0g8    = f0   * (int64_t) g8;
  int64_t f0g9    = f0   * (int64_t) g9;
  int64_t f1g0    = f1   * (int64_t) g0;
  int64_t f1g1_2  = f1_2 * (int64_t) g1;
  int64_t f1g2    = f1   * (int64_t) g2;
  int64_t f1g3_2  = f1_2 * (int64_t) g3;
  int64_t f1g4    = f1   * (int64_t) g4;
  int64_t f1g5_2  = f1_2 * (int64_t) g5;
  int64_t f1g6    = f1   * (int64_t) g6;
  int64_t f1g7_2  = f1_2 * (int64_t) g7;
  int64_t f1g8    = f1   * (int64_t) g8;
  int64_t f1g9_38 = f1_2 * (int64_t) g9_19;
  int64_t f2g0    = f2   * (int64_t) g0;
  int64_t f2g1    = f2   * (int64_t) g1;
  int64_t f2g2    = f2   * (int64_t) g2;
  int64_t f2g3    = f2   * (int64_t) g3;
  int64_t f2g4    = f2   * (int64_t) g4;
  int64_t f2g5    = f2   * (int64_t) g5;
  int64_t f2g6    = f2   * (int64_t) g6;
  int64_t f2g7    = f2   * (int64_t) g7;
  int64_t f2g8_19 = f2   * (int64_t) g8_19;
  int64_t f2g9_19 = f2   * (int64_t) g9_19;
  int64_t f3g0    = f3   * (int64_t) g0;
  int64_t f3g1_2  = f3_2 * (int64_t) g1;
  int64_t f3g2    = f3   * (int64_t) g2;
  int64_t f3g3_2  = f3_2 * (int64_t) g3;
  int64_t f3g4    = f3   * (int64_t) g4;
  int64_t f3g5_2  = f3_2 * (int64_t) g5;
  int64_t f3g6    = f3   * (int64_t) g6;
  int64_t f3g7_38 = f3_2 * (int64_t) g7_19;
  int64_t f3g8_19 = f3   * (int64_t) g8_19;
  int64_t f3g9_38 = f3_2 * (int64_t) g9_19;
  int64_t f4g0    = f4   * (int64_t) g0;
  int64_t f4g1    = f4   * (int64_t) g1;
  int64_t f4g2    = f4   * (int64_t) g2;
  int64_t f4g3    = f4   * (int64_t) g3;
  int64_t f4g4    = f4   * (int64_t) g4;
  int64_t f4g5    = f4   * (int64_t) g5;
  int64_t f4g6_19 = f4   * (int64_t) g6_19;
  int64_t f4g7_19 = f4   * (int64_t) g7_19;
  int64_t f4g8_19 = f4   * (int64_t) g8_19;
  int64_t f4g9_19 = f4   * (int64_t) g9_19;
  int64_t f5g0    = f5   * (int64_t) g0;
  int64_t f5g1_2  = f5_2 * (int64_t) g1;
  int64_t f5g2    = f5   * (int64_t) g2;
  int64_t f5g3_2  = f5_2 * (int64_t) g3;
  int64_t f5g4    = f5   * (int64_t) g4;
  int64_t f5g5_38 = f5_2 * (int64_t) g5_19;
  int64_t f5g6_19 = f5   * (int64_t) g6_19;
  int64_t f5g7_38 = f5_2 * (int64_t) g7_19;
  int64_t f5g8_19 = f5   * (int64_t) g8_19;
  int64_t f5g9_38 = f5_2 * (int64_t) g9_19;
  int64_t f6g0    = f6   * (int64_t) g0;
  int64_t f6g1    = f6   * (int64_t) g1;
  int64_t f6g2    = f6   * (int64_t) g2;
  int64_t f6g3    = f6   * (int64_t) g3;
  int64_t f6g4_19 = f6   * (int64_t) g4_19;
  int64_t f6g5_19 = f6   * (int64_t) g5_19;
  int64_t f6g6_19 = f6   * (int64_t) g6_19;
  int64_t f6g7_19 = f6   * (int64_t) g7_19;
  int64_t f6g8_19 = f6   * (int64_t) g8_19;
  int64_t f6g9_19 = f6   * (int64_t) g9_19;
  int64_t f7g0    = f7   * (int64_t) g0;
  int64_t f7g1_2  = f7_2 * (int64_t) g1;
  int64_t f7g2    = f7   * (int64_t) g2;
  int64_t f7g3_38 = f7_2 * (int64_t) g3_19;
  int64_t f7g4_19 = f7   * (int64_t) g4_19;
  int64_t f7g5_38 = f7_2 * (int64_t) g5_19;
  int64_t f7g6_19 = f7   * (int64_t) g6_19;
  int64_t f7g7_38 = f7_2 * (int64_t) g7_19;
  int64_t f7g8_19 = f7   * (int64_t) g8_19;
  int64_t f7g9_38 = f7_2 * (int64_t) g9_19;
  int64_t f8g0    = f8   * (int64_t) g0;
  int64_t f8g1    = f8   * (int64_t) g1;
  int64_t f8g2_19 = f8   * (int64_t) g2_19;
  int64_t f8g3_19 = f8   * (int64_t) g3_19;
  int64_t f8g4_19 = f8   * (int64_t) g4_19;
  int64_t f8g5_19 = f8   * (int64_t) g5_19;
  int64_t f8g6_19 = f8   * (int64_t) g6_19;
  int64_t f8g7_19 = f8   * (int64_t) g7_19;
  int64_t f8g8_19 = f8   * (int64_t) g8_19;
  int64_t f8g9_19 = f8   * (int64_t) g9_19;
  int64_t f9g0    = f9   * (int64_t) g0;
  int64_t f9g1_38 = f9_2 * (int64_t) g1_19;
  int64_t f9g2_19 = f9   * (int64_t) g2_19;
  int64_t f9g3_38 = f9_2 * (int64_t) g3_19;
  int64_t f9g4_19 = f9   * (int64_t) g4_19;
  int64_t f9g5_38 = f9_2 * (int64_t) g5_19;
  int64_t f9g6_19 = f9   * (int64_t) g6_19;
  int64_t f9g7_38 = f9_2 * (int64_t) g7_19;
  int64_t f9g8_19 = f9   * (int64_t) g8_19;
  int64_t f9g9_38 = f9_2 * (int64_t) g9_19;
  int64_t h0 = f0g0+f1g9_38+f2g8_19+f3g7_38+f4g6_19+f5g5_38+f6g4_19+f7g3_38+f8g2_19+f9g1_38;
  int64_t h1 = f0g1+f1g0   +f2g9_19+f3g8_19+f4g7_19+f5g6_19+f6g5_19+f7g4_19+f8g3_19+f9g2_19;
  int64_t h2 = f0g2+f1g1_2 +f2g0   +f3g9_38+f4g8_19+f5g7_38+f6g6_19+f7g5_38+f8g4_19+f9g3_38;
  int64_t h3 = f0g3+f1g2   +f2g1   +f3g0   +f4g9_19+f5g8_19+f6g7_19+f7g6_19+f8g5_19+f9g4_19;
  int64_t h4 = f0g4+f1g3_2 +f2g2   +f3g1_2 +f4g0   +f5g9_38+f6g8_19+f7g7_38+f8g6_19+f9g5_38;
  int64_t h5 = f0g5+f1g4   +f2g3   +f3g2   +f4g1   +f5g0   +f6g9_19+f7g8_19+f8g7_19+f9g6_19;
  int64_t h6 = f0g6+f1g5_2 +f2g4   +f3g3_2 +f4g2   +f5g1_2 +f6g0   +f7g9_38+f8g8_19+f9g7_38;
  int64_t h7 = f0g7+f1g6   +f2g5   +f3g4   +f4g3   +f5g2   +f6g1   +f7g0   +f8g9_19+f9g8_19;
  int64_t h8 = f0g8+f1g7_2 +f2g6   +f3g5_2 +f4g4   +f5g3_2 +f6g2   +f7g1_2 +f8g0   +f9g9_38;
  int64_t h9 = f0g9+f1g8   +f2g7   +f3g6   +f4g5   +f5g4   +f6g3   +f7g2   +f8g1   +f9g0   ;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;

  /*
  |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
    i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
  |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
    i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9
  */

  carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  /* |h0| <= 2^25 */
  /* |h4| <= 2^25 */
  /* |h1| <= 1.71*2^59 */
  /* |h5| <= 1.71*2^59 */

  carry1 = (h1 + (int64_t) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (int64_t) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  /* |h1| <= 2^24; from now on fits into int32 */
  /* |h5| <= 2^24; from now on fits into int32 */
  /* |h2| <= 1.41*2^60 */
  /* |h6| <= 1.41*2^60 */

  carry2 = (h2 + (int64_t) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (int64_t) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  /* |h2| <= 2^25; from now on fits into int32 unchanged */
  /* |h6| <= 2^25; from now on fits into int32 unchanged */
  /* |h3| <= 1.71*2^59 */
  /* |h7| <= 1.71*2^59 */

  carry3 = (h3 + (int64_t) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (int64_t) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
  /* |h3| <= 2^24; from now on fits into int32 unchanged */
  /* |h7| <= 2^24; from now on fits into int32 unchanged */
  /* |h4| <= 1.72*2^34 */
  /* |h8| <= 1.41*2^60 */

  carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (int64_t) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;
  /* |h4| <= 2^25; from now on fits into int32 unchanged */
  /* |h8| <= 2^25; from now on fits into int32 unchanged */
  /* |h5| <= 1.01*2^24 */
  /* |h9| <= 1.71*2^59 */

  carry9 = (h9 + (int64_t) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  /* |h9| <= 2^24; from now on fits into int32 unchanged */
  /* |h0| <= 1.1*2^39 */

  carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  /* |h0| <= 2^25; from now on fits into int32 unchanged */
  /* |h1| <= 1.01*2^24 */

  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

static void fe_neg(fe h, const fe f) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t h0 = -f0;
  int32_t h1 = -f1;
  int32_t h2 = -f2;
  int32_t h3 = -f3;
  int32_t h4 = -f4;
  int32_t h5 = -f5;
  int32_t h6 = -f6;
  int32_t h7 = -f7;
  int32_t h8 = -f8;
  int32_t h9 = -f9;
  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

static void fe_sq(fe h, const fe f) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t f0_2 = 2 * f0;
  int32_t f1_2 = 2 * f1;
  int32_t f2_2 = 2 * f2;
  int32_t f3_2 = 2 * f3;
  int32_t f4_2 = 2 * f4;
  int32_t f5_2 = 2 * f5;
  int32_t f6_2 = 2 * f6;
  int32_t f7_2 = 2 * f7;
  int32_t f5_38 = 38 * f5; /* 1.959375*2^30 */
  int32_t f6_19 = 19 * f6; /* 1.959375*2^30 */
  int32_t f7_38 = 38 * f7; /* 1.959375*2^30 */
  int32_t f8_19 = 19 * f8; /* 1.959375*2^30 */
  int32_t f9_38 = 38 * f9; /* 1.959375*2^30 */
  int64_t f0f0    = f0   * (int64_t) f0;
  int64_t f0f1_2  = f0_2 * (int64_t) f1;
  int64_t f0f2_2  = f0_2 * (int64_t) f2;
  int64_t f0f3_2  = f0_2 * (int64_t) f3;
  int64_t f0f4_2  = f0_2 * (int64_t) f4;
  int64_t f0f5_2  = f0_2 * (int64_t) f5;
  int64_t f0f6_2  = f0_2 * (int64_t) f6;
  int64_t f0f7_2  = f0_2 * (int64_t) f7;
  int64_t f0f8_2  = f0_2 * (int64_t) f8;
  int64_t f0f9_2  = f0_2 * (int64_t) f9;
  int64_t f1f1_2  = f1_2 * (int64_t) f1;
  int64_t f1f2_2  = f1_2 * (int64_t) f2;
  int64_t f1f3_4  = f1_2 * (int64_t) f3_2;
  int64_t f1f4_2  = f1_2 * (int64_t) f4;
  int64_t f1f5_4  = f1_2 * (int64_t) f5_2;
  int64_t f1f6_2  = f1_2 * (int64_t) f6;
  int64_t f1f7_4  = f1_2 * (int64_t) f7_2;
  int64_t f1f8_2  = f1_2 * (int64_t) f8;
  int64_t f1f9_76 = f1_2 * (int64_t) f9_38;
  int64_t f2f2    = f2   * (int64_t) f2;
  int64_t f2f3_2  = f2_2 * (int64_t) f3;
  int64_t f2f4_2  = f2_2 * (int64_t) f4;
  int64_t f2f5_2  = f2_2 * (int64_t) f5;
  int64_t f2f6_2  = f2_2 * (int64_t) f6;
  int64_t f2f7_2  = f2_2 * (int64_t) f7;
  int64_t f2f8_38 = f2_2 * (int64_t) f8_19;
  int64_t f2f9_38 = f2   * (int64_t) f9_38;
  int64_t f3f3_2  = f3_2 * (int64_t) f3;
  int64_t f3f4_2  = f3_2 * (int64_t) f4;
  int64_t f3f5_4  = f3_2 * (int64_t) f5_2;
  int64_t f3f6_2  = f3_2 * (int64_t) f6;
  int64_t f3f7_76 = f3_2 * (int64_t) f7_38;
  int64_t f3f8_38 = f3_2 * (int64_t) f8_19;
  int64_t f3f9_76 = f3_2 * (int64_t) f9_38;
  int64_t f4f4    = f4   * (int64_t) f4;
  int64_t f4f5_2  = f4_2 * (int64_t) f5;
  int64_t f4f6_38 = f4_2 * (int64_t) f6_19;
  int64_t f4f7_38 = f4   * (int64_t) f7_38;
  int64_t f4f8_38 = f4_2 * (int64_t) f8_19;
  int64_t f4f9_38 = f4   * (int64_t) f9_38;
  int64_t f5f5_38 = f5   * (int64_t) f5_38;
  int64_t f5f6_38 = f5_2 * (int64_t) f6_19;
  int64_t f5f7_76 = f5_2 * (int64_t) f7_38;
  int64_t f5f8_38 = f5_2 * (int64_t) f8_19;
  int64_t f5f9_76 = f5_2 * (int64_t) f9_38;
  int64_t f6f6_19 = f6   * (int64_t) f6_19;
  int64_t f6f7_38 = f6   * (int64_t) f7_38;
  int64_t f6f8_38 = f6_2 * (int64_t) f8_19;
  int64_t f6f9_38 = f6   * (int64_t) f9_38;
  int64_t f7f7_38 = f7   * (int64_t) f7_38;
  int64_t f7f8_38 = f7_2 * (int64_t) f8_19;
  int64_t f7f9_76 = f7_2 * (int64_t) f9_38;
  int64_t f8f8_19 = f8   * (int64_t) f8_19;
  int64_t f8f9_38 = f8   * (int64_t) f9_38;
  int64_t f9f9_38 = f9   * (int64_t) f9_38;
  int64_t h0 = f0f0  +f1f9_76+f2f8_38+f3f7_76+f4f6_38+f5f5_38;
  int64_t h1 = f0f1_2+f2f9_38+f3f8_38+f4f7_38+f5f6_38;
  int64_t h2 = f0f2_2+f1f1_2 +f3f9_76+f4f8_38+f5f7_76+f6f6_19;
  int64_t h3 = f0f3_2+f1f2_2 +f4f9_38+f5f8_38+f6f7_38;
  int64_t h4 = f0f4_2+f1f3_4 +f2f2   +f5f9_76+f6f8_38+f7f7_38;
  int64_t h5 = f0f5_2+f1f4_2 +f2f3_2 +f6f9_38+f7f8_38;
  int64_t h6 = f0f6_2+f1f5_4 +f2f4_2 +f3f3_2 +f7f9_76+f8f8_19;
  int64_t h7 = f0f7_2+f1f6_2 +f2f5_2 +f3f4_2 +f8f9_38;
  int64_t h8 = f0f8_2+f1f7_4 +f2f6_2 +f3f5_4 +f4f4   +f9f9_38;
  int64_t h9 = f0f9_2+f1f8_2 +f2f7_2 +f3f6_2 +f4f5_2;
  int64_t carry0;
  int64_t carry1;
  int64_t carry2;
  int64_t carry3;
  int64_t carry4;
  int64_t carry5;
  int64_t carry6;
  int64_t carry7;
  int64_t carry8;
  int64_t carry9;

  carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;

  carry1 = (h1 + (int64_t) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry5 = (h5 + (int64_t) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;

  carry2 = (h2 + (int64_t) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry6 = (h6 + (int64_t) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;

  carry3 = (h3 + (int64_t) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry7 = (h7 + (int64_t) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

  carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry8 = (h8 + (int64_t) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

  carry9 = (h9 + (int64_t) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;

  carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;

  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

static void fe_sub(fe h, const fe f, const fe g) {
  int32_t f0 = f[0];
  int32_t f1 = f[1];
  int32_t f2 = f[2];
  int32_t f3 = f[3];
  int32_t f4 = f[4];
  int32_t f5 = f[5];
  int32_t f6 = f[6];
  int32_t f7 = f[7];
  int32_t f8 = f[8];
  int32_t f9 = f[9];
  int32_t g0 = g[0];
  int32_t g1 = g[1];
  int32_t g2 = g[2];
  int32_t g3 = g[3];
  int32_t g4 = g[4];
  int32_t g5 = g[5];
  int32_t g6 = g[6];
  int32_t g7 = g[7];
  int32_t g8 = g[8];
  int32_t g9 = g[9];
  int32_t h0 = f0 - g0;
  int32_t h1 = f1 - g1;
  int32_t h2 = f2 - g2;
  int32_t h3 = f3 - g3;
  int32_t h4 = f4 - g4;
  int32_t h5 = f5 - g5;
  int32_t h6 = f6 - g6;
  int32_t h7 = f7 - g7;
  int32_t h8 = f8 - g8;
  int32_t h9 = f9 - g9;
  h[0] = h0;
  h[1] = h1;
  h[2] = h2;
  h[3] = h3;
  h[4] = h4;
  h[5] = h5;
  h[6] = h6;
  h[7] = h7;
  h[8] = h8;
  h[9] = h9;
}

void fe_tobytes(unsigned char *s, const fe h) {
  int32_t h0 = h[0];
  int32_t h1 = h[1];
  int32_t h2 = h[2];
  int32_t h3 = h[3];
  int32_t h4 = h[4];
  int32_t h5 = h[5];
  int32_t h6 = h[6];
  int32_t h7 = h[7];
  int32_t h8 = h[8];
  int32_t h9 = h[9];
  int32_t q;
  int32_t carry0;
  int32_t carry1;
  int32_t carry2;
  int32_t carry3;
  int32_t carry4;
  int32_t carry5;
  int32_t carry6;
  int32_t carry7;
  int32_t carry8;
  int32_t carry9;

  q = (19 * h9 + (((int32_t) 1) << 24)) >> 25;
  q = (h0 + q) >> 26;
  q = (h1 + q) >> 25;
  q = (h2 + q) >> 26;
  q = (h3 + q) >> 25;
  q = (h4 + q) >> 26;
  q = (h5 + q) >> 25;
  q = (h6 + q) >> 26;
  q = (h7 + q) >> 25;
  q = (h8 + q) >> 26;
  q = (h9 + q) >> 25;

  /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */
  h0 += 19 * q;
  /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

  carry0 = h0 >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry1 = h1 >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry2 = h2 >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry3 = h3 >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry4 = h4 >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry5 = h5 >> 25; h6 += carry5; h5 -= carry5 << 25;
  carry6 = h6 >> 26; h7 += carry6; h6 -= carry6 << 26;
  carry7 = h7 >> 25; h8 += carry7; h7 -= carry7 << 25;
  carry8 = h8 >> 26; h9 += carry8; h8 -= carry8 << 26;
  carry9 = h9 >> 25;               h9 -= carry9 << 25;
                  /* h10 = carry9 */

  /*
  Goal: Output h0+...+2^255 h10-2^255 q, which is between 0 and 2^255-20.
  Have h0+...+2^230 h9 between 0 and 2^255-1;
  evidently 2^255 h10-2^255 q = 0.
  Goal: Output h0+...+2^230 h9.
  */

  s[0] = h0 >> 0;
  s[1] = h0 >> 8;
  s[2] = h0 >> 16;
  s[3] = (h0 >> 24) | (h1 << 2);
  s[4] = h1 >> 6;
  s[5] = h1 >> 14;
  s[6] = (h1 >> 22) | (h2 << 3);
  s[7] = h2 >> 5;
  s[8] = h2 >> 13;
  s[9] = (h2 >> 21) | (h3 << 5);
  s[10] = h3 >> 3;
  s[11] = h3 >> 11;
  s[12] = (h3 >> 19) | (h4 << 6);
  s[13] = h4 >> 2;
  s[14] = h4 >> 10;
  s[15] = h4 >> 18;
  s[16] = h5 >> 0;
  s[17] = h5 >> 8;
  s[18] = h5 >> 16;
  s[19] = (h5 >> 24) | (h6 << 1);
  s[20] = h6 >> 7;
  s[21] = h6 >> 15;
  s[22] = (h6 >> 23) | (h7 << 3);
  s[23] = h7 >> 5;
  s[24] = h7 >> 13;
  s[25] = (h7 >> 21) | (h8 << 4);
  s[26] = h8 >> 4;
  s[27] = h8 >> 12;
  s[28] = (h8 >> 20) | (h9 << 6);
  s[29] = h9 >> 2;
  s[30] = h9 >> 10;
  s[31] = h9 >> 18;
}
// ---------------------------------------------------------------------------
// End verbatim ref10 field arithmetic
// ---------------------------------------------------------------------------

/**
 * ref10 fe_frombytes: decode 32 little-endian bytes into a field element.
 *
 * This is the standard ref10 routine, i.e. the canonicality check that
 * crypto-ops.c performs in ge_frombytes_vartime is intentionally absent: RFC
 * 7748 decodeUCoordinate masks off the most significant bit and reduces
 * modulo p rather than rejecting non-canonical encodings. The mask is applied
 * by the `& 8388607` on h9, which drops bit 255 of the input.
 */
static void fe_frombytes(fe h, const unsigned char *s) {
  int64_t h0 = load_4(s);
  int64_t h1 = load_3(s + 4) << 6;
  int64_t h2 = load_3(s + 7) << 5;
  int64_t h3 = load_3(s + 10) << 3;
  int64_t h4 = load_3(s + 13) << 2;
  int64_t h5 = load_4(s + 16);
  int64_t h6 = load_3(s + 20) << 7;
  int64_t h7 = load_3(s + 23) << 5;
  int64_t h8 = load_3(s + 26) << 4;
  int64_t h9 = (load_3(s + 29) & 8388607) << 2;
  int64_t carry0, carry1, carry2, carry3, carry4;
  int64_t carry5, carry6, carry7, carry8, carry9;

  carry9 = (h9 + (int64_t) (1<<24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
  carry1 = (h1 + (int64_t) (1<<24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
  carry3 = (h3 + (int64_t) (1<<24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
  carry5 = (h5 + (int64_t) (1<<24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
  carry7 = (h7 + (int64_t) (1<<24)) >> 25; h8 += carry7; h7 -= carry7 << 25;

  carry0 = (h0 + (int64_t) (1<<25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
  carry2 = (h2 + (int64_t) (1<<25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
  carry4 = (h4 + (int64_t) (1<<25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
  carry6 = (h6 + (int64_t) (1<<25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
  carry8 = (h8 + (int64_t) (1<<25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

  h[0] = (int32_t) h0; h[1] = (int32_t) h1; h[2] = (int32_t) h2;
  h[3] = (int32_t) h3; h[4] = (int32_t) h4; h[5] = (int32_t) h5;
  h[6] = (int32_t) h6; h[7] = (int32_t) h7; h[8] = (int32_t) h8;
  h[9] = (int32_t) h9;
}

/** Set h to the small non-negative constant v (v must fit in a 26-bit limb). */
static void fe_set_small(fe h, uint32_t v) {
  h[0] = (int32_t) v;
  for (int i = 1; i < 10; ++i) h[i] = 0;
}

/** Constant-time conditional swap of f and g when b is 1. */
static void fe_cswap(fe f, fe g, unsigned int b) {
  const int32_t mask = -(int32_t) b;
  for (int i = 0; i < 10; ++i) {
    const int32_t x = (f[i] ^ g[i]) & mask;
    f[i] ^= x;
    g[i] ^= x;
  }
}

/** Constant-time equality test of two field elements. Returns 1 or 0. */
static unsigned int fe_eq(const fe f, const fe g) {
  unsigned char sf[32], sg[32];
  fe_tobytes(sf, f);
  fe_tobytes(sg, g);
  unsigned int diff = 0;
  for (int i = 0; i < 32; ++i) diff |= (unsigned int) (sf[i] ^ sg[i]);
  // diff is zero iff the encodings match.
  return (unsigned int) ((diff - 1) >> 31) & 1u;
}

/**
 * out = z^((p-5)/8), the standard ref10 fe_pow22523 addition chain.
 * Used by Elligator2 to compute a candidate square root.
 */
static void fe_pow22523(fe out, const fe z) {
  fe t0, t1, t2;
  int i;

  fe_sq(t0, z);
  fe_sq(t1, t0); fe_sq(t1, t1);
  fe_mul(t1, z, t1);
  fe_mul(t0, t0, t1);
  fe_sq(t0, t0);
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0); for (i = 1; i < 5; ++i) fe_sq(t1, t1);
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0); for (i = 1; i < 10; ++i) fe_sq(t1, t1);
  fe_mul(t1, t1, t0);
  fe_sq(t2, t1); for (i = 1; i < 20; ++i) fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  fe_sq(t1, t1); for (i = 1; i < 10; ++i) fe_sq(t1, t1);
  fe_mul(t0, t1, t0);
  fe_sq(t1, t0); for (i = 1; i < 50; ++i) fe_sq(t1, t1);
  fe_mul(t1, t1, t0);
  fe_sq(t2, t1); for (i = 1; i < 100; ++i) fe_sq(t2, t2);
  fe_mul(t1, t2, t1);
  fe_sq(t1, t1); for (i = 1; i < 50; ++i) fe_sq(t1, t1);
  fe_mul(t0, t1, t0);
  fe_sq(t0, t0); fe_sq(t0, t0);
  fe_mul(out, t0, z);
}

/** sqrt(-1) mod p, i.e. ref10's fe_sqrtm1 constant. */
static const fe fe_sqrtm1 = {
  -32595792, -7943725, 9377950, 3500415, 12389472,
  -272473, -25146209, -2005654, 326686, 11406482
};

/** The Curve25519 Montgomery coefficient A = 486662. */
static const uint32_t kCurveJ = 486662;
/** (A + 2) / 4 = 121666, the ladder constant. */
static const uint32_t kCurveA24 = 121666;

} // anonymous namespace

void x25519_scalarmult(uint8_t out[X25519_KEY_SIZE],
                       const uint8_t scalar[X25519_KEY_SIZE],
                       const uint8_t point[X25519_KEY_SIZE]) {
  // decodeScalar25519 (RFC 7748 section 5)
  uint8_t k[32];
  memcpy(k, scalar, 32);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;

  // decodeUCoordinate: fe_frombytes masks bit 255 for us.
  fe x1, x2, z2, x3, z3;
  fe a, aa, b, bb, e, c, d, da, cb, t0, t1, t2, t3, t4;
  fe a24;

  fe_frombytes(x1, point);
  fe_set_small(x2, 1);
  fe_set_small(z2, 0);
  fe_copy(x3, x1);
  fe_set_small(z3, 1);
  fe_set_small(a24, kCurveA24);

  unsigned int swap = 0;
  // Bit 255 is always zero after clamping, so the ladder starts at bit 254.
  for (int i = 254; i >= 0; --i) {
    const unsigned int bit = (unsigned int) ((k[i >> 3] >> (i & 7)) & 1);
    swap ^= bit;
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    swap = bit;

    // Montgomery ladder step (hyperelliptic.org ladd-1987-m-3), matching
    // trezorlib.thp.curve25519.multiply().
    fe_add(a, x2, z2);
    fe_sq(aa, a);
    fe_sub(b, x2, z2);
    fe_sq(bb, b);
    fe_sub(e, aa, bb);
    fe_add(c, x3, z3);
    fe_sub(d, x3, z3);
    fe_mul(da, d, a);
    fe_mul(cb, c, b);

    fe_add(t0, da, cb);
    fe_sq(x3, t0);
    fe_sub(t1, da, cb);
    fe_sq(t2, t1);
    fe_mul(z3, x1, t2);

    fe_mul(x2, aa, bb);
    fe_mul(t3, a24, e);
    fe_add(t4, bb, t3);
    fe_mul(z2, e, t4);
  }
  fe_cswap(x2, x3, swap);
  fe_cswap(z2, z3, swap);

  fe_invert(z2, z2);
  fe_mul(x2, x2, z2);
  fe_tobytes(out, x2);
}

void x25519_base(uint8_t out[X25519_KEY_SIZE],
                 const uint8_t scalar[X25519_KEY_SIZE]) {
  uint8_t basepoint[X25519_KEY_SIZE] = {9};
  x25519_scalarmult(out, scalar, basepoint);
}

void elligator2(uint8_t out[X25519_KEY_SIZE],
                const uint8_t input[X25519_KEY_SIZE]) {
  // map_to_curve_elligator2_curve25519, RFC 9380 appendix G.2.1 (the
  // straight-line "optimized" formulation), mirroring
  // trezorlib.thp.curve25519.elligator2().
  fe u, tv1, tv2, tv3, xd, x1n, x2n, gxd, gx1, y11, y12, y1, xn, one, J;

  fe_frombytes(u, input);
  fe_set_small(one, 1);
  fe_set_small(J, kCurveJ);

  fe_sq(tv1, u);
  fe_add(tv1, tv1, tv1);          // tv1 = 2 * u^2
  fe_add(xd, tv1, one);           // xd = tv1 + 1
  fe_neg(x1n, J);                 // x1n = -J

  fe_sq(tv2, xd);                 // tv2 = xd^2
  fe_mul(gxd, tv2, xd);           // gxd = xd^3

  fe_mul(gx1, J, tv1);            // gx1 = J * tv1
  fe_mul(gx1, gx1, x1n);          // gx1 = gx1 * x1n
  fe_add(gx1, gx1, tv2);          // gx1 = gx1 + tv2
  fe_mul(gx1, gx1, x1n);          // gx1 = gx1 * x1n

  fe_sq(tv3, gxd);                // tv3 = gxd^2
  fe_sq(tv2, tv3);                // tv2 = tv3^2
  fe_mul(tv3, tv3, gxd);          // tv3 = tv3 * gxd
  fe_mul(tv3, tv3, gx1);          // tv3 = tv3 * gx1
  fe_mul(tv2, tv2, tv3);          // tv2 = tv2 * tv3

  fe_pow22523(y11, tv2);          // y11 = tv2^((p-5)/8)
  fe_mul(y11, y11, tv3);          // y11 = y11 * tv3
  fe_mul(y12, y11, fe_sqrtm1);    // y12 = y11 * sqrt(-1)

  fe_sq(tv2, y11);
  fe_mul(tv2, tv2, gxd);
  const unsigned int e1 = fe_eq(tv2, gx1);
  fe_copy(y1, y12);
  fe_cmov(y1, y11, e1);           // y1 = e1 ? y11 : y12

  fe_mul(x2n, x1n, tv1);          // x2n = x1n * tv1

  fe_sq(tv2, y1);
  fe_mul(tv2, tv2, gxd);
  const unsigned int e3 = fe_eq(tv2, gx1);
  fe_copy(xn, x2n);
  fe_cmov(xn, x1n, e3);           // xn = e3 ? x1n : x2n

  fe_invert(xd, xd);
  fe_mul(xn, xn, xd);             // x = xn / xd
  fe_tobytes(out, xn);
}

} // namespace thp
} // namespace trezor
} // namespace hw
