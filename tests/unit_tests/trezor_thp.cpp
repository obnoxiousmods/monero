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

#include "gtest/gtest.h"

#if defined(DEVICE_TREZOR_READY)

#include <boost/filesystem.hpp>
#include <cstdio>
#include <string>
#include <vector>

#include "device_trezor/trezor/thp_curve25519.hpp"
#include "device_trezor/trezor/thp_crypto.hpp"
#include "device_trezor/trezor/thp_wire.hpp"
#include "device_trezor/trezor/protocol_thp.hpp"

#include "trezor_thp_vectors.h"

using namespace hw::trezor::thp;

namespace
{
  std::vector<uint8_t> unhex(const std::string &s)
  {
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
      out.push_back((uint8_t) strtol(s.substr(i, 2).c_str(), nullptr, 16));
    return out;
  }

  std::string hex(const uint8_t *d, size_t n)
  {
    static const char *digits = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(digits[d[i] >> 4]); s.push_back(digits[d[i] & 0xF]); }
    return s;
  }

  std::string hex(const std::vector<uint8_t> &v) { return hex(v.data(), v.size()); }
}

//
// Curve25519
//

TEST(trezor_thp, x25519_rfc7748_vectors)
{
  // RFC 7748 section 5.2
  const auto s1 = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
  const auto u1 = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
  uint8_t out[32];
  x25519_scalarmult(out, s1.data(), u1.data());
  ASSERT_EQ("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", hex(out, 32));

  const auto s2 = unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
  const auto u2 = unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
  x25519_scalarmult(out, s2.data(), u2.data());
  ASSERT_EQ("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957", hex(out, 32));
}

TEST(trezor_thp, x25519_rfc7748_diffie_hellman)
{
  // RFC 7748 section 6.1
  const auto a_priv = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
  const auto b_priv = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
  uint8_t a_pub[32], b_pub[32], ss_a[32], ss_b[32];

  x25519_base(a_pub, a_priv.data());
  x25519_base(b_pub, b_priv.data());
  ASSERT_EQ("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", hex(a_pub, 32));
  ASSERT_EQ("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", hex(b_pub, 32));

  x25519_scalarmult(ss_a, a_priv.data(), b_pub);
  x25519_scalarmult(ss_b, b_priv.data(), a_pub);
  ASSERT_EQ(hex(ss_a, 32), hex(ss_b, 32));
  ASSERT_EQ("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", hex(ss_a, 32));
}

TEST(trezor_thp, x25519_reference_vectors)
{
  for (const auto &v : thp_vectors::X25519_MUL)
  {
    const auto s = unhex(v.a), p = unhex(v.b);
    uint8_t out[32];
    x25519_scalarmult(out, s.data(), p.data());
    ASSERT_EQ(std::string(v.out), hex(out, 32));
  }
}

TEST(trezor_thp, elligator2_reference_vectors)
{
  for (const auto &v : thp_vectors::ELLIGATOR2)
  {
    const auto in = unhex(v.in);
    uint8_t out[32];
    elligator2(out, in.data());
    ASSERT_EQ(std::string(v.out), hex(out, 32));
  }
}

//
// Noise primitives
//

TEST(trezor_thp, hkdf_reference_vectors)
{
  for (const auto &v : thp_vectors::HKDF)
  {
    const auto ck = unhex(v.a), in = unhex(v.b);
    hash256 o1, o2;
    hkdf(ck.data(), ck.size(), in.data(), in.size(), o1, o2);
    ASSERT_EQ(std::string(v.out), hex(o1.data(), 32) + hex(o2.data(), 32));
  }
}

TEST(trezor_thp, aes_gcm_reference_vectors)
{
  for (const auto &v : thp_vectors::AES_GCM)
  {
    const auto kv = unhex(v.key), ad = unhex(v.ad), pt = unhex(v.pt);
    key256 key{};
    std::copy(kv.begin(), kv.end(), key.begin());

    const auto ct = aes_gcm_encrypt(key, v.nonce, ad.data(), ad.size(), pt.data(), pt.size());
    ASSERT_EQ(std::string(v.ct), hex(ct));

    bytes back;
    ASSERT_TRUE(aes_gcm_decrypt(key, v.nonce, ad.data(), ad.size(), ct.data(), ct.size(), back));
    ASSERT_EQ(hex(pt), hex(back));
  }
}

TEST(trezor_thp, aes_gcm_rejects_tampering)
{
  key256 key{};
  key.fill(0x42);
  const bytes ad(16, 0x01), pt(64, 0x02);
  auto ct = aes_gcm_encrypt(key, 7, ad.data(), ad.size(), pt.data(), pt.size());

  bytes out;
  // flipped ciphertext bit
  ct[0] ^= 0x01;
  ASSERT_FALSE(aes_gcm_decrypt(key, 7, ad.data(), ad.size(), ct.data(), ct.size(), out));
  ct[0] ^= 0x01;
  // flipped tag bit
  ct.back() ^= 0x80;
  ASSERT_FALSE(aes_gcm_decrypt(key, 7, ad.data(), ad.size(), ct.data(), ct.size(), out));
  ct.back() ^= 0x80;
  // wrong nonce
  ASSERT_FALSE(aes_gcm_decrypt(key, 8, ad.data(), ad.size(), ct.data(), ct.size(), out));
  // wrong associated data
  bytes bad_ad(16, 0xFF);
  ASSERT_FALSE(aes_gcm_decrypt(key, 7, bad_ad.data(), bad_ad.size(), ct.data(), ct.size(), out));
  // unmodified still authenticates
  ASSERT_TRUE(aes_gcm_decrypt(key, 7, ad.data(), ad.size(), ct.data(), ct.size(), out));
  ASSERT_EQ(hex(pt), hex(out));
}

TEST(trezor_thp, cpace_generator_reference_vectors)
{
  for (const auto &v : thp_vectors::CPACE_GEN)
  {
    const auto hhv = unhex(v.hh);
    hash256 hh{};
    std::copy(hhv.begin(), hhv.end(), hh.begin());
    const auto gen = cpace_generator(v.code, hh);
    ASSERT_EQ(std::string(v.gen), hex(gen.data(), 32));
  }
}

TEST(trezor_thp, cpace_exchange_agrees)
{
  // Both sides derive the same generator from the same code, so the CPace
  // exchange must agree - this is what authenticates the channel.
  hash256 hh{};
  hh.fill(0x5A);
  const auto gen = cpace_generator("013579", hh);

  const auto a_priv = random_bytes(32), b_priv = random_bytes(32);
  uint8_t a_pub[32], b_pub[32], ss_a[32], ss_b[32];
  x25519_scalarmult(a_pub, a_priv.data(), gen.data());
  x25519_scalarmult(b_pub, b_priv.data(), gen.data());
  x25519_scalarmult(ss_a, a_priv.data(), b_pub);
  x25519_scalarmult(ss_b, b_priv.data(), a_pub);
  ASSERT_EQ(hex(ss_a, 32), hex(ss_b, 32));

  // A different code must not agree.
  const auto gen2 = cpace_generator("013578", hh);
  ASSERT_NE(hex(gen.data(), 32), hex(gen2.data(), 32));
  uint8_t b_pub2[32], ss_bad[32];
  x25519_scalarmult(b_pub2, b_priv.data(), gen2.data());
  x25519_scalarmult(ss_bad, a_priv.data(), b_pub2);
  ASSERT_NE(hex(ss_a, 32), hex(ss_bad, 32));
}

TEST(trezor_thp, cpace_generator_rejects_bad_code_length)
{
  hash256 hh{};
  ASSERT_ANY_THROW(cpace_generator("12345", hh));
  ASSERT_ANY_THROW(cpace_generator("1234567", hh));
}

//
// Transport framing
//

TEST(trezor_thp, crc32_reference_vectors)
{
  for (const auto &v : thp_vectors::CRC32)
  {
    const auto d = unhex(v.in);
    char buf[16];
    snprintf(buf, sizeof(buf), "%08x", crc32(d.data(), d.size()));
    ASSERT_EQ(std::string(v.out), std::string(buf));
  }
}

TEST(trezor_thp, message_encoding_reference_vectors)
{
  for (const auto &v : thp_vectors::MESSAGES)
  {
    Message m(v.ctrl, v.cid, unhex(v.data));
    ASSERT_EQ(std::string(v.encoded), hex(m.to_bytes()));
  }
}

TEST(trezor_thp, message_parse_round_trip)
{
  for (const auto &v : thp_vectors::MESSAGES)
  {
    const auto data = unhex(v.data);
    Message m(v.ctrl, v.cid, data);
    const auto encoded = m.to_bytes();
    // parse() takes the transport payload with CRC, i.e. everything past the
    // five-byte header.
    const bytes payload(encoded.begin() + INIT_HEADER_LENGTH, encoded.end());
    const Message parsed = Message::parse(v.ctrl, v.cid, payload);
    ASSERT_EQ(v.ctrl, parsed.ctrl_byte);
    ASSERT_EQ(v.cid, parsed.cid);
    ASSERT_EQ(hex(data), hex(parsed.data));
  }
}

TEST(trezor_thp, message_parse_rejects_bad_checksum)
{
  const bytes data(40, 0xAB);
  Message m(ctrl::ENCRYPTED_TRANSPORT, 0x1234, data);
  auto encoded = m.to_bytes();
  bytes payload(encoded.begin() + INIT_HEADER_LENGTH, encoded.end());

  // Corrupt the data, then separately the CRC itself.
  payload[3] ^= 0xFF;
  ASSERT_ANY_THROW(Message::parse(ctrl::ENCRYPTED_TRANSPORT, 0x1234, payload));
  payload[3] ^= 0xFF;
  payload.back() ^= 0xFF;
  ASSERT_ANY_THROW(Message::parse(ctrl::ENCRYPTED_TRANSPORT, 0x1234, payload));
  payload.back() ^= 0xFF;
  ASSERT_NO_THROW(Message::parse(ctrl::ENCRYPTED_TRANSPORT, 0x1234, payload));

  // The checksum is bound to the control byte and channel id as well.
  ASSERT_ANY_THROW(Message::parse(ctrl::HANDSHAKE_INIT_REQ, 0x1234, payload));
  ASSERT_ANY_THROW(Message::parse(ctrl::ENCRYPTED_TRANSPORT, 0x1235, payload));
}

TEST(trezor_thp, message_parse_rejects_short_payload)
{
  const bytes too_short(3, 0x00);
  ASSERT_ANY_THROW(Message::parse(ctrl::ENCRYPTED_TRANSPORT, 1, too_short));
}

TEST(trezor_thp, control_byte_classification)
{
  ASSERT_TRUE(ctrl::is_continuation(0x80));
  ASSERT_FALSE(ctrl::is_continuation(0x00));

  ASSERT_TRUE(ctrl::is_ack(0x20));
  ASSERT_TRUE(ctrl::is_ack(0x28));
  ASSERT_FALSE(ctrl::is_ack(0x04));
  ASSERT_FALSE(ctrl::get_ack_bit(0x20));
  ASSERT_TRUE(ctrl::get_ack_bit(0x28));
  ASSERT_EQ(0x20, ctrl::make_ack(false));
  ASSERT_EQ(0x28, ctrl::make_ack(true));

  ASSERT_TRUE(ctrl::is_data(0x00));
  ASSERT_TRUE(ctrl::is_data(0x04));
  ASSERT_TRUE(ctrl::is_data(0x14));
  ASSERT_FALSE(ctrl::is_data(0x40));
  ASSERT_TRUE(ctrl::is_error(0x42));
}

TEST(trezor_thp, handshake_control_bytes_have_fixed_sequence_bits)
{
  // The four handshake messages carry a fixed sequence number rather than
  // alternating; getting this wrong desynchronises the whole channel.
  bool has_seq = false;
  ASSERT_FALSE(ctrl::get_seq_bit(ctrl::HANDSHAKE_INIT_REQ, has_seq));
  ASSERT_TRUE(has_seq);
  ASSERT_FALSE(ctrl::get_seq_bit(ctrl::HANDSHAKE_INIT_RES, has_seq));
  ASSERT_TRUE(has_seq);
  ASSERT_TRUE(ctrl::get_seq_bit(ctrl::HANDSHAKE_COMP_REQ, has_seq));
  ASSERT_TRUE(has_seq);
  ASSERT_TRUE(ctrl::get_seq_bit(ctrl::HANDSHAKE_COMP_RES, has_seq));
  ASSERT_TRUE(has_seq);

  // Encrypted transport uses the alternating bit.
  ASSERT_FALSE(ctrl::get_seq_bit(ctrl::ENCRYPTED_TRANSPORT, has_seq));
  ASSERT_TRUE(has_seq);
  ASSERT_TRUE(ctrl::get_seq_bit(ctrl::ENCRYPTED_TRANSPORT | ctrl::DATA_SEQ_BIT, has_seq));
  ASSERT_TRUE(has_seq);

  // Channel allocation and ping carry no sequence number.
  ctrl::get_seq_bit(ctrl::CHANNEL_ALLOCATION_REQ, has_seq);
  ASSERT_FALSE(has_seq);
  ctrl::get_seq_bit(ctrl::PING, has_seq);
  ASSERT_FALSE(has_seq);
}

//
// Credential persistence
//

TEST(trezor_thp, credential_store_round_trip)
{
  namespace fs = boost::filesystem;
  const auto path = fs::temp_directory_path() / fs::unique_path("thp_creds_%%%%.json");
  FileCredentialStore store(path.string());

  // A missing file is not an error; it simply has no credentials.
  ASSERT_TRUE(store.load().empty());

  CredentialEntry a;
  a.trezor_static_pubkey.fill(0x11);
  a.host_static_privkey.fill(0x22);
  a.credential = bytes{0xDE, 0xAD, 0xBE, 0xEF};
  store.store(a);

  auto loaded = store.load();
  ASSERT_EQ(1u, loaded.size());
  ASSERT_EQ(a.trezor_static_pubkey, loaded[0].trezor_static_pubkey);
  ASSERT_EQ(a.host_static_privkey, loaded[0].host_static_privkey);
  ASSERT_EQ(hex(a.credential), hex(loaded[0].credential));

  // A second device is stored alongside the first.
  CredentialEntry b;
  b.trezor_static_pubkey.fill(0x33);
  b.host_static_privkey.fill(0x44);
  b.credential = bytes{0x01, 0x02};
  store.store(b);
  ASSERT_EQ(2u, store.load().size());

  // Re-pairing the same device replaces its credential rather than duplicating it.
  CredentialEntry a2 = a;
  a2.credential = bytes{0xAA, 0xBB, 0xCC};
  store.store(a2);
  loaded = store.load();
  ASSERT_EQ(2u, loaded.size());
  bool found = false;
  for (const auto &e : loaded)
    if (e.trezor_static_pubkey == a.trezor_static_pubkey)
    {
      found = true;
      ASSERT_EQ(hex(a2.credential), hex(e.credential));
    }
  ASSERT_TRUE(found);

  fs::remove(path);
}

TEST(trezor_thp, credential_store_ignores_malformed_file)
{
  namespace fs = boost::filesystem;
  const auto path = fs::temp_directory_path() / fs::unique_path("thp_creds_%%%%.json");
  {
    std::ofstream f(path.string());
    f << "this is not json";
  }
  FileCredentialStore store(path.string());
  // Malformed storage must not throw; the user just re-pairs.
  ASSERT_NO_THROW(store.load());
  ASSERT_TRUE(store.load().empty());
  fs::remove(path);
}

#endif // DEVICE_TREZOR_READY
