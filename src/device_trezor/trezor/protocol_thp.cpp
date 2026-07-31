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

#include "protocol_thp.hpp"
#include "messages_map.hpp"
#include "exceptions.hpp"
#include "misc_log_ex.h"

#include "messages/messages-thp.pb.h"
#include "messages/messages-common.pb.h"

#include <boost/filesystem.hpp>
#include <cstring>
#include <fstream>
#include <sstream>

#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor.thp"

namespace hw {
namespace trezor {

using namespace thp;
namespace mthp = messages::thp;

namespace {

std::string to_hex(const uint8_t *d, size_t n) {
  static const char *digits = "0123456789abcdef";
  std::string s;
  s.reserve(n * 2);
  for (size_t i = 0; i < n; ++i) {
    s.push_back(digits[d[i] >> 4]);
    s.push_back(digits[d[i] & 0xF]);
  }
  return s;
}

bool from_hex(const std::string &s, uint8_t *out, size_t n) {
  if (s.size() != n * 2) return false;
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < n; ++i) {
    const int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

bytes from_hex_vec(const std::string &s) {
  bytes out(s.size() / 2);
  if (!out.empty() && !from_hex(s, out.data(), out.size())) out.clear();
  return out;
}

bytes serialize_proto(const google::protobuf::Message &msg) {
  std::string s;
  CHECK_AND_ASSERT_THROW_MES(msg.SerializeToString(&s),
                             "THP: could not serialise " << msg.GetTypeName());
  return bytes(s.begin(), s.end());
}

template <class T>
T parse_proto(const bytes &data) {
  T msg;
  CHECK_AND_ASSERT_THROW_MES(
      msg.ParseFromArray(data.data(), static_cast<int>(data.size())),
      "THP: could not parse " << msg.GetTypeName());
  return msg;
}

} // namespace

// ---------------------------------------------------------------------------
// FileCredentialStore
// ---------------------------------------------------------------------------

namespace thp {

std::string FileCredentialStore::default_path() {
  namespace fs = boost::filesystem;
  fs::path base;
#ifdef _WIN32
  const char *appdata = std::getenv("APPDATA");
  base = appdata ? fs::path(appdata) : fs::path(".");
  base /= "feather";
#else
  const char *xdg = std::getenv("XDG_CONFIG_HOME");
  if (xdg && *xdg) {
    base = fs::path(xdg);
  } else {
    const char *home = std::getenv("HOME");
    base = home ? fs::path(home) / ".config" : fs::path(".");
  }
  base /= "feather";
#endif
  return (base / "trezor_thp_credentials.json").string();
}

std::vector<CredentialEntry> FileCredentialStore::load() {
  std::vector<CredentialEntry> out;
  std::ifstream f(m_path, std::ios::binary);
  if (!f.good()) return out;

  std::stringstream ss;
  ss << f.rdbuf();
  const std::string content = ss.str();
  if (content.empty()) return out;

  rapidjson::Document doc;
  if (doc.Parse(content.c_str()).HasParseError() || !doc.IsArray()) {
    MWARNING("THP: credential store at " << m_path << " is malformed, ignoring it");
    return out;
  }

  for (const auto &v : doc.GetArray()) {
    if (!v.IsObject()) continue;
    if (!v.HasMember("trezor_static_pubkey") || !v.HasMember("host_static_privkey") ||
        !v.HasMember("credential"))
      continue;
    CredentialEntry e;
    if (!from_hex(v["trezor_static_pubkey"].GetString(), e.trezor_static_pubkey.data(), 32))
      continue;
    if (!from_hex(v["host_static_privkey"].GetString(), e.host_static_privkey.data(), 32))
      continue;
    e.credential = from_hex_vec(v["credential"].GetString());
    out.push_back(std::move(e));
  }
  MDEBUG("THP: loaded " << out.size() << " pairing credential(s) from " << m_path);
  return out;
}

void FileCredentialStore::store(const CredentialEntry &entry) {
  auto entries = load();

  // Replace any existing credential for the same device.
  entries.erase(std::remove_if(entries.begin(), entries.end(),
                               [&](const CredentialEntry &e) {
                                 return e.trezor_static_pubkey == entry.trezor_static_pubkey;
                               }),
                entries.end());
  entries.push_back(entry);

  rapidjson::Document doc;
  doc.SetArray();
  auto &al = doc.GetAllocator();
  for (const auto &e : entries) {
    rapidjson::Value o(rapidjson::kObjectType);
    const auto tsp = to_hex(e.trezor_static_pubkey.data(), 32);
    const auto hsp = to_hex(e.host_static_privkey.data(), 32);
    const auto cred = to_hex(e.credential.data(), e.credential.size());
    o.AddMember("trezor_static_pubkey",
                rapidjson::Value(tsp.c_str(), al).Move(), al);
    o.AddMember("host_static_privkey",
                rapidjson::Value(hsp.c_str(), al).Move(), al);
    o.AddMember("credential", rapidjson::Value(cred.c_str(), al).Move(), al);
    doc.PushBack(o, al);
  }

  rapidjson::StringBuffer sb;
  rapidjson::Writer<rapidjson::StringBuffer> writer(sb);
  doc.Accept(writer);

  namespace fs = boost::filesystem;
  boost::system::error_code ec;
  fs::create_directories(fs::path(m_path).parent_path(), ec);

  // Write via a temporary file so an interrupted write cannot destroy existing
  // credentials.
  const std::string tmp = m_path + ".tmp";
  {
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    CHECK_AND_ASSERT_THROW_MES(f.good(), "THP: cannot write credential store " << tmp);
    f.write(sb.GetString(), static_cast<std::streamsize>(sb.GetSize()));
    CHECK_AND_ASSERT_THROW_MES(f.good(), "THP: failed writing credential store");
  }
  fs::rename(tmp, m_path, ec);
  if (ec) {
    // rename() cannot clobber an existing file on some platforms.
    fs::remove(m_path, ec);
    fs::rename(tmp, m_path, ec);
  }
  CHECK_AND_ASSERT_THROW_MES(!ec, "THP: cannot replace credential store " << m_path);
  MDEBUG("THP: stored pairing credential in " << m_path);
}

} // namespace thp

// ---------------------------------------------------------------------------
// ProtocolThp
// ---------------------------------------------------------------------------

ProtocolThp::ProtocolThp() = default;

void ProtocolThp::reset_channel() {
  m_channel_open = false;
  m_channel_id = 0;
  m_sync_bit_send = false;
  m_sync_bit_receive = false;
  m_session_created = false;
  m_session_id = 0;
  m_nonce_request = 0;
  m_nonce_response = 0;
  m_credential_matched = false;
  m_credential.clear();
  m_prologue.clear();
  m_pending_message = boost::none;
}

void ProtocolThp::set_passphrase(const std::string &passphrase, bool on_device) {
  m_passphrase = passphrase;
  m_passphrase_on_device = on_device;
  // A passphrase change requires a fresh session.
  m_session_created = false;
}

void ProtocolThp::clear_passphrase() {
  m_passphrase = boost::none;
  m_passphrase_on_device = false;
  m_session_created = false;
}

// --- transport helpers -----------------------------------------------------

void ProtocolThp::throw_transport_error(uint8_t code) {
  // Any of these leave the channel unusable, so drop our state; the next
  // attempt re-allocates and re-handshakes rather than talking to a channel the
  // device has already forgotten.
  switch (code) {
    case static_cast<uint8_t>(TransportError::UNALLOCATED_CHANNEL):
    case static_cast<uint8_t>(TransportError::DECRYPTION_FAILED):
    case static_cast<uint8_t>(TransportError::DEVICE_LOCKED):
      reset_channel();
      break;
    default:
      break;
  }

  if (code == static_cast<uint8_t>(TransportError::DEVICE_LOCKED)) {
    // The handshake asks the device to show its PIN prompt rather than refuse
    // (try_to_unlock), so reaching this means the device declined to unlock -
    // typically the PIN entry was cancelled or timed out.
    throw exc::CommunicationException(
        "THP: the Trezor is locked. Unlock it by entering your PIN on the "
        "device, then try again");
  }

  throw exc::CommunicationException(std::string("THP: transport error ") +
                                    transport_error_to_string(code));
}

void ProtocolThp::send_ack(Transport &transport, const Message &acked) {
  bool has_seq = false;
  const bool seq = ctrl::get_seq_bit(acked.ctrl_byte, has_seq);
  CHECK_AND_ASSERT_THROW_MES(has_seq, "THP: cannot acknowledge a message without a sequence bit");
  thp::write_message(transport, Message::ack(acked.cid, seq));
}

void ProtocolThp::await_ack(Transport &transport, bool expected_seq_bit) {
  for (int attempt = 0; attempt < 8; ++attempt) {
    const Message msg = thp::read_message(transport);
    if (ctrl::is_error(msg.ctrl_byte) && !msg.data.empty()) {
      throw_transport_error(msg.data[0]);
    }

    const bool ack_bit_ok = ctrl::get_ack_bit(msg.ctrl_byte) == expected_seq_bit;

    if (ctrl::is_ack(msg.ctrl_byte)) {
      if (!msg.data.empty()) {
        MWARNING("THP: ignoring ACK carrying unexpected data");
        continue;
      }
    } else if (ctrl::is_data(msg.ctrl_byte) && ack_bit_ok) {
      // We set the ACK bit on our outgoing messages, which newer firmware
      // reads as permission to piggyback: it may answer with the response
      // itself rather than a standalone ACK. Keep it for the next read instead
      // of discarding it, which would strand the exchange.
      MDEBUG("THP: acknowledgement piggybacked on a data message");
      m_pending_message = msg;
      return;
    } else {
      MWARNING("THP: expected an ACK, got " << msg.to_string());
      continue;
    }

    if (!ack_bit_ok) {
      MWARNING("THP: ACK with unexpected sequence bit");
      continue;
    }
    return;
  }
  throw exc::CommunicationException("THP: no valid acknowledgement received");
}

void ProtocolThp::send_message(Transport &transport, Message msg) {
  // Apply the alternating sequence bit and acknowledge the last message we
  // received by piggybacking (harmless on firmware that ignores the bit).
  if (ctrl::is_data(msg.ctrl_byte)) {
    if (m_sync_bit_send) msg.ctrl_byte |= ctrl::DATA_SEQ_BIT;
    if (!m_sync_bit_receive) msg.ctrl_byte |= ctrl::DATA_ACK_SEQ_BIT;
  }

  bool has_seq = false;
  const bool seq = ctrl::get_seq_bit(msg.ctrl_byte, has_seq);
  m_sync_bit_send = !m_sync_bit_send;

  thp::write_message(transport, msg);
  if (has_seq) await_ack(transport, seq);
}

Message ProtocolThp::read_message(Transport &transport, bool allow_broadcast) {
  while (true) {
    Message msg;
    if (m_pending_message) {
      // A message that arrived in place of a standalone ACK. Only its ACK bit
      // was inspected when it was stashed, so it still has to go through the
      // channel and sequence checks below.
      msg = *m_pending_message;
      m_pending_message = boost::none;
    } else {
      msg = thp::read_message(transport);
    }

    if (msg.cid != m_channel_id &&
        !(allow_broadcast && msg.cid == BROADCAST_CHANNEL_ID)) {
      MWARNING("THP: ignoring message for channel " << msg.cid);
      continue;
    }

    if (ctrl::is_error(msg.ctrl_byte) && !msg.data.empty()) {
      throw_transport_error(msg.data[0]);
    }

    bool has_seq = false;
    const bool seq = ctrl::get_seq_bit(msg.ctrl_byte, has_seq);
    if (has_seq) {
      if (seq != m_sync_bit_receive) {
        // A retransmission of a payload we already processed.
        MWARNING("THP: duplicate message, re-acknowledging");
        send_ack(transport, msg);
        continue;
      }
      m_sync_bit_receive = !m_sync_bit_receive;
    }
    return msg;
  }
}

// --- channel allocation ----------------------------------------------------

void ProtocolThp::allocate_channel(Transport &transport) {
  for (int attempt = 0; attempt < 3; ++attempt) {
    const bytes nonce = random_bytes(8);
    thp::write_message(transport,
                       Message::broadcast(ctrl::CHANNEL_ALLOCATION_REQ, nonce));

    const Message resp = thp::read_message(transport);
    if (!resp.is_channel_allocation_response()) {
      MWARNING("THP: unexpected response to channel allocation");
      continue;
    }
    CHECK_AND_ASSERT_THROW_MES(resp.data.size() >= 10,
                               "THP: truncated channel allocation response");
    if (!std::equal(nonce.begin(), nonce.end(), resp.data.begin())) {
      MWARNING("THP: channel allocation nonce mismatch, retrying");
      continue;
    }

    m_channel_id = static_cast<uint16_t>((resp.data[8] << 8) | resp.data[9]);
    // The remainder is the serialized ThpDeviceProperties; it doubles as the
    // Noise prologue and must be hashed verbatim.
    m_prologue.assign(resp.data.begin() + 10, resp.data.end());

    const auto props = parse_proto<mthp::ThpDeviceProperties>(m_prologue);
    m_internal_model = props.internal_model();
    m_pairing_methods.clear();
    for (int i = 0; i < props.pairing_methods_size(); ++i)
      m_pairing_methods.push_back(props.pairing_methods(i));

    MINFO("THP: allocated channel " << m_channel_id << " on " << m_internal_model
                                    << " (protocol " << props.protocol_version_major()
                                    << "." << props.protocol_version_minor() << ")");
    return;
  }
  throw exc::CommunicationException("THP: channel allocation failed");
}

bool ProtocolThp::probe(Transport &transport) {
  // A THP ping/pong is a single packet, so this deliberately does not go
  // through read_message(): reassembly could block, and a device speaking the
  // legacy codec will simply discard the packet and never answer. The bounded
  // read is what keeps that case from hanging forever.
  static constexpr unsigned PROBE_TIMEOUT_MS = 1500;

  try {
    const bytes nonce = random_bytes(8);
    thp::write_message(transport, Message::broadcast(ctrl::PING, nonce));

    // Give the device a couple of packets' worth of grace in case something
    // unrelated is still queued up on the interrupt endpoint.
    for (int i = 0; i < 3; ++i) {
      uint8_t packet[THP_PACKET_SIZE];
      const size_t nread = transport.read_chunk_timeout(packet, THP_PACKET_SIZE, PROBE_TIMEOUT_MS);
      if (nread != THP_PACKET_SIZE) {
        MDEBUG("THP: probe timed out; assuming the legacy codec");
        return false;
      }
      if (ctrl::is_continuation(packet[0])) continue;

      const uint16_t cid = static_cast<uint16_t>((packet[1] << 8) | packet[2]);
      const size_t len = static_cast<size_t>((packet[3] << 8) | packet[4]);
      if (packet[0] != ctrl::PONG || cid != BROADCAST_CHANNEL_ID) continue;
      if (len < 8 + CHECKSUM_LENGTH || len > THP_PACKET_SIZE - INIT_HEADER_LENGTH) continue;

      const bytes payload(packet + INIT_HEADER_LENGTH, packet + INIT_HEADER_LENGTH + len);
      try {
        const Message pong = Message::parse(packet[0], cid, payload);
        if (pong.data.size() >= 8 &&
            std::equal(nonce.begin(), nonce.end(), pong.data.begin())) {
          MINFO("THP: device answered the ping; using the Trezor-Host Protocol");
          return true;
        }
      } catch (const std::exception &) {
        // Bad checksum: not a pong we can trust.
      }
    }
    return false;
  } catch (const std::exception &e) {
    MDEBUG("THP: probe did not find a THP device: " << e.what());
    return false;
  }
}

// --- Noise XX handshake ----------------------------------------------------

void ProtocolThp::handshake(Transport &transport) {
  const uint8_t *pname = reinterpret_cast<const uint8_t *>(THP_PROTOCOL_NAME);

  // Host ephemeral key pair.
  const bytes eph = random_bytes(32);
  std::copy(eph.begin(), eph.end(), m_host_ephemeral_priv.begin());
  key256 host_eph_pub{};
  x25519_base(host_eph_pub.data(), m_host_ephemeral_priv.data());

  const uint8_t try_to_unlock = 1;

  // h = SHA256(protocol_name || device_properties)
  {
    bytes buf(pname, pname + THP_PROTOCOL_NAME_SIZE);
    buf.insert(buf.end(), m_prologue.begin(), m_prologue.end());
    m_h = sha256(buf);
  }
  auto mix_hash = [&](const uint8_t *d, size_t n) {
    bytes buf(m_h.begin(), m_h.end());
    buf.insert(buf.end(), d, d + n);
    m_h = sha256(buf);
  };
  mix_hash(host_eph_pub.data(), 32);
  mix_hash(&try_to_unlock, 1);

  // HandshakeInitiationRequest
  {
    bytes data(host_eph_pub.begin(), host_eph_pub.end());
    data.push_back(try_to_unlock);
    send_message(transport, Message(ctrl::HANDSHAKE_INIT_REQ, m_channel_id, data));
  }

  // HandshakeInitiationResponse
  const Message init_resp = read_message(transport);
  send_ack(transport, init_resp);
  CHECK_AND_ASSERT_THROW_MES(init_resp.is_handshake_init_response(),
                             "THP: expected a handshake initiation response");
  CHECK_AND_ASSERT_THROW_MES(init_resp.data.size() == 32 + 48 + 16,
                             "THP: malformed handshake initiation response");

  const uint8_t *trezor_eph_pub = init_resp.data.data();
  const uint8_t *enc_trezor_static = init_resp.data.data() + 32;
  const uint8_t *tag = init_resp.data.data() + 80;

  mix_hash(trezor_eph_pub, 32);

  key256 k{};
  {
    uint8_t dh[32];
    x25519_scalarmult(dh, m_host_ephemeral_priv.data(), trezor_eph_pub);
    hkdf(pname, THP_PROTOCOL_NAME_SIZE, dh, 32, m_ck, k);
  }

  bytes trezor_masked_static;
  CHECK_AND_ASSERT_THROW_MES(
      aes_gcm_decrypt(k, 0, m_h.data(), m_h.size(), enc_trezor_static, 48,
                      trezor_masked_static),
      "THP: could not decrypt the Trezor static public key");
  CHECK_AND_ASSERT_THROW_MES(trezor_masked_static.size() == 32,
                             "THP: unexpected Trezor static public key length");
  mix_hash(enc_trezor_static, 48);

  {
    uint8_t dh[32];
    x25519_scalarmult(dh, m_host_ephemeral_priv.data(), trezor_masked_static.data());
    hkdf(m_ck.data(), m_ck.size(), dh, 32, m_ck, k);
  }

  bytes empty_payload;
  CHECK_AND_ASSERT_THROW_MES(
      aes_gcm_decrypt(k, 0, m_h.data(), m_h.size(), tag, 16, empty_payload),
      "THP: handshake authentication tag did not verify");
  CHECK_AND_ASSERT_THROW_MES(empty_payload.empty(),
                             "THP: unexpected payload in handshake initiation response");
  mix_hash(tag, 16);

  // Look for a stored credential belonging to this device. The Trezor's static
  // public key is masked with its ephemeral key, so each candidate has to be
  // re-masked and compared.
  m_credential.clear();
  m_credential_matched = false;
  if (!m_credential_store) {
    m_credential_store = std::make_shared<FileCredentialStore>(FileCredentialStore::default_path());
  }
  for (const auto &entry : m_credential_store->load()) {
    bytes buf(entry.trezor_static_pubkey.begin(), entry.trezor_static_pubkey.end());
    buf.insert(buf.end(), trezor_eph_pub, trezor_eph_pub + 32);
    const hash256 mask = sha256(buf);
    uint8_t masked[32];
    x25519_scalarmult(masked, mask.data(), entry.trezor_static_pubkey.data());
    if (memcmp(masked, trezor_masked_static.data(), 32) == 0) {
      m_host_static_priv = entry.host_static_privkey;
      m_trezor_static_pub = entry.trezor_static_pubkey;
      m_credential = entry.credential;
      m_credential_matched = true;
      MINFO("THP: reusing stored pairing credential for this device");
      break;
    }
  }
  if (!m_credential_matched) {
    const bytes hs = random_bytes(32);
    std::copy(hs.begin(), hs.end(), m_host_static_priv.begin());
  }
  x25519_base(m_host_static_pub.data(), m_host_static_priv.data());

  // HandshakeCompletionRequest
  const bytes enc_host_static =
      aes_gcm_encrypt(k, 1, m_h.data(), m_h.size(), m_host_static_pub.data(), 32);
  mix_hash(enc_host_static.data(), enc_host_static.size());

  {
    uint8_t dh[32];
    x25519_scalarmult(dh, m_host_static_priv.data(), trezor_eph_pub);
    hkdf(m_ck.data(), m_ck.size(), dh, 32, m_ck, k);
  }

  mthp::ThpHandshakeCompletionReqNoisePayload payload;
  if (!m_credential.empty())
    payload.set_host_pairing_credential(m_credential.data(), m_credential.size());
  const bytes payload_bin = serialize_proto(payload);

  const bytes enc_payload =
      aes_gcm_encrypt(k, 0, m_h.data(), m_h.size(), payload_bin.data(), payload_bin.size());
  mix_hash(enc_payload.data(), enc_payload.size());

  {
    bytes data(enc_host_static.begin(), enc_host_static.end());
    data.insert(data.end(), enc_payload.begin(), enc_payload.end());
    send_message(transport, Message(ctrl::HANDSHAKE_COMP_REQ, m_channel_id, data));
  }

  // The handshake hash is `h` once the completion request has been folded in;
  // CPace binds the pairing code to it.
  m_handshake_hash = m_h;

  // Derive the transport keys.
  hkdf(m_ck.data(), m_ck.size(), nullptr, 0, m_key_request, m_key_response);
  m_nonce_request = 0;
  m_nonce_response = 0;

  // HandshakeCompletionResponse
  const Message comp_resp = read_message(transport);
  send_ack(transport, comp_resp);
  CHECK_AND_ASSERT_THROW_MES(comp_resp.is_handshake_comp_response(),
                             "THP: expected a handshake completion response");

  bytes state;
  CHECK_AND_ASSERT_THROW_MES(
      aes_gcm_decrypt(m_key_response, m_nonce_response, nullptr, 0,
                      comp_resp.data.data(), comp_resp.data.size(), state),
      "THP: could not decrypt the Trezor state");
  m_nonce_response = 1;
  CHECK_AND_ASSERT_THROW_MES(state.size() == 1, "THP: unexpected Trezor state length");

  switch (state[0]) {
    case 0: m_pairing_state = PairingState::UNPAIRED; break;
    case 1: m_pairing_state = PairingState::PAIRED; break;
    case 2: m_pairing_state = PairingState::PAIRED_AUTOCONNECT; break;
    default:
      throw exc::CommunicationException("THP: invalid Trezor pairing state");
  }
  MINFO("THP: handshake complete, device reports state " << static_cast<int>(state[0]));
}

// --- application layer -----------------------------------------------------

bytes ProtocolThp::noise_encrypt(const bytes &plaintext) {
  auto ct = aes_gcm_encrypt(m_key_request, m_nonce_request, nullptr, 0,
                            plaintext.data(), plaintext.size());
  ++m_nonce_request;
  return ct;
}

bytes ProtocolThp::noise_decrypt(const bytes &ciphertext) {
  bytes pt;
  CHECK_AND_ASSERT_THROW_MES(
      aes_gcm_decrypt(m_key_response, m_nonce_response, nullptr, 0,
                      ciphertext.data(), ciphertext.size(), pt),
      "THP: could not decrypt an encrypted transport message");
  ++m_nonce_response;
  return pt;
}

void ProtocolThp::write_app(Transport &transport, uint8_t session_id,
                            uint16_t msg_type, const bytes &payload) {
  bytes frame;
  frame.reserve(3 + payload.size());
  frame.push_back(session_id);
  frame.push_back(static_cast<uint8_t>((msg_type >> 8) & 0xFF));
  frame.push_back(static_cast<uint8_t>(msg_type & 0xFF));
  frame.insert(frame.end(), payload.begin(), payload.end());

  send_message(transport,
               Message(ctrl::ENCRYPTED_TRANSPORT, m_channel_id, noise_encrypt(frame)));
}

void ProtocolThp::read_app(Transport &transport, uint8_t &session_id,
                           uint16_t &msg_type, bytes &payload) {
  while (true) {
    const Message msg = read_message(transport);
    if (ctrl::is_ack(msg.ctrl_byte)) {
      MWARNING("THP: unexpected standalone ACK");
      continue;
    }
    CHECK_AND_ASSERT_THROW_MES(msg.is_encrypted_transport(),
                               "THP: expected an encrypted transport message");
    send_ack(transport, msg);

    const bytes frame = noise_decrypt(msg.data);
    CHECK_AND_ASSERT_THROW_MES(frame.size() >= 3, "THP: truncated application frame");
    session_id = frame[0];
    msg_type = static_cast<uint16_t>((frame[1] << 8) | frame[2]);
    payload.assign(frame.begin() + 3, frame.end());
    return;
  }
}

bytes ProtocolThp::read_app_expect(Transport &transport, uint8_t session_id,
                                   uint16_t expected_type, const char *what) {
  uint8_t sid = 0;
  uint16_t type = 0;
  bytes payload;

  while (true) {
    read_app(transport, sid, type, payload);

    if (type == wire_type::ButtonRequest) {
      // The device is waiting on the user; acknowledge and keep reading. This
      // can happen in any phase, so it is handled here rather than per call site.
      messages::common::ButtonAck ack;
      write_app(transport, sid, wire_type::ButtonAck, serialize_proto(ack));
      continue;
    }

    if (type == wire_type::Failure && expected_type != wire_type::Failure) {
      const auto f = parse_proto<messages::common::Failure>(payload);
      throw exc::CommunicationException(std::string("THP: the device reported a failure while ") +
                                        what + ": " + f.message());
    }

    if (type == expected_type) return payload;

    throw exc::CommunicationException(
        std::string("THP: unexpected message while ") + what +
        " (wire type " + std::to_string(type) + ")");
  }
}

// --- pairing ---------------------------------------------------------------

void ProtocolThp::do_pairing(Transport &transport) {
  CHECK_AND_ASSERT_THROW_MES(
      m_pairing_ui,
      "THP: the device requires pairing but no pairing UI has been provided");

  // ThpPairingRequest -> ThpPairingRequestApproved (the device asks the user to
  // confirm, so a ButtonRequest may arrive first).
  mthp::ThpPairingRequest req;
  req.set_host_name(m_pairing_ui->host_name());
  req.set_app_name(m_pairing_ui->app_name());
  write_app(transport, 0, wire_type::ThpPairingRequest, serialize_proto(req));
  read_app_expect(transport, 0, wire_type::ThpPairingRequestApproved,
                  "waiting for pairing to be approved on the device");

  const bool code_entry_supported =
      std::find(m_pairing_methods.begin(), m_pairing_methods.end(),
                static_cast<int>(mthp::CodeEntry)) != m_pairing_methods.end();
  CHECK_AND_ASSERT_THROW_MES(
      code_entry_supported,
      "THP: the device does not offer the CodeEntry pairing method, which is the "
      "only one this host implements");

  code_entry_pairing(transport);
}

void ProtocolThp::code_entry_pairing(Transport &transport) {
  // Select CodeEntry; the device answers with its commitment.
  mthp::ThpSelectMethod sel;
  sel.set_selected_pairing_method(mthp::CodeEntry);
  write_app(transport, 0, wire_type::ThpSelectMethod, serialize_proto(sel));

  bytes payload = read_app_expect(transport, 0, wire_type::ThpCodeEntryCommitment,
                                  "selecting the CodeEntry pairing method");
  const auto commitment_msg = parse_proto<mthp::ThpCodeEntryCommitment>(payload);
  const std::string commitment = commitment_msg.commitment();

  // Send our challenge; the device answers with its CPace public key and shows
  // the six-digit code on screen.
  const bytes challenge = random_bytes(16);
  mthp::ThpCodeEntryChallenge chal;
  chal.set_challenge(challenge.data(), challenge.size());
  write_app(transport, 0, wire_type::ThpCodeEntryChallenge, serialize_proto(chal));

  payload = read_app_expect(transport, 0, wire_type::ThpCodeEntryCpaceTrezor,
                            "waiting for the device to display the pairing code");
  const auto cpace_msg = parse_proto<mthp::ThpCodeEntryCpaceTrezor>(payload);
  const std::string trezor_cpace_pub = cpace_msg.cpace_trezor_public_key();
  CHECK_AND_ASSERT_THROW_MES(trezor_cpace_pub.size() == 32,
                             "THP: malformed Trezor CPace public key");

  // Ask the user for the code shown on the device. An empty result means either
  // a genuine cancellation or that the wallet front-end never surfaced the
  // prompt; say so, because the two are indistinguishable from here and the
  // second looks like an instant cancellation to the user.
  const auto code_opt = m_pairing_ui->on_pairing_code_request();
  CHECK_AND_ASSERT_THROW_MES(
      code_opt,
      "THP: no pairing code was supplied - either pairing was cancelled, or this "
      "application does not implement the pairing code prompt");
  const std::string code = *code_opt;
  CHECK_AND_ASSERT_THROW_MES(
      code.size() == 6 &&
          code.find_first_not_of("0123456789") == std::string::npos,
      "THP: the pairing code must be six digits");

  // CPace: derive the generator from the code and complete the exchange.
  const key256 generator = cpace_generator(code, m_handshake_hash);
  const bytes cpace_priv = random_bytes(32);
  key256 cpace_pub{}, shared{};
  x25519_scalarmult(cpace_pub.data(), cpace_priv.data(), generator.data());
  x25519_scalarmult(shared.data(), cpace_priv.data(),
                    reinterpret_cast<const uint8_t *>(trezor_cpace_pub.data()));
  const hash256 tag = sha256(shared.data(), shared.size());

  mthp::ThpCodeEntryCpaceHostTag host_tag;
  host_tag.set_cpace_host_public_key(cpace_pub.data(), cpace_pub.size());
  host_tag.set_tag(tag.data(), tag.size());
  write_app(transport, 0, wire_type::ThpCodeEntryCpaceHostTag, serialize_proto(host_tag));

  // A Failure here means the device rejected our tag, i.e. the code was wrong.
  payload = read_app_expect(transport, 0, wire_type::ThpCodeEntrySecret,
                            "verifying the pairing code");
  const auto secret_msg = parse_proto<mthp::ThpCodeEntrySecret>(payload);
  const std::string secret = secret_msg.secret();

  // The device only now reveals the secret behind its commitment; verifying it
  // is what actually rules out a man in the middle.
  const hash256 computed_commitment =
      sha256(reinterpret_cast<const uint8_t *>(secret.data()), secret.size());
  CHECK_AND_ASSERT_THROW_MES(
      commitment.size() == computed_commitment.size() &&
          ct_equal(reinterpret_cast<const uint8_t *>(commitment.data()),
                   computed_commitment.data(), computed_commitment.size()),
      "THP: the device's CodeEntry commitment did not verify");

  {
    bytes buf;
    buf.push_back(static_cast<uint8_t>(mthp::CodeEntry));
    buf.insert(buf.end(), m_handshake_hash.begin(), m_handshake_hash.end());
    buf.insert(buf.end(), secret.begin(), secret.end());
    buf.insert(buf.end(), challenge.begin(), challenge.end());
    const hash256 code_hash = sha256(buf);

    // Interpret the digest as a big-endian integer modulo 1e6.
    uint64_t acc = 0;
    for (uint8_t b : code_hash) acc = (acc * 256 + b) % 1000000;
    char expected[8];
    snprintf(expected, sizeof(expected), "%06u", static_cast<unsigned>(acc));
    CHECK_AND_ASSERT_THROW_MES(code == expected,
                               "THP: the pairing code did not verify");
  }

  MINFO("THP: pairing completed successfully");
  m_pairing_state = PairingState::PAIRED;
}

void ProtocolThp::request_credential(Transport &transport) {
  mthp::ThpCredentialRequest req;
  req.set_host_static_public_key(m_host_static_pub.data(), m_host_static_pub.size());
  // Autoconnect lets subsequent connections skip the confirmation dialog.
  req.set_autoconnect(true);
  if (!m_credential.empty())
    req.set_credential(m_credential.data(), m_credential.size());
  write_app(transport, 0, wire_type::ThpCredentialRequest, serialize_proto(req));

  bytes payload;
  try {
    payload = read_app_expect(transport, 0, wire_type::ThpCredentialResponse,
                              "requesting a pairing credential");
  } catch (const std::exception &e) {
    // Not fatal: the channel still works, the user will just have to pair again
    // next time rather than reconnecting silently.
    MWARNING("THP: the device did not issue a pairing credential: " << e.what());
    return;
  }

  const auto resp = parse_proto<mthp::ThpCredentialResponse>(payload);
  CHECK_AND_ASSERT_THROW_MES(resp.trezor_static_public_key().size() == 32,
                             "THP: malformed Trezor static public key");

  CredentialEntry entry;
  memcpy(entry.trezor_static_pubkey.data(), resp.trezor_static_public_key().data(), 32);
  entry.host_static_privkey = m_host_static_priv;
  entry.credential.assign(resp.credential().begin(), resp.credential().end());

  try {
    m_credential_store->store(entry);
  } catch (const std::exception &e) {
    // Losing the credential only costs the user another pairing next time.
    MWARNING("THP: could not persist the pairing credential: " << e.what());
  }
}

void ProtocolThp::end_handshake(Transport &transport) {
  mthp::ThpEndRequest req;
  write_app(transport, 0, wire_type::ThpEndRequest, serialize_proto(req));
  read_app_expect(transport, 0, wire_type::ThpEndResponse, "ending the handshake");
  m_channel_open = true;
}

void ProtocolThp::create_session(Transport &transport) {
  // Unlike the legacy protocol, THP does not ask for the passphrase mid-flow
  // with a PassphraseRequest: it is a parameter of session creation. If one has
  // not been set explicitly, ask the UI now.
  if (!m_passphrase && !m_passphrase_on_device && m_pairing_ui) {
    bool on_device = false;
    const auto passphrase = m_pairing_ui->on_passphrase_request(on_device);
    if (on_device) {
      m_passphrase_on_device = true;
    } else if (passphrase) {
      m_passphrase = *passphrase;
    }
  }

  mthp::ThpCreateNewSession req;
  if (m_passphrase_on_device) {
    req.set_on_device(true);
  } else if (m_passphrase) {
    req.set_passphrase(*m_passphrase);
  }
  req.set_derive_cardano(false);

  // Session 0 is the pairing/management session; passphrase wallets get their
  // own session id.
  m_session_id = (m_passphrase || m_passphrase_on_device) ? 1 : 0;

  write_app(transport, m_session_id, wire_type::ThpCreateNewSession, serialize_proto(req));
  read_app_expect(transport, m_session_id, wire_type::Success, "creating a session");
  m_session_created = true;
  MDEBUG("THP: created session " << static_cast<int>(m_session_id));
}

// --- Protocol interface ----------------------------------------------------

void ProtocolThp::session_begin(Transport &transport) {
  if (m_channel_open && m_session_created) return;

  reset_channel();
  allocate_channel(transport);
  handshake(transport);

  if (m_pairing_state == PairingState::UNPAIRED) {
    do_pairing(transport);
    request_credential(transport);
  } else if (!m_credential_matched) {
    // Paired without a stored credential (for example after the store was
    // cleared); take the opportunity to obtain one.
    request_credential(transport);
  }

  end_handshake(transport);
  create_session(transport);
}

void ProtocolThp::session_end(Transport &transport) {
  // THP channels are released by the device on an LRU basis; there is no
  // explicit teardown message. Drop our state so the next session re-handshakes.
  (void)transport;
  reset_channel();
}

void ProtocolThp::write(Transport &transport, const google::protobuf::Message &req) {
  CHECK_AND_ASSERT_THROW_MES(m_channel_open, "THP: channel is not open");
  const auto wire = MessageMapper::get_message_wire_number(req);
  write_app(transport, m_session_id, static_cast<uint16_t>(wire), serialize_proto(req));
}

void ProtocolThp::read(Transport &transport,
                       std::shared_ptr<google::protobuf::Message> &msg,
                       messages::MessageType *msg_type) {
  CHECK_AND_ASSERT_THROW_MES(m_channel_open, "THP: channel is not open");

  uint8_t sid = 0;
  uint16_t type = 0;
  bytes payload;
  while (true) {
    read_app(transport, sid, type, payload);
    if (sid == m_session_id) break;
    MWARNING("THP: discarding message for session " << static_cast<int>(sid));
  }

  const auto message_type = static_cast<messages::MessageType>(type);
  if (msg_type) *msg_type = message_type;

  std::shared_ptr<google::protobuf::Message> m(MessageMapper::get_message(type));
  CHECK_AND_ASSERT_THROW_MES(m, "THP: unknown message type " << type);
  CHECK_AND_ASSERT_THROW_MES(
      m->ParseFromArray(payload.data(), static_cast<int>(payload.size())),
      "THP: could not parse message of type " << type);
  msg = m;
}

} // namespace trezor
} // namespace hw
