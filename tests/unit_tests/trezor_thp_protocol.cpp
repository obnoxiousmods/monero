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

//
// End-to-end exercise of ProtocolThp against a simulated Trezor.
//
// The simulated device implements the Trezor side of the specification (states
// TH1/TH2 and the CodeEntry pairing flow) independently of the host code under
// test, so the two only agree if both follow the specification. That makes this
// a real check of the handshake transcript, the CPace exchange and the
// alternating-bit sequencing, rather than a restatement of the implementation.
//

#include "gtest/gtest.h"

#if defined(DEVICE_TREZOR_READY)

#include <boost/filesystem.hpp>
#include <deque>
#include <string>
#include <vector>

#include "device_trezor/trezor/protocol_thp.hpp"
#include "device_trezor/trezor/thp_crypto.hpp"
#include "device_trezor/trezor/thp_wire.hpp"
#include "device_trezor/trezor/transport.hpp"
#include "device_trezor/trezor/messages/messages-thp.pb.h"
#include "device_trezor/trezor/messages/messages-common.pb.h"

using namespace hw::trezor;
using namespace hw::trezor::thp;
namespace mthp = hw::trezor::messages::thp;

namespace
{
  constexpr uint16_t TEST_CHANNEL_ID = 0x0042;

  bytes proto_bytes(const google::protobuf::Message &m)
  {
    std::string s;
    m.SerializeToString(&s);
    return bytes(s.begin(), s.end());
  }

  hash256 mix(const hash256 &h, const uint8_t *d, size_t n)
  {
    bytes buf(h.begin(), h.end());
    buf.insert(buf.end(), d, d + n);
    return sha256(buf);
  }

  /**
   * The Trezor half of THP: transport framing, the Noise responder, and the
   * CodeEntry pairing state machine.
   */
  class SimulatedTrezor
  {
  public:
    // Visible to the test so the fake UI can echo the code the device "shows".
    std::string displayed_code;
    bool issued_credential = false;
    bool created_session = false;
    uint8_t session_id_used = 0xFF;
    std::string session_passphrase;
    bool saw_end_request = false;
    bool tag_rejected = false;
    bool saw_button_ack = false;
    /** Interleave a ButtonRequest before the end-of-handshake response. */
    bool button_request_before_end = true;

    key256 static_priv{}, static_pub{};

    SimulatedTrezor()
    {
      const auto sp = random_bytes(32);
      std::copy(sp.begin(), sp.end(), static_priv.begin());
      x25519_base(static_pub.data(), static_priv.data());

      mthp::ThpDeviceProperties props;
      props.set_internal_model("T3W1");
      props.set_protocol_version_major(2);
      props.set_protocol_version_minor(0);
      props.add_pairing_methods(mthp::CodeEntry);
      m_properties = proto_bytes(props);
    }

    // --- wire plumbing ---------------------------------------------------

    void feed(const uint8_t *packet)
    {
      if (ctrl::is_continuation(packet[0]))
      {
        m_rx.insert(m_rx.end(), packet + CONT_HEADER_LENGTH, packet + THP_PACKET_SIZE);
      }
      else
      {
        m_rx_ctrl = packet[0];
        m_rx_cid = static_cast<uint16_t>((packet[1] << 8) | packet[2]);
        m_rx_len = static_cast<size_t>((packet[3] << 8) | packet[4]);
        m_rx.assign(packet + INIT_HEADER_LENGTH, packet + THP_PACKET_SIZE);
      }
      if (m_rx.size() < m_rx_len) return;

      bytes payload(m_rx.begin(), m_rx.begin() + m_rx_len);
      m_rx.clear();
      handle(Message::parse(m_rx_ctrl, m_rx_cid, payload));
    }

    bool has_output() const { return !m_tx.empty(); }

    void pop(uint8_t *out)
    {
      memcpy(out, m_tx.front().data(), THP_PACKET_SIZE);
      m_tx.pop_front();
    }

  private:
    void emit(const Message &msg)
    {
      const bytes payload = msg.to_bytes();
      size_t off = 0;
      std::vector<uint8_t> pkt(THP_PACKET_SIZE, 0);

      const size_t first = std::min(payload.size(), THP_PACKET_SIZE);
      std::fill(pkt.begin(), pkt.end(), 0);
      memcpy(pkt.data(), payload.data(), first);
      m_tx.push_back(pkt);
      off = first;

      while (off < payload.size())
      {
        std::fill(pkt.begin(), pkt.end(), 0);
        pkt[0] = ctrl::CONTINUATION_BIT;
        pkt[1] = static_cast<uint8_t>((msg.cid >> 8) & 0xFF);
        pkt[2] = static_cast<uint8_t>(msg.cid & 0xFF);
        const size_t n = std::min(payload.size() - off, THP_PACKET_SIZE - CONT_HEADER_LENGTH);
        memcpy(pkt.data() + CONT_HEADER_LENGTH, payload.data() + off, n);
        m_tx.push_back(pkt);
        off += n;
      }
    }

    /** Send a data message, acknowledging the host's message first. */
    void emit_data(uint8_t ctrl_byte, const bytes &data, bool fixed_seq, bool seq)
    {
      uint8_t cb = ctrl_byte;
      const bool use = fixed_seq ? seq : m_tx_seq;
      if (!fixed_seq && use) cb |= ctrl::DATA_SEQ_BIT;
      if (!fixed_seq) m_tx_seq = !m_tx_seq;
      emit(Message(cb, TEST_CHANNEL_ID, data));
    }

    void ack(const Message &m)
    {
      bool has_seq = false;
      const bool seq = ctrl::get_seq_bit(m.ctrl_byte, has_seq);
      if (has_seq) emit(Message::ack(m.cid, seq));
    }

    void handle(const Message &msg)
    {
      if (ctrl::is_ack(msg.ctrl_byte)) return; // host acknowledging us

      if (msg.ctrl_byte == ctrl::PING)
      {
        emit(Message::broadcast(ctrl::PONG, msg.data));
        return;
      }
      if (msg.ctrl_byte == ctrl::CHANNEL_ALLOCATION_REQ)
      {
        bytes d(msg.data.begin(), msg.data.end()); // echo nonce
        d.push_back(static_cast<uint8_t>(TEST_CHANNEL_ID >> 8));
        d.push_back(static_cast<uint8_t>(TEST_CHANNEL_ID & 0xFF));
        d.insert(d.end(), m_properties.begin(), m_properties.end());
        emit(Message::broadcast(ctrl::CHANNEL_ALLOCATION_RES, d));
        return;
      }

      const uint8_t kind = msg.ctrl_byte & ctrl::DATA_MASK;
      if (kind == ctrl::HANDSHAKE_INIT_REQ) { ack(msg); handshake_init(msg); return; }
      if (kind == ctrl::HANDSHAKE_COMP_REQ) { ack(msg); handshake_completion(msg); return; }
      if (kind == ctrl::ENCRYPTED_TRANSPORT) { ack(msg); encrypted(msg); return; }
    }

    // --- Noise responder (specification states TH1 and TH2) ---------------

    void handshake_init(const Message &msg)
    {
      ASSERT_EQ(33u, msg.data.size());
      const uint8_t *host_eph_pub = msg.data.data();
      const uint8_t try_unlock = msg.data[32];

      const auto ep = random_bytes(32);
      std::copy(ep.begin(), ep.end(), m_eph_priv.begin());
      x25519_base(m_eph_pub.data(), m_eph_priv.data());

      const uint8_t *pname = reinterpret_cast<const uint8_t *>(THP_PROTOCOL_NAME);
      {
        bytes buf(pname, pname + THP_PROTOCOL_NAME_SIZE);
        buf.insert(buf.end(), m_properties.begin(), m_properties.end());
        m_h = sha256(buf);
      }
      m_h = mix(m_h, host_eph_pub, 32);
      m_h = mix(m_h, &try_unlock, 1);
      m_h = mix(m_h, m_eph_pub.data(), 32);

      key256 k{};
      {
        uint8_t dh[32];
        x25519_scalarmult(dh, m_eph_priv.data(), host_eph_pub);
        hkdf(pname, THP_PROTOCOL_NAME_SIZE, dh, 32, m_ck, k);
      }

      // The static key is masked with the ephemeral key before it goes on the wire.
      hash256 mask;
      {
        bytes buf(static_pub.begin(), static_pub.end());
        buf.insert(buf.end(), m_eph_pub.begin(), m_eph_pub.end());
        mask = sha256(buf);
      }
      uint8_t masked_static[32];
      x25519_scalarmult(masked_static, mask.data(), static_pub.data());

      const bytes enc_static =
          aes_gcm_encrypt(k, 0, m_h.data(), m_h.size(), masked_static, 32);
      m_h = mix(m_h, enc_static.data(), enc_static.size());

      {
        uint8_t ss[32], dh[32];
        x25519_scalarmult(ss, static_priv.data(), host_eph_pub);
        x25519_scalarmult(dh, mask.data(), ss);
        hkdf(m_ck.data(), m_ck.size(), dh, 32, m_ck, k);
      }
      const bytes tag = aes_gcm_encrypt(k, 0, m_h.data(), m_h.size(), nullptr, 0);
      m_h = mix(m_h, tag.data(), tag.size());
      m_k = k;

      bytes out(m_eph_pub.begin(), m_eph_pub.end());
      out.insert(out.end(), enc_static.begin(), enc_static.end());
      out.insert(out.end(), tag.begin(), tag.end());
      emit_data(ctrl::HANDSHAKE_INIT_RES, out, true, false);
    }

    void handshake_completion(const Message &msg)
    {
      ASSERT_GT(msg.data.size(), 48u);
      const bytes enc_host_static(msg.data.begin(), msg.data.begin() + 48);
      const bytes enc_payload(msg.data.begin() + 48, msg.data.end());

      bytes host_static_pub;
      ASSERT_TRUE(aes_gcm_decrypt(m_k, 1, m_h.data(), m_h.size(),
                                  enc_host_static.data(), enc_host_static.size(),
                                  host_static_pub));
      ASSERT_EQ(32u, host_static_pub.size());
      m_h = mix(m_h, enc_host_static.data(), enc_host_static.size());

      key256 k{};
      {
        uint8_t dh[32];
        x25519_scalarmult(dh, m_eph_priv.data(), host_static_pub.data());
        hkdf(m_ck.data(), m_ck.size(), dh, 32, m_ck, k);
      }

      bytes payload;
      ASSERT_TRUE(aes_gcm_decrypt(k, 0, m_h.data(), m_h.size(),
                                  enc_payload.data(), enc_payload.size(), payload));
      m_h = mix(m_h, enc_payload.data(), enc_payload.size());

      mthp::ThpHandshakeCompletionReqNoisePayload p;
      ASSERT_TRUE(p.ParseFromArray(payload.data(), (int) payload.size()));

      m_handshake_hash = m_h;
      m_host_static_pub.assign(host_static_pub.begin(), host_static_pub.end());

      // Treat a replayed credential as proof of previous pairing.
      const bool paired = !p.host_pairing_credential().empty();
      hkdf(m_ck.data(), m_ck.size(), nullptr, 0, m_key_req, m_key_res);
      m_nonce_req = 0;
      m_nonce_res = 0;

      const uint8_t state = paired ? 1 : 0;
      const bytes enc_state = aes_gcm_encrypt(m_key_res, m_nonce_res, nullptr, 0, &state, 1);
      m_nonce_res = 1;
      m_paired = paired;
      emit_data(ctrl::HANDSHAKE_COMP_RES, enc_state, true, true);
    }

    // --- application layer -------------------------------------------------

    void send_app(uint8_t session_id, uint16_t type, const bytes &body)
    {
      bytes frame;
      frame.push_back(session_id);
      frame.push_back(static_cast<uint8_t>(type >> 8));
      frame.push_back(static_cast<uint8_t>(type & 0xFF));
      frame.insert(frame.end(), body.begin(), body.end());
      const bytes ct = aes_gcm_encrypt(m_key_res, m_nonce_res, nullptr, 0,
                                       frame.data(), frame.size());
      ++m_nonce_res;
      emit_data(ctrl::ENCRYPTED_TRANSPORT, ct, false, false);
    }

    void encrypted(const Message &msg)
    {
      bytes frame;
      ASSERT_TRUE(aes_gcm_decrypt(m_key_req, m_nonce_req, nullptr, 0,
                                  msg.data.data(), msg.data.size(), frame));
      ++m_nonce_req;
      ASSERT_GE(frame.size(), 3u);

      const uint8_t sid = frame[0];
      const uint16_t type = static_cast<uint16_t>((frame[1] << 8) | frame[2]);
      const bytes body(frame.begin() + 3, frame.end());

      switch (type)
      {
        case wire_type::ThpPairingRequest:
          send_app(sid, wire_type::ThpPairingRequestApproved,
                   proto_bytes(mthp::ThpPairingRequestApproved()));
          break;

        case wire_type::ThpSelectMethod:
        {
          // Commit to a secret; the host cannot learn the code from this.
          m_secret = random_bytes(16);
          const hash256 commitment = sha256(m_secret);
          mthp::ThpCodeEntryCommitment c;
          c.set_commitment(commitment.data(), commitment.size());
          send_app(sid, wire_type::ThpCodeEntryCommitment, proto_bytes(c));
          break;
        }

        case wire_type::ThpCodeEntryChallenge:
        {
          mthp::ThpCodeEntryChallenge ch;
          ASSERT_TRUE(ch.ParseFromArray(body.data(), (int) body.size()));
          m_challenge.assign(ch.challenge().begin(), ch.challenge().end());

          bytes buf;
          buf.push_back(static_cast<uint8_t>(mthp::CodeEntry));
          buf.insert(buf.end(), m_handshake_hash.begin(), m_handshake_hash.end());
          buf.insert(buf.end(), m_secret.begin(), m_secret.end());
          buf.insert(buf.end(), m_challenge.begin(), m_challenge.end());
          const hash256 code_hash = sha256(buf);
          uint64_t acc = 0;
          for (uint8_t b : code_hash) acc = (acc * 256 + b) % 1000000;
          char buf6[8];
          snprintf(buf6, sizeof(buf6), "%06u", (unsigned) acc);
          displayed_code = buf6;

          const key256 gen = cpace_generator(displayed_code, m_handshake_hash);
          const auto priv = random_bytes(32);
          std::copy(priv.begin(), priv.end(), m_cpace_priv.begin());
          key256 pub{};
          x25519_scalarmult(pub.data(), m_cpace_priv.data(), gen.data());

          mthp::ThpCodeEntryCpaceTrezor t;
          t.set_cpace_trezor_public_key(pub.data(), pub.size());
          send_app(sid, wire_type::ThpCodeEntryCpaceTrezor, proto_bytes(t));
          break;
        }

        case wire_type::ThpCodeEntryCpaceHostTag:
        {
          mthp::ThpCodeEntryCpaceHostTag t;
          ASSERT_TRUE(t.ParseFromArray(body.data(), (int) body.size()));
          ASSERT_EQ(32u, t.cpace_host_public_key().size());

          uint8_t shared[32];
          x25519_scalarmult(shared, m_cpace_priv.data(),
                            (const uint8_t *) t.cpace_host_public_key().data());
          const hash256 expected = sha256(shared, 32);
          // The host proves it knows the displayed code. A real device answers
          // a mismatch with a Failure and refuses to reveal the secret, so do
          // the same rather than aborting the test process.
          if (std::string((const char *) expected.data(), expected.size()) != t.tag())
          {
            tag_rejected = true;
            messages::common::Failure f;
            f.set_message("CPace tag mismatch");
            send_app(sid, wire_type::Failure, proto_bytes(f));
            break;
          }

          mthp::ThpCodeEntrySecret s;
          s.set_secret(m_secret.data(), m_secret.size());
          send_app(sid, wire_type::ThpCodeEntrySecret, proto_bytes(s));
          break;
        }

        case wire_type::ThpCredentialRequest:
        {
          issued_credential = true;
          mthp::ThpCredentialResponse r;
          r.set_trezor_static_public_key(static_pub.data(), static_pub.size());
          r.set_credential("test-credential-blob");
          send_app(sid, wire_type::ThpCredentialResponse, proto_bytes(r));
          break;
        }

        case wire_type::ThpEndRequest:
          saw_end_request = true;
          if (button_request_before_end)
          {
            // Real devices interleave ButtonRequests into any phase when they
            // want the user to confirm something; the host must acknowledge and
            // keep reading rather than treating it as the wrong reply.
            m_pending_end_session = sid;
            messages::common::ButtonRequest br;
            send_app(sid, wire_type::ButtonRequest, proto_bytes(br));
          }
          else
          {
            send_app(sid, wire_type::ThpEndResponse, proto_bytes(mthp::ThpEndResponse()));
          }
          break;

        case wire_type::ButtonAck:
          saw_button_ack = true;
          if (m_pending_end_session >= 0)
          {
            const uint8_t s = static_cast<uint8_t>(m_pending_end_session);
            m_pending_end_session = -1;
            send_app(s, wire_type::ThpEndResponse, proto_bytes(mthp::ThpEndResponse()));
          }
          else
          {
            // No confirmation outstanding: treat it like any other application
            // message and echo, so it can be used to exercise the transport.
            send_app(sid, wire_type::Success, proto_bytes(messages::common::Success()));
          }
          break;

        case wire_type::ThpCreateNewSession:
        {
          mthp::ThpCreateNewSession s;
          ASSERT_TRUE(s.ParseFromArray(body.data(), (int) body.size()));
          created_session = true;
          session_id_used = sid;
          session_passphrase = s.passphrase();
          send_app(sid, wire_type::Success, proto_bytes(messages::common::Success()));
          break;
        }

        default:
          // Echo unknown application messages back as Success so the transport
          // round-trip can be exercised.
          send_app(sid, wire_type::Success, proto_bytes(messages::common::Success()));
          break;
      }
    }

    bytes m_properties;
    std::deque<std::vector<uint8_t>> m_tx;
    bytes m_rx;
    uint8_t m_rx_ctrl = 0;
    uint16_t m_rx_cid = 0;
    size_t m_rx_len = 0;

    key256 m_eph_priv{}, m_eph_pub{}, m_k{}, m_key_req{}, m_key_res{}, m_cpace_priv{};
    hash256 m_h{}, m_ck{}, m_handshake_hash{};
    uint64_t m_nonce_req = 0, m_nonce_res = 0;
    bytes m_secret, m_challenge, m_host_static_pub;
    bool m_paired = false;
    bool m_tx_seq = false;
    int m_pending_end_session = -1;
  };

  /** Transport that wires ProtocolThp directly to the simulated device. */
  class LoopbackTransport : public Transport
  {
  public:
    SimulatedTrezor device;

    void write(const google::protobuf::Message &) override {}
    void read(std::shared_ptr<google::protobuf::Message> &, messages::MessageType *) override {}

    void write_chunk(const void *buff, size_t size) override
    {
      ASSERT_EQ(THP_PACKET_SIZE, size);
      device.feed(static_cast<const uint8_t *>(buff));
    }

    size_t read_chunk(void *buff, size_t size) override
    {
      if (!device.has_output()) throw std::runtime_error("device produced no reply");
      device.pop(static_cast<uint8_t *>(buff));
      return size;
    }
  };

  /** Pairing UI that echoes back whatever code the device is displaying. */
  class EchoPairingUI : public PairingUI
  {
  public:
    explicit EchoPairingUI(SimulatedTrezor &d) : m_device(d) {}
    boost::optional<std::string> on_pairing_code_request() override
    {
      asked = true;
      if (override_code) return override_code;
      return m_device.displayed_code;
    }
    bool asked = false;
    boost::optional<std::string> override_code;
  private:
    SimulatedTrezor &m_device;
  };

  struct TempStore
  {
    boost::filesystem::path path;
    TempStore()
      : path(boost::filesystem::temp_directory_path() /
             boost::filesystem::unique_path("thp_proto_%%%%.json")) {}
    ~TempStore() { boost::system::error_code ec; boost::filesystem::remove(path, ec); }
  };
}

TEST(trezor_thp_protocol, full_pairing_handshake_and_session)
{
  LoopbackTransport transport;
  TempStore store;

  ProtocolThp proto;
  auto ui = std::make_shared<EchoPairingUI>(transport.device);
  proto.set_pairing_ui(ui);
  proto.set_credential_store(std::make_shared<FileCredentialStore>(store.path.string()));

  ASSERT_NO_THROW(proto.session_begin(transport));

  // The device and the host independently derived the same handshake hash, or
  // the CPace tag check inside the device would have failed.
  ASSERT_TRUE(ui->asked);
  ASSERT_EQ(6u, transport.device.displayed_code.size());
  ASSERT_TRUE(transport.device.issued_credential);
  ASSERT_TRUE(transport.device.saw_end_request);
  ASSERT_TRUE(transport.device.created_session);
  ASSERT_EQ("T3W1", proto.internal_model());
  // The device interleaved a ButtonRequest before the end-of-handshake
  // response; the host must have acknowledged it rather than giving up.
  ASSERT_TRUE(transport.device.saw_button_ack);

  // The credential was persisted for next time.
  FileCredentialStore reread(store.path.string());
  const auto entries = reread.load();
  ASSERT_EQ(1u, entries.size());
  ASSERT_EQ(transport.device.static_pub, entries[0].trezor_static_pubkey);
  ASSERT_EQ("test-credential-blob",
            std::string(entries[0].credential.begin(), entries[0].credential.end()));
}

TEST(trezor_thp_protocol, application_messages_round_trip)
{
  LoopbackTransport transport;
  TempStore store;

  ProtocolThp proto;
  proto.set_pairing_ui(std::make_shared<EchoPairingUI>(transport.device));
  proto.set_credential_store(std::make_shared<FileCredentialStore>(store.path.string()));
  ASSERT_NO_THROW(proto.session_begin(transport));

  // Several round trips, so the nonce counters and the alternating bit have to
  // stay in step in both directions.
  for (int i = 0; i < 5; ++i)
  {
    messages::common::ButtonAck req;
    ASSERT_NO_THROW(proto.write(transport, req));

    std::shared_ptr<google::protobuf::Message> resp;
    messages::MessageType type;
    ASSERT_NO_THROW(proto.read(transport, resp, &type));
    ASSERT_TRUE(resp != nullptr);
    ASSERT_EQ(wire_type::Success, static_cast<uint16_t>(type));
  }
}

TEST(trezor_thp_protocol, wrong_pairing_code_is_rejected)
{
  LoopbackTransport transport;
  TempStore store;

  ProtocolThp proto;
  auto ui = std::make_shared<EchoPairingUI>(transport.device);
  // A man in the middle would not know the code shown on the device.
  ui->override_code = std::string("000000");
  proto.set_pairing_ui(ui);
  proto.set_credential_store(std::make_shared<FileCredentialStore>(store.path.string()));

  // The device's tag check must fail; pairing must not silently succeed.
  ASSERT_ANY_THROW(proto.session_begin(transport));
  ASSERT_TRUE(transport.device.tag_rejected);
  ASSERT_FALSE(transport.device.issued_credential);
  ASSERT_FALSE(transport.device.created_session);
}

TEST(trezor_thp_protocol, stored_credential_skips_pairing)
{
  LoopbackTransport transport;
  TempStore store;

  // Pre-seed a credential for this device, as a previous pairing would have.
  {
    FileCredentialStore s(store.path.string());
    CredentialEntry e;
    e.trezor_static_pubkey = transport.device.static_pub;
    const auto priv = random_bytes(32);
    std::copy(priv.begin(), priv.end(), e.host_static_privkey.begin());
    e.credential = bytes{'p', 'r', 'e', 'v'};
    s.store(e);
  }

  ProtocolThp proto;
  auto ui = std::make_shared<EchoPairingUI>(transport.device);
  proto.set_pairing_ui(ui);
  proto.set_credential_store(std::make_shared<FileCredentialStore>(store.path.string()));

  ASSERT_NO_THROW(proto.session_begin(transport));

  // No pairing code was requested: the credential authenticated the channel.
  ASSERT_FALSE(ui->asked);
  ASSERT_TRUE(transport.device.saw_end_request);
  ASSERT_TRUE(transport.device.created_session);
}

TEST(trezor_thp_protocol, probe_detects_thp_device)
{
  LoopbackTransport transport;
  ASSERT_TRUE(ProtocolThp::probe(transport));
}

#endif // DEVICE_TREZOR_READY
