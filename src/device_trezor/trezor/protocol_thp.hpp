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

#include <memory>
#include <string>
#include <vector>

#include <boost/optional.hpp>

#include "thp_crypto.hpp"
#include "thp_wire.hpp"
#include "transport.hpp"

namespace hw {
namespace trezor {
namespace thp {

/** Wire type identifiers of the THP-specific messages. */
namespace wire_type {
constexpr uint16_t Cancel = 20;
constexpr uint16_t ButtonRequest = 26;
constexpr uint16_t ButtonAck = 27;
constexpr uint16_t Success = 2;
constexpr uint16_t Failure = 3;

constexpr uint16_t ThpCreateNewSession = 1000;
constexpr uint16_t ThpPairingRequest = 1008;
constexpr uint16_t ThpPairingRequestApproved = 1009;
constexpr uint16_t ThpSelectMethod = 1010;
constexpr uint16_t ThpPairingPreparationsFinished = 1011;
constexpr uint16_t ThpCredentialRequest = 1016;
constexpr uint16_t ThpCredentialResponse = 1017;
constexpr uint16_t ThpEndRequest = 1018;
constexpr uint16_t ThpEndResponse = 1019;
constexpr uint16_t ThpCodeEntryCommitment = 1024;
constexpr uint16_t ThpCodeEntryChallenge = 1025;
constexpr uint16_t ThpCodeEntryCpaceTrezor = 1026;
constexpr uint16_t ThpCodeEntryCpaceHostTag = 1027;
constexpr uint16_t ThpCodeEntrySecret = 1028;
} // namespace wire_type

/** Trezor channel state after the handshake, as carried by HandshakeCompletionResponse. */
enum class PairingState : uint8_t {
  UNPAIRED = 0,
  PAIRED = 1,
  PAIRED_AUTOCONNECT = 2,
};

/**
 * A pairing credential issued by a Trezor, together with the host static key
 * it was issued for.
 */
struct CredentialEntry {
  key256 trezor_static_pubkey{};
  key256 host_static_privkey{};
  bytes credential;
};

/**
 * Persistent storage for THP pairing credentials.
 *
 * Credentials are per (host application, device) rather than per wallet, so
 * they live outside the wallet file. Without persistence the user would have
 * to re-enter the pairing code on every connection.
 */
class CredentialStore {
public:
  virtual ~CredentialStore() = default;
  virtual std::vector<CredentialEntry> load() = 0;
  virtual void store(const CredentialEntry &entry) = 0;
};

/** A CredentialStore backed by a JSON file. */
class FileCredentialStore : public CredentialStore {
public:
  explicit FileCredentialStore(std::string path) : m_path(std::move(path)) {}
  std::vector<CredentialEntry> load() override;
  void store(const CredentialEntry &entry) override;

  /** Default location, honouring the platform's per-user config directory. */
  static std::string default_path();

private:
  std::string m_path;
};

/**
 * Host-side interaction required by THP that has no equivalent in the legacy
 * protocol. Implemented by the wallet UI.
 */
class PairingUI {
public:
  virtual ~PairingUI() = default;

  /**
   * Called when the device displays a six-digit pairing code and the host must
   * echo it back. Return boost::none to abort pairing.
   */
  virtual boost::optional<std::string> on_pairing_code_request() = 0;

  /**
   * Called while creating a session.
   *
   * Under THP the passphrase is supplied up front in ThpCreateNewSession
   * rather than in response to a PassphraseRequest, so it has to be collected
   * here instead of during the message exchange. Set `on_device` to have the
   * user type it on the Trezor itself.
   */
  virtual boost::optional<std::string> on_passphrase_request(bool &on_device) {
    on_device = false;
    return boost::none;
  }

  /** Human-readable host name reported to the device during pairing. */
  virtual std::string host_name() const { return "Feather"; }
  /** Human-readable application name reported to the device during pairing. */
  virtual std::string app_name() const { return "Monero"; }
};

} // namespace thp

/**
 * The Trezor-Host Protocol v2 codec.
 *
 * THP replaces the legacy `##`/`?##` framing on devices whose firmware is built
 * with the `thp` feature (currently the Trezor Safe 7 / T3W1). Such firmware
 * does not serve the v1 codec at all, so a THP implementation is mandatory
 * rather than optional for those devices.
 *
 * Everything above the wire framing - the Monero transaction signing protocol,
 * the protobuf message set, the passphrase and button flows - is unchanged;
 * this class only establishes and maintains the encrypted channel and re-frames
 * application messages into THP's session/type envelope.
 */
class ProtocolThp : public Protocol {
public:
  ProtocolThp();
  ~ProtocolThp() override = default;

  void session_begin(Transport &transport) override;
  void session_end(Transport &transport) override;
  void write(Transport &transport, const google::protobuf::Message &req) override;
  void read(Transport &transport, std::shared_ptr<google::protobuf::Message> &msg,
            messages::MessageType *msg_type = nullptr) override;

  /**
   * Drop the current THP session. The next application message creates a new
   * one, asking for the passphrase again - which is how the wallet retries with
   * a different passphrase after probing with an empty one.
   */
  void reset_session() override;

  /**
   * THP replaces the legacy Initialize/Features session entirely; the device
   * does not even register a handler for Initialize.
   */
  bool has_own_sessions() const override { return true; }

  /** Supply the UI used for pairing interaction. */
  void set_pairing_ui(std::shared_ptr<thp::PairingUI> ui) { m_pairing_ui = std::move(ui); }
  /** Supply persistent credential storage. Defaults to a file-backed store. */
  void set_credential_store(std::shared_ptr<thp::CredentialStore> store) {
    m_credential_store = std::move(store);
  }

  /**
   * Probe whether `transport` is talking to a THP device.
   *
   * Sends a broadcast ThpPing and waits for a ThpPong. Devices speaking the
   * legacy codec do not answer, so a timeout means "not THP".
   */
  static bool probe(Transport &transport);

  /** Internal model reported by the device, e.g. "T3W1". Empty before the handshake. */
  const std::string &internal_model() const { return m_internal_model; }

  /** Session id used for application messages. */
  uint8_t session_id() const { return m_session_id; }

  /** Request that a new passphrase-derived session be created on next use. */
  void set_passphrase(const std::string &passphrase, bool on_device);
  void clear_passphrase();

private:
  // --- transport layer helpers -------------------------------------------
  void allocate_channel(Transport &transport);
  void send_message(Transport &transport, thp::Message msg);
  thp::Message read_message(Transport &transport, bool allow_broadcast = false);
  void send_ack(Transport &transport, const thp::Message &acked);
  /** Translate a transport error code into an exception, resetting the channel
   *  when the error implies the device has dropped it. Never returns. */
  [[noreturn]] void throw_transport_error(uint8_t code);
  void await_ack(Transport &transport, bool expected_seq_bit);

  // --- secure channel layer ----------------------------------------------
  void handshake(Transport &transport);
  void do_pairing(Transport &transport);
  void code_entry_pairing(Transport &transport);
  void request_credential(Transport &transport);
  void end_handshake(Transport &transport);
  void create_session(Transport &transport);

  // --- application layer --------------------------------------------------
  void write_app(Transport &transport, uint8_t session_id, uint16_t msg_type,
                 const thp::bytes &payload);
  void read_app(Transport &transport, uint8_t &session_id, uint16_t &msg_type,
                thp::bytes &payload);

  /**
   * Read an application message, expecting a particular type.
   *
   * Any phase of the connection can be interrupted by a ButtonRequest when the
   * device wants the user to confirm something; those are acknowledged and the
   * read continues. A Failure is turned into an exception carrying the device's
   * own message, and an unexpected type reports what actually arrived.
   *
   * `what` names the step for the error message, e.g. "ending the handshake".
   */
  thp::bytes read_app_expect(Transport &transport, uint8_t session_id,
                             uint16_t expected_type, const char *what);

  thp::bytes noise_encrypt(const thp::bytes &plaintext);
  thp::bytes noise_decrypt(const thp::bytes &ciphertext);

  void reset_channel();

  // --- state --------------------------------------------------------------
  bool m_channel_open = false;
  uint16_t m_channel_id = 0;
  thp::bytes m_prologue;          // serialized ThpDeviceProperties
  std::string m_internal_model;
  std::vector<int> m_pairing_methods;

  // Alternating bit protocol state.
  bool m_sync_bit_send = false;
  bool m_sync_bit_receive = false;

  // Set when a data message arrives carrying a piggybacked acknowledgement
  // instead of a standalone ACK; the next read consumes it.
  boost::optional<thp::Message> m_pending_message;

  // Noise handshake state.
  thp::hash256 m_h{};
  thp::hash256 m_ck{};
  thp::key256 m_host_ephemeral_priv{};
  thp::key256 m_host_static_priv{};
  thp::key256 m_host_static_pub{};
  thp::key256 m_trezor_static_pub{};   // recovered when a credential matches
  thp::hash256 m_handshake_hash{};

  // Encrypted transport state.
  thp::key256 m_key_request{};
  thp::key256 m_key_response{};
  uint64_t m_nonce_request = 0;
  uint64_t m_nonce_response = 0;

  thp::PairingState m_pairing_state = thp::PairingState::UNPAIRED;
  thp::bytes m_credential;             // credential replayed during handshake
  bool m_credential_matched = false;

  uint8_t m_session_id = 0;
  /** Incremented per created session; 0 stays reserved for pairing/management. */
  unsigned m_session_counter = 0;
  bool m_session_created = false;
  boost::optional<std::string> m_passphrase;
  bool m_passphrase_on_device = false;

  std::shared_ptr<thp::PairingUI> m_pairing_ui;
  std::shared_ptr<thp::CredentialStore> m_credential_store;
};

} // namespace trezor
} // namespace hw
