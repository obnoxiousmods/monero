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
#include <string>
#include <vector>

namespace hw {
namespace trezor {

class Transport;

namespace thp {

using bytes = std::vector<uint8_t>;

/** Packet size of the USB data transfer layer. */
constexpr size_t THP_PACKET_SIZE = 64;
/** control_byte + cid + length */
constexpr size_t INIT_HEADER_LENGTH = 5;
/** control_byte + cid */
constexpr size_t CONT_HEADER_LENGTH = 3;
/** Length of the CRC-32 appended to every transport payload. */
constexpr size_t CHECKSUM_LENGTH = 4;
/** Channel used for allocation requests and ping/pong. */
constexpr uint16_t BROADCAST_CHANNEL_ID = 0xFFFF;

/** Control byte definitions, per the THP specification's packet table. */
namespace ctrl {
constexpr uint8_t CONTINUATION_BIT = 0x80;

// Data packets (handshake and encrypted transport) share a mask.
constexpr uint8_t DATA_MASK = 0xE7;
constexpr uint8_t HANDSHAKE_INIT_REQ = 0x00;
constexpr uint8_t HANDSHAKE_INIT_RES = 0x01;
constexpr uint8_t HANDSHAKE_COMP_REQ = 0x02;
constexpr uint8_t HANDSHAKE_COMP_RES = 0x03;
constexpr uint8_t ENCRYPTED_TRANSPORT = 0x04;
constexpr uint8_t DATA_SEQ_BIT = 0x10;
constexpr uint8_t DATA_ACK_SEQ_BIT = 0x08;
constexpr uint8_t DATA_DETECT_BASE = 0x00;
constexpr uint8_t DATA_DETECT_MASK = 0xE0;

// Acknowledgements.
constexpr uint8_t ACK_MASK = 0xF7;
constexpr uint8_t ACK_BASE = 0x20;
constexpr uint8_t ACK_SEQ_BIT = 0x08;

// Single-byte control messages.
constexpr uint8_t CODEC_V1 = 0x3F;
constexpr uint8_t CHANNEL_ALLOCATION_REQ = 0x40;
constexpr uint8_t CHANNEL_ALLOCATION_RES = 0x41;
constexpr uint8_t ERROR = 0x42;
constexpr uint8_t PING = 0x43;
constexpr uint8_t PONG = 0x44;

inline bool is_continuation(uint8_t cb) { return (cb & CONTINUATION_BIT) != 0; }
inline bool is_ack(uint8_t cb) { return (cb & ACK_MASK) == ACK_BASE; }
inline bool is_data(uint8_t cb) { return (cb & DATA_DETECT_MASK) == DATA_DETECT_BASE; }
inline bool is_error(uint8_t cb) { return cb == ERROR; }
inline uint8_t make_ack(bool ack_bit) {
  return static_cast<uint8_t>(ACK_BASE | (ack_bit ? ACK_SEQ_BIT : 0));
}
inline bool get_ack_bit(uint8_t cb) { return (cb & ACK_SEQ_BIT) != 0; }

/**
 * Sequence bit of a data message.
 *
 * The four handshake control bytes carry a fixed sequence number rather than
 * alternating, matching trezorlib's HANDSHAKE_SEQ_BITS: the two initiation
 * messages are sequence 0 and the two completion messages are sequence 1.
 */
bool get_seq_bit(uint8_t cb, bool &has_seq);
} // namespace ctrl

/** Transport-layer error codes carried by the `transport_error` control byte. */
enum class TransportError : uint8_t {
  TRANSPORT_BUSY = 1,
  UNALLOCATED_CHANNEL = 2,
  DECRYPTION_FAILED = 3,
  DEVICE_LOCKED = 5,
};

const char *transport_error_to_string(uint8_t code);

/** CRC-32-IEEE, as used by the THP error detection layer. */
uint32_t crc32(const uint8_t *data, size_t len);

/**
 * One THP transport payload, i.e. what is carried by an initiation packet plus
 * any continuation packets.
 */
struct Message {
  uint8_t ctrl_byte = 0;
  uint16_t cid = 0;
  bytes data;

  Message() = default;
  Message(uint8_t cb, uint16_t c, bytes d)
      : ctrl_byte(cb), cid(c), data(std::move(d)) {}

  /** Header (control byte, cid, length) followed by the data. */
  bytes checked_bytes() const;
  /** CRC-32 over checked_bytes(), big-endian. */
  uint32_t checksum() const;
  /** checked_bytes() followed by the big-endian checksum. */
  bytes to_bytes() const;

  /**
   * Reassembled-payload constructor. `payload` is the transport payload with
   * its trailing CRC. Throws if the CRC does not verify.
   */
  static Message parse(uint8_t ctrl_byte, uint16_t cid, const bytes &payload);

  static Message ack(uint16_t cid, bool ack_bit);
  static Message broadcast(uint8_t ctrl_byte, bytes data);

  bool is_channel_allocation_response() const;
  bool is_pong() const;
  bool is_handshake_init_response() const;
  bool is_handshake_comp_response() const;
  bool is_encrypted_transport() const;

  std::string to_string() const;
};

/** Segment `msg` into 64-byte packets and write them to the transport. */
void write_message(Transport &transport, const Message &msg);

/**
 * Read and reassemble one transport payload.
 *
 * Unexpected continuation packets and packets belonging to another channel are
 * skipped, mirroring the reference host implementation. Payloads whose CRC
 * fails are retried up to `max_retries` times before throwing.
 */
Message read_message(Transport &transport, size_t max_retries = 10);

} // namespace thp
} // namespace trezor
} // namespace hw
