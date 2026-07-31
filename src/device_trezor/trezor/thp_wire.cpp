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

#include "thp_wire.hpp"
#include "transport.hpp"
#include "exceptions.hpp"
#include "misc_log_ex.h"

#include <cstring>
#include <sstream>
#include <iomanip>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor.thp"

namespace hw {
namespace trezor {
namespace thp {

namespace ctrl {
bool get_seq_bit(uint8_t cb, bool &has_seq) {
  // The handshake control bytes are matched exactly, not masked: their
  // sequence number is fixed by the specification rather than alternating.
  switch (cb) {
    case HANDSHAKE_INIT_REQ:
    case HANDSHAKE_INIT_RES:
      has_seq = true;
      return false;
    case HANDSHAKE_COMP_REQ:
    case HANDSHAKE_COMP_RES:
      has_seq = true;
      return true;
    default:
      break;
  }
  if (!is_data(cb)) {
    has_seq = false;
    return false;
  }
  has_seq = true;
  return (cb & DATA_SEQ_BIT) != 0;
}
} // namespace ctrl

const char *transport_error_to_string(uint8_t code) {
  switch (code) {
    case static_cast<uint8_t>(TransportError::TRANSPORT_BUSY): return "TRANSPORT_BUSY";
    case static_cast<uint8_t>(TransportError::UNALLOCATED_CHANNEL): return "UNALLOCATED_CHANNEL";
    case static_cast<uint8_t>(TransportError::DECRYPTION_FAILED): return "DECRYPTION_FAILED";
    case static_cast<uint8_t>(TransportError::DEVICE_LOCKED): return "DEVICE_LOCKED";
    default: return "UNKNOWN";
  }
}

namespace {
/** Table-free CRC-32-IEEE (reflected polynomial 0xEDB88320). */
uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
  crc = ~crc;
  for (size_t i = 0; i < len; ++i) {
    crc ^= data[i];
    for (int k = 0; k < 8; ++k) {
      crc = (crc >> 1) ^ (0xEDB88320u & (~(crc & 1u) + 1u));
    }
  }
  return ~crc;
}
} // namespace

uint32_t crc32(const uint8_t *data, size_t len) {
  return crc32_update(0, data, len);
}

bytes Message::checked_bytes() const {
  const size_t total = data.size() + CHECKSUM_LENGTH;
  CHECK_AND_ASSERT_THROW_MES(total <= 0xFFFF, "THP: encoded message is too long");

  bytes out;
  out.reserve(INIT_HEADER_LENGTH + data.size());
  out.push_back(ctrl_byte);
  out.push_back(static_cast<uint8_t>((cid >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(cid & 0xFF));
  out.push_back(static_cast<uint8_t>((total >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(total & 0xFF));
  out.insert(out.end(), data.begin(), data.end());
  return out;
}

uint32_t Message::checksum() const {
  const auto cb = checked_bytes();
  return crc32(cb.data(), cb.size());
}

bytes Message::to_bytes() const {
  auto out = checked_bytes();
  const uint32_t crc = crc32(out.data(), out.size());
  out.push_back(static_cast<uint8_t>((crc >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((crc >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(crc & 0xFF));
  return out;
}

Message Message::parse(uint8_t ctrl_byte, uint16_t cid, const bytes &payload) {
  CHECK_AND_ASSERT_THROW_MES(payload.size() >= CHECKSUM_LENGTH,
                             "THP: transport payload too short");
  Message msg(ctrl_byte, cid,
              bytes(payload.begin(), payload.end() - CHECKSUM_LENGTH));

  const uint8_t *rx = payload.data() + payload.size() - CHECKSUM_LENGTH;
  const uint32_t received = (static_cast<uint32_t>(rx[0]) << 24) |
                            (static_cast<uint32_t>(rx[1]) << 16) |
                            (static_cast<uint32_t>(rx[2]) << 8) |
                            static_cast<uint32_t>(rx[3]);
  CHECK_AND_ASSERT_THROW_MES(received == msg.checksum(),
                             "THP: invalid message checksum");
  return msg;
}

Message Message::ack(uint16_t cid, bool ack_bit) {
  return Message(ctrl::make_ack(ack_bit), cid, bytes());
}

Message Message::broadcast(uint8_t ctrl_byte, bytes data) {
  return Message(ctrl_byte, BROADCAST_CHANNEL_ID, std::move(data));
}

bool Message::is_channel_allocation_response() const {
  return cid == BROADCAST_CHANNEL_ID && ctrl_byte == ctrl::CHANNEL_ALLOCATION_RES;
}
bool Message::is_pong() const {
  return cid == BROADCAST_CHANNEL_ID && ctrl_byte == ctrl::PONG;
}
bool Message::is_handshake_init_response() const {
  return (ctrl_byte & ctrl::DATA_MASK) == ctrl::HANDSHAKE_INIT_RES;
}
bool Message::is_handshake_comp_response() const {
  return (ctrl_byte & ctrl::DATA_MASK) == ctrl::HANDSHAKE_COMP_RES;
}
bool Message::is_encrypted_transport() const {
  return (ctrl_byte & ctrl::DATA_MASK) == ctrl::ENCRYPTED_TRANSPORT;
}

std::string Message::to_string() const {
  std::ostringstream ss;
  ss << "Message(ctrl=0x" << std::hex << std::setw(2) << std::setfill('0')
     << static_cast<unsigned>(ctrl_byte) << ", cid=0x" << std::setw(4)
     << static_cast<unsigned>(cid) << std::dec << ", len=" << data.size() << ")";
  return ss.str();
}

void write_message(Transport &transport, const Message &msg) {
  const bytes payload = msg.to_bytes();

  uint8_t packet[THP_PACKET_SIZE];
  size_t offset = 0;

  // Initiation packet: the header is already at the front of `payload`.
  const size_t first = std::min(payload.size(), THP_PACKET_SIZE);
  memcpy(packet, payload.data(), first);
  if (first < THP_PACKET_SIZE) memset(packet + first, 0, THP_PACKET_SIZE - first);
  transport.write_chunk(packet, THP_PACKET_SIZE);
  offset = first;

  // Continuation packets.
  while (offset < payload.size()) {
    packet[0] = ctrl::CONTINUATION_BIT;
    packet[1] = static_cast<uint8_t>((msg.cid >> 8) & 0xFF);
    packet[2] = static_cast<uint8_t>(msg.cid & 0xFF);
    const size_t to_copy =
        std::min(payload.size() - offset, THP_PACKET_SIZE - CONT_HEADER_LENGTH);
    memcpy(packet + CONT_HEADER_LENGTH, payload.data() + offset, to_copy);
    if (to_copy < THP_PACKET_SIZE - CONT_HEADER_LENGTH) {
      memset(packet + CONT_HEADER_LENGTH + to_copy, 0,
             THP_PACKET_SIZE - CONT_HEADER_LENGTH - to_copy);
    }
    transport.write_chunk(packet, THP_PACKET_SIZE);
    offset += to_copy;
  }
}

Message read_message(Transport &transport, size_t max_retries) {
  uint8_t packet[THP_PACKET_SIZE];

  for (size_t attempt = 0; attempt <= max_retries; ++attempt) {
    // Read an initiation packet, skipping stray continuations.
    bool have_init = false;
    uint8_t ctrl_byte = 0;
    uint16_t cid = 0;
    size_t data_length = 0;
    bytes acc;

    while (!have_init) {
      const size_t nread = transport.read_chunk(packet, THP_PACKET_SIZE);
      CHECK_AND_ASSERT_THROW_MES(nread == THP_PACKET_SIZE,
                                 "THP: short read on the data transfer layer");
      if (ctrl::is_continuation(packet[0])) {
        MWARNING("THP: skipping unexpected continuation packet");
        continue;
      }
      ctrl_byte = packet[0];
      cid = static_cast<uint16_t>((packet[1] << 8) | packet[2]);
      data_length = static_cast<size_t>((packet[3] << 8) | packet[4]);
      acc.assign(packet + INIT_HEADER_LENGTH, packet + THP_PACKET_SIZE);
      have_init = true;
    }

    // Collect continuation packets until the payload is complete.
    bool restart = false;
    while (acc.size() < data_length) {
      const size_t nread = transport.read_chunk(packet, THP_PACKET_SIZE);
      CHECK_AND_ASSERT_THROW_MES(nread == THP_PACKET_SIZE,
                                 "THP: short read on the data transfer layer");
      if (!ctrl::is_continuation(packet[0])) {
        // A new payload started before this one finished; abandon this one.
        MWARNING("THP: expected a continuation packet, restarting reassembly");
        restart = true;
        break;
      }
      const uint16_t cont_cid = static_cast<uint16_t>((packet[1] << 8) | packet[2]);
      if (cont_cid != cid) {
        MWARNING("THP: ignoring continuation packet for channel " << cont_cid);
        continue;
      }
      acc.insert(acc.end(), packet + CONT_HEADER_LENGTH, packet + THP_PACKET_SIZE);
    }
    if (restart) continue;

    acc.resize(data_length);
    try {
      return Message::parse(ctrl_byte, cid, acc);
    } catch (const std::exception &e) {
      MWARNING("THP: discarding message with invalid checksum: " << e.what());
    }
  }

  throw exc::CommunicationException(
      "THP: exceeded retry budget waiting for a message with a valid checksum");
}

} // namespace thp
} // namespace trezor
} // namespace hw
