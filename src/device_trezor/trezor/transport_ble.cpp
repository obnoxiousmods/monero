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

#include "transport_ble.hpp"
#include "protocol_thp.hpp"
#include "exceptions.hpp"
#include "misc_log_ex.h"

#include <boost/algorithm/string/predicate.hpp>
#include <cstring>
#include <functional>
#include <mutex>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor.ble"

namespace hw {
namespace trezor {

namespace ble {

const char TREZOR_SERVICE_UUID[] = "8c000001-a59b-4d58-a9ad-073df69fa1b1";
const char TREZOR_CHAR_RX_UUID[] = "8c000002-a59b-4d58-a9ad-073df69fa1b1";
const char TREZOR_CHAR_TX_UUID[] = "8c000003-a59b-4d58-a9ad-073df69fa1b1";

namespace {
std::mutex g_backend_mutex;
std::function<std::shared_ptr<BleBackend>()> g_backend_factory;
} // namespace

void set_backend_factory(std::function<std::shared_ptr<BleBackend>()> factory) {
  std::lock_guard<std::mutex> lock(g_backend_mutex);
  g_backend_factory = std::move(factory);
}

bool has_backend() {
  std::lock_guard<std::mutex> lock(g_backend_mutex);
  return static_cast<bool>(g_backend_factory);
}

namespace {
std::shared_ptr<BleBackend> make_backend() {
  std::lock_guard<std::mutex> lock(g_backend_mutex);
  return g_backend_factory ? g_backend_factory() : nullptr;
}
} // namespace

} // namespace ble

const char *BleTransport::PATH_PREFIX = "ble:";

BleTransport::BleTransport() = default;

BleTransport::BleTransport(std::string address, boost::optional<std::shared_ptr<Protocol>> proto)
    : m_address(std::move(address)) {
  // Bluetooth was introduced alongside THP; the legacy codec was never carried
  // over it, so there is nothing to probe for.
  m_proto = proto ? proto.get() : std::make_shared<ProtocolThp>();
  m_proto_explicit = (bool)proto;
}

BleTransport::~BleTransport() {
  if (m_backend && m_backend->is_connected()) {
    try {
      close();
    } catch (const std::exception &e) {
      MWARNING("BLE: error while closing transport: " << e.what());
    }
  }
}

std::string BleTransport::get_path() const {
  if (m_address.empty()) return "";
  return std::string(PATH_PREFIX) + m_address;
}

void BleTransport::enumerate(t_transport_vect &res) {
  if (!ble::has_backend()) {
    MDEBUG("BLE: no backend installed, skipping enumeration");
    return;
  }

  auto backend = ble::make_backend();
  if (!backend) return;

  for (const auto &dev : backend->enumerate()) {
    auto t = std::make_shared<BleTransport>(dev.address);
    t->m_name = dev.name;
    res.push_back(t);
  }
}

void BleTransport::open() {
  if (!pre_open()) return;

  CHECK_AND_ASSERT_THROW_MES(!m_address.empty(), "BLE: no device address");

  if (!m_backend) {
    m_backend = ble::make_backend();
  }
  CHECK_AND_ASSERT_THROW_MES(m_backend, "BLE: no Bluetooth backend is installed");

  try {
    m_backend->connect(m_address);
  } catch (const std::exception &e) {
    m_open_counter = 0;
    throw exc::DeviceAcquireException(std::string("BLE: could not connect: ") + e.what());
  }

  m_open_counter = 1;

  auto thp_proto = std::dynamic_pointer_cast<ProtocolThp>(m_proto);
  if (thp_proto) {
    thp_proto->set_pairing_ui(m_pairing_ui);
  }

  m_proto->session_begin(*this);
}

void BleTransport::close() {
  if (!pre_close()) return;

  MTRACE("Closing Trezor:BleTransport");
  if (m_proto) m_proto->session_end(*this);
  if (m_backend) m_backend->disconnect();
}

bool BleTransport::ping() {
  if (!m_backend || !m_backend->is_connected()) return false;
  return ProtocolThp::probe(*this);
}

void BleTransport::require_connected() const {
  CHECK_AND_ASSERT_THROW_MES(m_backend && m_backend->is_connected(),
                             "BLE: device is not connected");
}

size_t BleTransport::packet_size() const {
  if (m_backend) {
    const size_t negotiated = m_backend->negotiated_packet_size();
    if (negotiated >= 16) return negotiated;
  }
  return ble::BLE_PACKET_SIZE;
}

void BleTransport::write_chunk(const void *buff, size_t size) {
  require_connected();
  m_backend->write_packet(static_cast<const uint8_t *>(buff), size);
}

size_t BleTransport::read_chunk(void *buff, size_t size) {
  // No timeout: the caller is waiting on the device, which may be waiting on
  // the user. Matches the USB transport's behaviour.
  require_connected();
  while (true) {
    const size_t n = m_backend->read_packet(static_cast<uint8_t *>(buff), size, 60000);
    if (n > 0) {
      CHECK_AND_ASSERT_THROW_MES(n == size, "BLE: short packet received");
      return n;
    }
    MDEBUG("BLE: still waiting for a packet from the device");
  }
}

size_t BleTransport::read_chunk_timeout(void *buff, size_t size, unsigned timeout_ms) {
  require_connected();
  const size_t n = m_backend->read_packet(static_cast<uint8_t *>(buff), size, timeout_ms);
  if (n == 0) return 0;
  CHECK_AND_ASSERT_THROW_MES(n == size, "BLE: short packet received");
  return n;
}

void BleTransport::write(const google::protobuf::Message &req) {
  m_proto->write(*this, req);
}

void BleTransport::read(std::shared_ptr<google::protobuf::Message> &msg,
                        messages::MessageType *msg_type) {
  m_proto->read(*this, msg, msg_type);
}

std::ostream &BleTransport::dump(std::ostream &o) const {
  return o << "BleTransport<path=" << get_path()
           << ", name=" << (m_name.empty() ? "?" : m_name)
           << ", connected=" << (m_backend && m_backend->is_connected()) << ">";
}

} // namespace trezor
} // namespace hw
