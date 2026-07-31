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
#include <memory>
#include <string>
#include <vector>

#include "transport.hpp"

namespace hw {
namespace trezor {
namespace ble {

/**
 * GATT identifiers of the Trezor BLE service, from the device firmware
 * (nordic/trezor/trezor-ble/src/ble/ble_internal.h). The characteristic names
 * are from the device's point of view: the host writes to the device's RX
 * characteristic and subscribes to notifications on its TX characteristic.
 */
extern const char TREZOR_SERVICE_UUID[];   // 8c000001-...
extern const char TREZOR_CHAR_RX_UUID[];   // 8c000002-... host -> device
extern const char TREZOR_CHAR_TX_UUID[];   // 8c000003-... device -> host

/**
 * Packet size of the BLE data transfer layer, per the THP specification.
 * USB uses 64; Bluetooth Low Energy uses 244.
 */
constexpr size_t BLE_PACKET_SIZE = 244;

/** A Trezor discovered over BLE. */
struct BleDeviceInfo {
  std::string address;  // platform address string, e.g. "AA:BB:CC:DD:EE:FF"
  std::string name;     // advertised name, for display
  bool paired = false;  // already bonded at the operating system level
};

/**
 * Platform Bluetooth Low Energy backend.
 *
 * Kept abstract so that monero core carries no dependency on any particular
 * Bluetooth stack: the host application installs an implementation (WinRT/Win32
 * on Windows, BlueZ on Linux, CoreBluetooth on macOS). Every method is
 * synchronous from the caller's point of view; implementations wrap whatever
 * asynchronous API the platform provides.
 */
class BleBackend {
public:
  virtual ~BleBackend() = default;

  /** Devices advertising or bonded with the Trezor service UUID. */
  virtual std::vector<BleDeviceInfo> enumerate() = 0;

  /**
   * Connect to `address` and discover the Trezor service. Throws on failure.
   * Must subscribe to notifications on the TX characteristic so that read()
   * can return data.
   */
  virtual void connect(const std::string &address) = 0;
  virtual void disconnect() = 0;
  virtual bool is_connected() const = 0;

  /** Write one packet to the device's RX characteristic. */
  virtual void write_packet(const uint8_t *data, size_t len) = 0;

  /**
   * Read one notification packet from the device's TX characteristic.
   * Blocks until a packet arrives or `timeout_ms` elapses; returns the number
   * of bytes written to `out`, or 0 on timeout.
   */
  virtual size_t read_packet(uint8_t *out, size_t max_len, unsigned timeout_ms) = 0;

  /**
   * Negotiated ATT payload size, if the platform exposes it. Returning 0 means
   * "unknown", and BLE_PACKET_SIZE is used.
   */
  virtual size_t negotiated_packet_size() const { return 0; }
};

/**
 * Install the platform backend factory.
 *
 * Called once by the host application during start-up. Without it, BLE
 * enumeration yields nothing and BLE paths cannot be opened - which is the
 * correct behaviour for builds and platforms with no Bluetooth support.
 */
void set_backend_factory(std::function<std::shared_ptr<BleBackend>()> factory);

/** True when a backend factory has been installed. */
bool has_backend();

} // namespace ble

/**
 * Transport carrying the Trezor-Host Protocol over Bluetooth Low Energy.
 *
 * BLE devices always speak THP - the legacy codec was never carried over
 * Bluetooth - so this transport pins ProtocolThp rather than probing, and
 * reports the 244-byte BLE packet size to the framing layer.
 */
class BleTransport : public Transport {
public:
  BleTransport();
  explicit BleTransport(std::string address,
                        boost::optional<std::shared_ptr<Protocol>> proto = boost::none);
  ~BleTransport() override;

  static const char *PATH_PREFIX;

  bool ping() override;
  std::string get_path() const override;
  void enumerate(t_transport_vect &res) override;
  void open() override;
  void close() override;

  void write(const google::protobuf::Message &req) override;
  void read(std::shared_ptr<google::protobuf::Message> &msg,
            messages::MessageType *msg_type = nullptr) override;

  void write_chunk(const void *buff, size_t size) override;
  size_t read_chunk(void *buff, size_t size) override;
  size_t read_chunk_timeout(void *buff, size_t size, unsigned timeout_ms) override;

  size_t packet_size() const override;

  void reset_protocol_session() override { if (m_proto) m_proto->reset_session(); };
  bool protocol_has_own_sessions() const override {
    return m_proto && m_proto->has_own_sessions();
  };

  std::ostream &dump(std::ostream &o) const override;

private:
  void require_connected() const;

  std::string m_address;
  std::string m_name;
  std::shared_ptr<ble::BleBackend> m_backend;
  std::shared_ptr<Protocol> m_proto;
};

} // namespace trezor
} // namespace hw
