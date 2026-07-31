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
// Windows Bluetooth Low Energy backend.
//
// Uses the Win32 GATT API (bluetoothleapis.h) rather than WinRT, because the
// former is reachable from a mingw-w64 cross build while C++/WinRT is not.
//
// A consequence of that choice, and the main thing to know when using this:
// the Win32 API can only talk to devices that Windows has *already bonded*.
// There is no programmatic pairing here. The user pairs the Trezor once in
// Windows Settings > Bluetooth & devices, after which it shows up in
// enumerate() and can be opened. Attempting to connect to an unpaired device
// fails with a clear message rather than silently hanging.
//

#include "transport_ble.hpp"

#if defined(_WIN32) && defined(WITH_DEVICE_TREZOR_BLE)

#include "misc_log_ex.h"

#include <windows.h>
// initguid.h must precede the headers that declare GUIDs: it turns DEFINE_GUID
// into a definition rather than a declaration, so GUID_BLUETOOTHLE_DEVICE_INTERFACE
// is emitted into this object file instead of being left to the linker.
#include <initguid.h>
#include <setupapi.h>
#include <devguid.h>
#include <bthdef.h>
#include <bthledef.h>
#include <bluetoothapis.h>
#include <bluetoothleapis.h>

#include <condition_variable>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor.ble"

namespace hw {
namespace trezor {
namespace ble {

namespace {

/** 8c000001-a59b-4d58-a9ad-073df69fa1b1 - the Trezor GATT service. */
const GUID TREZOR_SERVICE_GUID =
    {0x8c000001, 0xa59b, 0x4d58, {0xa9, 0xad, 0x07, 0x3d, 0xf6, 0x9f, 0xa1, 0xb1}};
/** ...0002 - written by the host, received by the device. */
const GUID TREZOR_RX_GUID =
    {0x8c000002, 0xa59b, 0x4d58, {0xa9, 0xad, 0x07, 0x3d, 0xf6, 0x9f, 0xa1, 0xb1}};
/** ...0003 - notified by the device, read by the host. */
const GUID TREZOR_TX_GUID =
    {0x8c000003, 0xa59b, 0x4d58, {0xa9, 0xad, 0x07, 0x3d, 0xf6, 0x9f, 0xa1, 0xb1}};

bool uuid_equals(const BTH_LE_UUID &uuid, const GUID &guid) {
  // Trezor's identifiers are all 128-bit, so a short UUID never matches.
  if (uuid.IsShortUuid) return false;
  return IsEqualGUID(uuid.Value.LongUuid, guid) == TRUE;
}

std::string wide_to_utf8(const std::wstring &w) {
  if (w.empty()) return {};
  const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
  std::string out(n, '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], n, nullptr, nullptr);
  return out;
}

std::wstring utf8_to_wide(const std::string &s) {
  if (s.empty()) return {};
  const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
  std::wstring out(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &out[0], n);
  return out;
}

/** RAII wrapper for a SetupAPI device information set. */
struct DevInfoSet {
  HDEVINFO h = INVALID_HANDLE_VALUE;
  explicit DevInfoSet(HDEVINFO handle) : h(handle) {}
  ~DevInfoSet() { if (h != INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(h); }
  DevInfoSet(const DevInfoSet &) = delete;
  DevInfoSet &operator=(const DevInfoSet &) = delete;
};

/**
 * Walk the bonded BLE device interfaces, invoking `fn(path, friendly_name)` for
 * each. The interface path is what CreateFile() needs, and doubles as the
 * stable address we hand back to the transport.
 */
template <class F>
void for_each_ble_interface(F &&fn) {
  DevInfoSet set(SetupDiGetClassDevsW(&GUID_BLUETOOTHLE_DEVICE_INTERFACE, nullptr, nullptr,
                                      DIGCF_PRESENT | DIGCF_DEVICEINTERFACE));
  if (set.h == INVALID_HANDLE_VALUE) return;

  SP_DEVICE_INTERFACE_DATA ifd{};
  ifd.cbSize = sizeof(ifd);

  for (DWORD i = 0; SetupDiEnumDeviceInterfaces(set.h, nullptr, &GUID_BLUETOOTHLE_DEVICE_INTERFACE,
                                                i, &ifd); ++i) {
    DWORD needed = 0;
    SetupDiGetDeviceInterfaceDetailW(set.h, &ifd, nullptr, 0, &needed, nullptr);
    if (needed == 0) continue;

    std::vector<uint8_t> buf(needed);
    auto *detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buf.data());
    detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

    SP_DEVINFO_DATA devinfo{};
    devinfo.cbSize = sizeof(devinfo);
    if (!SetupDiGetDeviceInterfaceDetailW(set.h, &ifd, detail, needed, nullptr, &devinfo)) {
      continue;
    }

    // Friendly name is for display only; absence is not fatal.
    std::wstring name;
    WCHAR namebuf[256] = {};
    DWORD namelen = sizeof(namebuf);
    if (SetupDiGetDeviceRegistryPropertyW(set.h, &devinfo, SPDRP_FRIENDLYNAME, nullptr,
                                          reinterpret_cast<PBYTE>(namebuf), namelen, nullptr)) {
      name = namebuf;
    }

    fn(std::wstring(detail->DevicePath), name);
  }
}

} // namespace

/**
 * BleBackend over the Win32 GATT API.
 *
 * Notifications arrive on a Windows-owned callback thread, so received packets
 * are pushed onto a queue and handed to read_packet() through a condition
 * variable. That keeps the transport's blocking read model intact without
 * pumping a message loop on the caller's thread.
 */
class WindowsBleBackend : public BleBackend {
public:
  ~WindowsBleBackend() override { disconnect(); }

  std::vector<BleDeviceInfo> enumerate() override {
    std::vector<BleDeviceInfo> out;
    for_each_ble_interface([&](const std::wstring &path, const std::wstring &name) {
      HANDLE h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
      if (h == INVALID_HANDLE_VALUE) return;

      const bool is_trezor = has_trezor_service(h);
      CloseHandle(h);
      if (!is_trezor) return;

      BleDeviceInfo info;
      info.address = wide_to_utf8(path);
      info.name = name.empty() ? std::string("Trezor") : wide_to_utf8(name);
      info.paired = true;  // only bonded devices appear in this enumeration
      out.push_back(std::move(info));
      MDEBUG("BLE: found Trezor \"" << out.back().name << "\"");
    });
    return out;
  }

  void connect(const std::string &address) override {
    disconnect();

    const std::wstring path = utf8_to_wide(address);
    m_device = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (m_device == INVALID_HANDLE_VALUE) {
      m_device = nullptr;
      throw std::runtime_error(
          "cannot open the Bluetooth device. Pair the Trezor in Windows Settings first "
          "(Bluetooth & devices), then try again");
    }

    if (!find_characteristics()) {
      disconnect();
      throw std::runtime_error("the Trezor GATT service was not found on this device");
    }
    if (!subscribe()) {
      disconnect();
      throw std::runtime_error("could not subscribe to device notifications");
    }
    MINFO("BLE: connected and subscribed");
  }

  void disconnect() override {
    if (m_event) {
      BluetoothGATTUnregisterEvent(m_event, BLUETOOTH_GATT_FLAG_NONE);
      m_event = nullptr;
    }
    if (m_device) {
      CloseHandle(m_device);
      m_device = nullptr;
    }
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.clear();
    m_have_chars = false;
  }

  bool is_connected() const override { return m_device != nullptr && m_have_chars; }

  void write_packet(const uint8_t *data, size_t len) override {
    if (!is_connected()) throw std::runtime_error("BLE: not connected");

    // BTH_LE_GATT_CHARACTERISTIC_VALUE is a header followed by the payload.
    std::vector<uint8_t> buf(sizeof(BTH_LE_GATT_CHARACTERISTIC_VALUE) + len, 0);
    auto *value = reinterpret_cast<PBTH_LE_GATT_CHARACTERISTIC_VALUE>(buf.data());
    value->DataSize = static_cast<ULONG>(len);
    memcpy(value->Data, data, len);

    // Write without response: THP does its own acknowledgement, and requiring a
    // GATT-level response per packet roughly halves throughput.
    const HRESULT hr = BluetoothGATTSetCharacteristicValue(
        m_device, &m_rx, value, 0, BLUETOOTH_GATT_FLAG_WRITE_WITHOUT_RESPONSE);
    if (FAILED(hr)) {
      throw std::runtime_error("BLE: characteristic write failed (hr=" + std::to_string(hr) + ")");
    }
  }

  size_t read_packet(uint8_t *out, size_t max_len, unsigned timeout_ms) override {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (!m_cond.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                         [&] { return !m_queue.empty(); })) {
      return 0;
    }

    auto packet = std::move(m_queue.front());
    m_queue.pop_front();
    lock.unlock();

    // THP packets are fixed size; a short notification is padded so the framing
    // layer sees the packet length it expects.
    const size_t n = std::min(packet.size(), max_len);
    memcpy(out, packet.data(), n);
    if (n < max_len) memset(out + n, 0, max_len - n);
    return max_len;
  }

  size_t negotiated_packet_size() const override {
    // The Win32 API does not expose the negotiated ATT MTU, so fall back to the
    // specified BLE packet size.
    return 0;
  }

private:
  bool has_trezor_service(HANDLE h) const {
    USHORT count = 0;
    HRESULT hr = BluetoothGATTGetServices(h, 0, nullptr, &count, BLUETOOTH_GATT_FLAG_NONE);
    if (count == 0) return false;

    std::vector<BTH_LE_GATT_SERVICE> services(count);
    hr = BluetoothGATTGetServices(h, count, services.data(), &count, BLUETOOTH_GATT_FLAG_NONE);
    if (FAILED(hr)) return false;

    for (const auto &svc : services) {
      if (uuid_equals(svc.ServiceUuid, TREZOR_SERVICE_GUID)) return true;
    }
    return false;
  }

  bool find_characteristics() {
    USHORT svc_count = 0;
    BluetoothGATTGetServices(m_device, 0, nullptr, &svc_count, BLUETOOTH_GATT_FLAG_NONE);
    if (svc_count == 0) return false;

    std::vector<BTH_LE_GATT_SERVICE> services(svc_count);
    if (FAILED(BluetoothGATTGetServices(m_device, svc_count, services.data(), &svc_count,
                                        BLUETOOTH_GATT_FLAG_NONE))) {
      return false;
    }

    for (auto &svc : services) {
      if (!uuid_equals(svc.ServiceUuid, TREZOR_SERVICE_GUID)) continue;

      USHORT ch_count = 0;
      BluetoothGATTGetCharacteristics(m_device, &svc, 0, nullptr, &ch_count,
                                      BLUETOOTH_GATT_FLAG_NONE);
      if (ch_count == 0) return false;

      std::vector<BTH_LE_GATT_CHARACTERISTIC> chars(ch_count);
      if (FAILED(BluetoothGATTGetCharacteristics(m_device, &svc, ch_count, chars.data(),
                                                 &ch_count, BLUETOOTH_GATT_FLAG_NONE))) {
        return false;
      }

      bool have_rx = false, have_tx = false;
      for (const auto &c : chars) {
        if (uuid_equals(c.CharacteristicUuid, TREZOR_RX_GUID)) { m_rx = c; have_rx = true; }
        else if (uuid_equals(c.CharacteristicUuid, TREZOR_TX_GUID)) { m_tx = c; have_tx = true; }
      }
      if (have_rx && have_tx) {
        m_have_chars = true;
        return true;
      }
    }
    return false;
  }

  bool subscribe() {
    // Enable notifications by writing the Client Characteristic Configuration
    // descriptor, then register for the value-changed event.
    USHORT desc_count = 0;
    BluetoothGATTGetDescriptors(m_device, &m_tx, 0, nullptr, &desc_count, BLUETOOTH_GATT_FLAG_NONE);
    if (desc_count > 0) {
      std::vector<BTH_LE_GATT_DESCRIPTOR> descs(desc_count);
      if (SUCCEEDED(BluetoothGATTGetDescriptors(m_device, &m_tx, desc_count, descs.data(),
                                                &desc_count, BLUETOOTH_GATT_FLAG_NONE))) {
        for (auto &d : descs) {
          if (d.DescriptorType != ClientCharacteristicConfiguration) continue;
          BTH_LE_GATT_DESCRIPTOR_VALUE value{};
          value.DescriptorType = ClientCharacteristicConfiguration;
          value.ClientCharacteristicConfiguration.IsSubscribeToNotification = TRUE;
          BluetoothGATTSetDescriptorValue(m_device, &d, &value, BLUETOOTH_GATT_FLAG_NONE);
          break;
        }
      }
    }

    BLUETOOTH_GATT_VALUE_CHANGED_EVENT_REGISTRATION reg{};
    reg.NumCharacteristics = 1;
    reg.Characteristics[0] = m_tx;

    const HRESULT hr = BluetoothGATTRegisterEvent(
        m_device, CharacteristicValueChangedEvent, &reg,
        &WindowsBleBackend::on_value_changed, this, &m_event, BLUETOOTH_GATT_FLAG_NONE);
    return SUCCEEDED(hr);
  }

  /** Called by Windows on its own thread for every notification. */
  static void CALLBACK on_value_changed(BTH_LE_GATT_EVENT_TYPE, PVOID param, PVOID context) {
    auto *self = static_cast<WindowsBleBackend *>(context);
    auto *evt = static_cast<PBLUETOOTH_GATT_VALUE_CHANGED_EVENT>(param);
    if (!self || !evt || !evt->CharacteristicValue) return;

    const auto *value = evt->CharacteristicValue;
    std::vector<uint8_t> packet(value->Data, value->Data + value->DataSize);
    {
      std::lock_guard<std::mutex> lock(self->m_mutex);
      self->m_queue.push_back(std::move(packet));
    }
    self->m_cond.notify_one();
  }

  HANDLE m_device = nullptr;
  BLUETOOTH_GATT_EVENT_HANDLE m_event = nullptr;
  BTH_LE_GATT_CHARACTERISTIC m_rx{};
  BTH_LE_GATT_CHARACTERISTIC m_tx{};
  bool m_have_chars = false;

  mutable std::mutex m_mutex;
  std::condition_variable m_cond;
  std::deque<std::vector<uint8_t>> m_queue;
};

void install_default_backend() {
  set_backend_factory([]() -> std::shared_ptr<BleBackend> {
    return std::make_shared<WindowsBleBackend>();
  });
  MINFO("BLE: Windows backend installed");
}

} // namespace ble
} // namespace trezor
} // namespace hw

#else  // no Windows BLE support in this build

namespace hw { namespace trezor { namespace ble {
void install_default_backend() { /* no platform backend available */ }
}}}

#endif
