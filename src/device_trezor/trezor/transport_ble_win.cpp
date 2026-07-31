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

/**
 * Windows Bluetooth Low Energy backend for the Trezor transport, built on WinRT.
 *
 * Why WinRT and not the Win32 GATT API
 * ------------------------------------
 * The obvious Win32 route (bluetoothleapis.h + SetupDiEnumDeviceInterfaces over
 * GUID_BLUETOOTHLE_DEVICE_INTERFACE) can only see peripherals that Windows has
 * already *bonded* with: the device interface it enumerates is created by the OS
 * pairing flow. A Trezor advertising its GATT service is never bonded that way,
 * so that enumeration is permanently empty and no amount of fiddling in Windows
 * Settings changes it. The device also does not show up in the Settings
 * "Add a device" list, because a peripheral advertising only a custom 128-bit
 * service is not offered there - which makes the Win32 route look like a device
 * problem when it is really an API mismatch.
 *
 * Every working Trezor BLE host takes the other route instead: scan raw
 * advertisements, filter by the Trezor service UUID, and connect directly
 * without bonding. trezorlib does it with BleakScanner.discover(), and Cake
 * Wallet does it with the universal_ble package. On Windows the only API that
 * exposes advertisement scanning and connect-without-bonding is WinRT, so that
 * is what this backend uses.
 *
 * Reaching WinRT from a mingw-w64 cross build
 * -------------------------------------------
 * C++/WinRT is not available here, so this talks to the WinRT ABI directly
 * through the MIDL-generated headers mingw-w64 ships. Three consequences worth
 * knowing about, each handled below:
 *
 *   - Async methods are awaited by polling IAsyncInfo rather than by installing
 *     completion handlers. Polling behaves identically in either COM apartment
 *     and needs no message pump, which matters because the wallet calls this
 *     from several different threads.
 *   - Event handlers (advertisement received, characteristic notified) are
 *     hand-rolled COM objects. They advertise IAgileObject so the runtime
 *     invokes them straight from a threadpool thread instead of marshalling
 *     back to the registering apartment - again, no message pump required.
 *   - IBluetoothLEDevice3 is forward-declared but never defined by mingw-w64 14,
 *     so it is declared here from the Windows SDK IDL.
 */

// Monero and protobuf headers first: windows.h defines `interface`, `min` and
// `max` as macros, which those headers do not survive.
#include "transport_ble.hpp"
#include "exceptions.hpp"
#include "misc_log_ex.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "device.trezor.ble"

#if defined(_WIN32) && defined(WITH_DEVICE_TREZOR_BLE)

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

// mingw-w64 14's windows.foundation.h declares IReference<BYTE> and
// IReference<boolean> as distinct template specialisations, but both `BYTE` and
// `boolean` resolve to `unsigned char`, so the second is a redefinition and the
// header does not compile as shipped. Claiming the guard of the later block
// keeps the earlier, equivalent specialisation. Neither type is used here.
#define ____FIReference_1_boolean_INTERFACE_DEFINED__

#include <roapi.h>
#include <winstring.h>
#include <robuffer.h>
#include <windows.foundation.h>
#include <windows.devices.bluetooth.h>
#include <windows.devices.bluetooth.advertisement.h>
#include <windows.devices.bluetooth.genericattributeprofile.h>
#include <windows.storage.streams.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace hw {
namespace trezor {
namespace ble {

namespace {

namespace wf = ABI::Windows::Foundation;
namespace wfc = ABI::Windows::Foundation::Collections;
namespace wdb = ABI::Windows::Devices::Bluetooth;
namespace wda = ABI::Windows::Devices::Bluetooth::Advertisement;
namespace wdg = ABI::Windows::Devices::Bluetooth::GenericAttributeProfile;
namespace wss = ABI::Windows::Storage::Streams;

// ---------------------------------------------------------------------------
// Trezor GATT profile, as binary GUIDs.
//
// These mirror the TREZOR_*_UUID strings in transport_ble.hpp; the Windows APIs
// want GUIDs, so they are spelled out rather than parsed at run time.
// ---------------------------------------------------------------------------

const GUID kTrezorService =
    {0x8c000001, 0xa59b, 0x4d58, {0xa9, 0xad, 0x07, 0x3d, 0xf6, 0x9f, 0xa1, 0xb1}};
const GUID kTrezorCharRx =  // host -> device
    {0x8c000002, 0xa59b, 0x4d58, {0xa9, 0xad, 0x07, 0x3d, 0xf6, 0x9f, 0xa1, 0xb1}};
const GUID kTrezorCharTx =  // device -> host, via notifications
    {0x8c000003, 0xa59b, 0x4d58, {0xa9, 0xad, 0x07, 0x3d, 0xf6, 0x9f, 0xa1, 0xb1}};

/**
 * IBluetoothLEDevice3, transcribed from the Windows SDK IDL
 * (Include/10.0.26100.0/winrt/windows.devices.bluetooth.idl).
 *
 * mingw-w64 14 forward-declares this interface but never defines it, leaving the
 * async GATT discovery methods unreachable. Its predecessor only offers the
 * deprecated synchronous `GattServices` property, which reads a cache that is
 * empty for a device we have never bonded with - exactly our situation. Writing
 * the vtable out by hand is safe: published COM interfaces never change.
 *
 * Unused slots still have to be declared so the later entries land at the right
 * vtable offsets.
 */
const GUID kIidBluetoothLEDevice3 =
    {0xaee9e493, 0x44ac, 0x40dc, {0xaf, 0x33, 0xb2, 0xc1, 0x3c, 0x01, 0xca, 0x46}};

struct IBluetoothLEDevice3 : public IInspectable {
  virtual HRESULT STDMETHODCALLTYPE get_DeviceAccessInformation(void **value) = 0;
  virtual HRESULT STDMETHODCALLTYPE RequestAccessAsync(void **operation) = 0;
  virtual HRESULT STDMETHODCALLTYPE GetGattServicesAsync(
      wf::IAsyncOperation<wdg::GattDeviceServicesResult *> **operation) = 0;
  virtual HRESULT STDMETHODCALLTYPE GetGattServicesWithCacheModeAsync(
      wdb::BluetoothCacheMode cacheMode,
      wf::IAsyncOperation<wdg::GattDeviceServicesResult *> **operation) = 0;
  virtual HRESULT STDMETHODCALLTYPE GetGattServicesForUuidAsync(
      GUID serviceUuid,
      wf::IAsyncOperation<wdg::GattDeviceServicesResult *> **operation) = 0;
  virtual HRESULT STDMETHODCALLTYPE GetGattServicesForUuidWithCacheModeAsync(
      GUID serviceUuid, wdb::BluetoothCacheMode cacheMode,
      wf::IAsyncOperation<wdg::GattDeviceServicesResult *> **operation) = 0;
};

/**
 * IAgileObject is a marker interface with no methods. Implementing it tells the
 * Windows runtime our callbacks are safe to invoke on any thread, so it calls
 * them directly from a threadpool thread. Without it, a handler registered from
 * a single-threaded apartment - which is what Qt establishes on the GUI thread -
 * would only fire while a message pump runs, and the transport blocks without
 * pumping while it waits for device packets.
 */
const GUID kIidAgileObject =
    {0x94ea2b94, 0xe9cc, 0x49e0, {0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90}};

// ---------------------------------------------------------------------------
// Minimal COM plumbing
// ---------------------------------------------------------------------------

template <typename T>
class ComPtr {
public:
  ComPtr() = default;
  ComPtr(const ComPtr &o) : m_p(o.m_p) { if (m_p) m_p->AddRef(); }
  ComPtr(ComPtr &&o) noexcept : m_p(o.m_p) { o.m_p = nullptr; }
  ~ComPtr() { reset(); }
  ComPtr &operator=(ComPtr o) { std::swap(m_p, o.m_p); return *this; }

  T **put() { reset(); return &m_p; }
  void **put_void() { reset(); return reinterpret_cast<void **>(&m_p); }
  T *get() const { return m_p; }
  T *operator->() const { return m_p; }
  explicit operator bool() const { return m_p != nullptr; }
  void reset() { if (m_p) { m_p->Release(); m_p = nullptr; } }

  template <typename U>
  HRESULT as(const IID &iid, ComPtr<U> &out) const {
    if (!m_p) return E_POINTER;
    return m_p->QueryInterface(iid, out.put_void());
  }

private:
  T *m_p = nullptr;
};

/** RAII wrapper for HSTRING. */
class HStr {
public:
  HStr() = default;
  explicit HStr(const wchar_t *s) { WindowsCreateString(s, (UINT32)wcslen(s), &m_h); }
  ~HStr() { if (m_h) WindowsDeleteString(m_h); }
  HStr(const HStr &) = delete;
  HStr &operator=(const HStr &) = delete;

  HSTRING get() const { return m_h; }
  HSTRING *put() { if (m_h) { WindowsDeleteString(m_h); m_h = nullptr; } return &m_h; }

  std::string to_utf8() const {
    if (!m_h) return {};
    UINT32 len = 0;
    const wchar_t *raw = WindowsGetStringRawBuffer(m_h, &len);
    if (!len) return {};
    const int n =
        WideCharToMultiByte(CP_UTF8, 0, raw, (int)len, nullptr, 0, nullptr, nullptr);
    std::string out((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, raw, (int)len, &out[0], n, nullptr, nullptr);
    return out;
  }

private:
  HSTRING m_h = nullptr;
};

/**
 * Put the calling thread into a state where WinRT calls are legal.
 *
 * The wallet reaches this backend from several threads. RPC_E_CHANGED_MODE means
 * the thread already belongs to a single-threaded apartment (Qt does this to the
 * GUI thread); that is fine, because everything here either polls or relies on
 * agile callbacks.
 */
void ensure_apartment() {
  static thread_local bool initialised = false;
  if (initialised) return;
  const HRESULT hr = RoInitialize(RO_INIT_MULTITHREADED);
  if (SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE || hr == S_FALSE) {
    initialised = true;
  } else {
    MWARNING("BLE: RoInitialize failed, hr=0x" << std::hex << hr);
  }
}

template <typename T>
HRESULT get_activation_factory(const wchar_t *class_name, const IID &iid, ComPtr<T> &out) {
  HStr name(class_name);
  return RoGetActivationFactory(name.get(), iid, out.put_void());
}

/**
 * Await a WinRT async operation by polling its IAsyncInfo status.
 *
 * Polling rather than installing a completion handler keeps this correct in
 * either COM apartment and free of any dependency on a running message pump.
 */
template <typename TOp>
HRESULT await_op(ComPtr<TOp> &op, unsigned timeout_ms = 30000) {
  if (!op) return E_POINTER;

  // mingw declares IAsyncInfo and AsyncStatus at global scope, not under
  // ABI::Windows::Foundation.
  ComPtr<::IAsyncInfo> info;
  HRESULT hr = op.as(__uuidof(::IAsyncInfo), info);
  if (FAILED(hr)) return hr;

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
  for (;;) {
    ::AsyncStatus status = ::Started;
    hr = info->get_Status(&status);
    if (FAILED(hr)) return hr;
    if (status == ::Completed) return S_OK;
    if (status == ::Error) {
      HRESULT err = S_OK;
      info->get_ErrorCode(&err);
      return FAILED(err) ? err : E_FAIL;
    }
    if (status == ::Canceled) return E_ABORT;
    if (std::chrono::steady_clock::now() >= deadline) {
      info->Cancel();
      return HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    }
    Sleep(5);
  }
}

/** Reference-counted, agile base for the two event handlers we install. */
template <typename TInterface>
class HandlerBase : public TInterface {
public:
  explicit HandlerBase(const IID &self_iid) : m_iid(self_iid) {}
  virtual ~HandlerBase() = default;

  ULONG STDMETHODCALLTYPE AddRef() override {
    return (ULONG)InterlockedIncrement(&m_refs);
  }
  ULONG STDMETHODCALLTYPE Release() override {
    const LONG n = InterlockedDecrement(&m_refs);
    if (n == 0) delete this;
    return (ULONG)n;
  }
  HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppv) override {
    if (!ppv) return E_POINTER;
    if (IsEqualGUID(riid, IID_IUnknown) || IsEqualGUID(riid, m_iid) ||
        IsEqualGUID(riid, kIidAgileObject)) {
      *ppv = static_cast<TInterface *>(this);
      AddRef();
      return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
  }

private:
  LONG m_refs = 1;
  IID m_iid;
};

std::string mac_to_string(uint64_t addr) {
  char buf[24];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           (unsigned)((addr >> 40) & 0xFF), (unsigned)((addr >> 32) & 0xFF),
           (unsigned)((addr >> 24) & 0xFF), (unsigned)((addr >> 16) & 0xFF),
           (unsigned)((addr >> 8) & 0xFF), (unsigned)(addr & 0xFF));
  return buf;
}

/** Parse "AA:BB:CC:DD:EE:FF" back into the 48-bit address WinRT wants. */
bool string_to_mac(const std::string &s, uint64_t &out) {
  uint64_t addr = 0;
  int nibbles = 0;
  for (char c : s) {
    if (c == ':' || c == '-') continue;
    int v;
    if (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else return false;
    addr = (addr << 4) | (uint64_t)v;
    if (++nibbles > 12) return false;
  }
  if (nibbles != 12) return false;
  out = addr;
  return true;
}

// ---------------------------------------------------------------------------
// Advertisement scanning
// ---------------------------------------------------------------------------

using AdvHandlerIface =
    wf::ITypedEventHandler<wda::BluetoothLEAdvertisementWatcher *,
                           wda::BluetoothLEAdvertisementReceivedEventArgs *>;

/**
 * Collects advertisements that carry the Trezor service UUID.
 *
 * A peripheral often splits its payload between the advertisement and the scan
 * response, so the same device is reported several times with different fields
 * populated. Reports are therefore merged per address, and neither a later
 * empty name nor a later report without the service UUID undoes what an earlier
 * one established.
 */
class AdvertisementCollector : public HandlerBase<AdvHandlerIface> {
public:
  AdvertisementCollector() : HandlerBase(__uuidof(AdvHandlerIface)) {}

  HRESULT STDMETHODCALLTYPE Invoke(
      wda::IBluetoothLEAdvertisementWatcher * /*sender*/,
      wda::IBluetoothLEAdvertisementReceivedEventArgs *args) override {
    if (!args) return S_OK;

    uint64_t addr = 0;
    if (FAILED(args->get_BluetoothAddress(&addr)) || !addr) return S_OK;

    ComPtr<wda::IBluetoothLEAdvertisement> adv;
    if (FAILED(args->get_Advertisement(adv.put())) || !adv) return S_OK;

    bool is_trezor = false;
    ComPtr<wfc::IVector<GUID>> uuids;
    if (SUCCEEDED(adv->get_ServiceUuids(uuids.put())) && uuids) {
      unsigned size = 0;
      uuids->get_Size(&size);
      for (unsigned i = 0; i < size; ++i) {
        GUID g{};
        if (SUCCEEDED(uuids->GetAt(i, &g)) && IsEqualGUID(g, kTrezorService)) {
          is_trezor = true;
          break;
        }
      }
    }

    HStr local_name;
    adv->get_LocalName(local_name.put());
    const std::string name = local_name.to_utf8();

    bool now_matches = false;
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      Entry &e = m_seen[addr];
      const bool was_trezor = e.is_trezor;
      e.is_trezor = e.is_trezor || is_trezor;
      if (!name.empty()) e.name = name;
      now_matches = e.is_trezor && !was_trezor;
    }
    // Wake enumerate() as soon as the first Trezor shows up, so discovery
    // usually finishes well inside its timeout.
    if (now_matches) m_found.notify_all();
    return S_OK;
  }

  std::vector<BleDeviceInfo> wait_for_devices(unsigned timeout_ms) {
    std::unique_lock<std::mutex> lock(m_mutex);
    m_found.wait_for(lock, std::chrono::milliseconds(timeout_ms), [this] {
      for (const auto &kv : m_seen) {
        if (kv.second.is_trezor) return true;
      }
      return false;
    });

    std::vector<BleDeviceInfo> out;
    for (const auto &kv : m_seen) {
      if (!kv.second.is_trezor) continue;
      BleDeviceInfo info;
      info.address = mac_to_string(kv.first);
      info.name = kv.second.name.empty() ? "Trezor" : kv.second.name;
      // This transport never uses operating-system bonding, so a device is
      // never "paired" in that sense. Trezor pairing happens inside THP.
      info.paired = false;
      out.push_back(std::move(info));
    }
    return out;
  }

private:
  struct Entry {
    std::string name;
    bool is_trezor = false;
  };

  std::mutex m_mutex;
  std::condition_variable m_found;
  std::map<uint64_t, Entry> m_seen;
};

// ---------------------------------------------------------------------------
// GATT notifications
// ---------------------------------------------------------------------------

using ValueHandlerIface =
    wf::ITypedEventHandler<wdg::GattCharacteristic *, wdg::GattValueChangedEventArgs *>;

/** Queues notification payloads for the transport's blocking reads. */
class NotificationQueue : public HandlerBase<ValueHandlerIface> {
public:
  NotificationQueue() : HandlerBase(__uuidof(ValueHandlerIface)) {}

  HRESULT STDMETHODCALLTYPE Invoke(wdg::IGattCharacteristic * /*sender*/,
                                   wdg::IGattValueChangedEventArgs *args) override {
    if (!args) return S_OK;

    ComPtr<wss::IBuffer> buf;
    if (FAILED(args->get_CharacteristicValue(buf.put())) || !buf) return S_OK;

    UINT32 len = 0;
    buf->get_Length(&len);
    if (!len) return S_OK;

    // IBufferByteAccess is the only route to the bytes behind an IBuffer.
    ComPtr<Windows::Storage::Streams::IBufferByteAccess> access;
    if (FAILED(buf.as(__uuidof(Windows::Storage::Streams::IBufferByteAccess), access)) ||
        !access) {
      return S_OK;
    }
    byte *raw = nullptr;
    if (FAILED(access->Buffer(&raw)) || !raw) return S_OK;

    {
      std::lock_guard<std::mutex> lock(m_mutex);
      m_queue.emplace_back(raw, raw + len);
    }
    m_cv.notify_one();
    return S_OK;
  }

  /** Returns an empty vector on timeout or once cancelled. */
  std::vector<uint8_t> pop(unsigned timeout_ms) {
    std::unique_lock<std::mutex> lock(m_mutex);
    if (!m_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                       [this] { return !m_queue.empty() || m_cancelled; })) {
      return {};
    }
    if (m_queue.empty()) return {};
    std::vector<uint8_t> out = std::move(m_queue.front());
    m_queue.pop_front();
    return out;
  }

  /** Release any blocked reader; used when the link drops or we disconnect. */
  void cancel() {
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      m_cancelled = true;
    }
    m_cv.notify_all();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_queue.clear();
    m_cancelled = false;
  }

private:
  std::mutex m_mutex;
  std::condition_variable m_cv;
  std::deque<std::vector<uint8_t>> m_queue;
  bool m_cancelled = false;
};

// ---------------------------------------------------------------------------
// The backend
// ---------------------------------------------------------------------------

class WinRtBleBackend : public BleBackend {
public:
  ~WinRtBleBackend() override {
    try {
      disconnect();
    } catch (...) {
      // Nothing useful to do while unwinding.
    }
  }

  std::vector<BleDeviceInfo> enumerate() override {
    ensure_apartment();

    // Device enumeration runs this on every scan, alongside USB, so an
    // unconditional multi-second radio scan would add that delay to opening any
    // Trezor at all - including one plugged in over USB. The scan is therefore
    // kept short, exits the moment a Trezor answers, and its result is reused
    // for a few seconds so back-to-back enumerations cost nothing.
    //
    // This bounds the cost but does not eliminate it. Scanning belongs behind an
    // explicit "look for Bluetooth devices" action in the UI; until that exists,
    // this keeps the delay tolerable.
    {
      std::lock_guard<std::mutex> lock(s_cache_mutex);
      const auto now = std::chrono::steady_clock::now();
      if (s_cache_valid && now - s_cache_time < std::chrono::seconds(cache_ttl_locked())) {
        MDEBUG("BLE: reusing scan result from cache");
        return s_cache;
      }
    }

    ComPtr<IActivationFactory> factory;
    HRESULT hr = get_activation_factory(
        L"Windows.Devices.Bluetooth.Advertisement.BluetoothLEAdvertisementWatcher",
        __uuidof(IActivationFactory), factory);
    if (FAILED(hr)) {
      MWARNING("BLE: no advertisement watcher available, hr=0x" << std::hex << hr
               << " (is Bluetooth turned on?)");
      return {};
    }

    ComPtr<IInspectable> inspectable;
    if (FAILED(factory->ActivateInstance(inspectable.put()))) return {};

    ComPtr<wda::IBluetoothLEAdvertisementWatcher> watcher;
    if (FAILED(inspectable.as(__uuidof(wda::IBluetoothLEAdvertisementWatcher), watcher))) {
      return {};
    }

    // Active scanning solicits scan responses too, which is where a peripheral
    // commonly puts its local name.
    watcher->put_ScanningMode(wda::BluetoothLEScanningMode_Active);

    AdvertisementCollector *collector = new AdvertisementCollector();
    EventRegistrationToken token{};
    hr = watcher->add_Received(collector, &token);
    if (FAILED(hr)) {
      collector->Release();
      MWARNING("BLE: could not subscribe to advertisements, hr=0x" << std::hex << hr);
      return {};
    }

    std::vector<BleDeviceInfo> devices;
    if (SUCCEEDED(watcher->Start())) {
      devices = collector->wait_for_devices(SCAN_TIMEOUT_MS);
      watcher->Stop();
    } else {
      MWARNING("BLE: advertisement scan could not be started");
    }
    watcher->remove_Received(token);
    collector->Release();

    {
      std::lock_guard<std::mutex> lock(s_cache_mutex);
      // Machines with no Bluetooth Trezor nearby - which is most of them, and
      // any machine whose radio cannot scan - should not keep paying for a scan
      // that never finds anything. Backing off after repeated empty results
      // makes the steady-state cost negligible, while any successful scan drops
      // straight back to the responsive interval.
      if (devices.empty()) {
        if (s_empty_streak < 5) ++s_empty_streak;
      } else {
        s_empty_streak = 0;
      }
      s_cache = devices;
      s_cache_time = std::chrono::steady_clock::now();
      s_cache_valid = true;
    }

    MDEBUG("BLE: scan found " << devices.size() << " Trezor device(s)");
    return devices;
  }

  void connect(const std::string &address) override {
    ensure_apartment();
    std::lock_guard<std::mutex> lock(m_mutex);

    disconnect_locked();

    uint64_t addr = 0;
    CHECK_AND_ASSERT_THROW_MES(string_to_mac(address, addr),
                               "BLE: malformed device address: " << address);

    ComPtr<wdb::IBluetoothLEDeviceStatics> statics;
    HRESULT hr = get_activation_factory(L"Windows.Devices.Bluetooth.BluetoothLEDevice",
                                        __uuidof(wdb::IBluetoothLEDeviceStatics), statics);
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr), "BLE: Bluetooth is unavailable on this system");

    ComPtr<wf::IAsyncOperation<wdb::BluetoothLEDevice *>> dev_op;
    hr = statics->FromBluetoothAddressAsync(addr, dev_op.put());
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && SUCCEEDED(await_op(dev_op)),
                               "BLE: could not reach the device at " << address);
    hr = dev_op->GetResults(m_device.put());
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && m_device,
                               "BLE: device " << address << " is not reachable");

    ComPtr<IBluetoothLEDevice3> device3;
    hr = m_device.as(kIidBluetoothLEDevice3, device3);
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && device3,
                               "BLE: this Windows version is too old for GATT discovery");

    // Uncached forces real over-the-air discovery rather than trusting anything
    // Windows may have remembered; this is also what establishes the link.
    ComPtr<wf::IAsyncOperation<wdg::GattDeviceServicesResult *>> svc_op;
    hr = device3->GetGattServicesForUuidWithCacheModeAsync(
        kTrezorService, wdb::BluetoothCacheMode_Uncached, svc_op.put());
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && SUCCEEDED(await_op(svc_op)),
                               "BLE: service discovery failed; is the device awake and in range?");

    ComPtr<wdg::IGattDeviceServicesResult> svc_result;
    hr = svc_op->GetResults(svc_result.put());
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && svc_result, "BLE: service discovery failed");

    wdg::GattCommunicationStatus status = wdg::GattCommunicationStatus_Unreachable;
    svc_result->get_Status(&status);
    CHECK_AND_ASSERT_THROW_MES(status == wdg::GattCommunicationStatus_Success,
                               "BLE: could not read services from the device ("
                                   << describe_status(status) << ")");

    ComPtr<wfc::IVectorView<wdg::GattDeviceService *>> services;
    svc_result->get_Services(services.put());
    unsigned count = 0;
    if (services) services->get_Size(&count);
    CHECK_AND_ASSERT_THROW_MES(count > 0,
                               "BLE: the device does not expose the Trezor service");
    services->GetAt(0, m_service.put());

    hr = m_service.as(__uuidof(wdg::IGattDeviceService3), m_service3);
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && m_service3, "BLE: unsupported GATT service");

    resolve_characteristic(kTrezorCharRx, "RX", m_rx);
    resolve_characteristic(kTrezorCharTx, "TX", m_tx);

    hr = m_rx.as(__uuidof(wdg::IGattCharacteristic3), m_rx3);
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && m_rx3, "BLE: unsupported RX characteristic");

    configure_session();
    subscribe();

    m_connected = true;
    MINFO("BLE: connected to " << address << ", packet size " << m_packet_size);
  }

  void disconnect() override {
    std::lock_guard<std::mutex> lock(m_mutex);
    disconnect_locked();
  }

  bool is_connected() const override {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_connected;
  }

  void write_packet(const uint8_t *data, size_t len) override {
    ensure_apartment();
    std::lock_guard<std::mutex> lock(m_mutex);
    CHECK_AND_ASSERT_THROW_MES(m_connected && m_rx3, "BLE: device is not connected");

    // DataWriter is the sanctioned way to turn raw bytes into an IBuffer.
    ComPtr<IActivationFactory> factory;
    HRESULT hr = get_activation_factory(L"Windows.Storage.Streams.DataWriter",
                                        __uuidof(IActivationFactory), factory);
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr), "BLE: could not create a write buffer");
    ComPtr<IInspectable> inspectable;
    factory->ActivateInstance(inspectable.put());
    ComPtr<wss::IDataWriter> writer;
    hr = inspectable.as(__uuidof(wss::IDataWriter), writer);
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && writer,
                               "BLE: could not create a write buffer");

    writer->WriteBytes((UINT32)len, const_cast<BYTE *>(data));
    ComPtr<wss::IBuffer> buffer;
    hr = writer->DetachBuffer(buffer.put());
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && buffer,
                               "BLE: could not create a write buffer");

    // The Trezor RX characteristic is write-without-response, which matches the
    // fire-and-forget framing THP expects.
    ComPtr<wf::IAsyncOperation<wdg::GattWriteResult *>> op;
    hr = m_rx3->WriteValueWithResultAndOptionAsync(
        buffer.get(), wdg::GattWriteOption_WriteWithoutResponse, op.put());
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && SUCCEEDED(await_op(op, WRITE_TIMEOUT_MS)),
                               "BLE: writing to the device failed");

    ComPtr<wdg::IGattWriteResult> result;
    if (SUCCEEDED(op->GetResults(result.put())) && result) {
      wdg::GattCommunicationStatus status = wdg::GattCommunicationStatus_Unreachable;
      result->get_Status(&status);
      CHECK_AND_ASSERT_THROW_MES(status == wdg::GattCommunicationStatus_Success,
                                 "BLE: the device rejected a write ("
                                     << describe_status(status) << ")");
    }
  }

  size_t read_packet(uint8_t *out, size_t max_len, unsigned timeout_ms) override {
    // Deliberately not holding m_mutex: this blocks, and the notification
    // callback that feeds the queue must stay free to run. The queue has its own
    // lock, and m_notifications is stable for the lifetime of the connection.
    NotificationQueue *queue = nullptr;
    {
      std::lock_guard<std::mutex> lock(m_mutex);
      CHECK_AND_ASSERT_THROW_MES(m_connected && m_notifications,
                                 "BLE: device is not connected");
      queue = m_notifications;
      queue->AddRef();
    }
    struct Releaser {
      NotificationQueue *q;
      ~Releaser() { if (q) q->Release(); }
    } releaser{queue};

    const std::vector<uint8_t> packet = queue->pop(timeout_ms);
    if (packet.empty()) return 0;

    const size_t n = std::min(packet.size(), max_len);
    memcpy(out, packet.data(), n);
    if (n < max_len) {
      // THP packets are a fixed width, so a short notification means the device
      // trimmed trailing padding. The framing layer reads an explicit length and
      // a checksum, so zero-filling the tail is harmless and keeps the caller's
      // fixed-size contract.
      memset(out + n, 0, max_len - n);
      MDEBUG("BLE: notification was " << packet.size() << " bytes, padded to " << max_len);
    }
    return max_len;
  }

  size_t negotiated_packet_size() const override {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_packet_size;
  }

private:
  // Short enough not to be felt when opening a USB device, long enough for a
  // peripheral advertising at a typical 100-1000ms interval to be heard. The
  // scan returns early as soon as a Trezor answers, so this is a worst case.
  static constexpr unsigned SCAN_TIMEOUT_MS = 2500;
  static constexpr unsigned WRITE_TIMEOUT_MS = 10000;
  static constexpr unsigned CACHE_TTL_S = 10;
  static constexpr unsigned MAX_CACHE_TTL_S = 320;

  /** How long the current cached result stays good. Caller must hold the lock. */
  static unsigned cache_ttl_locked() {
    if (!s_cache.empty()) return CACHE_TTL_S;
    return std::min<unsigned>(MAX_CACHE_TTL_S, CACHE_TTL_S << s_empty_streak);
  }

  // Shared across backend instances: enumeration creates a fresh backend each
  // time, so per-instance caching would never hit.
  static std::mutex s_cache_mutex;
  static std::vector<BleDeviceInfo> s_cache;
  static std::chrono::steady_clock::time_point s_cache_time;
  static bool s_cache_valid;
  static unsigned s_empty_streak;

  static const char *describe_status(wdg::GattCommunicationStatus status) {
    switch (status) {
      case wdg::GattCommunicationStatus_Success: return "success";
      case wdg::GattCommunicationStatus_Unreachable: return "device unreachable";
      case wdg::GattCommunicationStatus_ProtocolError: return "protocol error";
      case wdg::GattCommunicationStatus_AccessDenied: return "access denied";
      default: return "unknown error";
    }
  }

  void resolve_characteristic(const GUID &uuid, const char *label,
                              ComPtr<wdg::IGattCharacteristic> &out) {
    ComPtr<wf::IAsyncOperation<wdg::GattCharacteristicsResult *>> op;
    HRESULT hr = m_service3->GetCharacteristicsForUuidWithCacheModeAsync(
        uuid, wdb::BluetoothCacheMode_Uncached, op.put());
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && SUCCEEDED(await_op(op)),
                               "BLE: could not read the " << label << " characteristic");

    ComPtr<wdg::IGattCharacteristicsResult> result;
    hr = op->GetResults(result.put());
    CHECK_AND_ASSERT_THROW_MES(SUCCEEDED(hr) && result,
                               "BLE: could not read the " << label << " characteristic");

    wdg::GattCommunicationStatus status = wdg::GattCommunicationStatus_Unreachable;
    result->get_Status(&status);
    CHECK_AND_ASSERT_THROW_MES(status == wdg::GattCommunicationStatus_Success,
                               "BLE: could not read the " << label << " characteristic ("
                                   << describe_status(status) << ")");

    ComPtr<wfc::IVectorView<wdg::GattCharacteristic *>> chars;
    result->get_Characteristics(chars.put());
    unsigned count = 0;
    if (chars) chars->get_Size(&count);
    CHECK_AND_ASSERT_THROW_MES(count > 0, "BLE: the device is missing its " << label
                                              << " characteristic");
    chars->GetAt(0, out.put());
  }

  /**
   * Ask Windows to hold the link open and work out the usable packet size.
   *
   * Without MaintainConnection the stack is free to drop the link between GATT
   * operations, which would tear down our notification subscription part-way
   * through a THP exchange.
   */
  void configure_session() {
    m_packet_size = BLE_PACKET_SIZE;
    if (FAILED(m_service3->get_Session(m_session.put())) || !m_session) {
      MDEBUG("BLE: no GATT session available, assuming " << m_packet_size << " byte packets");
      return;
    }
    m_session->put_MaintainConnection(true);

    UINT16 mtu = 0;
    if (SUCCEEDED(m_session->get_MaxPduSize(&mtu)) && mtu > 3) {
      // Three bytes of the ATT PDU are opcode and handle; the rest is payload.
      // The firmware sizes its packets the same way, so the two agree.
      m_packet_size = std::min<size_t>(BLE_PACKET_SIZE, (size_t)mtu - 3);
      MDEBUG("BLE: negotiated ATT MTU " << mtu << ", packet size " << m_packet_size);
    }
  }

  void subscribe() {
    m_notifications = new NotificationQueue();
    HRESULT hr = m_tx->add_ValueChanged(m_notifications, &m_value_token);
    if (FAILED(hr)) {
      m_notifications->Release();
      m_notifications = nullptr;
      CHECK_AND_ASSERT_THROW_MES(false, "BLE: could not listen for device notifications");
    }

    ComPtr<wf::IAsyncOperation<wdg::GattCommunicationStatus>> op;
    hr = m_tx->WriteClientCharacteristicConfigurationDescriptorAsync(
        wdg::GattClientCharacteristicConfigurationDescriptorValue_Notify, op.put());
    bool ok = SUCCEEDED(hr) && SUCCEEDED(await_op(op));
    if (ok) {
      wdg::GattCommunicationStatus status = wdg::GattCommunicationStatus_Unreachable;
      op->GetResults(&status);
      ok = (status == wdg::GattCommunicationStatus_Success);
    }
    if (!ok) {
      m_tx->remove_ValueChanged(m_value_token);
      m_notifications->Release();
      m_notifications = nullptr;
      CHECK_AND_ASSERT_THROW_MES(false, "BLE: the device refused our notification request");
    }
  }

  /** Caller must hold m_mutex. */
  void disconnect_locked() {
    if (m_notifications) {
      m_notifications->cancel();  // release anyone blocked in read_packet
      if (m_tx) m_tx->remove_ValueChanged(m_value_token);
      m_notifications->Release();
      m_notifications = nullptr;
    }

    m_rx3.reset();
    m_rx.reset();
    m_tx.reset();
    m_session.reset();
    m_service3.reset();

    // Closing the service is what actually tells Windows to drop the link;
    // simply releasing the references leaves it up for a while.
    if (m_service) {
      ComPtr<wf::IClosable> closable;
      if (SUCCEEDED(m_service.as(__uuidof(wf::IClosable), closable)) && closable) {
        closable->Close();
      }
      m_service.reset();
    }
    if (m_device) {
      ComPtr<wf::IClosable> closable;
      if (SUCCEEDED(m_device.as(__uuidof(wf::IClosable), closable)) && closable) {
        closable->Close();
      }
      m_device.reset();
    }

    m_packet_size = BLE_PACKET_SIZE;
    m_connected = false;
  }

  mutable std::mutex m_mutex;
  bool m_connected = false;
  size_t m_packet_size = BLE_PACKET_SIZE;

  ComPtr<wdb::IBluetoothLEDevice> m_device;
  ComPtr<wdg::IGattDeviceService> m_service;
  ComPtr<wdg::IGattDeviceService3> m_service3;
  ComPtr<wdg::IGattSession> m_session;
  ComPtr<wdg::IGattCharacteristic> m_rx;
  ComPtr<wdg::IGattCharacteristic3> m_rx3;
  ComPtr<wdg::IGattCharacteristic> m_tx;

  // Raw pointer because its lifetime is shared with the Windows runtime while
  // the subscription is live; reference counted by hand.
  NotificationQueue *m_notifications = nullptr;
  EventRegistrationToken m_value_token{};
};

std::mutex WinRtBleBackend::s_cache_mutex;
std::vector<BleDeviceInfo> WinRtBleBackend::s_cache;
std::chrono::steady_clock::time_point WinRtBleBackend::s_cache_time;
bool WinRtBleBackend::s_cache_valid = false;
unsigned WinRtBleBackend::s_empty_streak = 0;

} // namespace

void install_default_backend() {
  set_backend_factory([]() -> std::shared_ptr<BleBackend> {
    return std::make_shared<WinRtBleBackend>();
  });
  MDEBUG("BLE: WinRT backend installed");
}

} // namespace ble
} // namespace trezor
} // namespace hw

#else  // no Windows BLE support in this build

namespace hw {
namespace trezor {
namespace ble {

void install_default_backend() { /* no platform backend available */ }

} // namespace ble
} // namespace trezor
} // namespace hw

#endif
