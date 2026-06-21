#pragma once

/// DNS and local network interface helpers.

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "i_socket.hpp"

namespace socketwire {

class ThreadPool;

enum class AddressFamily : std::uint8_t {
  kAny,
  kIPv4,
  kIPv6,
};

struct ResolveHostResult {
  SocketError error = SocketError::kNone;
  std::vector<SocketAddress> addresses;

  [[nodiscard]] bool Succeeded() const { return error == SocketError::kNone; }
  [[nodiscard]] bool Failed() const { return error != SocketError::kNone; }
};

ResolveHostResult ResolveHost(
  std::string_view host, std::uint16_t port,
  AddressFamily family = AddressFamily::kAny);

using ResolveHostCallback = std::function<void(ResolveHostResult)>;

bool ResolveHostAsync(ThreadPool& pool, std::string host, std::uint16_t port,
                      AddressFamily family, ResolveHostCallback callback);

struct NetworkInterface {
  std::string name;
  std::uint32_t index = 0;
  bool isUp = false;
  bool isLoopback = false;
  bool supportsMulticast = false;
  std::vector<SocketAddress> addresses;
};

struct ListNetworkInterfacesResult {
  SocketError error = SocketError::kNone;
  std::vector<NetworkInterface> interfaces;

  [[nodiscard]] bool Succeeded() const { return error == SocketError::kNone; }
  [[nodiscard]] bool Failed() const { return error != SocketError::kNone; }
};

ListNetworkInterfacesResult ListNetworkInterfaces();

}  // namespace socketwire
