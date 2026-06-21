#include "socket_resolver.hpp"

#include <cerrno>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>

#include "socket_address_utils.hpp"
#include "thread_pool.hpp"

#if defined(__EMSCRIPTEN__)
#define SOCKETWIRE_RESOLVER_EMSCRIPTEN 1
#else
#define SOCKETWIRE_RESOLVER_EMSCRIPTEN 0
#endif

#if !SOCKETWIRE_PLATFORM_WINDOWS && !SOCKETWIRE_RESOLVER_EMSCRIPTEN && \
  !(defined(__ANDROID__) && defined(__ANDROID_API__) && __ANDROID_API__ < 24)
#define SOCKETWIRE_HAVE_GETIFADDRS 1
#else
#define SOCKETWIRE_HAVE_GETIFADDRS 0
#endif

#if SOCKETWIRE_PLATFORM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#if SOCKETWIRE_HAVE_GETIFADDRS
#include <ifaddrs.h>
#include <net/if.h>
#endif
#endif

namespace socketwire {
namespace {

#if SOCKETWIRE_PLATFORM_WINDOWS
class ResolverWsaInitializer {
public:
  ResolverWsaInitializer() {
    WSADATA wsa_data;
    initialized_ = WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0;
  }

  ~ResolverWsaInitializer() {
    if (initialized_) WSACleanup();
  }

  [[nodiscard]] bool IsInitialized() const { return initialized_; }

private:
  bool initialized_ = false;
};

bool EnsureWinsock() {
  static ResolverWsaInitializer initializer;
  return initializer.IsInitialized();
}
#endif

int ToNativeFamily(AddressFamily family) {
  switch (family) {
    case AddressFamily::kAny:
      return AF_UNSPEC;
    case AddressFamily::kIPv4:
      return AF_INET;
    case AddressFamily::kIPv6:
      return AF_INET6;
  }
  return -1;
}

SocketError MapGetAddrInfoError(int error) {
  switch (error) {
#if defined(EAI_AGAIN)
    case EAI_AGAIN:
      return SocketError::kWouldBlock;
#endif
#if defined(EAI_BADFLAGS)
    case EAI_BADFLAGS:
#endif
#if defined(EAI_FAMILY)
    case EAI_FAMILY:
#endif
#if defined(EAI_NONAME)
    case EAI_NONAME:
#endif
#if defined(EAI_SERVICE)
    case EAI_SERVICE:
#endif
      return SocketError::kInvalidParam;
    default:
      return SocketError::kSystem;
  }
}

SocketAddress AddressFromSockaddr(const sockaddr* addr) {
  sockaddr_storage storage{};
  if (addr->sa_family == AF_INET) {
    std::memcpy(&storage, addr, sizeof(sockaddr_in));
  } else if (addr->sa_family == AF_INET6) {
    std::memcpy(&storage, addr, sizeof(sockaddr_in6));
  }
  return detail::SocketAddressFromSockaddr(storage);
}

#if SOCKETWIRE_HAVE_GETIFADDRS
SocketError MapErrno(int e) {
  switch (e) {
    case EINVAL:
      return SocketError::kInvalidParam;
    default:
      return SocketError::kSystem;
  }
}
#endif

}  // namespace

ResolveHostResult ResolveHost(std::string_view host, std::uint16_t port,
                              AddressFamily family) {
  ResolveHostResult result;

  if (host.empty() || host.find('\0') != std::string_view::npos) {
    result.error = SocketError::kInvalidParam;
    return result;
  }

  const int native_family = ToNativeFamily(family);
  if (native_family == -1) {
    result.error = SocketError::kInvalidParam;
    return result;
  }

#if SOCKETWIRE_RESOLVER_EMSCRIPTEN
  (void)port;
  result.error = SocketError::kUnsupported;
  return result;
#else
#if SOCKETWIRE_PLATFORM_WINDOWS
  if (!EnsureWinsock()) {
    result.error = SocketError::kSystem;
    return result;
  }
#endif

  const std::string host_string(host);
  const std::string service = std::to_string(port);

  addrinfo hints{};
  hints.ai_family = native_family;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;

  addrinfo* addresses = nullptr;
  const int lookup_error =
    getaddrinfo(host_string.c_str(), service.c_str(), &hints, &addresses);
  if (lookup_error != 0) {
    result.error = MapGetAddrInfoError(lookup_error);
    return result;
  }

  for (const addrinfo* current = addresses; current != nullptr;
       current = current->ai_next) {
    if (current->ai_addr == nullptr) continue;
    if (current->ai_family != AF_INET && current->ai_family != AF_INET6) {
      continue;
    }
    result.addresses.push_back(AddressFromSockaddr(current->ai_addr));
  }

  freeaddrinfo(addresses);
  return result;
#endif
}

bool ResolveHostAsync(ThreadPool& pool, std::string host, std::uint16_t port,
                      AddressFamily family, ResolveHostCallback callback) {
  if (!callback) return false;

  return pool.Submit([host = std::move(host), port, family,
                      callback = std::move(callback)]() mutable {
    callback(ResolveHost(host, port, family));
  });
}

ListNetworkInterfacesResult ListNetworkInterfaces() {
  ListNetworkInterfacesResult result;

#if SOCKETWIRE_RESOLVER_EMSCRIPTEN
  result.error = SocketError::kUnsupported;
  return result;
#elif SOCKETWIRE_PLATFORM_WINDOWS
  if (!EnsureWinsock()) {
    result.error = SocketError::kSystem;
    return result;
  }

  ULONG buffer_size = 15 * 1024;
  std::vector<unsigned char> buffer(buffer_size);
  IP_ADAPTER_ADDRESSES* adapters =
    reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

  ULONG error = GetAdaptersAddresses(
    AF_UNSPEC,
    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
    nullptr, adapters, &buffer_size);
  if (error == ERROR_BUFFER_OVERFLOW) {
    buffer.resize(buffer_size);
    adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    error = GetAdaptersAddresses(
      AF_UNSPEC,
      GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
      nullptr, adapters, &buffer_size);
  }

  if (error != NO_ERROR) {
    result.error =
      error == ERROR_NOT_SUPPORTED ? SocketError::kUnsupported
                                   : SocketError::kSystem;
    return result;
  }

  for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    NetworkInterface iface;
    iface.name = adapter->AdapterName != nullptr ? adapter->AdapterName : "";
    iface.index = adapter->IfIndex != 0 ? adapter->IfIndex : adapter->Ipv6IfIndex;
    iface.isUp = adapter->OperStatus == IfOperStatusUp;
    iface.isLoopback = adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK;
    iface.supportsMulticast = (adapter->Flags & IP_ADAPTER_NO_MULTICAST) == 0;

    if (iface.name.empty()) {
      iface.name = "if" + std::to_string(iface.index);
    }

    for (auto* unicast = adapter->FirstUnicastAddress; unicast != nullptr;
         unicast = unicast->Next) {
      const sockaddr* addr = unicast->Address.lpSockaddr;
      if (addr == nullptr) continue;
      if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6) continue;
      iface.addresses.push_back(AddressFromSockaddr(addr));
    }

    if (!iface.addresses.empty()) {
      result.interfaces.push_back(std::move(iface));
    }
  }

  return result;
#else
#if !SOCKETWIRE_HAVE_GETIFADDRS
  result.error = SocketError::kUnsupported;
  return result;
#else
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) {
    result.error = MapErrno(errno);
    return result;
  }

  std::unordered_map<std::string, std::size_t> indices;
  for (const ifaddrs* current = list; current != nullptr; current = current->ifa_next) {
    if (current->ifa_name == nullptr || current->ifa_addr == nullptr) continue;
    const int family = current->ifa_addr->sa_family;
    if (family != AF_INET && family != AF_INET6) continue;

    const std::string name(current->ifa_name);
    auto position = indices.find(name);
    if (position == indices.end()) {
      NetworkInterface iface;
      iface.name = name;
      iface.index = if_nametoindex(name.c_str());
      iface.isUp = (current->ifa_flags & IFF_UP) != 0;
      iface.isLoopback = (current->ifa_flags & IFF_LOOPBACK) != 0;
      iface.supportsMulticast = (current->ifa_flags & IFF_MULTICAST) != 0;
      position = indices.emplace(name, result.interfaces.size()).first;
      result.interfaces.push_back(std::move(iface));
    }

    result.interfaces.at(position->second).addresses.push_back(
      AddressFromSockaddr(current->ifa_addr));
  }

  freeifaddrs(list);
  return result;
#endif
#endif
}

}  // namespace socketwire
