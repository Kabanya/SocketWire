#include "i_socket.hpp"

#include <atomic>

#include "bit_stream.hpp"

namespace socketwire {
/*
  BitStream accessor stubs
  Implementation of helper functions used in ISocket::sendBitStream.
  They are separated out to avoid exposing BitStream internals and
  maintain loose coupling between the network layer and serialization.
*/

const std::uint8_t* BitstreamAccessData(const BitStream& bs) {
  return bs.GetData();
}

std::size_t BitstreamAccessSize(const BitStream& bs) {
  return bs.GetSizeBytes();
}

// SocketFactoryRegistry
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
static std::atomic<ISocketFactory*> g_factory_instance{nullptr};

void SocketFactoryRegistry::SetFactory(ISocketFactory* factory) {
  g_factory_instance.store(factory, std::memory_order_release);
}

ISocketFactory* SocketFactoryRegistry::GetFactory() {
  return g_factory_instance.load(std::memory_order_acquire);
}

const char* ToString(SocketError error) noexcept {
  switch (error) {
    case SocketError::kNone:
      return "None";
    case SocketError::kWouldBlock:
      return "WouldBlock";
    case SocketError::kClosed:
      return "Closed";
    case SocketError::kSystem:
      return "System";
    case SocketError::kInvalidParam:
      return "InvalidParam";
    case SocketError::kNotBound:
      return "NotBound";
    case SocketError::kUnsupported:
      return "Unsupported";
    default:
      return "Unknown";
  }
}

}  // namespace socketwire
