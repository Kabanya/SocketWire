#include "i_socket.hpp"

#include <atomic>

namespace socketwire {
namespace {

std::atomic<ISocketFactory*>& FactoryInstance() {
  static std::atomic<ISocketFactory*> instance{nullptr};
  return instance;
}

}  // namespace

void SocketFactoryRegistry::SetFactory(ISocketFactory* factory) {
  FactoryInstance().store(factory);
}

ISocketFactory* SocketFactoryRegistry::GetFactory() {
  return FactoryInstance().load();
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
