#include "i_socket.hpp"
#include "bit_stream.hpp"
#include <atomic>

namespace socketwire
{
/*
  BitStream accessor stubs
  Implementation of helper functions used in ISocket::sendBitStream.
  They are separated out to avoid exposing BitStream internals and
  maintain loose coupling between the network layer and serialization.
*/

const std::uint8_t* bitstream_access_data(const BitStream& bs)
{
  return bs.getData();
}

std::size_t bitstream_access_size(const BitStream& bs)
{
  return bs.getSizeBytes();
}

// SocketFactoryRegistry
static std::atomic<ISocketFactory*> g_FactoryInstance{nullptr};

void SocketFactoryRegistry::setFactory(ISocketFactory* factory)
{
  g_FactoryInstance.store(factory, std::memory_order_release);
}

ISocketFactory* SocketFactoryRegistry::getFactory()
{
  return g_FactoryInstance.load(std::memory_order_acquire);
}

const char* to_string(SocketError error) noexcept
{
  switch (error)
  {
    case SocketError::None: return "None";
    case SocketError::WouldBlock: return "WouldBlock";
    case SocketError::Closed: return "Closed";
    case SocketError::System: return "System";
    case SocketError::InvalidParam: return "InvalidParam";
    case SocketError::NotBound: return "NotBound";
    case SocketError::Unsupported: return "Unsupported";
    case SocketError::Unknown: return "Unknown";
    default: return "Unknown";
  }
}

} // namespace socketwire
