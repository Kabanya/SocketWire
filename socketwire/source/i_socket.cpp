#include "i_socket.hpp"
#include "bit_stream.hpp"

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
static ISocketFactory* g_FactoryInstance = nullptr;

void SocketFactoryRegistry::setFactory(ISocketFactory* factory)
{
  g_FactoryInstance = factory;
}

ISocketFactory* SocketFactoryRegistry::getFactory()
{
  return g_FactoryInstance;
}

} // namespace socketwire
