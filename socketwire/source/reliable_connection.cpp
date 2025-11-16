#include "reliable_connection.hpp"
#include <cstring>
#include <algorithm>


namespace socketwire
{

ReliableConnection::ReliableConnection(ISocket* socket, const ReliableConnectionConfig& cfg)
  : socket(socket)
  , config(cfg)
{
  lastSendTime = std::chrono::steady_clock::now();
  lastReceiveTime = std::chrono::steady_clock::now();
  lastPingTime = std::chrono::steady_clock::now();
}

void ReliableConnection::connect(const SocketAddress& addr, std::uint16_t port)
{
  remoteAddr = addr;
  remotePort = port;
  state = ConnectionState::Connecting;

  // Send connection request
  sendPacket(PacketType::Connect, 0, nullptr, 0);
}

void ReliableConnection::disconnect()
{
  if (state == ConnectionState::Connected || state == ConnectionState::Connecting)
  {
    sendPacket(PacketType::Disconnect, 0, nullptr, 0);
    state = ConnectionState::Disconnecting;

    if (eventHandler != nullptr)
      eventHandler->onDisconnected();
  }

  state = ConnectionState::Disconnected;
  pendingPackets.clear();
  receivedSequences.clear();
  pendingReceived.clear();
}

void ReliableConnection::setRemoteAddress(const SocketAddress& addr, std::uint16_t port)
{
  remoteAddr = addr;
  remotePort = port;
}


ReliableConnection::~ReliableConnection()
{
  disconnect();
}


}