#include "reliable_connection.hpp"
#include <cstring>
#include <algorithm>


namespace socketwire
{

// ---------------------------------- Helpers ----------------------------------
static void writePacketHeader(BitStream& bs, PacketType type, std::uint8_t channel, std::uint32_t sequence)
{
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(type));
  bs.write<std::uint8_t>(channel);
  bs.write<std::uint32_t>(sequence);
}

// Helper to read packet header
static bool readPacketHeader(BitStream& bs, PacketType& type, std::uint8_t& channel, std::uint32_t& sequence)
{
  std::uint8_t typeVal;
  bs.read<std::uint8_t>(typeVal);

  // Validate packet type range
  if (typeVal > static_cast<std::uint8_t>(PacketType::Ack))
    return false;

  type = static_cast<PacketType>(typeVal);
  bs.read<std::uint8_t>(channel);
  bs.read<std::uint32_t>(sequence);
  return true;
}


// ---------------------------------- ReliableConnection ----------------------------------
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
  seqWindowHigh = 0;
  seqWindowBits.reset();
  pendingReceived.clear();
}

void ReliableConnection::setRemoteAddress(const SocketAddress& addr, std::uint16_t port)
{
  remoteAddr = addr;
  remotePort = port;
}

bool ReliableConnection::sendReliable(const std::uint8_t channel, const void* data, std::size_t size)
{
  if (state != ConnectionState::Connected)
  return false;

  if (size > config.maxPacketSize)
  return false;

  std::uint32_t seq = getNextSequence();
  sendPacket(PacketType::Reliable, channel, data, size, seq);

  // Store for retransmission
  PendingPacket pending;
  pending.sequence = seq;
  pending.data.assign(static_cast<const std::uint8_t*>(data),
  static_cast<const std::uint8_t*>(data) + size);
  pending.sendTime = std::chrono::steady_clock::now();
  pending.channel = channel;
  pendingPackets.push_back(pending);

  return true;
}

bool ReliableConnection::sendUnreliable(const std::uint8_t channel, const void* data, std::size_t size)
{
  if (state != ConnectionState::Connected)
    return false;

  if (size > config.maxPacketSize)
    return false;

  sendPacket(PacketType::Unreliable, channel, data, size, 0);
  return true;
}

bool ReliableConnection::sendUnsequenced(const std::uint8_t channel, const void* data, std::size_t size)
{
  if (state != ConnectionState::Connected)
    return false;

  if (size > config.maxPacketSize)
    return false;

  std::uint32_t seq = getNextSequence();
  sendPacket(PacketType::Unsequenced, channel, data, size, seq);

  // Store for retransmission but don't require ordering
  PendingPacket pending;
  pending.sequence = seq;
  pending.data.assign(static_cast<const std::uint8_t*>(data),
                     static_cast<const std::uint8_t*>(data) + size);
  pending.sendTime = std::chrono::steady_clock::now();
  pending.channel = channel;
  pendingPackets.push_back(pending);

  return true;
}

bool ReliableConnection::sendReliable(const std::uint8_t channel, const BitStream& stream)
{
  return sendReliable(channel, stream.getData(), stream.getSizeBytes());
}

bool ReliableConnection::sendUnreliable(const std::uint8_t channel, const BitStream& stream)
{
  return sendUnreliable(channel, stream.getData(), stream.getSizeBytes());
}

bool ReliableConnection::sendUnsequenced(const std::uint8_t channel, const BitStream& stream)
{
  return sendUnsequenced(channel, stream.getData(), stream.getSizeBytes());
}


void ReliableConnection::update()
{
  auto now = std::chrono::steady_clock::now();

  // Retry pending packets
  retryPendingPackets();

  // Send periodic ping
  if (state == ConnectionState::Connected)
  {
    auto timeSincePing = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastPingTime).count();
    if (timeSincePing > config.pingIntervalMs)
    {
      sendPing();
      lastPingTime = now;
    }
  }

  checkTimeout();

  processPendingReliable();
}


void ReliableConnection::processPacket(const void* data, std::size_t size,
                                      const SocketAddress& from, std::uint16_t fromPort)
{
  if (size < 6) // Minimum packet size (type + channel + sequence)
    return;

  BitStream bs(static_cast<const std::uint8_t*>(data), size);

  PacketType type;
  std::uint8_t channel;
  std::uint32_t sequence;

  if (!readPacketHeader(bs, type, channel, sequence))
    return;

  lastReceiveTime = std::chrono::steady_clock::now();
  statsReceivedPackets++;

  // Handle different packet types
  switch (type)
  {
    case PacketType::Connect:
    {
      if (state == ConnectionState::Disconnected)
      {
        remoteAddr = from;
        remotePort = fromPort;
        state = ConnectionState::Connected;

        // Send accept
        sendPacket(PacketType::Accept, 0, nullptr, 0);

        if (eventHandler != nullptr)
          eventHandler->onConnected();
      }
      break;
    }

    case PacketType::Accept:
    {
      if (state == ConnectionState::Connecting)
      {
        state = ConnectionState::Connected;

        if (eventHandler != nullptr)
          eventHandler->onConnected();
      }
      break;
    }

    case PacketType::Disconnect:
    {
      if (eventHandler != nullptr)
        eventHandler->onDisconnected();

      state = ConnectionState::Disconnected;
      break;
    }

    case PacketType::Ping:
    {
      // Send pong with same sequence
      sendPacket(PacketType::Pong, 0, nullptr, 0, sequence);
      break;
    }

    case PacketType::Pong:
    {
      // Calculate RTT
      auto now = std::chrono::steady_clock::now();
      for (auto& pending : pendingPackets)
      {
        if (pending.sequence == sequence)
        {
          auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - pending.sendTime).count();
          rtt = rtt * 0.9f + elapsed * 0.1f; // Exponential moving average
          break;
        }
      }
      break;
    }

    case PacketType::Ack:
    {
      // Remove acknowledged packet from pending list
      auto it = std::find_if(pendingPackets.begin(), pendingPackets.end(),
        [sequence](const PendingPacket& p) { return p.sequence == sequence; });

      if (it != pendingPackets.end())
      {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->sendTime).count();
        rtt = rtt * 0.9f + elapsed * 0.1f;

        pendingPackets.erase(it);
      }
      break;
    }

    case PacketType::Reliable:
    {
      // Send ACK
      sendAck(sequence);

      // Check for duplicate
      if (isDuplicateSequence(sequence))
        return; // Already processed

      markSequenceReceived(sequence);

      // Read payload
      std::size_t payloadSize = size - 6; // subtract header
      std::vector<std::uint8_t> payload(payloadSize);
      bs.readBytes(payload.data(), payloadSize);

      // Store for ordered processing
      ReceivedPacket received;
      received.sequence = sequence;
      received.data = std::move(payload);
      received.channel = channel;
      pendingReceived[sequence] = std::move(received);

      break;
    }

    case PacketType::Unsequenced:
    {
      // Send ACK
      sendAck(sequence);

      // Check for duplicate
      if (isDuplicateSequence(sequence))
        return;

      markSequenceReceived(sequence);

      // Process immediately (no ordering required)
      std::size_t payloadSize = size - 6;
      std::vector<std::uint8_t> payload(payloadSize);
      bs.readBytes(payload.data(), payloadSize);

      if (eventHandler != nullptr)
        eventHandler->onReliableReceived(channel, payload.data(), payload.size());

      break;
    }

    case PacketType::Unreliable:
    {
      // No ACK needed
      std::size_t payloadSize = size - 6;
      std::vector<std::uint8_t> payload(payloadSize);
      bs.readBytes(payload.data(), payloadSize);

      if (eventHandler != nullptr)
        eventHandler->onUnreliableReceived(channel, payload.data(), payload.size());

      break;
    }

    default:
    {
      // Unknown packet type — ignore
      break;
    }
  }
}

void ReliableConnection::sendPacket(PacketType type, std::uint8_t channel,
                                   const void* data, std::size_t size,
                                   std::uint32_t sequence)
{
  BitStream bs;
  writePacketHeader(bs, type, channel, sequence);

  if (data != nullptr && size > 0)
    bs.writeBytes(data, size);

  socket->sendTo(bs.getData(), bs.getSizeBytes(), remoteAddr, remotePort);
  lastSendTime = std::chrono::steady_clock::now();
  statsSentPackets++;
}

void ReliableConnection::sendAck(std::uint32_t sequence)
{
  sendPacket(PacketType::Ack, 0, nullptr, 0, sequence);
}

void ReliableConnection::sendPing()
{
  std::uint32_t seq = getNextSequence();
  sendPacket(PacketType::Ping, 0, nullptr, 0, seq);

  // Store as pending to measure RTT
  PendingPacket pending;
  pending.sequence = seq;
  pending.sendTime = std::chrono::steady_clock::now();
  pendingPackets.push_back(pending);
}


void ReliableConnection::processPendingReliable()
{
  // Process packets in order
  while (true)
  {
    auto it = pendingReceived.find(receiveSequence);
    if (it == pendingReceived.end())
      break; // Next expected packet not yet received

    if (eventHandler != nullptr)
    {
      eventHandler->onReliableReceived(it->second.channel,
                                      it->second.data.data(),
                                      it->second.data.size());
    }

    pendingReceived.erase(it);
    receiveSequence++;
  }
}


void ReliableConnection::retryPendingPackets()
{
  auto now = std::chrono::steady_clock::now();

  for (auto& pending : pendingPackets)
  {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - pending.sendTime).count();

    if (elapsed > config.retryTimeoutMs)
    {
      if (pending.retries >= config.maxRetries)
      {
        // Packet lost
        statsLostPackets++;
        continue;
      }

      // Resend
      BitStream bs;
      PacketType type = pending.data.empty() ? PacketType::Ping : PacketType::Reliable;
      writePacketHeader(bs, type, pending.channel, pending.sequence);

      if (!pending.data.empty())
        bs.writeBytes(pending.data.data(), pending.data.size());

      socket->sendTo(bs.getData(), bs.getSizeBytes(), remoteAddr, remotePort);

      pending.sendTime = now;
      pending.retries++;
      statsSentPackets++;
    }
  }

  // Remove packets that exceeded retry limit
  pendingPackets.erase(
    std::remove_if(pendingPackets.begin(), pendingPackets.end(),
      [this](const PendingPacket& p) { return p.retries >= config.maxRetries; }),
    pendingPackets.end()
  );
}

void ReliableConnection::checkTimeout()
{
  if (state != ConnectionState::Connected)
    return;

  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - lastReceiveTime).count();

  if (elapsed > config.disconnectTimeoutMs)
  {
    if (eventHandler != nullptr)
      eventHandler->onTimeout();

    disconnect();
  }
}

bool ReliableConnection::isDuplicateSequence(std::uint32_t seq) const
{
  // Sequence before the window base (too old) — treat as duplicate
  const std::uint32_t windowBase = seqWindowHigh - kSeqWindowSize;
  if (isSequenceNewer(windowBase, seq))
    return true;
  // Sequence newer than the highest seen — definitely not a duplicate
  if (isSequenceNewer(seq, seqWindowHigh))
    return false;
  // Within the window — check the bit
  return seqWindowBits[seq % kSeqWindowSize];
}

void ReliableConnection::markSequenceReceived(std::uint32_t seq)
{
  if (isSequenceNewer(seq, seqWindowHigh))
  {
    // Advance the window, clearing the newly exposed slots
    const std::uint32_t advance = seq + 1 - seqWindowHigh;
    if (advance >= kSeqWindowSize)
    {
      seqWindowBits.reset();
    }
    else
    {
      for (std::uint32_t i = 0; i < advance; ++i)
        seqWindowBits[(seqWindowHigh + i) % kSeqWindowSize] = false;
    }
    seqWindowHigh = seq + 1;
  }
  seqWindowBits[seq % kSeqWindowSize] = true;
}

/*static*/ bool ReliableConnection::isSequenceNewer(std::uint32_t s1, std::uint32_t s2)
{
  return ((s1 > s2) && (s1 - s2 <= 0x7FFFFFFF)) ||
         ((s1 < s2) && (s2 - s1 > 0x7FFFFFFF));
}

ReliableConnection::~ReliableConnection()
{
  // Don't call disconnect() which may trigger callbacks during destruction
  // Just clean up resources directly
  state = ConnectionState::Disconnected;
  pendingPackets.clear();
  seqWindowHigh = 0;
  seqWindowBits.reset();
  pendingReceived.clear();
}

// ---------------------------------- ConnectionManager ----------------------------------

ConnectionManager::ConnectionManager(ISocket* socket, const ReliableConnectionConfig& cfg)
  : socket(socket)
  , config(cfg)
{
}

ConnectionManager::~ConnectionManager()
{
  clients.clear();
  clientMap.clear();
}

void ConnectionManager::update()
{
  for (auto& client : clients)
  {
    if (client->connection != nullptr)
      client->connection->update();
  }

  // Remove disconnected clients
  std::erase_if(clients,
    [this](const std::unique_ptr<RemoteClient>& client) {
      if (client->connection->getState() == ConnectionState::Disconnected)
      {
        if (onClientDisconnected != nullptr)
          onClientDisconnected(client.get());

        auto key = makeAddressKey(client->address, client->port);
        clientMap.erase(key);

        return true;
      }
      return false;
    }
  );
}

void ConnectionManager::processPacket(const void* data, std::size_t size,
                                     const SocketAddress& from, std::uint16_t fromPort)
{
  RemoteClient* client = findOrCreateClient(from, fromPort);
  if (client != nullptr && client->connection != nullptr)
  {
    client->connection->processPacket(data, size, from, fromPort);
  }
}

void ConnectionManager::broadcastReliable(std::uint8_t channel, const void* data, std::size_t size)
{
  for (auto& client : clients)
  {
    if (client->connection != nullptr && client->connection->isConnected())
      client->connection->sendReliable(channel, data, size);
  }
}

void ConnectionManager::broadcastUnreliable(std::uint8_t channel, const void* data, std::size_t size)
{
  for (auto& client : clients)
  {
    if (client->connection != nullptr && client->connection->isConnected())
      client->connection->sendUnreliable(channel, data, size);
  }
}

std::vector<ConnectionManager::RemoteClient*> ConnectionManager::getConnections()
{
  std::vector<RemoteClient*> result;
  result.reserve(clients.size());
  for (auto& client : clients)
    result.push_back(client.get());
  return result;
}

ConnectionManager::RemoteClient* ConnectionManager::getConnection(const SocketAddress& addr, std::uint16_t port)
{
  auto key = makeAddressKey(addr, port);
  auto it = clientMap.find(key);
  return (it != clientMap.end()) ? it->second : nullptr;
}

ConnectionManager::RemoteClient* ConnectionManager::findOrCreateClient(const SocketAddress& addr, std::uint16_t port)
{
  auto key = makeAddressKey(addr, port);

  auto it = clientMap.find(key);
  if (it != clientMap.end())
    return it->second;

  // Create new client
  auto client = std::make_unique<RemoteClient>();
  client->address = addr;
  client->port = port;
  client->connection = std::make_unique<ReliableConnection>(socket, config);
  client->connection->setRemoteAddress(addr, port);
  client->connection->setHandler(eventHandler);

  RemoteClient* raw = client.get();
  clients.push_back(std::move(client));
  clientMap[key] = raw;

  return raw;
}

void ConnectionManager::removeClient(RemoteClient* client)
{
  auto key = makeAddressKey(client->address, client->port);
  clientMap.erase(key);

  auto it = std::find_if(clients.begin(), clients.end(),
    [client](const std::unique_ptr<RemoteClient>& c) { return c.get() == client; });
  if (it != clients.end())
    clients.erase(it);
}

std::string ConnectionManager::makeAddressKey(const SocketAddress& addr, std::uint16_t port)
{
  return makeConnectionKey(addr, port);
}

} // namespace socketwire