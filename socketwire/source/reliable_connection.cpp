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
  if (typeVal > static_cast<std::uint8_t>(PacketType::Fragment))
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
  const auto n = static_cast<std::size_t>(cfg.numChannels);
  sendSequence.assign(n, 0);
  receiveSequence.assign(n, 0);
  seqWindowHigh.assign(n, 0);
  seqWindowBits.resize(n);
  pendingReceived.resize(n);
  nextFragmentGroupId.assign(n, 0);
  fragmentGroups.resize(n);

  // Initialise congestion control window
  currentSendWindow = (config.sendWindowSize > 0) ? config.sendWindowSize : 0;
  ssthresh = (config.sendWindowSize > 0) ? std::max(1u, config.sendWindowSize / 2) : 32;

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
  for (auto& h : seqWindowHigh) h = 0;
  for (auto& b : seqWindowBits) b.reset();
  for (auto& pr : pendingReceived) pr.clear();
  for (auto& fg : fragmentGroups) fg.clear();
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

  // Congestion window check (only when send-window limiting is enabled)
  if (currentSendWindow > 0 && pendingPackets.size() >= currentSendWindow)
    return false; // window full — caller must retry later

  // Maximum payload for a single Reliable packet (subtract base 6-byte header)
  const std::size_t maxPayload = (config.maxPacketSize > 6) ? (config.maxPacketSize - 6) : 512;

  if (size > maxPayload)
  {
    // Too large for one packet — split into Fragment packets
    if (channel < nextFragmentGroupId.size())
      sendFragmented(channel, data, size);
    return true;
  }

  std::uint32_t seq = getNextSequence(channel);
  sendPacket(PacketType::Reliable, channel, data, size, seq);

  // Store for retransmission
  PendingPacket pending;
  pending.sequence = seq;
  pending.data.assign(static_cast<const std::uint8_t*>(data),
  static_cast<const std::uint8_t*>(data) + size);
  pending.sendTime = std::chrono::steady_clock::now();
  pending.channel = channel;
  pending.type = PacketType::Reliable;
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

  std::uint32_t seq = getNextSequence(channel);
  sendPacket(PacketType::Unsequenced, channel, data, size, seq);

  // Store for retransmission but don't require ordering
  PendingPacket pending;
  pending.sequence = seq;
  pending.data.assign(static_cast<const std::uint8_t*>(data),
                     static_cast<const std::uint8_t*>(data) + size);
  pending.sendTime = std::chrono::steady_clock::now();
  pending.channel = channel;
  pending.type = PacketType::Unsequenced;
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

  cleanupFragments();
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
      if (isDuplicateSequence(channel, sequence))
        return; // Already processed

      markSequenceReceived(channel, sequence);

      // Read payload
      std::size_t payloadSize = size - 6; // subtract header
      std::vector<std::uint8_t> payload(payloadSize);
      bs.readBytes(payload.data(), payloadSize);

      // Store for ordered processing
      ReceivedPacket received;
      received.sequence = sequence;
      received.data = std::move(payload);
      received.channel = channel;
      if (channel < pendingReceived.size())
        pendingReceived[channel][sequence] = std::move(received);

      break;
    }

    case PacketType::Unsequenced:
    {
      // Send ACK
      sendAck(sequence);

      // Check for duplicate
      if (isDuplicateSequence(channel, sequence))
        return;

      markSequenceReceived(channel, sequence);

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

    case PacketType::Fragment:
    {
      // ACK each fragment individually so it can be retried if lost
      sendAck(sequence);

      if (isDuplicateSequence(channel, sequence))
        break;
      markSequenceReceived(channel, sequence);

      // Fragment metadata is embedded in the payload after the base header:
      // [groupId:2][fragIndex:2][fragTotal:2][data...]
      static constexpr std::size_t kFragMeta = 6;
      if (size < 6 + kFragMeta)
        break;

      std::uint16_t groupId = 0, fragIndex = 0, fragTotal = 0;
      bs.readBytes(&groupId, 2);
      bs.readBytes(&fragIndex, 2);
      bs.readBytes(&fragTotal, 2);

      const std::size_t payloadSize = size - 6 - kFragMeta;
      std::vector<std::uint8_t> payload(payloadSize);
      if (payloadSize > 0)
        bs.readBytes(payload.data(), payloadSize);

      if (channel >= fragmentGroups.size() || fragTotal == 0 || fragIndex >= fragTotal)
        break;

      auto& groups = fragmentGroups[channel];
      auto it = groups.find(groupId);
      if (it == groups.end())
      {
        FragmentGroup fg;
        fg.total = fragTotal;
        fg.pieces.resize(fragTotal);
        fg.firstReceived = std::chrono::steady_clock::now();
        fg.channel = channel;
        it = groups.emplace(groupId, std::move(fg)).first;
      }

      FragmentGroup& fg = it->second;
      if (fragIndex < fg.pieces.size() && !fg.pieces[fragIndex].has_value())
      {
        fg.pieces[fragIndex] = std::move(payload);
        ++fg.receivedCount;
      }

      if (fg.receivedCount == fg.total)
      {
        // All fragments received — reassemble and deliver
        std::vector<std::uint8_t> full;
        full.reserve(fg.total * payloadSize + payloadSize);
        for (auto& piece : fg.pieces)
          if (piece.has_value())
            full.insert(full.end(), piece->begin(), piece->end());

        if (eventHandler != nullptr)
          eventHandler->onReliableReceived(channel, full.data(), full.size());

        groups.erase(it);
      }
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

void ReliableConnection::sendFragmented(std::uint8_t channel, const void* data, std::size_t size)
{
  // Max payload per fragment: maxPacketSize − base header (6) − frag metadata (6)
  const std::size_t maxFragPayload = (config.maxPacketSize > 12) ? (config.maxPacketSize - 12) : 64;
  const std::uint16_t fragTotal = static_cast<std::uint16_t>((size + maxFragPayload - 1) / maxFragPayload);
  const std::uint16_t groupId = nextFragmentGroupId[channel]++;
  const auto* src = static_cast<const std::uint8_t*>(data);

  for (std::uint16_t i = 0; i < fragTotal; ++i)
  {
    const std::size_t offset = i * maxFragPayload;
    const std::size_t fragSize = std::min(maxFragPayload, size - offset);

    // Layout: [groupId:2][fragIndex:2][fragTotal:2][payload...]
    std::vector<std::uint8_t> fragPayload(6 + fragSize);
    std::memcpy(fragPayload.data() + 0, &groupId, 2);
    std::memcpy(fragPayload.data() + 2, &i, 2);
    std::memcpy(fragPayload.data() + 4, &fragTotal, 2);
    std::memcpy(fragPayload.data() + 6, src + offset, fragSize);

    const std::uint32_t seq = getNextSequence(channel);
    sendPacket(PacketType::Fragment, channel, fragPayload.data(), fragPayload.size(), seq);

    // Store for retransmission
    PendingPacket pending;
    pending.sequence = seq;
    pending.data = std::move(fragPayload);
    pending.sendTime = std::chrono::steady_clock::now();
    pending.channel = channel;
    pending.type = PacketType::Fragment;
    pendingPackets.push_back(std::move(pending));
  }
}

void ReliableConnection::cleanupFragments()
{
  auto now = std::chrono::steady_clock::now();
  for (auto& chGroups : fragmentGroups)
  {
    std::erase_if(chGroups, [&](const auto& kv)
    {
      const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - kv.second.firstReceived).count();
      return elapsed > static_cast<long long>(config.fragmentTimeoutMs);
    });
  }
}

void ReliableConnection::sendAck(std::uint32_t sequence)
{
  sendPacket(PacketType::Ack, 0, nullptr, 0, sequence);
}

void ReliableConnection::sendPing()
{
  std::uint32_t seq = getNextSequence(0);
  sendPacket(PacketType::Ping, 0, nullptr, 0, seq);

  // Store as pending to measure RTT
  PendingPacket pending;
  pending.sequence = seq;
  pending.sendTime = std::chrono::steady_clock::now();
  pending.type = PacketType::Ping;
  pendingPackets.push_back(pending);
}


void ReliableConnection::processPendingReliable()
{
  // Process packets in order for each channel independently
  for (std::uint8_t ch = 0; ch < static_cast<std::uint8_t>(receiveSequence.size()); ++ch)
  {
    while (true)
    {
      auto it = pendingReceived[ch].find(receiveSequence[ch]);
      if (it == pendingReceived[ch].end())
        break; // Next expected packet not yet received

      if (eventHandler != nullptr)
      {
        eventHandler->onReliableReceived(it->second.channel,
                                        it->second.data.data(),
                                        it->second.data.size());
      }

      pendingReceived[ch].erase(it);
      receiveSequence[ch]++;
    }
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
      writePacketHeader(bs, pending.type, pending.channel, pending.sequence);

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

bool ReliableConnection::isDuplicateSequence(std::uint8_t channel, std::uint32_t seq) const
{
  if (channel >= seqWindowHigh.size()) return false;
  // Sequence before the window base (too old) — treat as duplicate
  const std::uint32_t windowBase = seqWindowHigh[channel] - kSeqWindowSize;
  if (isSequenceNewer(windowBase, seq))
    return true;
  // Sequence newer than the highest seen — definitely not a duplicate
  if (isSequenceNewer(seq, seqWindowHigh[channel]))
    return false;
  // Within the window — check the bit
  return seqWindowBits[channel][seq % kSeqWindowSize];
}

void ReliableConnection::markSequenceReceived(std::uint8_t channel, std::uint32_t seq)
{
  if (channel >= seqWindowHigh.size()) return;
  if (isSequenceNewer(seq, seqWindowHigh[channel]))
  {
    // Advance the window, clearing the newly exposed slots
    const std::uint32_t advance = seq + 1 - seqWindowHigh[channel];
    if (advance >= kSeqWindowSize)
    {
      seqWindowBits[channel].reset();
    }
    else
    {
      for (std::uint32_t i = 0; i < advance; ++i)
        seqWindowBits[channel][(seqWindowHigh[channel] + i) % kSeqWindowSize] = false;
    }
    seqWindowHigh[channel] = seq + 1;
  }
  seqWindowBits[channel][seq % kSeqWindowSize] = true;
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
  for (auto& h : seqWindowHigh) h = 0;
  for (auto& b : seqWindowBits) b.reset();
  for (auto& pr : pendingReceived) pr.clear();
  for (auto& fg : fragmentGroups) fg.clear();
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
  // Check whether the sender is already a known client
  const bool isKnown = (clientMap.find(makeAddressKey(from, fromPort)) != clientMap.end());

  if (!isKnown)
  {
    // Peek at the packet type (byte 0). Only accept Connect packets from new senders,
    // and only at the configured maximum rate.
    if (size < 1)
      return;
    const auto typeVal = static_cast<const std::uint8_t*>(data)[0];
    if (typeVal != static_cast<std::uint8_t>(PacketType::Connect))
      return; // Ignore non-Connect packets from unknown senders
    if (!handshakeAllowed())
      return; // Rate limit exceeded — silently drop
  }

  RemoteClient* client = findOrCreateClient(from, fromPort);
  if (client != nullptr && client->connection != nullptr)
    client->connection->processPacket(data, size, from, fromPort);
}

bool ConnectionManager::handshakeAllowed()
{
  if (config.maxHandshakesPerSecond == 0)
    return true; // unlimited

  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - connectWindowStart).count();

  if (elapsed >= 1000)
  {
    // Start a fresh 1-second window
    connectWindowStart = now;
    connectWindowCount = 0;
  }

  if (connectWindowCount >= config.maxHandshakesPerSecond)
    return false;

  ++connectWindowCount;
  return true;
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

void ReliableConnection::tick()
{
  std::vector<std::uint8_t> buf(config.maxPacketSize);
  SocketAddress fromAddr{};
  std::uint16_t fromPort = 0;

  while (true)
  {
    SocketResult res = socket->receive(buf.data(), buf.size(), fromAddr, fromPort);
    if (res.failed())
      break; // WouldBlock or error — no more packets
    if (res.bytes > 0)
      processPacket(buf.data(), static_cast<std::size_t>(res.bytes), fromAddr, fromPort);
  }

  update();
}

void ConnectionManager::tick()
{
  std::vector<std::uint8_t> buf(config.maxPacketSize);
  SocketAddress fromAddr{};
  std::uint16_t fromPort = 0;

  while (true)
  {
    SocketResult res = socket->receive(buf.data(), buf.size(), fromAddr, fromPort);
    if (res.failed())
      break; // WouldBlock or error — no more packets
    if (res.bytes > 0)
      processPacket(buf.data(), static_cast<std::size_t>(res.bytes), fromAddr, fromPort);
  }

  update();
}

} // namespace socketwire