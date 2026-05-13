#include "reliable_connection.hpp"
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <array>
#include <limits>


namespace socketwire
{

// ---------------------------------- Helpers ----------------------------------
static constexpr std::size_t kPacketHeaderSize = 6;

static void writePacketHeader(BitStream& bs, PacketType type, std::uint8_t channel, std::uint32_t sequence)
{
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(type));
  bs.write<std::uint8_t>(channel);
  bs.write<std::uint32_t>(sequence);
}

static std::array<std::uint8_t, kPacketHeaderSize>
makePacketHeaderData(PacketType type, std::uint8_t channel, std::uint32_t sequence)
{
  std::array<std::uint8_t, kPacketHeaderSize> header{};
  header[0] = static_cast<std::uint8_t>(type);
  header[1] = channel;
  std::memcpy(header.data() + 2, &sequence, sizeof(sequence));
  return header;
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

bool ReliableConnection::connect(const SocketAddress& addr, std::uint16_t port)
{
  remoteAddr = addr;
  remotePort = port;

  if (secureMode())
  {
    if (!canUseCrypto() || !crypto::valid_public_key(config.crypto.expected_server_public_key))
    {
      state = ConnectionState::Disconnected;
      return false;
    }

    auto result = cryptoHandshake.start_client(config.crypto.localKeyPair,
                                             config.crypto.expected_server_public_key);
    if (!result.ok)
    {
      state = ConnectionState::Disconnected;
      return false;
    }

    BitStream clientHello;
    result = cryptoHandshake.write_client_hello(clientHello);
    if (!result.ok)
    {
      state = ConnectionState::Disconnected;
      return false;
    }

    state = ConnectionState::Connecting;
    if (!sendPacket(PacketType::Connect, 0, clientHello.getData(), clientHello.getSizeBytes()))
    {
      state = ConnectionState::Disconnected;
      return false;
    }
    return true;
  }

  state = ConnectionState::Connecting;

  // Send connection request
  return sendPacket(PacketType::Connect, 0, nullptr, 0);
}

void ReliableConnection::disconnect()
{
  if (state == ConnectionState::Connected || state == ConnectionState::Connecting)
  {
    (void)sendPacket(PacketType::Disconnect, 0, nullptr, 0);
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

  const std::size_t maxPayload = maxPayloadForPacket();

  if (maxPayload == 0)
    return false;

  if (size > maxPayload)
  {
    // Too large for one packet, split into Fragment packets.
    if (channel >= nextFragmentGroupId.size())
      return false;
    return sendFragmented(channel, data, size);
  }

  std::uint32_t seq = getNextSequence(channel);
  if (!sendPacket(PacketType::Reliable, channel, data, size, seq))
    return false;

  // Store for retransmission
  PendingPacket pending;
  pending.sequence = seq;
  if (data != nullptr && size > 0)
  {
    pending.data.assign(static_cast<const std::uint8_t*>(data),
                        static_cast<const std::uint8_t*>(data) + size);
  }
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

  const std::size_t maxPayload = maxPayloadForPacket();
  if (maxPayload == 0 || size > maxPayload)
    return false;

  if (!sendPacket(PacketType::Unreliable, channel, data, size, 0))
    return false;
  return true;
}

bool ReliableConnection::sendUnsequenced(const std::uint8_t channel, const void* data, std::size_t size)
{
  if (state != ConnectionState::Connected)
    return false;

  const std::size_t maxPayload = maxPayloadForPacket();
  if (maxPayload == 0 || size > maxPayload)
    return false;

  std::uint32_t seq = getNextSequence(channel);
  if (!sendPacket(PacketType::Unsequenced, channel, data, size, seq))
    return false;

  // Store for retransmission but don't require ordering
  PendingPacket pending;
  pending.sequence = seq;
  if (data != nullptr && size > 0)
  {
    pending.data.assign(static_cast<const std::uint8_t*>(data),
                        static_cast<const std::uint8_t*>(data) + size);
  }
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
  if (size < kPacketHeaderSize)
    return;

  const auto* packetData = static_cast<const std::uint8_t*>(data);
  BitStream bs(packetData, size);

  PacketType type;
  std::uint8_t channel;
  std::uint32_t sequence;

  if (!readPacketHeader(bs, type, channel, sequence))
    return;

  auto headerData = makePacketHeaderData(type, channel, sequence);
  const std::uint8_t* payloadData = packetData + kPacketHeaderSize;
  std::size_t payloadSize = size - kPacketHeaderSize;
  BitStream decryptedPayload;

  if (secureMode() && type != PacketType::Connect && type != PacketType::Accept)
  {
    if (!cryptoReady)
      return;

    const auto decryptResult = cryptoContext.decrypt(payloadData,
                                                     payloadSize,
                                                     headerData.data(),
                                                     headerData.size(),
                                                     decryptedPayload);
    if (!decryptResult.ok)
      return;

    payloadData = decryptedPayload.getData();
    payloadSize = decryptedPayload.getSizeBytes();
  }

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

        if (secureMode())
        {
          if (!canUseCrypto())
            return;

          auto result = cryptoHandshake.start_server(config.crypto.localKeyPair);
          if (!result.ok)
            return;

          result = cryptoHandshake.process_client_hello(payloadData, payloadSize);
          if (!result.ok)
          {
            state = ConnectionState::Disconnected;
            return;
          }

          cryptoContext = cryptoHandshake.create_server_crypto_context();
          cryptoReady = cryptoContext.is_ready();
          if (!cryptoReady)
          {
            state = ConnectionState::Disconnected;
            return;
          }

          BitStream serverHello;
          result = cryptoHandshake.write_server_hello(serverHello);
          if (!result.ok)
          {
            cryptoReady = false;
            state = ConnectionState::Disconnected;
            return;
          }

          state = ConnectionState::Connected;
          (void)sendPacket(PacketType::Accept, 0, serverHello.getData(), serverHello.getSizeBytes());
        }
        else
        {
          state = ConnectionState::Connected;
          (void)sendPacket(PacketType::Accept, 0, nullptr, 0);
        }

        if (eventHandler != nullptr)
          eventHandler->onConnected();
      }
      break;
    }

    case PacketType::Accept:
    {
      if (state == ConnectionState::Connecting)
      {
        if (secureMode())
        {
          auto result = cryptoHandshake.process_server_hello(payloadData, payloadSize);
          if (!result.ok)
          {
            cryptoReady = false;
            state = ConnectionState::Disconnected;
            return;
          }

          cryptoContext = cryptoHandshake.create_client_crypto_context();
          cryptoReady = cryptoContext.is_ready();
          if (!cryptoReady)
          {
            state = ConnectionState::Disconnected;
            return;
          }
        }

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
      (void)sendPacket(PacketType::Pong, 0, nullptr, 0, sequence);
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
          rtt = rtt * 0.9f + static_cast<float>(elapsed) * 0.1f; // Exponential moving average
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
        rtt = rtt * 0.9f + static_cast<float>(elapsed) * 0.1f;

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

      std::vector<std::uint8_t> payload(payloadSize);
      if (payloadSize > 0)
        std::memcpy(payload.data(), payloadData, payloadSize);

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

      std::vector<std::uint8_t> payload(payloadSize);
      if (payloadSize > 0)
        std::memcpy(payload.data(), payloadData, payloadSize);

      if (eventHandler != nullptr)
        eventHandler->onReliableReceived(channel, payload.data(), payload.size());

      break;
    }

    case PacketType::Unreliable:
    {
      // No ACK needed
      std::vector<std::uint8_t> payload(payloadSize);
      if (payloadSize > 0)
        std::memcpy(payload.data(), payloadData, payloadSize);

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
      if (payloadSize < kFragMeta)
        break;

      BitStream fragBs(payloadData, payloadSize);
      std::uint16_t groupId = 0, fragIndex = 0, fragTotal = 0;
      fragBs.readBytes(&groupId, 2);
      fragBs.readBytes(&fragIndex, 2);
      fragBs.readBytes(&fragTotal, 2);

      const std::size_t fragmentPayloadSize = payloadSize - kFragMeta;
      std::vector<std::uint8_t> payload(fragmentPayloadSize);
      if (fragmentPayloadSize > 0)
        fragBs.readBytes(payload.data(), fragmentPayloadSize);

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
        full.reserve(fg.total * fragmentPayloadSize + fragmentPayloadSize);
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

bool ReliableConnection::sendPacket(PacketType type, std::uint8_t channel,
                                   const void* data, std::size_t size,
                                   std::uint32_t sequence)
{
  BitStream bs;
  writePacketHeader(bs, type, channel, sequence);

  if (shouldEncryptPacket(type))
  {
    const auto headerData = makePacketHeaderData(type, channel, sequence);
    BitStream encrypted;
    const auto* payload = static_cast<const std::uint8_t*>(data);
    const auto result = cryptoContext.encrypt(payload,
                                              size,
                                              headerData.data(),
                                              headerData.size(),
                                              encrypted);
    if (!result.ok)
      return false;
    bs.writeBytes(encrypted.getData(), encrypted.getSizeBytes());
  }
  else if (data != nullptr && size > 0)
  {
    bs.writeBytes(data, size);
  }

  socket->sendTo(bs.getData(), bs.getSizeBytes(), remoteAddr, remotePort);
  lastSendTime = std::chrono::steady_clock::now();
  statsSentPackets++;
  return true;
}

bool ReliableConnection::sendFragmented(std::uint8_t channel, const void* data, std::size_t size)
{
  if (channel >= nextFragmentGroupId.size())
    return false;

  const std::size_t maxFragPayload = maxPayloadForPacket(kFragmentHeaderExtra);
  if (maxFragPayload == 0)
    return false;
  const std::size_t fragTotalSize = (size + maxFragPayload - 1) / maxFragPayload;
  if (fragTotalSize > std::numeric_limits<std::uint16_t>::max())
    return false;

  const std::uint16_t fragTotal = static_cast<std::uint16_t>(fragTotalSize);
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
    if (!sendPacket(PacketType::Fragment, channel, fragPayload.data(), fragPayload.size(), seq))
      return false;

    // Store for retransmission
    PendingPacket pending;
    pending.sequence = seq;
    pending.data = std::move(fragPayload);
    pending.sendTime = std::chrono::steady_clock::now();
    pending.channel = channel;
    pending.type = PacketType::Fragment;
    pendingPackets.push_back(std::move(pending));
  }

  return true;
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
      return elapsed > static_cast<std::int64_t>(config.fragmentTimeoutMs);
    });
  }
}

bool ReliableConnection::canUseCrypto() const
{
  if (!secureMode())
    return true;

  const auto initResult = crypto::initialize();
  return initResult.ok &&
         crypto::cipher_suite_supported(crypto::CipherSuite::XChaCha20Poly1305) &&
         config.crypto.localKeyPair.valid();
}

bool ReliableConnection::shouldEncryptPacket(PacketType type) const
{
  return secureMode() &&
         cryptoReady &&
         type != PacketType::Connect &&
         type != PacketType::Accept;
}

std::size_t ReliableConnection::cryptoEnvelopeOverhead() const
{
  return secureMode() ? (crypto::k_nonce_size + crypto::k_mac_size) : 0;
}

std::size_t ReliableConnection::maxPayloadForPacket(std::size_t headerExtra) const
{
  const std::size_t overhead = kPacketHeaderSize + headerExtra + cryptoEnvelopeOverhead();
  if (config.maxPacketSize < overhead)
    return 0;
  return config.maxPacketSize - overhead;
}

void ReliableConnection::sendAck(std::uint32_t sequence)
{
  (void)sendPacket(PacketType::Ack, 0, nullptr, 0, sequence);
}

void ReliableConnection::sendPing()
{
  std::uint32_t seq = getNextSequence(0);
  if (!sendPacket(PacketType::Ping, 0, nullptr, 0, seq))
    return;

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

      const void* payload = pending.data.empty() ? nullptr : pending.data.data();
      if (sendPacket(pending.type, pending.channel, payload, pending.data.size(), pending.sequence))
      {
        pending.sendTime = now;
        pending.retries++;
      }
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
  {
    client->connection->processPacket(data, size, from, fromPort);
    if (!isKnown && client->connection->getState() == ConnectionState::Disconnected)
      removeClient(client);
  }
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
