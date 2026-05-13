#include "reliable_connection.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

namespace socketwire {

// ---------------------------------- Helpers ----------------------------------
static constexpr std::size_t kPacketHeaderSize = 6;

static void WritePacketHeader(BitStream& bs, PacketType type,
                              std::uint8_t channel, std::uint32_t sequence) {
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(type));
  bs.Write<std::uint8_t>(channel);
  bs.Write<std::uint32_t>(sequence);
}

static std::array<std::uint8_t, kPacketHeaderSize> MakePacketHeaderData(
    PacketType type, std::uint8_t channel, std::uint32_t sequence) {
  std::array<std::uint8_t, kPacketHeaderSize> header{};
  header.at(0) = static_cast<std::uint8_t>(type);
  header.at(1) = channel;
  std::memcpy(header.data() + 2, &sequence, sizeof(sequence));
  return header;
}

// Helper to read packet header
static bool ReadPacketHeader(BitStream& bs, PacketType& type,
                             std::uint8_t& channel, std::uint32_t& sequence) {
  std::uint8_t type_val = 0;
  bs.Read<std::uint8_t>(type_val);

  // Validate packet type range
  if (type_val > static_cast<std::uint8_t>(PacketType::kFragment)) return false;

  type = static_cast<PacketType>(type_val);
  bs.Read<std::uint8_t>(channel);
  bs.Read<std::uint32_t>(sequence);
  return true;
}

// ---------------------------------- ReliableConnection
// ----------------------------------
ReliableConnection::ReliableConnection(ISocket* socket,
                                       const ReliableConnectionConfig& cfg)
    : socket(socket),
      config(cfg),
      currentSendWindow((config.sendWindowSize > 0) ? config.sendWindowSize
                                                    : 0) {
  const auto n = static_cast<std::size_t>(cfg.numChannels);
  sendSequence.assign(n, 0);
  receiveSequence.assign(n, 0);
  seqWindowHigh.assign(n, 0);
  seqWindowBits.resize(n);
  pendingReceived.resize(n);
  nextFragmentGroupId.assign(n, 0);
  fragmentGroups.resize(n);

  // Initialise congestion control window
  ssthresh = (config.sendWindowSize > 0)
                 ? std::max(1u, config.sendWindowSize / 2)
                 : 32;

  lastSendTime = std::chrono::steady_clock::now();
  lastReceiveTime = std::chrono::steady_clock::now();
  lastPingTime = std::chrono::steady_clock::now();
}

bool ReliableConnection::Connect(const SocketAddress& addr,
                                 std::uint16_t port) {
  remoteAddr = addr;
  remotePort = port;

  if (SecureMode()) {
    if (!CanUseCrypto() ||
        !crypto::ValidPublicKey(config.crypto.expected_server_public_key)) {
      state = ConnectionState::kDisconnected;
      return false;
    }

    auto result = cryptoHandshake.StartClient(
        config.crypto.localKeyPair, config.crypto.expected_server_public_key);
    if (!result.ok) {
      state = ConnectionState::kDisconnected;
      return false;
    }

    BitStream client_hello;
    result = cryptoHandshake.WriteClientHello(client_hello);
    if (!result.ok) {
      state = ConnectionState::kDisconnected;
      return false;
    }

    state = ConnectionState::kConnecting;
    if (!SendPacket(PacketType::kConnect, 0, client_hello.GetData(),
                    client_hello.GetSizeBytes())) {
      state = ConnectionState::kDisconnected;
      return false;
    }
    return true;
  }

  state = ConnectionState::kConnecting;

  // Send connection request
  return SendPacket(PacketType::kConnect, 0, nullptr, 0);
}

void ReliableConnection::Disconnect() {
  if (state == ConnectionState::kConnected ||
      state == ConnectionState::kConnecting) {
    (void)SendPacket(PacketType::kDisconnect, 0, nullptr, 0);
    state = ConnectionState::kDisconnecting;

    if (eventHandler != nullptr) eventHandler->OnDisconnected();
  }

  state = ConnectionState::kDisconnected;
  pendingPackets.clear();
  for (auto& h : seqWindowHigh) h = 0;
  for (auto& b : seqWindowBits) b.reset();
  for (auto& pr : pendingReceived) pr.clear();
  for (auto& fg : fragmentGroups) fg.clear();
}

void ReliableConnection::SetRemoteAddress(const SocketAddress& addr,
                                          std::uint16_t port) {
  remoteAddr = addr;
  remotePort = port;
}

bool ReliableConnection::SendReliable(const std::uint8_t channel,
                                      const void* data, std::size_t size) {
  if (state != ConnectionState::kConnected) return false;

  // Congestion window check (only when send-window limiting is enabled)
  if (currentSendWindow > 0 && pendingPackets.size() >= currentSendWindow) {
    return false;  // window full — caller must retry later
  }

  const std::size_t max_payload = MaxPayloadForPacket();

  if (max_payload == 0) return false;

  if (size > max_payload) {
    // Too large for one packet, split into Fragment packets.
    if (channel >= nextFragmentGroupId.size()) return false;
    return SendFragmented(channel, data, size);
  }

  std::uint32_t seq = GetNextSequence(channel);
  if (!SendPacket(PacketType::kReliable, channel, data, size, seq)) {
    return false;
  }

  // Store for retransmission
  PendingPacket pending;
  pending.sequence = seq;
  if (data != nullptr && size > 0) {
    pending.data.assign(static_cast<const std::uint8_t*>(data),
                        static_cast<const std::uint8_t*>(data) + size);
  }
  pending.sendTime = std::chrono::steady_clock::now();
  pending.channel = channel;
  pending.type = PacketType::kReliable;
  pendingPackets.push_back(pending);

  return true;
}

bool ReliableConnection::SendUnreliable(const std::uint8_t channel,
                                        const void* data, std::size_t size) {
  if (state != ConnectionState::kConnected) return false;

  const std::size_t max_payload = MaxPayloadForPacket();
  if (max_payload == 0 || size > max_payload) return false;

  if (!SendPacket(PacketType::kUnreliable, channel, data, size, 0)) {
    return false;
  }
  return true;
}

bool ReliableConnection::SendUnsequenced(const std::uint8_t channel,
                                         const void* data, std::size_t size) {
  if (state != ConnectionState::kConnected) return false;

  const std::size_t max_payload = MaxPayloadForPacket();
  if (max_payload == 0 || size > max_payload) return false;

  std::uint32_t seq = GetNextSequence(channel);
  if (!SendPacket(PacketType::kUnsequenced, channel, data, size, seq)) {
    return false;
  }

  // Store for retransmission but don't require ordering
  PendingPacket pending;
  pending.sequence = seq;
  if (data != nullptr && size > 0) {
    pending.data.assign(static_cast<const std::uint8_t*>(data),
                        static_cast<const std::uint8_t*>(data) + size);
  }
  pending.sendTime = std::chrono::steady_clock::now();
  pending.channel = channel;
  pending.type = PacketType::kUnsequenced;
  pendingPackets.push_back(pending);

  return true;
}

bool ReliableConnection::SendReliable(const std::uint8_t channel,
                                      const BitStream& stream) {
  return SendReliable(channel, stream.GetData(), stream.GetSizeBytes());
}

bool ReliableConnection::SendUnreliable(const std::uint8_t channel,
                                        const BitStream& stream) {
  return SendUnreliable(channel, stream.GetData(), stream.GetSizeBytes());
}

bool ReliableConnection::SendUnsequenced(const std::uint8_t channel,
                                         const BitStream& stream) {
  return SendUnsequenced(channel, stream.GetData(), stream.GetSizeBytes());
}

void ReliableConnection::Update() {
  auto now = std::chrono::steady_clock::now();

  // Retry pending packets
  RetryPendingPackets();

  // Send periodic ping
  if (state == ConnectionState::kConnected) {
    auto time_since_ping =
        std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                              lastPingTime)
            .count();
    if (std::cmp_greater(time_since_ping, config.pingIntervalMs)) {
      SendPing();
      lastPingTime = now;
    }
  }

  CheckTimeout();

  ProcessPendingReliable();

  CleanupFragments();
}

void ReliableConnection::ProcessPacket(const void* data, std::size_t size,
                                       const SocketAddress& from,
                                       std::uint16_t from_port) {
  if (size < kPacketHeaderSize) return;

  const auto* packet_data = static_cast<const std::uint8_t*>(data);
  BitStream bs(packet_data, size);

  PacketType type = PacketType::kUnreliable;
  std::uint8_t channel = 0;
  std::uint32_t sequence = 0;

  if (!ReadPacketHeader(bs, type, channel, sequence)) return;

  auto header_data = MakePacketHeaderData(type, channel, sequence);
  const std::uint8_t* payload_data = packet_data + kPacketHeaderSize;
  std::size_t payload_size = size - kPacketHeaderSize;
  BitStream decrypted_payload;

  if (SecureMode() && type != PacketType::kConnect &&
      type != PacketType::kAccept) {
    if (!cryptoReady) return;

    const auto decrypt_result =
        cryptoContext.Decrypt(payload_data, payload_size, header_data.data(),
                              header_data.size(), decrypted_payload);
    if (!decrypt_result.ok) return;

    payload_data = decrypted_payload.GetData();
    payload_size = decrypted_payload.GetSizeBytes();
  }

  lastReceiveTime = std::chrono::steady_clock::now();
  statsReceivedPackets++;

  // Handle different packet types
  switch (type) {
    case PacketType::kConnect: {
      if (state == ConnectionState::kDisconnected) {
        remoteAddr = from;
        remotePort = from_port;

        if (SecureMode()) {
          if (!CanUseCrypto()) return;

          auto result = cryptoHandshake.StartServer(config.crypto.localKeyPair);
          if (!result.ok) return;

          result =
              cryptoHandshake.ProcessClientHello(payload_data, payload_size);
          if (!result.ok) {
            state = ConnectionState::kDisconnected;
            return;
          }

          cryptoContext = cryptoHandshake.CreateServerCryptoContext();
          cryptoReady = cryptoContext.IsReady();
          if (!cryptoReady) {
            state = ConnectionState::kDisconnected;
            return;
          }

          BitStream server_hello;
          result = cryptoHandshake.WriteServerHello(server_hello);
          if (!result.ok) {
            cryptoReady = false;
            state = ConnectionState::kDisconnected;
            return;
          }

          state = ConnectionState::kConnected;
          (void)SendPacket(PacketType::kAccept, 0, server_hello.GetData(),
                           server_hello.GetSizeBytes());
        } else {
          state = ConnectionState::kConnected;
          (void)SendPacket(PacketType::kAccept, 0, nullptr, 0);
        }

        if (eventHandler != nullptr) eventHandler->OnConnected();
      }
      break;
    }

    case PacketType::kAccept: {
      if (state == ConnectionState::kConnecting) {
        if (SecureMode()) {
          auto result =
              cryptoHandshake.ProcessServerHello(payload_data, payload_size);
          if (!result.ok) {
            cryptoReady = false;
            state = ConnectionState::kDisconnected;
            return;
          }

          cryptoContext = cryptoHandshake.CreateClientCryptoContext();
          cryptoReady = cryptoContext.IsReady();
          if (!cryptoReady) {
            state = ConnectionState::kDisconnected;
            return;
          }
        }

        state = ConnectionState::kConnected;

        if (eventHandler != nullptr) eventHandler->OnConnected();
      }
      break;
    }

    case PacketType::kDisconnect: {
      if (eventHandler != nullptr) eventHandler->OnDisconnected();

      state = ConnectionState::kDisconnected;
      break;
    }

    case PacketType::kPing: {
      // Send pong with same sequence
      (void)SendPacket(PacketType::kPong, 0, nullptr, 0, sequence);
      break;
    }

    case PacketType::kPong: {
      // Calculate RTT
      auto now = std::chrono::steady_clock::now();
      for (auto& pending : pendingPackets) {
        if (pending.sequence == sequence) {
          auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - pending.sendTime)
                             .count();
          rtt = rtt * 0.9f + static_cast<float>(elapsed) *
                                 0.1f;  // Exponential moving average
          break;
        }
      }
      break;
    }

    case PacketType::kAck: {
      // Remove acknowledged packet from pending list
      auto it = std::ranges::find_if(pendingPackets,
                                     [sequence](const PendingPacket& p) {
                                       return p.sequence == sequence;
                                     });

      if (it != pendingPackets.end()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           now - it->sendTime)
                           .count();
        rtt = rtt * 0.9f + static_cast<float>(elapsed) * 0.1f;

        pendingPackets.erase(it);
      }
      break;
    }

    case PacketType::kReliable: {
      // Send ACK
      SendAck(sequence);

      // Check for duplicate
      if (IsDuplicateSequence(channel, sequence)) return;  // Already processed

      MarkSequenceReceived(channel, sequence);

      std::vector<std::uint8_t> payload(payload_size);
      if (payload_size > 0) {
        std::memcpy(payload.data(), payload_data, payload_size);
      }

      // Store for ordered processing
      ReceivedPacket received;
      received.sequence = sequence;
      received.data = std::move(payload);
      received.channel = channel;
      if (channel < pendingReceived.size()) {
        pendingReceived.at(channel)[sequence] = std::move(received);
      }

      break;
    }

    case PacketType::kUnsequenced: {
      // Send ACK
      SendAck(sequence);

      // Check for duplicate
      if (IsDuplicateSequence(channel, sequence)) return;

      MarkSequenceReceived(channel, sequence);

      std::vector<std::uint8_t> payload(payload_size);
      if (payload_size > 0) {
        std::memcpy(payload.data(), payload_data, payload_size);
      }

      if (eventHandler != nullptr) {
        eventHandler->OnReliableReceived(channel, payload.data(),
                                         payload.size());
      }

      break;
    }

    case PacketType::kUnreliable: {
      // No ACK needed
      std::vector<std::uint8_t> payload(payload_size);
      if (payload_size > 0) {
        std::memcpy(payload.data(), payload_data, payload_size);
      }

      if (eventHandler != nullptr) {
        eventHandler->OnUnreliableReceived(channel, payload.data(),
                                           payload.size());
      }

      break;
    }

    case PacketType::kFragment: {
      // ACK each fragment individually so it can be retried if lost
      SendAck(sequence);

      if (IsDuplicateSequence(channel, sequence)) break;
      MarkSequenceReceived(channel, sequence);

      // Fragment metadata is embedded in the payload after the base header:
      // [groupId:2][fragIndex:2][fragTotal:2][data...]
      static constexpr std::size_t kFragMeta = 6;
      if (payload_size < kFragMeta) break;

      BitStream frag_bs(payload_data, payload_size);
      std::uint16_t group_id = 0, frag_index = 0, frag_total = 0;
      frag_bs.ReadBytes(&group_id, 2);
      frag_bs.ReadBytes(&frag_index, 2);
      frag_bs.ReadBytes(&frag_total, 2);

      const std::size_t fragment_payload_size = payload_size - kFragMeta;
      std::vector<std::uint8_t> payload(fragment_payload_size);
      if (fragment_payload_size > 0) {
        frag_bs.ReadBytes(payload.data(), fragment_payload_size);
      }

      if (channel >= fragmentGroups.size() || frag_total == 0 ||
          frag_index >= frag_total) {
        break;
      }

      auto& groups = fragmentGroups.at(channel);
      auto it = groups.find(group_id);
      if (it == groups.end()) {
        FragmentGroup fg;
        fg.total = frag_total;
        fg.pieces.resize(frag_total);
        fg.firstReceived = std::chrono::steady_clock::now();
        fg.channel = channel;
        it = groups.emplace(group_id, std::move(fg)).first;
      }

      FragmentGroup& fg = it->second;
      if (frag_index < fg.pieces.size() && !fg.pieces.at(frag_index).has_value()) {
        fg.pieces.at(frag_index) = std::move(payload);
        ++fg.receivedCount;
      }

      if (fg.receivedCount == fg.total) {
        // All fragments received — reassemble and deliver
        std::vector<std::uint8_t> full;
        full.reserve(fg.total * fragment_payload_size + fragment_payload_size);
        for (auto& piece : fg.pieces) {
          if (piece.has_value()) {
            full.insert(full.end(), piece->begin(), piece->end());
          }
        }

        if (eventHandler != nullptr) {
          eventHandler->OnReliableReceived(channel, full.data(), full.size());
        }

        groups.erase(it);
      }
      break;
    }

    default: {
      // Unknown packet type — ignore
      break;
    }
  }
}

bool ReliableConnection::SendPacket(PacketType type, std::uint8_t channel,
                                    const void* data, std::size_t size,
                                    std::uint32_t sequence) {
  BitStream bs;
  WritePacketHeader(bs, type, channel, sequence);

  if (ShouldEncryptPacket(type)) {
    const auto header_data = MakePacketHeaderData(type, channel, sequence);
    BitStream encrypted;
    const auto* payload = static_cast<const std::uint8_t*>(data);
    const auto result = cryptoContext.Encrypt(payload, size, header_data.data(),
                                              header_data.size(), encrypted);
    if (!result.ok) return false;
    bs.WriteBytes(encrypted.GetData(), encrypted.GetSizeBytes());
  } else if (data != nullptr && size > 0) {
    bs.WriteBytes(data, size);
  }

  socket->SendTo(bs.GetData(), bs.GetSizeBytes(), remoteAddr, remotePort);
  lastSendTime = std::chrono::steady_clock::now();
  statsSentPackets++;
  return true;
}

bool ReliableConnection::SendFragmented(std::uint8_t channel, const void* data,
                                        std::size_t size) {
  if (channel >= nextFragmentGroupId.size()) return false;

  const std::size_t max_frag_payload =
      MaxPayloadForPacket(kFragmentHeaderExtra);
  if (max_frag_payload == 0) return false;
  const std::size_t frag_total_size =
      (size + max_frag_payload - 1) / max_frag_payload;
  if (frag_total_size > std::numeric_limits<std::uint16_t>::max()) return false;

  const auto frag_total = static_cast<std::uint16_t>(frag_total_size);
  const std::uint16_t group_id = nextFragmentGroupId.at(channel)++;
  const auto* src = static_cast<const std::uint8_t*>(data);

  for (std::uint16_t i = 0; i < frag_total; ++i) {
    const std::size_t offset = i * max_frag_payload;
    const std::size_t frag_size = std::min(max_frag_payload, size - offset);

    // Layout: [groupId:2][fragIndex:2][fragTotal:2][payload...]
    std::vector<std::uint8_t> frag_payload(6 + frag_size);
    std::memcpy(frag_payload.data() + 0, &group_id, 2);
    std::memcpy(frag_payload.data() + 2, &i, 2);
    std::memcpy(frag_payload.data() + 4, &frag_total, 2);
    std::memcpy(frag_payload.data() + 6, src + offset, frag_size);

    const std::uint32_t seq = GetNextSequence(channel);
    if (!SendPacket(PacketType::kFragment, channel, frag_payload.data(),
                    frag_payload.size(), seq)) {
      return false;
    }

    // Store for retransmission
    PendingPacket pending;
    pending.sequence = seq;
    pending.data = std::move(frag_payload);
    pending.sendTime = std::chrono::steady_clock::now();
    pending.channel = channel;
    pending.type = PacketType::kFragment;
    pendingPackets.push_back(std::move(pending));
  }

  return true;
}

void ReliableConnection::CleanupFragments() {
  auto now = std::chrono::steady_clock::now();
  for (auto& ch_groups : fragmentGroups) {
    std::erase_if(ch_groups, [&](const auto& kv) {
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              now - kv.second.firstReceived)
              .count();
      return elapsed > static_cast<std::int64_t>(config.fragmentTimeoutMs);
    });
  }
}

bool ReliableConnection::CanUseCrypto() const {
  if (!SecureMode()) return true;

  const auto init_result = crypto::Initialize();
  return init_result.ok &&
         crypto::CipherSuiteSupported(
             crypto::CipherSuite::kXChaCha20Poly1305) &&
         config.crypto.localKeyPair.Valid();
}

bool ReliableConnection::ShouldEncryptPacket(PacketType type) const {
  return SecureMode() && cryptoReady && type != PacketType::kConnect &&
         type != PacketType::kAccept;
}

std::size_t ReliableConnection::CryptoEnvelopeOverhead() const {
  return SecureMode() ? (crypto::kNonceSize + crypto::kMacSize) : 0;
}

std::size_t ReliableConnection::MaxPayloadForPacket(
    std::size_t header_extra) const {
  const std::size_t overhead =
      kPacketHeaderSize + header_extra + CryptoEnvelopeOverhead();
  if (config.maxPacketSize < overhead) return 0;
  return config.maxPacketSize - overhead;
}

void ReliableConnection::SendAck(std::uint32_t sequence) {
  (void)SendPacket(PacketType::kAck, 0, nullptr, 0, sequence);
}

void ReliableConnection::SendPing() {
  std::uint32_t seq = GetNextSequence(0);
  if (!SendPacket(PacketType::kPing, 0, nullptr, 0, seq)) return;

  // Store as pending to measure RTT
  PendingPacket pending;
  pending.sequence = seq;
  pending.sendTime = std::chrono::steady_clock::now();
  pending.type = PacketType::kPing;
  pendingPackets.push_back(pending);
}

void ReliableConnection::ProcessPendingReliable() {
  // Process packets in order for each channel independently
  for (std::uint8_t ch = 0;
       ch < static_cast<std::uint8_t>(receiveSequence.size()); ++ch) {
    while (true) {
      auto it = pendingReceived.at(ch).find(receiveSequence.at(ch));
      if (it == pendingReceived.at(ch).end()) {
        break;  // Next expected packet not yet received
      }

      if (eventHandler != nullptr) {
        eventHandler->OnReliableReceived(
            it->second.channel, it->second.data.data(), it->second.data.size());
      }

      pendingReceived.at(ch).erase(it);
      receiveSequence.at(ch)++;
    }
  }
}

void ReliableConnection::RetryPendingPackets() {
  auto now = std::chrono::steady_clock::now();

  for (auto& pending : pendingPackets) {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now - pending.sendTime)
                       .count();

    if (std::cmp_greater(elapsed, config.retryTimeoutMs)) {
      if (pending.retries >= config.maxRetries) {
        // Packet lost
        statsLostPackets++;
        continue;
      }

      const void* payload =
          pending.data.empty() ? nullptr : pending.data.data();
      if (SendPacket(pending.type, pending.channel, payload,
                     pending.data.size(), pending.sequence)) {
        pending.sendTime = now;
        pending.retries++;
      }
    }
  }

  // Remove packets that exceeded retry limit
  pendingPackets.erase(
      std::remove_if(pendingPackets.begin(), pendingPackets.end(),
                     [this](const PendingPacket& p) {
                       return p.retries >= config.maxRetries;
                     }),
      pendingPackets.end());
}

void ReliableConnection::CheckTimeout() {
  if (state != ConnectionState::kConnected) return;

  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                     now - lastReceiveTime)
                     .count();

  if (std::cmp_greater(elapsed, config.disconnectTimeoutMs)) {
    if (eventHandler != nullptr) eventHandler->OnTimeout();

    Disconnect();
  }
}

bool ReliableConnection::IsDuplicateSequence(std::uint8_t channel,
                                             std::uint32_t seq) const {
  if (channel >= seqWindowHigh.size()) return false;
  // Sequence before the window base (too old) — treat as duplicate
  const std::uint32_t window_base = seqWindowHigh.at(channel) - kSeqWindowSize;
  if (IsSequenceNewer(window_base, seq)) return true;
  // Sequence newer than the highest seen — definitely not a duplicate
  if (IsSequenceNewer(seq, seqWindowHigh.at(channel))) return false;
  // Within the window — check the bit
  return seqWindowBits.at(channel).test(seq % kSeqWindowSize);
}

void ReliableConnection::MarkSequenceReceived(std::uint8_t channel,
                                              std::uint32_t seq) {
  if (channel >= seqWindowHigh.size()) return;
  if (IsSequenceNewer(seq, seqWindowHigh.at(channel))) {
    // Advance the window, clearing the newly exposed slots
    const std::uint32_t advance = seq + 1 - seqWindowHigh.at(channel);
    if (advance >= kSeqWindowSize) {
      seqWindowBits.at(channel).reset();
    } else {
      for (std::uint32_t i = 0; i < advance; ++i) {
        seqWindowBits.at(channel).set((seqWindowHigh.at(channel) + i) % kSeqWindowSize, false);
      }
    }
    seqWindowHigh.at(channel) = seq + 1;
  }
  seqWindowBits.at(channel).set(seq % kSeqWindowSize);
}

/*static*/ bool ReliableConnection::IsSequenceNewer(std::uint32_t s1,
                                                    std::uint32_t s2) {
  return ((s1 > s2) && (s1 - s2 <= 0x7FFFFFFF)) ||
         ((s1 < s2) && (s2 - s1 > 0x7FFFFFFF));
}

ReliableConnection::~ReliableConnection() {
  // Don't call disconnect() which may trigger callbacks during destruction
  // Just clean up resources directly
  state = ConnectionState::kDisconnected;
  pendingPackets.clear();
  for (auto& h : seqWindowHigh) h = 0;
  for (auto& b : seqWindowBits) b.reset();
  for (auto& pr : pendingReceived) pr.clear();
  for (auto& fg : fragmentGroups) fg.clear();
}

// ---------------------------------- ConnectionManager
// ----------------------------------

ConnectionManager::ConnectionManager(ISocket* socket,
                                     const ReliableConnectionConfig& cfg)
    : socket(socket), config(cfg) {}

ConnectionManager::~ConnectionManager() {
  clients.clear();
  clientMap.clear();
}

void ConnectionManager::Update() {
  for (auto& client : clients) {
    if (client->connection != nullptr) client->connection->Update();
  }

  // Remove disconnected clients
  std::erase_if(clients, [this](const std::unique_ptr<RemoteClient>& client) {
    if (client->connection->GetState() == ConnectionState::kDisconnected) {
      if (onClientDisconnected != nullptr) onClientDisconnected(client.get());

      auto key = MakeAddressKey(client->address, client->port);
      clientMap.erase(key);

      return true;
    }
    return false;
  });
}

void ConnectionManager::ProcessPacket(const void* data, std::size_t size,
                                      const SocketAddress& from,
                                      std::uint16_t from_port) {
  // Check whether the sender is already a known client
  const bool is_known =
      (clientMap.find(MakeAddressKey(from, from_port)) != clientMap.end());

  if (!is_known) {
    // Peek at the packet type (byte 0). Only accept Connect packets from new
    // senders, and only at the configured maximum rate.
    if (size < 1) return;
    const auto type_val = static_cast<const std::uint8_t*>(data)[0];
    if (type_val != static_cast<std::uint8_t>(PacketType::kConnect)) {
      return;  // Ignore non-Connect packets from unknown senders
    }
    if (!HandshakeAllowed()) return;  // Rate limit exceeded — silently drop
  }

  RemoteClient* client = FindOrCreateClient(from, from_port);
  if (client != nullptr && client->connection != nullptr) {
    client->connection->ProcessPacket(data, size, from, from_port);
    if (!is_known &&
        client->connection->GetState() == ConnectionState::kDisconnected) {
      RemoveClient(client);
    }
  }
}

bool ConnectionManager::HandshakeAllowed() {
  if (config.maxHandshakesPerSecond == 0) return true;  // unlimited

  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                     now - connectWindowStart)
                     .count();

  if (elapsed >= 1000) {
    // Start a fresh 1-second window
    connectWindowStart = now;
    connectWindowCount = 0;
  }

  if (connectWindowCount >= config.maxHandshakesPerSecond) return false;

  ++connectWindowCount;
  return true;
}

void ConnectionManager::BroadcastReliable(std::uint8_t channel,
                                          const void* data, std::size_t size) {
  for (auto& client : clients) {
    if (client->connection != nullptr && client->connection->IsConnected()) {
      client->connection->SendReliable(channel, data, size);
    }
  }
}

void ConnectionManager::BroadcastUnreliable(std::uint8_t channel,
                                            const void* data,
                                            std::size_t size) {
  for (auto& client : clients) {
    if (client->connection != nullptr && client->connection->IsConnected()) {
      client->connection->SendUnreliable(channel, data, size);
    }
  }
}

std::vector<ConnectionManager::RemoteClient*>
ConnectionManager::GetConnections() {
  std::vector<RemoteClient*> result;
  result.reserve(clients.size());
  for (auto& client : clients) result.push_back(client.get());
  return result;
}

ConnectionManager::RemoteClient* ConnectionManager::GetConnection(
    const SocketAddress& addr, std::uint16_t port) {
  auto key = MakeAddressKey(addr, port);
  auto it = clientMap.find(key);
  return (it != clientMap.end()) ? it->second : nullptr;
}

ConnectionManager::RemoteClient* ConnectionManager::FindOrCreateClient(
    const SocketAddress& addr, std::uint16_t port) {
  auto key = MakeAddressKey(addr, port);

  auto it = clientMap.find(key);
  if (it != clientMap.end()) return it->second;

  // Create new client
  auto client = std::make_unique<RemoteClient>();
  client->address = addr;
  client->port = port;
  client->connection = std::make_unique<ReliableConnection>(socket, config);
  client->connection->SetRemoteAddress(addr, port);
  client->connection->SetHandler(eventHandler);

  RemoteClient* raw = client.get();
  clients.push_back(std::move(client));
  clientMap[key] = raw;

  return raw;
}

void ConnectionManager::RemoveClient(RemoteClient* client) {
  auto key = MakeAddressKey(client->address, client->port);
  clientMap.erase(key);

  auto it = std::ranges::find_if(
      clients, [client](const std::unique_ptr<RemoteClient>& c) {
        return c.get() == client;
      });
  if (it != clients.end()) clients.erase(it);
}

std::string ConnectionManager::MakeAddressKey(const SocketAddress& addr,
                                              std::uint16_t port) {
  return MakeConnectionKey(addr, port);
}

void ReliableConnection::Tick() {
  std::vector<std::uint8_t> buf(config.maxPacketSize);
  SocketAddress from_addr{};
  std::uint16_t from_port = 0;

  while (true) {
    const SocketResult res =
        socket->Receive(buf.data(), buf.size(), from_addr, from_port);
    if (res.Failed()) break;  // WouldBlock or error — no more packets
    if (res.bytes > 0) {
      ProcessPacket(buf.data(), static_cast<std::size_t>(res.bytes), from_addr,
                    from_port);
    }
  }

  Update();
}

void ConnectionManager::Tick() {
  std::vector<std::uint8_t> buf(config.maxPacketSize);
  SocketAddress from_addr{};
  std::uint16_t from_port = 0;

  while (true) {
    const SocketResult res =
        socket->Receive(buf.data(), buf.size(), from_addr, from_port);
    if (res.Failed()) break;  // WouldBlock or error — no more packets
    if (res.bytes > 0) {
      ProcessPacket(buf.data(), static_cast<std::size_t>(res.bytes), from_addr,
                    from_port);
    }
  }

  Update();
}

}  // namespace socketwire
