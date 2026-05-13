#include "reliable_connection.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

namespace socketwire {

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

ReliableConnection::ReliableConnection(ISocket* socket,
                                       const ReliableConnectionConfig& cfg)
    : socket_(socket),
      config_(cfg),
      current_send_window_((config_.sendWindowSize > 0) ? config_.sendWindowSize
                                                        : 0) {
  const auto n = static_cast<std::size_t>(cfg.numChannels);
  send_sequence_.assign(n, 0);
  receive_sequence_.assign(n, 0);
  seq_window_high_.assign(n, 0);
  seq_window_bits_.resize(n);
  pending_received_.resize(n);
  next_fragment_group_id_.assign(n, 0);
  fragment_groups_.resize(n);

  // Initialize the congestion-control window.
  ssthresh_ = (config_.sendWindowSize > 0)
                  ? std::max(1u, config_.sendWindowSize / 2)
                  : 32;

  last_send_time_ = std::chrono::steady_clock::now();
  last_receive_time_ = std::chrono::steady_clock::now();
  last_ping_time_ = std::chrono::steady_clock::now();
}

bool ReliableConnection::Connect(const SocketAddress& addr,
                                 std::uint16_t port) {
  remote_addr_ = addr;
  remote_port_ = port;

  if (SecureMode()) {
    if (!CanUseCrypto() ||
        !crypto::ValidPublicKey(config_.crypto.expected_server_public_key)) {
      state_ = ConnectionState::kDisconnected;
      return false;
    }

    auto result = crypto_handshake_.StartClient(
        config_.crypto.localKeyPair, config_.crypto.expected_server_public_key);
    if (!result.ok) {
      state_ = ConnectionState::kDisconnected;
      return false;
    }

    BitStream client_hello;
    result = crypto_handshake_.WriteClientHello(client_hello);
    if (!result.ok) {
      state_ = ConnectionState::kDisconnected;
      return false;
    }

    state_ = ConnectionState::kConnecting;
    if (!SendPacket(PacketType::kConnect, 0, client_hello.GetData(),
                    client_hello.GetSizeBytes())) {
      state_ = ConnectionState::kDisconnected;
      return false;
    }
    return true;
  }

  state_ = ConnectionState::kConnecting;

  // Send connection request
  return SendPacket(PacketType::kConnect, 0, nullptr, 0);
}

void ReliableConnection::Disconnect() {
  if (state_ == ConnectionState::kConnected ||
      state_ == ConnectionState::kConnecting) {
    (void)SendPacket(PacketType::kDisconnect, 0, nullptr, 0);
    state_ = ConnectionState::kDisconnecting;

    if (event_handler_ != nullptr) event_handler_->OnDisconnected();
  }

  state_ = ConnectionState::kDisconnected;
  pending_packets_.clear();
  for (auto& h : seq_window_high_) h = 0;
  for (auto& b : seq_window_bits_) b.reset();
  for (auto& pr : pending_received_) pr.clear();
  for (auto& fg : fragment_groups_) fg.clear();
}

void ReliableConnection::SetRemoteAddress(const SocketAddress& addr,
                                          std::uint16_t port) {
  remote_addr_ = addr;
  remote_port_ = port;
}

bool ReliableConnection::SendReliable(const std::uint8_t channel,
                                      const void* data, std::size_t size) {
  if (state_ != ConnectionState::kConnected) return false;

  // Congestion window check (only when send-window limiting is enabled)
  if (current_send_window_ > 0 &&
      pending_packets_.size() >= current_send_window_) {
    return false;
  }

  const std::size_t max_payload = MaxPayloadForPacket();

  if (max_payload == 0) return false;

  if (size > max_payload) {
    // Too large for one packet, split into Fragment packets.
    if (channel >= next_fragment_group_id_.size()) return false;
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
  pending_packets_.push_back(pending);

  return true;
}

bool ReliableConnection::SendUnreliable(const std::uint8_t channel,
                                        const void* data, std::size_t size) {
  if (state_ != ConnectionState::kConnected) return false;

  const std::size_t max_payload = MaxPayloadForPacket();
  if (max_payload == 0 || size > max_payload) return false;

  if (!SendPacket(PacketType::kUnreliable, channel, data, size, 0)) {
    return false;
  }
  return true;
}

bool ReliableConnection::SendUnsequenced(const std::uint8_t channel,
                                         const void* data, std::size_t size) {
  if (state_ != ConnectionState::kConnected) return false;

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
  pending_packets_.push_back(pending);

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
  if (state_ == ConnectionState::kConnected) {
    auto time_since_ping =
        std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                              last_ping_time_)
                                                             .count();
    if (std::cmp_greater(time_since_ping, config_.pingIntervalMs)) {
      SendPing();
      last_ping_time_ = now;
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
    if (!crypto_ready_) return;

    const auto decrypt_result =
        crypto_context_.Decrypt(payload_data, payload_size, header_data.data(),
                                header_data.size(), decrypted_payload);
    if (!decrypt_result.ok) return;

    payload_data = decrypted_payload.GetData();
    payload_size = decrypted_payload.GetSizeBytes();
  }

  last_receive_time_ = std::chrono::steady_clock::now();
  stats_received_packets_++;

  // Handle different packet types
  switch (type) {
    case PacketType::kConnect: {
      if (state_ == ConnectionState::kDisconnected) {
        remote_addr_ = from;
        remote_port_ = from_port;

        if (SecureMode()) {
          if (!CanUseCrypto()) return;

          auto result =
              crypto_handshake_.StartServer(config_.crypto.localKeyPair);
          if (!result.ok) return;

          result =
              crypto_handshake_.ProcessClientHello(payload_data, payload_size);
          if (!result.ok) {
            state_ = ConnectionState::kDisconnected;
            return;
          }

          crypto_context_ = crypto_handshake_.CreateServerCryptoContext();
          crypto_ready_ = crypto_context_.IsReady();
          if (!crypto_ready_) {
            state_ = ConnectionState::kDisconnected;
            return;
          }

          BitStream server_hello;
          result = crypto_handshake_.WriteServerHello(server_hello);
          if (!result.ok) {
            crypto_ready_ = false;
            state_ = ConnectionState::kDisconnected;
            return;
          }

          state_ = ConnectionState::kConnected;
          (void)SendPacket(PacketType::kAccept, 0, server_hello.GetData(),
                           server_hello.GetSizeBytes());
        } else {
          state_ = ConnectionState::kConnected;
          (void)SendPacket(PacketType::kAccept, 0, nullptr, 0);
        }

        if (event_handler_ != nullptr) event_handler_->OnConnected();
      }
      break;
    }

    case PacketType::kAccept: {
      if (state_ == ConnectionState::kConnecting) {
        if (SecureMode()) {
          auto result =
              crypto_handshake_.ProcessServerHello(payload_data, payload_size);
          if (!result.ok) {
            crypto_ready_ = false;
            state_ = ConnectionState::kDisconnected;
            return;
          }

          crypto_context_ = crypto_handshake_.CreateClientCryptoContext();
          crypto_ready_ = crypto_context_.IsReady();
          if (!crypto_ready_) {
            state_ = ConnectionState::kDisconnected;
            return;
          }
        }

        state_ = ConnectionState::kConnected;

        if (event_handler_ != nullptr) event_handler_->OnConnected();
      }
      break;
    }

    case PacketType::kDisconnect: {
      if (event_handler_ != nullptr) event_handler_->OnDisconnected();

      state_ = ConnectionState::kDisconnected;
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
      for (auto& pending : pending_packets_) {
        if (pending.sequence == sequence) {
          auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                             now - pending.sendTime)
                             .count();
          rtt_ = rtt_ * 0.9f + static_cast<float>(elapsed) *
                                   0.1f;  // Exponential moving average
          break;
        }
      }
      break;
    }

    case PacketType::kAck: {
      // Remove acknowledged packet from pending list
      auto it = std::ranges::find_if(pending_packets_,
                                     [sequence](const PendingPacket& p) {
                                       return p.sequence == sequence;
                                     });

      if (it != pending_packets_.end()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           now - it->sendTime)
                           .count();
        rtt_ = rtt_ * 0.9f + static_cast<float>(elapsed) * 0.1f;

        pending_packets_.erase(it);
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
      if (channel < pending_received_.size()) {
        pending_received_.at(channel)[sequence] = std::move(received);
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

      if (event_handler_ != nullptr) {
        event_handler_->OnReliableReceived(channel, payload.data(),
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

      if (event_handler_ != nullptr) {
        event_handler_->OnUnreliableReceived(channel, payload.data(),
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

      if (channel >= fragment_groups_.size() || frag_total == 0 ||
          frag_index >= frag_total) {
        break;
      }

      auto& groups = fragment_groups_.at(channel);
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
      if (frag_index < fg.pieces.size() &&
          !fg.pieces.at(frag_index).has_value()) {
        fg.pieces.at(frag_index) = std::move(payload);
        ++fg.receivedCount;
      }

      if (fg.receivedCount == fg.total) {
        // Reassemble the completed fragment group.
        std::vector<std::uint8_t> full;
        full.reserve(fg.total * fragment_payload_size + fragment_payload_size);
        for (auto& piece : fg.pieces) {
          if (piece.has_value()) {
            full.insert(full.end(), piece->begin(), piece->end());
          }
        }

        if (event_handler_ != nullptr) {
          event_handler_->OnReliableReceived(channel, full.data(), full.size());
        }

        groups.erase(it);
      }
      break;
    }

    default: {
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
    const auto result = crypto_context_.Encrypt(
        payload, size, header_data.data(), header_data.size(), encrypted);
    if (!result.ok) return false;
    bs.WriteBytes(encrypted.GetData(), encrypted.GetSizeBytes());
  } else if (data != nullptr && size > 0) {
    bs.WriteBytes(data, size);
  }

  socket_->SendTo(bs.GetData(), bs.GetSizeBytes(), remote_addr_, remote_port_);
  last_send_time_ = std::chrono::steady_clock::now();
  stats_sent_packets_++;
  return true;
}

bool ReliableConnection::SendFragmented(std::uint8_t channel, const void* data,
                                        std::size_t size) {
  if (channel >= next_fragment_group_id_.size()) return false;

  const std::size_t max_frag_payload =
      MaxPayloadForPacket(kFragmentHeaderExtra);
  if (max_frag_payload == 0) return false;
  const std::size_t frag_total_size =
      (size + max_frag_payload - 1) / max_frag_payload;
  if (frag_total_size > std::numeric_limits<std::uint16_t>::max()) return false;

  const auto frag_total = static_cast<std::uint16_t>(frag_total_size);
  const std::uint16_t group_id = next_fragment_group_id_.at(channel)++;
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
    pending_packets_.push_back(std::move(pending));
  }

  return true;
}

void ReliableConnection::CleanupFragments() {
  auto now = std::chrono::steady_clock::now();
  for (auto& ch_groups : fragment_groups_) {
    std::erase_if(ch_groups, [&](const auto& kv) {
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              now - kv.second.firstReceived)
              .count();
      return elapsed > static_cast<std::int64_t>(config_.fragmentTimeoutMs);
    });
  }
}

bool ReliableConnection::CanUseCrypto() const {
  if (!SecureMode()) return true;

  const auto init_result = crypto::Initialize();
  return init_result.ok &&
         crypto::CipherSuiteSupported(
             crypto::CipherSuite::kXChaCha20Poly1305) &&
         config_.crypto.localKeyPair.Valid();
}

bool ReliableConnection::ShouldEncryptPacket(PacketType type) const {
  return SecureMode() && crypto_ready_ && type != PacketType::kConnect &&
         type != PacketType::kAccept;
}

std::size_t ReliableConnection::CryptoEnvelopeOverhead() const {
  return SecureMode() ? (crypto::kNonceSize + crypto::kMacSize) : 0;
}

std::size_t ReliableConnection::MaxPayloadForPacket(
    std::size_t header_extra) const {
  const std::size_t overhead =
      kPacketHeaderSize + header_extra + CryptoEnvelopeOverhead();
  if (config_.maxPacketSize < overhead) return 0;
  return config_.maxPacketSize - overhead;
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
  pending_packets_.push_back(pending);
}

void ReliableConnection::ProcessPendingReliable() {
  // Process packets in order for each channel independently
  for (std::uint8_t ch = 0;
       ch < static_cast<std::uint8_t>(receive_sequence_.size()); ++ch) {
    while (true) {
      auto it = pending_received_.at(ch).find(receive_sequence_.at(ch));
      if (it == pending_received_.at(ch).end()) {
        break;  // Next expected packet not yet received
      }

      if (event_handler_ != nullptr) {
        event_handler_->OnReliableReceived(
            it->second.channel, it->second.data.data(), it->second.data.size());
      }

      pending_received_.at(ch).erase(it);
      receive_sequence_.at(ch)++;
    }
  }
}

void ReliableConnection::RetryPendingPackets() {
  auto now = std::chrono::steady_clock::now();

  for (auto& pending : pending_packets_) {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now - pending.sendTime)
                       .count();

    if (std::cmp_greater(elapsed, config_.retryTimeoutMs)) {
      if (pending.retries >= config_.maxRetries) {
        // Packet lost
        stats_lost_packets_++;
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
  pending_packets_.erase(
      std::remove_if(pending_packets_.begin(), pending_packets_.end(),
                     [this](const PendingPacket& p) {
                       return p.retries >= config_.maxRetries;
                     }),
      pending_packets_.end());
}

void ReliableConnection::CheckTimeout() {
  if (state_ != ConnectionState::kConnected) return;

  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                     now - last_receive_time_)
                     .count();

  if (std::cmp_greater(elapsed, config_.disconnectTimeoutMs)) {
    if (event_handler_ != nullptr) event_handler_->OnTimeout();

    Disconnect();
  }
}

bool ReliableConnection::IsDuplicateSequence(std::uint8_t channel,
                                             std::uint32_t seq) const {
  if (channel >= seq_window_high_.size()) return false;
  // Sequence before the window base is too old.
  const std::uint32_t window_base =
      seq_window_high_.at(channel) - kSeqWindowSize;
  if (IsSequenceNewer(window_base, seq)) return true;
  // Sequence newer than the highest seen is definitely not a duplicate.
  if (IsSequenceNewer(seq, seq_window_high_.at(channel))) return false;
  // Within the window, check the bitset.
  return seq_window_bits_.at(channel).test(seq % kSeqWindowSize);
}

void ReliableConnection::MarkSequenceReceived(std::uint8_t channel,
                                              std::uint32_t seq) {
  if (channel >= seq_window_high_.size()) return;
  if (IsSequenceNewer(seq, seq_window_high_.at(channel))) {
    // Advance the window, clearing the newly exposed slots
    const std::uint32_t advance = seq + 1 - seq_window_high_.at(channel);
    if (advance >= kSeqWindowSize) {
      seq_window_bits_.at(channel).reset();
    } else {
      for (std::uint32_t i = 0; i < advance; ++i) {
        seq_window_bits_.at(channel).set(
            (seq_window_high_.at(channel) + i) % kSeqWindowSize, false);
      }
    }
    seq_window_high_.at(channel) = seq + 1;
  }
  seq_window_bits_.at(channel).set(seq % kSeqWindowSize);
}

bool ReliableConnection::IsSequenceNewer(std::uint32_t s1, std::uint32_t s2) {
  return ((s1 > s2) && (s1 - s2 <= 0x7FFFFFFF)) ||
         ((s1 < s2) && (s2 - s1 > 0x7FFFFFFF));
}

ReliableConnection::~ReliableConnection() {
  // Don't call disconnect() which may trigger callbacks during destruction
  // Just clean up resources directly
  state_ = ConnectionState::kDisconnected;
  pending_packets_.clear();
  for (auto& h : seq_window_high_) h = 0;
  for (auto& b : seq_window_bits_) b.reset();
  for (auto& pr : pending_received_) pr.clear();
  for (auto& fg : fragment_groups_) fg.clear();
}

ConnectionManager::ConnectionManager(ISocket* socket,
                                     const ReliableConnectionConfig& cfg)
    : socket_(socket), config_(cfg) {}

ConnectionManager::~ConnectionManager() {
  clients_.clear();
  client_map_.clear();
}

void ConnectionManager::Update() {
  for (auto& client : clients_) {
    if (client->connection != nullptr) client->connection->Update();
  }

  // Remove disconnected clients.
  std::erase_if(clients_, [this](const std::unique_ptr<RemoteClient>& client) {
    if (client->connection->GetState() == ConnectionState::kDisconnected) {
      if (onClientDisconnected != nullptr) onClientDisconnected(client.get());

      auto key = MakeAddressKey(client->address, client->port);
      client_map_.erase(key);

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
      (client_map_.find(MakeAddressKey(from, from_port)) != client_map_.end());

  if (!is_known) {
    // Peek at the packet type (byte 0). Only accept Connect packets from new
    // senders, and only at the configured maximum rate.
    if (size < 1) return;
    const auto type_val = static_cast<const std::uint8_t*>(data)[0];
    if (type_val != static_cast<std::uint8_t>(PacketType::kConnect)) {
      return;  // Ignore non-Connect packets from unknown senders
    }
    if (!HandshakeAllowed()) return;
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
  if (config_.maxHandshakesPerSecond == 0) return true;  // unlimited

  auto now = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                     now - connect_window_start_)
                     .count();

  if (elapsed >= 1000) {
    // Start a fresh 1-second window
    connect_window_start_ = now;
    connect_window_count_ = 0;
  }

  if (connect_window_count_ >= config_.maxHandshakesPerSecond) return false;

  ++connect_window_count_;
  return true;
}

void ConnectionManager::BroadcastReliable(std::uint8_t channel,
                                          const void* data, std::size_t size) {
  for (auto& client : clients_) {
    if (client->connection != nullptr && client->connection->IsConnected()) {
      client->connection->SendReliable(channel, data, size);
    }
  }
}

void ConnectionManager::BroadcastUnreliable(std::uint8_t channel,
                                            const void* data,
                                            std::size_t size) {
  for (auto& client : clients_) {
    if (client->connection != nullptr && client->connection->IsConnected()) {
      client->connection->SendUnreliable(channel, data, size);
    }
  }
}

std::vector<ConnectionManager::RemoteClient*>
ConnectionManager::GetConnections() {
  std::vector<RemoteClient*> result;
  result.reserve(clients_.size());
  for (auto& client : clients_) result.push_back(client.get());
  return result;
}

ConnectionManager::RemoteClient* ConnectionManager::GetConnection(
    const SocketAddress& addr, std::uint16_t port) {
  auto key = MakeAddressKey(addr, port);
  auto it = client_map_.find(key);
  return (it != client_map_.end()) ? it->second : nullptr;
}

ConnectionManager::RemoteClient* ConnectionManager::FindOrCreateClient(
    const SocketAddress& addr, std::uint16_t port) {
  auto key = MakeAddressKey(addr, port);

  auto it = client_map_.find(key);
  if (it != client_map_.end()) return it->second;

  // Create new client
  auto client = std::make_unique<RemoteClient>();
  client->address = addr;
  client->port = port;
  client->connection = std::make_unique<ReliableConnection>(socket_, config_);
  client->connection->SetRemoteAddress(addr, port);
  client->connection->SetHandler(event_handler_);

  RemoteClient* raw = client.get();
  clients_.push_back(std::move(client));
  client_map_[key] = raw;

  return raw;
}

void ConnectionManager::RemoveClient(RemoteClient* client) {
  auto key = MakeAddressKey(client->address, client->port);
  client_map_.erase(key);

  auto it = std::ranges::find_if(
      clients_, [client](const std::unique_ptr<RemoteClient>& c) {
        return c.get() == client;
      });
  if (it != clients_.end()) clients_.erase(it);
}

std::string ConnectionManager::MakeAddressKey(const SocketAddress& addr,
                                              std::uint16_t port) {
  return MakeConnectionKey(addr, port);
}

void ReliableConnection::Tick() {
  std::vector<std::uint8_t> buf(config_.maxPacketSize);
  SocketAddress from_addr{};
  std::uint16_t from_port = 0;

  while (true) {
    const SocketResult res =
        socket_->Receive(buf.data(), buf.size(), from_addr, from_port);
    if (res.Failed()) break;
    if (res.bytes > 0) {
      ProcessPacket(buf.data(), static_cast<std::size_t>(res.bytes), from_addr,
                    from_port);
    }
  }

  Update();
}

void ConnectionManager::Tick() {
  std::vector<std::uint8_t> buf(config_.maxPacketSize);
  SocketAddress from_addr{};
  std::uint16_t from_port = 0;

  while (true) {
    const SocketResult res =
        socket_->Receive(buf.data(), buf.size(), from_addr, from_port);
    if (res.Failed()) break;
    if (res.bytes > 0) {
      ProcessPacket(buf.data(), static_cast<std::size_t>(res.bytes), from_addr,
                    from_port);
    }
  }

  Update();
}

}  // namespace socketwire
