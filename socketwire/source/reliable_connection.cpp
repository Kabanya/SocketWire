#include "reliable_connection.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

namespace socketwire {

static constexpr std::size_t kPacketHeaderSize = 6;
static constexpr std::size_t kPacketHeaderExtensionSize = 10;
static constexpr std::uint8_t kPacketHeaderExtensionFlag = 0x80;
static constexpr std::uint8_t kPacketTypeMask = 0x7F;
static constexpr std::uint8_t kDeadlineExtensionVersion = 1;
static constexpr std::size_t kReceiveBatchSize = 32;
static constexpr std::uint16_t kMaxBatchCommandsHardLimit = 256;

struct ParsedPacketHeader {
  PacketType type = PacketType::kUnreliable;
  std::uint8_t channel = 0;
  std::uint32_t sequence = 0;
  bool hasDeadline = false;
  std::uint32_t deadline_ms = 0;
  std::uint32_t ageMsAtSend = 0;
  std::size_t headerSize = kPacketHeaderSize;
};

static std::size_t PacketHeaderSize(const bool has_deadline) {
  return kPacketHeaderSize +
         (has_deadline ? kPacketHeaderExtensionSize : std::size_t{0});
}

static void WriteU16(std::uint8_t* dst, std::uint16_t value) {
  std::memcpy(dst, &value, sizeof(value));
}

static std::uint16_t ReadU16(const std::uint8_t* src) {
  std::uint16_t value = 0;
  std::memcpy(&value, src, sizeof(value));
  return value;
}

static std::uint32_t DeadlineAgeMs(
    std::chrono::steady_clock::time_point created_time,
    std::chrono::steady_clock::time_point now) {
  const auto elapsed =
      std::chrono::duration_cast<std::chrono::milliseconds>(now - created_time)
          .count();
  if (elapsed <= 0) return 0;
  if (std::cmp_greater(elapsed, std::numeric_limits<std::uint32_t>::max())) {
    return std::numeric_limits<std::uint32_t>::max();
  }
  return static_cast<std::uint32_t>(elapsed);
}

static std::size_t WritePacketHeader(
    std::uint8_t* dst, PacketType type, std::uint8_t channel,
    std::uint32_t sequence, bool has_deadline, std::uint32_t deadline_ms,
    std::chrono::steady_clock::time_point created_time,
    std::chrono::steady_clock::time_point now) {
  auto type_and_flags = static_cast<std::uint8_t>(type);
  if (has_deadline) type_and_flags |= kPacketHeaderExtensionFlag;
  dst[0] = type_and_flags;
  dst[1] = channel;
  std::memcpy(dst + 2, &sequence, sizeof(sequence));

  if (has_deadline) {
    const std::uint8_t extension_flags = 0;
    const std::uint32_t age_ms = DeadlineAgeMs(created_time, now);
    dst[6] = kDeadlineExtensionVersion;
    dst[7] = extension_flags;
    std::memcpy(dst + 8, &deadline_ms, sizeof(deadline_ms));
    std::memcpy(dst + 12, &age_ms, sizeof(age_ms));
  }

  return PacketHeaderSize(has_deadline);
}

static bool ReadPacketHeader(const std::uint8_t* data, std::size_t size,
                             ParsedPacketHeader& header) {
  if (size < kPacketHeaderSize) return false;

  const std::uint8_t type_and_flags = data[0];

  const bool has_extension = (type_and_flags & kPacketHeaderExtensionFlag) != 0;
  const std::uint8_t type_val = type_and_flags & kPacketTypeMask;

  // Validate packet type range
  if (type_val > static_cast<std::uint8_t>(PacketType::kBatch)) return false;

  header.type = static_cast<PacketType>(type_val);
  header.channel = data[1];
  std::memcpy(&header.sequence, data + 2, sizeof(header.sequence));
  header.headerSize = kPacketHeaderSize;

  if (has_extension) {
    if (size < kPacketHeaderSize + kPacketHeaderExtensionSize) return false;

    const std::uint8_t extension_version = data[6];
    const std::uint8_t extension_flags = data[7];
    if (extension_version != kDeadlineExtensionVersion) return false;

    header.hasDeadline = true;
    std::memcpy(&header.deadline_ms, data + 8, sizeof(header.deadline_ms));
    std::memcpy(&header.ageMsAtSend, data + 12, sizeof(header.ageMsAtSend));
    header.headerSize = kPacketHeaderSize + kPacketHeaderExtensionSize;
    (void)extension_flags;
  }

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
  const std::size_t receive_window =
      std::max<std::uint32_t>(1, config_.receiveWindowSize);
  for (auto& channel_pending : pending_received_) {
    channel_pending.resize(receive_window);
  }
  next_fragment_group_id_.assign(n, 0);
  fragment_groups_.resize(n);
  send_buffer_.resize(config_.maxPacketSize);
  batch_buffer_.resize(config_.maxPacketSize);
  batch_scratch_buffer_.resize(config_.maxPacketSize);
  receive_buffer_.resize(config_.maxPacketSize);
  queued_acks_.reserve(std::max<std::uint16_t>(1, config_.maxBatchCommands));
  EnsureReceiveBatchBuffers();
  const auto pending_reserve =
      config_.sendWindowSize > 0 ? config_.sendWindowSize : 1024U;
  pending_packets_.reserve(pending_reserve);
  free_pending_slots_.reserve(pending_reserve);
  pending_by_sequence_.reserve(pending_reserve);
  pending_sequence_counts_.reserve(pending_reserve);

  // Initialize the congestion-control window.
  ssthresh_ = (config_.sendWindowSize > 0)
                  ? std::max(1u, config_.sendWindowSize / 2)
                  : 32;

  const auto now = std::chrono::steady_clock::now();
  last_send_time_ = now;
  last_receive_time_ = now;
  last_ping_time_ = now;
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
  ClearPendingPackets();
  for (auto& h : seq_window_high_) h = 0;
  for (auto& b : seq_window_bits_) b.reset();
  for (auto& pr : pending_received_) {
    for (auto& slot : pr) {
      slot.packet.data.Clear();
      slot.occupied = false;
    }
  }
  for (auto& fg : fragment_groups_) fg.clear();
}

void ReliableConnection::SetRemoteAddress(const SocketAddress& addr,
                                          std::uint16_t port) {
  remote_addr_ = addr;
  remote_port_ = port;
}

bool ReliableConnection::SendReliable(const std::uint8_t channel,
                                      const void* data, std::size_t size) {
  return SendReliableInternal(channel, data, size, 0);
}

bool ReliableConnection::SendUnreliable(const std::uint8_t channel,
                                        const void* data, std::size_t size) {
  return SendUnreliableInternal(channel, data, size, 0);
}

bool ReliableConnection::SendUnsequenced(const std::uint8_t channel,
                                         const void* data, std::size_t size) {
  return SendUnsequencedInternal(channel, data, size, 0);
}

bool ReliableConnection::SendReliableWithDeadline(const std::uint8_t channel,
                                                  const void* data,
                                                  std::size_t size,
                                                  std::uint32_t deadline_ms) {
  return SendReliableInternal(channel, data, size, deadline_ms);
}

bool ReliableConnection::SendUnreliableWithDeadline(const std::uint8_t channel,
                                                    const void* data,
                                                    std::size_t size,
                                                    std::uint32_t deadline_ms) {
  return SendUnreliableInternal(channel, data, size, deadline_ms);
}

bool ReliableConnection::SendUnsequencedWithDeadline(
    const std::uint8_t channel, const void* data, std::size_t size,
    std::uint32_t deadline_ms) {
  return SendUnsequencedInternal(channel, data, size, deadline_ms);
}

bool ReliableConnection::SendReliableInternal(const std::uint8_t channel,
                                              const void* data,
                                              std::size_t size,
                                              std::uint32_t deadline_ms) {
  if (state_ != ConnectionState::kConnected) return false;

  const auto now = std::chrono::steady_clock::now();
  DeadlineMetadata deadline;
  if (!PrepareDeadline(deadline_ms, deadline, now)) return false;

  // Congestion window check (only when send-window limiting is enabled)
  if (current_send_window_ > 0 &&
      pending_active_count_ >= current_send_window_) {
    return false;
  }

  const std::size_t max_payload = MaxPayloadForPacket(deadline.hasDeadline);

  if (max_payload == 0) return false;

  if (size > max_payload) {
    // Too large for one packet, split into Fragment packets.
    if (channel >= next_fragment_group_id_.size()) return false;
    return SendFragmented(channel, data, size, deadline);
  }

  std::uint32_t seq = GetNextSequence(channel);
  const auto pending_handle = AllocatePendingPacket(seq);
  PendingPacket* pending = GetPendingPacket(pending_handle);
  if (pending == nullptr) return false;
  if (data != nullptr && size > 0) {
    pending->data.Assign(static_cast<const std::uint8_t*>(data),
                         static_cast<const std::uint8_t*>(data) + size);
  }
  pending->sendTime = now;
  pending->channel = channel;
  pending->type = PacketType::kReliable;
  CopyDeadlineToPending(*pending, deadline);

  const void* payload = pending->data.Empty() ? nullptr : pending->data.Data();
  if (!SendPacket(PacketType::kReliable, channel, payload, pending->data.Size(),
                  seq, deadline, now)) {
    ErasePendingPacket(pending_handle);
    return false;
  }
  ScheduleRetry(pending_handle, now);

  return true;
}

bool ReliableConnection::SendUnreliableInternal(const std::uint8_t channel,
                                                const void* data,
                                                std::size_t size,
                                                std::uint32_t deadline_ms) {
  if (state_ != ConnectionState::kConnected) return false;

  const auto now = std::chrono::steady_clock::now();
  DeadlineMetadata deadline;
  if (!PrepareDeadline(deadline_ms, deadline, now)) return false;

  const std::size_t max_payload = MaxPayloadForPacket(deadline.hasDeadline);
  if (max_payload == 0 || size > max_payload) return false;

  if (!SendPacket(PacketType::kUnreliable, channel, data, size, 0, deadline,
                  now)) {
    return false;
  }
  return true;
}

bool ReliableConnection::SendUnsequencedInternal(const std::uint8_t channel,
                                                 const void* data,
                                                 std::size_t size,
                                                 std::uint32_t deadline_ms) {
  if (state_ != ConnectionState::kConnected) return false;

  const auto now = std::chrono::steady_clock::now();
  DeadlineMetadata deadline;
  if (!PrepareDeadline(deadline_ms, deadline, now)) return false;

  const std::size_t max_payload = MaxPayloadForPacket(deadline.hasDeadline);
  if (max_payload == 0 || size > max_payload) return false;

  std::uint32_t seq = GetNextSequence(channel);
  const auto pending_handle = AllocatePendingPacket(seq);
  PendingPacket* pending = GetPendingPacket(pending_handle);
  if (pending == nullptr) return false;
  if (data != nullptr && size > 0) {
    pending->data.Assign(static_cast<const std::uint8_t*>(data),
                         static_cast<const std::uint8_t*>(data) + size);
  }
  pending->sendTime = now;
  pending->channel = channel;
  pending->type = PacketType::kUnsequenced;
  CopyDeadlineToPending(*pending, deadline);

  const void* payload = pending->data.Empty() ? nullptr : pending->data.Data();
  if (!SendPacket(PacketType::kUnsequenced, channel, payload,
                  pending->data.Size(), seq, deadline, now)) {
    ErasePendingPacket(pending_handle);
    return false;
  }
  ScheduleRetry(pending_handle, now);

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

bool ReliableConnection::SendReliableWithDeadline(const std::uint8_t channel,
                                                  const BitStream& stream,
                                                  std::uint32_t deadline_ms) {
  return SendReliableWithDeadline(channel, stream.GetData(),
                                  stream.GetSizeBytes(), deadline_ms);
}

bool ReliableConnection::SendUnreliableWithDeadline(const std::uint8_t channel,
                                                    const BitStream& stream,
                                                    std::uint32_t deadline_ms) {
  return SendUnreliableWithDeadline(channel, stream.GetData(),
                                    stream.GetSizeBytes(), deadline_ms);
}

bool ReliableConnection::SendUnsequencedWithDeadline(
    const std::uint8_t channel, const BitStream& stream,
    std::uint32_t deadline_ms) {
  return SendUnsequencedWithDeadline(channel, stream.GetData(),
                                     stream.GetSizeBytes(), deadline_ms);
}

void ReliableConnection::Update() {
  auto now = std::chrono::steady_clock::now();

  // Retry pending packets
  RetryPendingPackets(now);

  // Send periodic ping
  if (state_ == ConnectionState::kConnected) {
    auto time_since_ping =
        std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                              last_ping_time_)
            .count();
    if (std::cmp_greater(time_since_ping, config_.pingIntervalMs)) {
      SendPing(now);
      last_ping_time_ = now;
    }
  }

  CheckTimeout(now);

  ProcessPendingReliable(now);

  CleanupFragments(now);

  (void)FlushQueuedAcks(now);
}

void ReliableConnection::ProcessPacket(const void* data, std::size_t size,
                                       const SocketAddress& from,
                                       std::uint16_t from_port) {
  if (size < kPacketHeaderSize) return;

  const auto* packet_data = static_cast<const std::uint8_t*>(data);

  ParsedPacketHeader header;
  if (!ReadPacketHeader(packet_data, size, header)) return;

  if (header.type == PacketType::kBatch) {
    if (SecureMode()) return;
    ProcessBatchPacket(packet_data + header.headerSize,
                       size - header.headerSize, from, from_port);
    return;
  }

  ProcessSinglePacket(packet_data, size, header.type, header.channel,
                      header.sequence, header.hasDeadline, header.deadline_ms,
                      header.ageMsAtSend, header.headerSize, from, from_port);
}

void ReliableConnection::ProcessSinglePacket(
    const std::uint8_t* packet_data, std::size_t size, PacketType type,
    std::uint8_t channel, std::uint32_t sequence, bool has_deadline,
    std::uint32_t deadline_ms, std::uint32_t age_ms_at_send,
    std::size_t header_size, const SocketAddress& from,
    std::uint16_t from_port) {
  const std::uint8_t* payload_data = packet_data + header_size;
  std::size_t payload_size = size - header_size;
  BitStream decrypted_payload;

  if (SecureMode() && type != PacketType::kConnect &&
      type != PacketType::kAccept) {
    if (!crypto_ready_) return;

    const auto decrypt_result =
        crypto_context_.Decrypt(payload_data, payload_size, packet_data,
                                header_size, decrypted_payload);
    if (!decrypt_result.ok) return;

    payload_data = decrypted_payload.GetData();
    payload_size = decrypted_payload.GetSizeBytes();
  }

  const auto now = std::chrono::steady_clock::now();
  last_receive_time_ = now;
  stats_received_packets_++;
  const bool deadline_expired =
      config_.deadlinesEnabled && config_.dropExpiredOnReceive &&
      has_deadline && deadline_ms > 0 && age_ms_at_send >= deadline_ms;

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
                           server_hello.GetSizeBytes(), 0, DeadlineMetadata{},
                           now);
        } else {
          state_ = ConnectionState::kConnected;
          (void)SendPacket(PacketType::kAccept, 0, nullptr, 0, 0,
                           DeadlineMetadata{}, now);
        }

        if (event_handler_ != nullptr) event_handler_->OnConnected();
      } else if (state_ == ConnectionState::kConnected &&
                 remote_port_ == from_port && remote_addr_ == from &&
                 !SecureMode()) {
        (void)SendPacket(PacketType::kAccept, 0, nullptr, 0, 0,
                         DeadlineMetadata{}, now);
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
      (void)SendPacket(PacketType::kPong, 0, nullptr, 0, sequence,
                       DeadlineMetadata{}, now);
      break;
    }

    case PacketType::kPong: {
      // Calculate RTT
      const PendingPacket* pending =
          GetPendingPacket(FindPendingPacket(sequence));
      if (pending != nullptr) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           now - pending->sendTime)
                           .count();
        rtt_ = rtt_ * 0.9f + static_cast<float>(elapsed) *
                                 0.1f;  // Exponential moving average
      }
      break;
    }

    case PacketType::kAck: {
      // Remove acknowledged packet from pending list
      auto pending_handle = FindPendingPacket(sequence);
      const PendingPacket* pending = GetPendingPacket(pending_handle);

      if (pending != nullptr) {
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                           now - pending->sendTime)
                           .count();
        rtt_ = rtt_ * 0.9f + static_cast<float>(elapsed) * 0.1f;

        ErasePendingPacket(pending_handle);
      }
      break;
    }

    case PacketType::kReliable: {
      if (deadline_expired) {
        if (config_.ackExpiredReliable) SendAck(sequence, now);
        ++stats_deadline_receive_drops_;
        break;
      }

      // Check for duplicate
      if (IsDuplicateSequence(channel, sequence)) {
        SendAck(sequence, now);
        return;  // Already processed
      }

      MarkSequenceReceived(channel, sequence);

      if (channel >= pending_received_.size()) break;

      if (sequence == receive_sequence_.at(channel)) {
        SendAck(sequence, now);
        if (event_handler_ != nullptr) {
          event_handler_->OnReliableReceived(channel, payload_data,
                                             payload_size);
        }
        ++receive_sequence_.at(channel);
        ProcessPendingReliableChannel(channel, now);
        break;
      }

      // Store for ordered processing
      auto& pending_channel = pending_received_.at(channel);
      const auto& expected_sequence = receive_sequence_.at(channel);
      if (pending_channel.empty() ||
          !IsSequenceNewer(sequence, expected_sequence)) {
        break;
      }
      const std::uint32_t distance = sequence - expected_sequence;
      if (distance >= pending_channel.size()) {
        break;
      }

      ReceivedSlot& slot =
          pending_channel.at(sequence % pending_channel.size());
      if (slot.occupied && slot.packet.sequence != sequence) {
        break;
      }

      slot.packet.sequence = sequence;
      if (payload_size > 0) {
        slot.packet.data.Assign(payload_data, payload_data + payload_size);
      } else {
        slot.packet.data.Clear();
      }
      slot.packet.channel = channel;
      slot.occupied = true;

      break;
    }

    case PacketType::kUnsequenced: {
      if (deadline_expired) {
        if (config_.ackExpiredReliable) SendAck(sequence, now);
        ++stats_deadline_receive_drops_;
        break;
      }

      // Send ACK
      SendAck(sequence, now);

      // Check for duplicate
      if (IsDuplicateSequence(channel, sequence)) return;

      MarkSequenceReceived(channel, sequence);

      if (event_handler_ != nullptr) {
        event_handler_->OnReliableReceived(channel, payload_data, payload_size);
      }

      break;
    }

    case PacketType::kUnreliable: {
      if (deadline_expired) {
        ++stats_deadline_receive_drops_;
        break;
      }

      if (event_handler_ != nullptr) {
        event_handler_->OnUnreliableReceived(channel, payload_data,
                                             payload_size);
      }

      break;
    }

    case PacketType::kFragment: {
      if (deadline_expired) {
        if (config_.ackExpiredReliable) SendAck(sequence, now);
        ++stats_deadline_receive_drops_;
        break;
      }

      // ACK each fragment individually so it can be retried if lost
      SendAck(sequence, now);

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
        fg.firstReceived = now;
        if (config_.deadlinesEnabled && has_deadline &&
            deadline_ms > age_ms_at_send) {
          fg.hasDeadline = true;
          fg.expireTime =
              now + std::chrono::milliseconds(deadline_ms - age_ms_at_send);
        }
        fg.channel = channel;
        it = groups.emplace(group_id, std::move(fg)).first;
      } else if (config_.deadlinesEnabled && has_deadline &&
                 deadline_ms > age_ms_at_send) {
        const auto fragment_expire_time =
            now + std::chrono::milliseconds(deadline_ms - age_ms_at_send);
        FragmentGroup& existing = it->second;
        if (!existing.hasDeadline ||
            fragment_expire_time < existing.expireTime) {
          existing.hasDeadline = true;
          existing.expireTime = fragment_expire_time;
        }
      }

      FragmentGroup& fg = it->second;
      if (fg.hasDeadline && now >= fg.expireTime) {
        ++stats_deadline_receive_drops_;
        ++stats_deadline_expired_fragment_groups_;
        groups.erase(it);
        break;
      }

      if (frag_index < fg.pieces.size() &&
          !fg.pieces.at(frag_index).has_value()) {
        fg.pieces.at(frag_index) = std::move(payload);
        ++fg.receivedCount;
      }

      if (fg.receivedCount == fg.total) {
        if (fg.hasDeadline && now >= fg.expireTime) {
          ++stats_deadline_receive_drops_;
          ++stats_deadline_expired_fragment_groups_;
          groups.erase(it);
          break;
        }

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
  const DeadlineMetadata deadline;
  return SendPacket(type, channel, data, size, sequence, deadline);
}

bool ReliableConnection::SendPacket(PacketType type, std::uint8_t channel,
                                    const void* data, std::size_t size,
                                    std::uint32_t sequence,
                                    const DeadlineMetadata& deadline) {
  const auto now = std::chrono::steady_clock::now();
  return SendPacket(type, channel, data, size, sequence, deadline, now);
}

bool ReliableConnection::SendPacket(PacketType type, std::uint8_t channel,
                                    const void* data, std::size_t size,
                                    std::uint32_t sequence,
                                    const DeadlineMetadata& deadline,
                                    std::chrono::steady_clock::time_point now) {
  if (type == PacketType::kAck && CanBatchPacket(type)) {
    QueueAck(sequence, now);
    return true;
  }

  if (!CanBatchPacket(type) || queued_acks_.empty()) {
    return SendSinglePacket(type, channel, data, size, sequence, deadline, now);
  }

  std::size_t command_size = 0;
  if (!BuildPacket(type, channel, data, size, sequence, deadline, now,
                   batch_scratch_buffer_, command_size)) {
    return false;
  }

  if (SendBatchWithCommand(batch_scratch_buffer_.data(), command_size, now)) {
    return true;
  }

  if (!FlushQueuedAcks(now)) return false;
  return SendSinglePacket(type, channel, data, size, sequence, deadline, now);
}

bool ReliableConnection::SendSinglePacket(
    PacketType type, std::uint8_t channel, const void* data, std::size_t size,
    std::uint32_t sequence, const DeadlineMetadata& deadline,
    std::chrono::steady_clock::time_point now) {
  std::size_t packet_size = 0;
  if (!BuildPacket(type, channel, data, size, sequence, deadline, now,
                   send_buffer_, packet_size)) {
    return false;
  }
  return SendRawDatagram(send_buffer_.data(), packet_size, now);
}

bool ReliableConnection::BuildPacket(PacketType type, std::uint8_t channel,
                                     const void* data, std::size_t size,
                                     std::uint32_t sequence,
                                     const DeadlineMetadata& deadline,
                                     std::chrono::steady_clock::time_point now,
                                     std::vector<std::uint8_t>& buffer,
                                     std::size_t& packet_size) {
  if (DeadlineExpired(deadline, now)) {
    ++stats_deadline_send_drops_;
    return false;
  }

  const std::size_t header_size = PacketHeaderSize(deadline.hasDeadline);
  if (buffer.size() < config_.maxPacketSize) {
    buffer.resize(config_.maxPacketSize);
  }
  if (header_size > buffer.size()) return false;

  const std::size_t written_header_size = WritePacketHeader(
      buffer.data(), type, channel, sequence, deadline.hasDeadline,
      deadline.deadline_ms, deadline.createdTime, now);
  packet_size = written_header_size;

  if (ShouldEncryptPacket(type)) {
    BitStream encrypted;
    const auto* payload = static_cast<const std::uint8_t*>(data);
    const auto result = crypto_context_.Encrypt(payload, size, buffer.data(),
                                                written_header_size, encrypted);
    if (!result.ok) return false;
    if (packet_size + encrypted.GetSizeBytes() > buffer.size()) {
      return false;
    }
    std::memcpy(buffer.data() + packet_size, encrypted.GetData(),
                encrypted.GetSizeBytes());
    packet_size += encrypted.GetSizeBytes();
  } else if (data != nullptr && size > 0) {
    if (packet_size + size > buffer.size()) return false;
    std::memcpy(buffer.data() + packet_size, data, size);
    packet_size += size;
  }

  return true;
}

bool ReliableConnection::SendRawDatagram(
    const std::uint8_t* data, std::size_t size,
    std::chrono::steady_clock::time_point now, std::uint32_t logical_packets) {
  if (data == nullptr || size == 0) return false;

  const SocketResult result =
      socket_->SendTo(data, size, remote_addr_, remote_port_);
  if (result.Failed()) return false;
  last_send_time_ = now;
  stats_sent_packets_ += logical_packets;
  return true;
}

bool ReliableConnection::CanBatchPacket(PacketType type) const {
  if (!config_.enablePacketBatching || SecureMode()) return false;
  switch (type) {
    case PacketType::kAck:
    case PacketType::kPing:
    case PacketType::kPong:
    case PacketType::kReliable:
    case PacketType::kUnreliable:
    case PacketType::kUnsequenced:
    case PacketType::kFragment:
      return true;
    default:
      return false;
  }
}

bool ReliableConnection::SendBatchWithCommand(
    const std::uint8_t* command, std::size_t command_size,
    std::chrono::steady_clock::time_point now) {
  if (queued_acks_.empty()) return false;

  const std::uint16_t max_commands = std::clamp<std::uint16_t>(
      config_.maxBatchCommands, 1, kMaxBatchCommandsHardLimit);
  const std::size_t max_size = config_.maxPacketSize;
  if (batch_buffer_.size() < max_size) batch_buffer_.resize(max_size);

  const std::size_t batch_header_size = WritePacketHeader(
      batch_buffer_.data(), PacketType::kBatch, 0, 0, false, 0, {}, now);
  if (batch_header_size + sizeof(std::uint16_t) > max_size) return false;

  std::size_t offset = batch_header_size + sizeof(std::uint16_t);
  std::uint16_t command_count = 0;

  auto append_command = [&](const std::uint8_t* src,
                            std::size_t src_size) -> bool {
    if (command_count >= max_commands ||
        src_size > std::numeric_limits<std::uint16_t>::max() ||
        offset + sizeof(std::uint16_t) + src_size > max_size) {
      return false;
    }
    WriteU16(batch_buffer_.data() + offset,
             static_cast<std::uint16_t>(src_size));
    offset += sizeof(std::uint16_t);
    std::memcpy(batch_buffer_.data() + offset, src, src_size);
    offset += src_size;
    ++command_count;
    return true;
  };

  for (const std::uint32_t ack_sequence : queued_acks_) {
    std::size_t ack_size = 0;
    if (!BuildPacket(PacketType::kAck, 0, nullptr, 0, ack_sequence,
                     DeadlineMetadata{}, now, send_buffer_, ack_size)) {
      return false;
    }
    if (!append_command(send_buffer_.data(), ack_size)) return false;
  }

  if (!append_command(command, command_size)) return false;

  WriteU16(batch_buffer_.data() + batch_header_size, command_count);
  if (!SendRawDatagram(batch_buffer_.data(), offset, now, command_count)) {
    return false;
  }

  queued_acks_.clear();
  return true;
}

bool ReliableConnection::FlushQueuedAcks(
    std::chrono::steady_clock::time_point now) {
  while (!queued_acks_.empty()) {
    if (queued_acks_.size() == 1) {
      const std::uint32_t sequence = queued_acks_.front();
      std::size_t ack_size = 0;
      if (!BuildPacket(PacketType::kAck, 0, nullptr, 0, sequence,
                       DeadlineMetadata{}, now, send_buffer_, ack_size)) {
        return false;
      }
      if (!SendRawDatagram(send_buffer_.data(), ack_size, now)) return false;
      queued_acks_.clear();
      return true;
    }

    const std::uint16_t max_commands = std::clamp<std::uint16_t>(
        config_.maxBatchCommands, 1, kMaxBatchCommandsHardLimit);
    const std::size_t max_size = config_.maxPacketSize;
    if (batch_buffer_.size() < max_size) batch_buffer_.resize(max_size);

    const std::size_t batch_header_size = WritePacketHeader(
        batch_buffer_.data(), PacketType::kBatch, 0, 0, false, 0, {}, now);
    if (batch_header_size + sizeof(std::uint16_t) > max_size) return false;

    std::size_t offset = batch_header_size + sizeof(std::uint16_t);
    std::uint16_t command_count = 0;
    std::size_t consumed = 0;

    for (const std::uint32_t ack_sequence : queued_acks_) {
      if (command_count >= max_commands) break;

      std::size_t ack_size = 0;
      if (!BuildPacket(PacketType::kAck, 0, nullptr, 0, ack_sequence,
                       DeadlineMetadata{}, now, send_buffer_, ack_size)) {
        return false;
      }
      if (offset + sizeof(std::uint16_t) + ack_size > max_size) break;

      WriteU16(batch_buffer_.data() + offset,
               static_cast<std::uint16_t>(ack_size));
      offset += sizeof(std::uint16_t);
      std::memcpy(batch_buffer_.data() + offset, send_buffer_.data(), ack_size);
      offset += ack_size;
      ++command_count;
      ++consumed;
    }

    if (command_count == 0) return false;

    WriteU16(batch_buffer_.data() + batch_header_size, command_count);
    if (!SendRawDatagram(batch_buffer_.data(), offset, now, command_count)) {
      return false;
    }

    queued_acks_.erase(
        queued_acks_.begin(),
        queued_acks_.begin() + static_cast<std::ptrdiff_t>(consumed));
  }

  return true;
}

void ReliableConnection::QueueAck(std::uint32_t sequence,
                                  std::chrono::steady_clock::time_point now) {
  if (!CanBatchPacket(PacketType::kAck)) {
    (void)SendSinglePacket(PacketType::kAck, 0, nullptr, 0, sequence,
                           DeadlineMetadata{}, now);
    return;
  }

  if (std::ranges::find(queued_acks_, sequence) == queued_acks_.end()) {
    queued_acks_.push_back(sequence);
  }

  const std::uint16_t max_commands = std::clamp<std::uint16_t>(
      config_.maxBatchCommands, 1, kMaxBatchCommandsHardLimit);
  if (queued_acks_.size() >= max_commands) {
    (void)FlushQueuedAcks(now);
  }
}

void ReliableConnection::ProcessBatchPacket(const std::uint8_t* payload,
                                            std::size_t size,
                                            const SocketAddress& from,
                                            std::uint16_t from_port) {
  if (payload == nullptr || size < sizeof(std::uint16_t)) return;

  const std::uint16_t command_count = ReadU16(payload);
  const std::uint16_t max_commands = std::clamp<std::uint16_t>(
      config_.maxBatchCommands, 1, kMaxBatchCommandsHardLimit);
  if (command_count == 0 || command_count > max_commands) return;

  std::size_t offset = sizeof(std::uint16_t);
  for (std::uint16_t i = 0; i < command_count; ++i) {
    if (offset + sizeof(std::uint16_t) > size) return;

    const std::uint16_t command_size = ReadU16(payload + offset);
    offset += sizeof(std::uint16_t);
    if (command_size < kPacketHeaderSize || offset + command_size > size) {
      return;
    }

    ParsedPacketHeader command_header;
    if (!ReadPacketHeader(payload + offset, command_size, command_header)) {
      return;
    }
    if (command_header.type == PacketType::kBatch) return;

    ProcessSinglePacket(payload + offset, command_size, command_header.type,
                        command_header.channel, command_header.sequence,
                        command_header.hasDeadline, command_header.deadline_ms,
                        command_header.ageMsAtSend, command_header.headerSize,
                        from, from_port);
    offset += command_size;
  }
}

bool ReliableConnection::SendFragmented(std::uint8_t channel, const void* data,
                                        std::size_t size,
                                        const DeadlineMetadata& deadline) {
  if (channel >= next_fragment_group_id_.size()) return false;

  const std::size_t max_frag_payload =
      MaxPayloadForPacket(deadline.hasDeadline, kFragmentHeaderExtra);
  if (max_frag_payload == 0) return false;
  const std::size_t frag_total_size =
      (size + max_frag_payload - 1) / max_frag_payload;
  if (frag_total_size > std::numeric_limits<std::uint16_t>::max()) return false;

  const auto frag_total = static_cast<std::uint16_t>(frag_total_size);
  const std::uint16_t group_id = next_fragment_group_id_.at(channel)++;
  const auto* src = static_cast<const std::uint8_t*>(data);

  for (std::uint16_t i = 0; i < frag_total; ++i) {
    const auto now = std::chrono::steady_clock::now();
    if (DeadlineExpired(deadline, now)) {
      ++stats_deadline_send_drops_;
      return false;
    }

    const std::size_t offset = i * max_frag_payload;
    const std::size_t frag_size = std::min(max_frag_payload, size - offset);
    const std::uint32_t seq = GetNextSequence(channel);
    const auto pending_handle = AllocatePendingPacket(seq);
    PendingPacket* pending = GetPendingPacket(pending_handle);
    if (pending == nullptr) return false;

    // Layout: [groupId:2][fragIndex:2][fragTotal:2][payload...]
    pending->data.Resize(6 + frag_size);
    std::memcpy(pending->data.Data() + 0, &group_id, 2);
    std::memcpy(pending->data.Data() + 2, &i, 2);
    std::memcpy(pending->data.Data() + 4, &frag_total, 2);
    std::memcpy(pending->data.Data() + 6, src + offset, frag_size);

    pending->sendTime = now;
    pending->channel = channel;
    pending->type = PacketType::kFragment;
    CopyDeadlineToPending(*pending, deadline);

    if (!SendPacket(PacketType::kFragment, channel, pending->data.Data(),
                    pending->data.Size(), seq, deadline, now)) {
      ErasePendingPacket(pending_handle);
      return false;
    }
    ScheduleRetry(pending_handle, now);
  }

  return true;
}

void ReliableConnection::CleanupFragments(
    std::chrono::steady_clock::time_point now) {
  for (auto& ch_groups : fragment_groups_) {
    for (auto it = ch_groups.begin(); it != ch_groups.end();) {
      const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
              now - it->second.firstReceived)
              .count();
      const bool deadline_expired =
          it->second.hasDeadline && now >= it->second.expireTime;
      const bool fragment_timeout =
          std::cmp_greater(elapsed, config_.fragmentTimeoutMs);

      if (deadline_expired || fragment_timeout) {
        if (deadline_expired) {
          ++stats_deadline_expired_fragment_groups_;
        }
        it = ch_groups.erase(it);
      } else {
        ++it;
      }
    }
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
    bool has_deadline, std::size_t header_extra) const {
  const std::size_t overhead =
      PacketHeaderSize(has_deadline) + header_extra + CryptoEnvelopeOverhead();
  if (config_.maxPacketSize < overhead) return 0;
  return config_.maxPacketSize - overhead;
}

bool ReliableConnection::PrepareDeadline(
    std::uint32_t deadline_ms, DeadlineMetadata& deadline,
    std::chrono::steady_clock::time_point now) const {
  deadline = {};
  if (deadline_ms == 0) return true;
  if (!config_.deadlinesEnabled) return false;
  if (deadline_ms > config_.maxdeadline_ms) return false;

  deadline.hasDeadline = true;
  deadline.deadline_ms = deadline_ms;
  deadline.createdTime = now;
  deadline.expireTime = now + std::chrono::milliseconds(deadline_ms);
  return true;
}

bool ReliableConnection::DeadlineExpired(
    const DeadlineMetadata& deadline,
    std::chrono::steady_clock::time_point now) {
  return deadline.hasDeadline && now >= deadline.expireTime;
}

void ReliableConnection::CopyDeadlineToPending(
    PendingPacket& pending, const DeadlineMetadata& deadline) {
  pending.hasDeadline = deadline.hasDeadline;
  pending.deadline_ms = deadline.deadline_ms;
  pending.createdTime = deadline.createdTime;
  pending.expireTime = deadline.expireTime;
}

ReliableConnection::PendingHandle ReliableConnection::AllocatePendingPacket(
    std::uint32_t sequence) {
  std::size_t index = 0;
  if (!free_pending_slots_.empty()) {
    index = free_pending_slots_.back();
    free_pending_slots_.pop_back();
  } else {
    index = pending_packets_.size();
    pending_packets_.emplace_back();
  }

  PendingSlot& slot = pending_packets_.at(index);
  slot.active = true;
  ++slot.generation;
  if (slot.generation == 0) ++slot.generation;
  ResetPendingPacketForReuse(slot.packet, sequence);

  const PendingHandle handle{index, slot.generation};
  ++pending_active_count_;
  ++pending_sequence_counts_[sequence];
  if (pending_by_sequence_.find(sequence) == pending_by_sequence_.end()) {
    pending_by_sequence_.emplace(sequence, handle);
  }
  return handle;
}

void ReliableConnection::ResetPendingPacketForReuse(PendingPacket& pending,
                                                    std::uint32_t sequence) {
  pending.sequence = sequence;
  pending.data.Clear();
  pending.sendTime = {};
  pending.retries = 0;
  pending.channel = 0;
  pending.type = PacketType::kReliable;
  pending.createdTime = {};
  pending.deadline_ms = 0;
  pending.expireTime = {};
  pending.hasDeadline = false;
}

void ReliableConnection::ErasePendingPacket(PendingHandle handle) {
  if (!IsPendingHandleValid(handle)) return;

  PendingSlot& slot = pending_packets_.at(handle.index);
  const std::uint32_t sequence = slot.packet.sequence;
  const auto indexed = pending_by_sequence_.find(sequence);
  const bool erased_indexed = indexed != pending_by_sequence_.end() &&
                              indexed->second.index == handle.index &&
                              indexed->second.generation == handle.generation;
  const auto count_it = pending_sequence_counts_.find(sequence);
  const bool has_sequence_collision =
      count_it != pending_sequence_counts_.end() && count_it->second > 1;

  slot.active = false;
  if (pending_active_count_ > 0) --pending_active_count_;
  if (count_it != pending_sequence_counts_.end()) {
    if (count_it->second > 1) {
      --count_it->second;
    } else {
      pending_sequence_counts_.erase(count_it);
    }
  }

  if (erased_indexed) {
    pending_by_sequence_.erase(indexed);
    if (has_sequence_collision) {
      for (std::size_t index = 0; index < pending_packets_.size(); ++index) {
        const PendingSlot& candidate = pending_packets_.at(index);
        if (!candidate.active || (index == handle.index &&
                                  candidate.generation == handle.generation)) {
          continue;
        }
        if (candidate.packet.sequence == sequence) {
          pending_by_sequence_.emplace(
              sequence, PendingHandle{index, candidate.generation});
          break;
        }
      }
    }
  }

  free_pending_slots_.push_back(handle.index);
}

PendingPacket* ReliableConnection::GetPendingPacket(PendingHandle handle) {
  if (!IsPendingHandleValid(handle)) return nullptr;
  return &pending_packets_.at(handle.index).packet;
}

const PendingPacket* ReliableConnection::GetPendingPacket(
    PendingHandle handle) const {
  if (!IsPendingHandleValid(handle)) return nullptr;
  return &pending_packets_.at(handle.index).packet;
}

ReliableConnection::PendingHandle ReliableConnection::FindPendingPacket(
    std::uint32_t sequence) const {
  const auto it = pending_by_sequence_.find(sequence);
  return it == pending_by_sequence_.end() ? PendingHandle{} : it->second;
}

bool ReliableConnection::IsPendingHandleValid(PendingHandle handle) const {
  if (handle.index == std::numeric_limits<std::size_t>::max() ||
      handle.index >= pending_packets_.size()) {
    return false;
  }
  const PendingSlot& slot = pending_packets_.at(handle.index);
  return slot.active && slot.generation == handle.generation;
}

void ReliableConnection::ClearPendingPackets() {
  pending_packets_.clear();
  pending_order_.clear();
  pending_retry_order_.clear();
  free_pending_slots_.clear();
  pending_by_sequence_.clear();
  pending_sequence_counts_.clear();
  retry_heap_ = {};
  pending_active_count_ = 0;
}

void ReliableConnection::SendAck(std::uint32_t sequence) {
  (void)SendPacket(PacketType::kAck, 0, nullptr, 0, sequence);
}

void ReliableConnection::SendAck(std::uint32_t sequence,
                                 std::chrono::steady_clock::time_point now) {
  (void)SendPacket(PacketType::kAck, 0, nullptr, 0, sequence,
                   DeadlineMetadata{}, now);
}

void ReliableConnection::SendPing() {
  SendPing(std::chrono::steady_clock::now());
}

void ReliableConnection::SendPing(std::chrono::steady_clock::time_point now) {
  std::uint32_t seq = GetNextSequence(0);
  if (!SendPacket(PacketType::kPing, 0, nullptr, 0, seq, DeadlineMetadata{},
                  now)) {
    return;
  }

  // Store as pending to measure RTT
  const auto pending_handle = AllocatePendingPacket(seq);
  PendingPacket* pending = GetPendingPacket(pending_handle);
  if (pending == nullptr) return;
  pending->sendTime = now;
  pending->type = PacketType::kPing;
  ScheduleRetry(pending_handle, now);
}

void ReliableConnection::ProcessPendingReliable(
    std::chrono::steady_clock::time_point now) {
  // Process packets in order for each channel independently
  for (std::uint8_t ch = 0;
       ch < static_cast<std::uint8_t>(receive_sequence_.size()); ++ch) {
    ProcessPendingReliableChannel(ch, now);
  }
}

void ReliableConnection::ProcessPendingReliableChannel(
    std::uint8_t channel, std::chrono::steady_clock::time_point now) {
  if (channel >= pending_received_.size() ||
      channel >= receive_sequence_.size()) {
    return;
  }

  auto& pending_channel = pending_received_.at(channel);
  auto& expected_sequence = receive_sequence_.at(channel);
  while (true) {
    if (pending_channel.empty()) break;
    ReceivedSlot& slot =
        pending_channel.at(expected_sequence % pending_channel.size());
    if (!slot.occupied || slot.packet.sequence != expected_sequence) {
      break;  // Next expected packet not yet received
    }

    SendAck(slot.packet.sequence, now);
    if (event_handler_ != nullptr) {
      event_handler_->OnReliableReceived(slot.packet.channel,
                                         slot.packet.data.Data(),
                                         slot.packet.data.Size());
    }

    slot.packet.data.Clear();
    slot.occupied = false;
    ++expected_sequence;
  }
}

void ReliableConnection::RetryPendingPackets(
    std::chrono::steady_clock::time_point now) {
  while (!retry_heap_.empty()) {
    const RetryEntry entry = retry_heap_.top();
    PendingPacket* pending_packet = GetPendingPacket(entry.handle);
    if (pending_packet == nullptr ||
        pending_packet->retries != entry.retryGeneration) {
      retry_heap_.pop();
      continue;
    }
    if (now < entry.dueTime) break;

    retry_heap_.pop();

    const PendingHandle handle = entry.handle;
    pending_packet = GetPendingPacket(handle);
    if (pending_packet == nullptr) {
      continue;
    }

    PendingPacket& pending = *pending_packet;
    if (pending.hasDeadline && now >= pending.expireTime) {
      ++stats_deadline_retries_prevented_;
      ErasePendingPacket(handle);
      continue;
    }

    if (pending.retries >= config_.maxRetries) {
      // Packet lost
      stats_lost_packets_++;
      ErasePendingPacket(handle);
      continue;
    }

    const void* payload = pending.data.Empty() ? nullptr : pending.data.Data();
    DeadlineMetadata deadline;
    deadline.hasDeadline = pending.hasDeadline;
    deadline.deadline_ms = pending.deadline_ms;
    deadline.createdTime = pending.createdTime;
    deadline.expireTime = pending.expireTime;

    if (SendPacket(pending.type, pending.channel, payload, pending.data.Size(),
                   pending.sequence, deadline, now)) {
      pending.sendTime = now;
      pending.retries++;
      ScheduleRetry(handle, now);
    } else if (pending.hasDeadline && DeadlineExpired(deadline, now)) {
      ++stats_deadline_retries_prevented_;
      ErasePendingPacket(handle);
      continue;
    } else {
      ScheduleRetry(handle, now);
    }
  }
}

void ReliableConnection::ScheduleRetry(
    PendingHandle handle, std::chrono::steady_clock::time_point now) {
  const PendingPacket* pending = GetPendingPacket(handle);
  if (pending == nullptr) return;

  const auto due_time = now + std::chrono::milliseconds(config_.retryTimeoutMs);
  retry_heap_.push(RetryEntry{due_time, handle, pending->retries});
}

void ReliableConnection::EnsureReceiveBatchBuffers() {
  if (receive_batch_buffers_.size() != kReceiveBatchSize) {
    receive_batch_buffers_.resize(kReceiveBatchSize);
    receive_batch_.resize(kReceiveBatchSize);
  }

  for (std::size_t i = 0; i < kReceiveBatchSize; ++i) {
    auto& buffer = receive_batch_buffers_.at(i);
    if (buffer.size() < config_.maxPacketSize) {
      buffer.resize(config_.maxPacketSize);
    }
    receive_batch_.at(i).data = buffer.data();
    receive_batch_.at(i).capacity = buffer.size();
    receive_batch_.at(i).result = {};
  }
}

void ReliableConnection::CheckTimeout(
    std::chrono::steady_clock::time_point now) {
  if (state_ != ConnectionState::kConnected) return;

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
  // Don't call Disconnect() which may trigger callbacks during destruction
  // Just clean up resources directly
  state_ = ConnectionState::kDisconnected;
  ClearPendingPackets();
  for (auto& h : seq_window_high_) h = 0;
  for (auto& b : seq_window_bits_) b.reset();
  for (auto& pr : pending_received_) {
    for (auto& slot : pr) {
      slot.packet.data.Clear();
      slot.occupied = false;
    }
  }
  for (auto& fg : fragment_groups_) fg.clear();
}

ConnectionManager::ConnectionManager(ISocket* socket,
                                     const ReliableConnectionConfig& cfg)
    : socket_(socket), config_(cfg) {
  receive_buffer_.resize(config_.maxPacketSize);
  receive_batch_buffers_.resize(kReceiveBatchSize);
  receive_batch_.resize(kReceiveBatchSize);
  for (std::size_t i = 0; i < kReceiveBatchSize; ++i) {
    receive_batch_buffers_.at(i).resize(config_.maxPacketSize);
    receive_batch_.at(i).data = receive_batch_buffers_.at(i).data();
    receive_batch_.at(i).capacity = receive_batch_buffers_.at(i).size();
  }
}

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
  const auto key = MakeAddressKey(from, from_port);
  const auto known_it = client_map_.find(key);
  const bool is_known = known_it != client_map_.end();

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

  RemoteClient* client =
      is_known ? known_it->second : FindOrCreateClient(from, from_port);
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

ConnectionManager::ConnectionKey ConnectionManager::MakeAddressKey(
    const SocketAddress& addr, std::uint16_t port) {
  ConnectionKey key;
  key.isIPv6 = addr.isIPv6;
  key.port = port;
  if (addr.isIPv6) {
    key.ipv6 = addr.ipv6.bytes;
    key.scopeId = addr.ipv6.scopeId;
  } else {
    key.ipv4 = addr.ipv4.hostOrderAddress;
  }
  return key;
}

void ReliableConnection::Tick() {
  while (true) {
    EnsureReceiveBatchBuffers();
    const std::size_t received = socket_->ReceiveMany(receive_batch_);
    if (received == 0) break;

    for (std::size_t i = 0; i < received; ++i) {
      const IncomingDatagram& datagram = receive_batch_.at(i);
      if (datagram.result.bytes > 0) {
        ProcessPacket(receive_batch_buffers_.at(i).data(),
                      static_cast<std::size_t>(datagram.result.bytes),
                      datagram.fromAddr, datagram.fromPort);
      }
    }

    if (received < receive_batch_.size()) break;
  }

  Update();
}

void ConnectionManager::Tick() {
  while (true) {
    for (std::size_t i = 0; i < receive_batch_buffers_.size(); ++i) {
      auto& buffer = receive_batch_buffers_.at(i);
      if (buffer.size() < config_.maxPacketSize) {
        buffer.resize(config_.maxPacketSize);
      }
      receive_batch_.at(i).data = buffer.data();
      receive_batch_.at(i).capacity = buffer.size();
      receive_batch_.at(i).result = {};
    }

    const std::size_t received = socket_->ReceiveMany(receive_batch_);
    if (received == 0) break;

    for (std::size_t i = 0; i < received; ++i) {
      const IncomingDatagram& datagram = receive_batch_.at(i);
      if (datagram.result.bytes > 0) {
        ProcessPacket(receive_batch_buffers_.at(i).data(),
                      static_cast<std::size_t>(datagram.result.bytes),
                      datagram.fromAddr, datagram.fromPort);
      }
    }

    if (received < receive_batch_.size()) break;
  }

  Update();
}

}  // namespace socketwire
