#include "reliable_connection.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <utility>
#include <vector>

namespace socketwire {
namespace {

constexpr std::size_t kReceiveBatchSize = 32;

std::span<const std::uint8_t> AsBytes(const void* data, std::size_t size) {
  if (data == nullptr || size == 0) return {};
  return {static_cast<const std::uint8_t*>(data), size};
}

std::size_t DecodedHeaderSize(const detail::DecodedPacket& packet) {
  return detail::PacketCodec::kBaseHeaderSize +
         (packet.hasDeadline ? detail::PacketCodec::kDeadlineExtensionSize
                             : std::size_t{0}) +
         (packet.fragment.hasFragment
            ? detail::PacketCodec::kFragmentExtensionSize
            : std::size_t{0});
}

bool SameEndpoint(const SocketAddress& lhs_addr, std::uint16_t lhs_port,
                  const SocketAddress& rhs_addr, std::uint16_t rhs_port) {
  return lhs_port == rhs_port && lhs_addr == rhs_addr;
}

}  // namespace

class ReliableConnection::AsyncReliableConnectionHandler final
    : public IReliableConnectionHandler {
 public:
  void Configure(IReliableConnectionHandler* target, ThreadPool* pool) {
    target_ = target;
    pool_ = pool;
  }

  void OnConnected() override {
    if (target_ != nullptr) target_->OnConnected();
  }

  void OnDisconnected() override {
    if (target_ != nullptr) target_->OnDisconnected();
  }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    DispatchPayload(channel, data, size, true);
  }

  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            std::size_t size) override {
    DispatchPayload(channel, data, size, false);
  }

  void OnTimeout() override {
    if (target_ != nullptr) target_->OnTimeout();
  }

 private:
  void DispatchPayload(std::uint8_t channel, const void* data,
                       std::size_t size, bool reliable) {
    if (target_ == nullptr) return;

    const auto bytes = AsBytes(data, size);
    std::vector<std::uint8_t> payload(bytes.begin(), bytes.end());
    IReliableConnectionHandler* target = target_;
    const ThreadPool::Task task =
      [target, channel, reliable, payload = std::move(payload)]() mutable {
        if (reliable) {
          target->OnReliableReceived(channel, payload.data(), payload.size());
        } else {
          target->OnUnreliableReceived(channel, payload.data(),
                                       payload.size());
        }
      };

    if (pool_ != nullptr && pool_->Post(task)) return;
    task();
  }

  IReliableConnectionHandler* target_ = nullptr;
  ThreadPool* pool_ = nullptr;
};

ReliableConnection::ReliableConnection(ISocket* socket,
                                       const ReliableConnectionConfig& cfg,
                                       IClock* clock)
    : socket_(socket),
      config_(cfg),
      clock_(clock != nullptr ? clock : &SystemClock::Instance()) {
  const auto n = static_cast<std::size_t>(config_.numChannels);
  send_sequence_.assign(n, 0);
  next_fragment_group_id_.assign(n, 0);
  send_buffer_.resize(config_.maxPacketSize);
  batch_buffer_.resize(config_.maxPacketSize);
  batch_scratch_buffer_.resize(config_.maxPacketSize);
  batch_command_buffer_.reserve(static_cast<std::size_t>(
    std::max<std::uint16_t>(config_.maxBatchCommands, 1)) *
                                detail::PacketCodec::kBaseHeaderSize);
  batch_payload_buffer_.reserve(config_.maxPacketSize);
  batch_command_spans_.reserve(config_.maxBatchCommands);
  send_queue_.Configure(config_.maxPendingReliablePackets);
  ack_batcher_.Configure(config_.enablePacketBatching,
                         config_.maxBatchCommands);
  congestion_.Configure(config_.sendWindowSize);
  receive_sequencer_.Configure(config_.numChannels, config_.receiveWindowSize);
  fragment_reassembler_.Configure(
    config_.numChannels, config_.maxFragmentGroupsPerChannel,
    config_.maxFragmentsPerMessage, config_.maxMessageSize,
    config_.fragmentTimeoutMs);
  EnsureReceiveBatchBuffers();

  const auto now = clock_->Now();
  last_send_time_ = now;
  last_receive_time_ = now;
  last_ping_time_ = now;
}

ReliableConnection::~ReliableConnection() {
  if (owned_handler_pool_ != nullptr) owned_handler_pool_->Shutdown(true);
  (void)DrainPostedTasks();
  state_ = ConnectionState::kDisconnected;
  ClearPendingPackets();
  receive_sequencer_.Reset();
  fragment_reassembler_.Reset();
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
    if (!SendPacket(detail::PacketType::kConnect, 0, client_hello.GetData(),
                    client_hello.GetSizeBytes())) {
      state_ = ConnectionState::kDisconnected;
      return false;
    }
    return true;
  }

  state_ = ConnectionState::kConnecting;
  return SendPacket(detail::PacketType::kConnect, 0, nullptr, 0);
}

void ReliableConnection::Disconnect() {
  if (state_ == ConnectionState::kConnected ||
      state_ == ConnectionState::kConnecting) {
    (void)SendPacket(detail::PacketType::kDisconnect, 0, nullptr, 0);
    state_ = ConnectionState::kDisconnecting;
    if (event_handler_ != nullptr) event_handler_->OnDisconnected();
  }

  state_ = ConnectionState::kDisconnected;
  ClearPendingPackets();
  receive_sequencer_.Reset();
  fragment_reassembler_.Reset();
}

void ReliableConnection::SetRemoteAddress(const SocketAddress& addr,
                                          std::uint16_t port) {
  remote_addr_ = addr;
  remote_port_ = port;
}

void ReliableConnection::SetHandler(IReliableConnectionHandler* handler) {
  user_event_handler_ = handler;
  ApplyHandlerDispatch();
}

void ReliableConnection::SetHandlerThreadPool(ThreadPool* pool) {
  if (handler_pool_ == pool && owned_handler_pool_ == nullptr) return;

  if (owned_handler_pool_ != nullptr) {
    owned_handler_pool_->Shutdown(true);
    owned_handler_pool_.reset();
  }
  handler_pool_ = pool;
  ApplyHandlerDispatch();
}

bool ReliableConnection::Post(std::function<void()> task) {
  return posted_network_tasks_.Post(std::move(task));
}

std::size_t ReliableConnection::DrainPostedTasks(std::size_t max_tasks) {
  return posted_network_tasks_.Drain(max_tasks);
}

void ReliableConnection::EnsureOwnedHandlerThreadPool() {
  if (handler_pool_ != nullptr) return;
  const std::size_t worker_count =
    config_.handlerWorkerThreads == 0 ? ThreadPool::DefaultWorkerCount()
                                      : config_.handlerWorkerThreads;
  owned_handler_pool_ =
    std::make_unique<ThreadPool>(worker_count, config_.handlerMaxQueueSize);
  handler_pool_ = owned_handler_pool_.get();
}

void ReliableConnection::ApplyHandlerDispatch() {
  if (user_event_handler_ == nullptr) {
    event_handler_ = nullptr;
    return;
  }

  if (config_.handlerDispatchMode != HandlerDispatchMode::kAsyncPayload) {
    event_handler_ = user_event_handler_;
    return;
  }

  EnsureOwnedHandlerThreadPool();
  if (async_handler_ == nullptr) {
    async_handler_ = std::make_unique<AsyncReliableConnectionHandler>();
  }
  async_handler_->Configure(user_event_handler_, handler_pool_);
  event_handler_ = async_handler_.get();
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
  if (state_ != ConnectionState::kConnected ||
      channel >= send_sequence_.size()) {
    return false;
  }
  if (size > config_.maxMessageSize) return false;

  const auto now = clock_->Now();
  detail::DeadlineMetadata deadline;
  if (!PrepareDeadline(deadline_ms, deadline, now)) return false;
  if (!congestion_.CanSend(send_queue_.ActiveCount())) return false;

  const std::size_t max_payload = MaxPayloadForPacket(deadline.hasDeadline);
  if (max_payload == 0) return false;
  if (size > max_payload) return SendFragmented(channel, data, size, deadline);

  const std::uint32_t seq = GetNextSequence(channel);
  auto handle_result = send_queue_.Allocate(channel, seq);
  if (!handle_result.has_value()) return false;

  detail::PendingPacket* pending = send_queue_.Get(*handle_result);
  if (pending == nullptr) return false;
  pending->data.Assign(AsBytes(data, size));
  pending->sendTime = now;
  pending->channel = channel;
  pending->type = detail::PacketType::kReliable;
  CopyDeadlineToPending(*pending, deadline);

  if (!SendPacket(detail::PacketType::kReliable, channel, pending->data.Data(),
                  pending->data.Size(), seq, deadline, now)) {
    send_queue_.Erase(*handle_result);
    return false;
  }
  send_queue_.ScheduleRetry(*handle_result, now, config_.retryTimeoutMs);
  return true;
}

bool ReliableConnection::SendUnreliableInternal(const std::uint8_t channel,
                                                const void* data,
                                                std::size_t size,
                                                std::uint32_t deadline_ms) {
  if (state_ != ConnectionState::kConnected ||
      channel >= send_sequence_.size()) {
    return false;
  }
  if (size > config_.maxMessageSize) return false;

  const auto now = clock_->Now();
  detail::DeadlineMetadata deadline;
  if (!PrepareDeadline(deadline_ms, deadline, now)) return false;

  const std::size_t max_payload = MaxPayloadForPacket(deadline.hasDeadline);
  if (max_payload == 0 || size > max_payload) return false;
  return SendPacket(detail::PacketType::kUnreliable, channel, data, size, 0,
                    deadline, now);
}

bool ReliableConnection::SendUnsequencedInternal(const std::uint8_t channel,
                                                 const void* data,
                                                 std::size_t size,
                                                 std::uint32_t deadline_ms) {
  if (state_ != ConnectionState::kConnected ||
      channel >= send_sequence_.size()) {
    return false;
  }
  if (size > config_.maxMessageSize) return false;

  const auto now = clock_->Now();
  detail::DeadlineMetadata deadline;
  if (!PrepareDeadline(deadline_ms, deadline, now)) return false;
  if (!congestion_.CanSend(send_queue_.ActiveCount())) return false;

  const std::size_t max_payload = MaxPayloadForPacket(deadline.hasDeadline);
  if (max_payload == 0 || size > max_payload) return false;

  const std::uint32_t seq = GetNextSequence(channel);
  auto handle_result = send_queue_.Allocate(channel, seq);
  if (!handle_result.has_value()) return false;

  detail::PendingPacket* pending = send_queue_.Get(*handle_result);
  if (pending == nullptr) return false;
  pending->data.Assign(AsBytes(data, size));
  pending->sendTime = now;
  pending->channel = channel;
  pending->type = detail::PacketType::kUnsequenced;
  CopyDeadlineToPending(*pending, deadline);

  if (!SendPacket(detail::PacketType::kUnsequenced, channel,
                  pending->data.Data(), pending->data.Size(), seq, deadline,
                  now)) {
    send_queue_.Erase(*handle_result);
    return false;
  }
  send_queue_.ScheduleRetry(*handle_result, now, config_.retryTimeoutMs);
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
  const auto now = clock_->Now();
  Update(now);
}

void ReliableConnection::Update(std::chrono::steady_clock::time_point now) {
  (void)DrainPostedTasks(config_.maxNetworkTasksPerDrain);

  RetryPendingPackets(now);

  if (state_ == ConnectionState::kConnected) {
    const auto time_since_ping =
      std::chrono::duration_cast<std::chrono::milliseconds>(now -
                                                            last_ping_time_)
        .count();
    if (std::cmp_greater(time_since_ping, config_.pingIntervalMs)) {
      SendPing(now);
      last_ping_time_ = now;
    }
  }

  CheckTimeout(now);
  stats_deadline_expired_fragment_groups_ += fragment_reassembler_.Cleanup(now);
  (void)FlushQueuedAcks(now);
  (void)DrainPostedTasks(config_.maxNetworkTasksPerDrain);
}

void ReliableConnection::ProcessPacket(const void* data, std::size_t size,
                                       const SocketAddress& from,
                                       std::uint16_t from_port) {
  const auto bytes = AsBytes(data, size);
  const auto decoded = detail::PacketCodec::Decode(bytes);
  if (!decoded.has_value()) return;

  if (decoded->type == detail::PacketType::kBatch) {
    if (SecureMode()) return;
    ProcessBatchPacket(decoded->payload.data(), decoded->payload.size(), from,
                       from_port);
    return;
  }

  ProcessSinglePacket(bytes.data(), bytes.size(), *decoded, from, from_port);
}

bool ReliableConnection::IsConnectPacket(const void* data, std::size_t size) {
  const auto decoded = detail::PacketCodec::Decode(AsBytes(data, size));
  return decoded.has_value() &&
         decoded->type == detail::PacketType::kConnect;
}

void ReliableConnection::ProcessSinglePacket(
  const std::uint8_t* packet_data, std::size_t size,
  const detail::DecodedPacket& packet, const SocketAddress& from,
  std::uint16_t from_port) {
  (void)size;
  std::span<const std::uint8_t> payload = packet.payload;
  BitStream decrypted_payload;

  if (SecureMode() && packet.type != detail::PacketType::kConnect &&
      packet.type != detail::PacketType::kAccept) {
    if (!crypto_ready_) return;

    const std::size_t header_size = DecodedHeaderSize(packet);
    const auto decrypt_result =
      crypto_context_.Decrypt(payload.data(), payload.size(), packet_data,
                              header_size, decrypted_payload);
    if (!decrypt_result.ok) return;
    payload = {decrypted_payload.GetData(), decrypted_payload.GetSizeBytes()};
  }

  const auto now = clock_->Now();
  last_receive_time_ = now;
  ++stats_received_packets_;

  const bool deadline_expired = config_.deadlinesEnabled &&
                                config_.dropExpiredOnReceive &&
                                packet.hasDeadline && packet.deadline_ms > 0 &&
                                packet.ageMsAtSend >= packet.deadline_ms;

  switch (packet.type) {
    case detail::PacketType::kConnect: {
      if (state_ == ConnectionState::kDisconnected) {
        remote_addr_ = from;
        remote_port_ = from_port;

        if (SecureMode()) {
          if (!CanUseCrypto()) return;

          auto result =
            crypto_handshake_.StartServer(config_.crypto.localKeyPair);
          if (!result.ok) return;

          result = crypto_handshake_.ProcessClientHello(payload.data(),
                                                        payload.size());
          if (!result.ok) {
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

          crypto_context_ = crypto_handshake_.CreateServerCryptoContext();
          crypto_ready_ = crypto_context_.IsReady();
          if (!crypto_ready_) {
            state_ = ConnectionState::kDisconnected;
            return;
          }

          state_ = ConnectionState::kConnected;
          (void)SendPacket(detail::PacketType::kAccept, 0,
                           server_hello.GetData(), server_hello.GetSizeBytes(),
                           0, detail::DeadlineMetadata{}, now);
        } else {
          state_ = ConnectionState::kConnected;
          (void)SendPacket(detail::PacketType::kAccept, 0, nullptr, 0, 0,
                           detail::DeadlineMetadata{}, now);
        }

        if (event_handler_ != nullptr) event_handler_->OnConnected();
      } else if (state_ == ConnectionState::kConnected &&
                 SameEndpoint(remote_addr_, remote_port_, from, from_port) &&
                 !SecureMode()) {
        (void)SendPacket(detail::PacketType::kAccept, 0, nullptr, 0, 0,
                         detail::DeadlineMetadata{}, now);
      }
      break;
    }

    case detail::PacketType::kAccept: {
      if (state_ == ConnectionState::kConnecting) {
        if (SecureMode()) {
          auto result = crypto_handshake_.ProcessServerHello(payload.data(),
                                                             payload.size());
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

    case detail::PacketType::kDisconnect: {
      if (event_handler_ != nullptr) event_handler_->OnDisconnected();
      state_ = ConnectionState::kDisconnected;
      break;
    }

    case detail::PacketType::kPing: {
      (void)SendPacket(detail::PacketType::kPong, 0, nullptr, 0,
                       packet.sequence, detail::DeadlineMetadata{}, now);
      break;
    }

    case detail::PacketType::kPong: {
      const auto handle = send_queue_.Find(0, packet.sequence);
      const detail::PendingPacket* pending = send_queue_.Get(handle);
      if (pending != nullptr) {
        const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
            now - pending->sendTime)
            .count();
        rtt_ = rtt_ * 0.9f + static_cast<float>(elapsed) * 0.1f;
        send_queue_.Erase(handle);
      }
      break;
    }

    case detail::PacketType::kAck: {
      const auto handle = send_queue_.Find(packet.channel, packet.sequence);
      const detail::PendingPacket* pending = send_queue_.Get(handle);
      if (pending != nullptr) {
        const auto elapsed =
          std::chrono::duration_cast<std::chrono::milliseconds>(
            now - pending->sendTime)
            .count();
        rtt_ = rtt_ * 0.9f + static_cast<float>(elapsed) * 0.1f;
        send_queue_.Erase(handle);
        congestion_.OnAck();
      }
      break;
    }

    case detail::PacketType::kReliable: {
      if (deadline_expired) {
        if (config_.ackExpiredReliable) {
          SendAck(packet.channel, packet.sequence, now);
        }
        ++stats_deadline_receive_drops_;
        break;
      }

      std::vector<detail::ReceiveSequencer::Message> ready;
      const auto result = receive_sequencer_.AcceptReliable(
        packet.channel, packet.sequence, payload, ready);
      if (result.ack) SendAck(packet.channel, packet.sequence, now);
      DeliverReliableMessages(ready);
      break;
    }

    case detail::PacketType::kUnsequenced: {
      if (deadline_expired) {
        if (config_.ackExpiredReliable) {
          SendAck(packet.channel, packet.sequence, now);
        }
        ++stats_deadline_receive_drops_;
        break;
      }

      const auto result =
        receive_sequencer_.AcceptUnsequenced(packet.channel, packet.sequence);
      if (result.ack) SendAck(packet.channel, packet.sequence, now);
      if (result.status == detail::ReceiveSequencer::AcceptStatus::kDelivered &&
          event_handler_ != nullptr) {
        event_handler_->OnReliableReceived(packet.channel, payload.data(),
                                           payload.size());
      }
      break;
    }

    case detail::PacketType::kUnreliable: {
      if (deadline_expired) {
        ++stats_deadline_receive_drops_;
        break;
      }
      if (event_handler_ != nullptr) {
        event_handler_->OnUnreliableReceived(packet.channel, payload.data(),
                                             payload.size());
      }
      break;
    }

    case detail::PacketType::kFragment: {
      if (deadline_expired) {
        if (config_.ackExpiredReliable) {
          SendAck(packet.channel, packet.sequence, now);
        }
        ++stats_deadline_receive_drops_;
        break;
      }

      const auto seq_result =
        receive_sequencer_.AcceptUnsequenced(packet.channel, packet.sequence);
      if (seq_result.ack) SendAck(packet.channel, packet.sequence, now);
      if (seq_result.status !=
          detail::ReceiveSequencer::AcceptStatus::kDelivered) {
        break;
      }

      const bool has_deadline = config_.deadlinesEnabled &&
                                packet.hasDeadline &&
                                packet.deadline_ms > packet.ageMsAtSend;
      const auto expire_time =
        has_deadline ? now + std::chrono::milliseconds(packet.deadline_ms -
                                                       packet.ageMsAtSend)
                     : std::chrono::steady_clock::time_point{};
      const auto frag_result = fragment_reassembler_.AddFragment(
        packet.channel, packet.fragment, payload, now, has_deadline,
        expire_time);
      if (frag_result.deadlineExpired) {
        ++stats_deadline_receive_drops_;
        ++stats_deadline_expired_fragment_groups_;
      }
      if (frag_result.message.has_value() && event_handler_ != nullptr) {
        const auto& message = *frag_result.message;
        event_handler_->OnReliableReceived(
          message.channel, message.payload.data(), message.payload.size());
      }
      break;
    }

    case detail::PacketType::kBatch:
      break;
  }
}

bool ReliableConnection::SendPacket(detail::PacketType type,
                                    std::uint8_t channel, const void* data,
                                    std::size_t size, std::uint32_t sequence) {
  return SendPacket(type, channel, data, size, sequence,
                    detail::DeadlineMetadata{});
}

bool ReliableConnection::SendPacket(detail::PacketType type,
                                    std::uint8_t channel, const void* data,
                                    std::size_t size, std::uint32_t sequence,
                                    const detail::DeadlineMetadata& deadline) {
  return SendPacket(type, channel, data, size, sequence, deadline,
                    clock_->Now());
}

bool ReliableConnection::SendPacket(detail::PacketType type,
                                    std::uint8_t channel, const void* data,
                                    std::size_t size, std::uint32_t sequence,
                                    const detail::DeadlineMetadata& deadline,
                                    std::chrono::steady_clock::time_point now) {
  return SendPacket(type, channel, data, size, sequence, deadline,
                    detail::FragmentMetadata{}, now);
}

bool ReliableConnection::SendPacket(detail::PacketType type,
                                    std::uint8_t channel, const void* data,
                                    std::size_t size, std::uint32_t sequence,
                                    const detail::DeadlineMetadata& deadline,
                                    const detail::FragmentMetadata& fragment,
                                    std::chrono::steady_clock::time_point now) {
  if (type == detail::PacketType::kAck && CanBatchPacket(type)) {
    QueueAck(channel, sequence, now);
    return true;
  }

  if (!CanBatchPacket(type) || ack_batcher_.Empty()) {
    return SendSinglePacket(type, channel, data, size, sequence, deadline,
                            fragment, now);
  }

  std::size_t command_size = 0;
  if (!BuildPacket(type, channel, data, size, sequence, deadline, fragment, now,
                   batch_scratch_buffer_, command_size)) {
    return false;
  }

  if (SendBatchWithCommand(batch_scratch_buffer_.data(), command_size, now)) {
    return true;
  }
  if (!FlushQueuedAcks(now)) return false;
  return SendSinglePacket(type, channel, data, size, sequence, deadline,
                          fragment, now);
}

bool ReliableConnection::SendSinglePacket(
  detail::PacketType type, std::uint8_t channel, const void* data,
  std::size_t size, std::uint32_t sequence,
  const detail::DeadlineMetadata& deadline,
  const detail::FragmentMetadata& fragment,
  std::chrono::steady_clock::time_point now) {
  std::size_t packet_size = 0;
  if (!BuildPacket(type, channel, data, size, sequence, deadline, fragment, now,
                   send_buffer_, packet_size)) {
    return false;
  }
  return SendRawDatagram(send_buffer_.data(), packet_size, now);
}

bool ReliableConnection::BuildPacket(detail::PacketType type,
                                     std::uint8_t channel, const void* data,
                                     std::size_t size, std::uint32_t sequence,
                                     const detail::DeadlineMetadata& deadline,
                                     const detail::FragmentMetadata& fragment,
                                     std::chrono::steady_clock::time_point now,
                                     std::vector<std::uint8_t>& buffer,
                                     std::size_t& packet_size) {
  if (DeadlineExpired(deadline, now)) {
    ++stats_deadline_send_drops_;
    return false;
  }

  if (buffer.size() < config_.maxPacketSize) {
    buffer.resize(config_.maxPacketSize);
  }

  const auto payload = AsBytes(data, size);
  detail::PacketBuild packet{.type = type,
                             .channel = channel,
                             .sequence = sequence,
                             .deadline = deadline,
                             .fragment = fragment,
                             .payload = payload};

  BitStream encrypted_payload;
  if (ShouldEncryptPacket(type)) {
    const std::size_t encrypted_payload_size =
      payload.size() + crypto::kNonceSize + crypto::kMacSize;
    std::vector<std::uint8_t> associated_data(
      detail::PacketCodec::HeaderSize(packet));
    const auto header_result = detail::PacketCodec::EncodeHeader(
      packet, encrypted_payload_size, now, associated_data);
    if (!header_result.has_value()) return false;
    const auto result = crypto_context_.Encrypt(
      payload.data(), payload.size(), associated_data.data(), *header_result,
      encrypted_payload);
    if (!result.ok) return false;
    packet.payload = {encrypted_payload.GetData(),
                      encrypted_payload.GetSizeBytes()};
  }

  const auto encoded = detail::PacketCodec::Encode(packet, now, buffer);
  if (!encoded.has_value()) return false;
  packet_size = *encoded;
  return true;
}

bool ReliableConnection::SendRawDatagram(
  const std::uint8_t* data, std::size_t size,
  std::chrono::steady_clock::time_point now, std::uint32_t logical_packets) {
  if (data == nullptr || size == 0 || size > config_.maxPacketSize) {
    return false;
  }
  const SocketResult result =
    socket_->SendTo(data, size, remote_addr_, remote_port_);
  if (result.Failed()) return false;
  last_send_time_ = now;
  stats_sent_packets_ += logical_packets;
  return true;
}

bool ReliableConnection::CanBatchPacket(detail::PacketType type) const {
  if (!ack_batcher_.Enabled() || SecureMode()) return false;
  switch (type) {
    case detail::PacketType::kAck:
    case detail::PacketType::kPing:
    case detail::PacketType::kPong:
    case detail::PacketType::kReliable:
    case detail::PacketType::kUnreliable:
    case detail::PacketType::kUnsequenced:
    case detail::PacketType::kFragment:
      return true;
    default:
      return false;
  }
}

bool ReliableConnection::SendBatchWithCommand(
  const std::uint8_t* command, std::size_t command_size,
  std::chrono::steady_clock::time_point now) {
  if (ack_batcher_.Empty() || command == nullptr || command_size == 0) {
    return false;
  }

  const std::size_t ack_count = ack_batcher_.Size();
  ResetBatchCommandScratch(ack_count + 1,
                           ack_count * detail::PacketCodec::kBaseHeaderSize);
  for (const detail::PacketKey ack : ack_batcher_.Queued()) {
    if (!AppendAckBatchCommand(ack, now)) return false;
  }
  batch_command_spans_.emplace_back(command, command_size);

  if (!EncodeAndSendCurrentBatch(now)) {
    return false;
  }

  ack_batcher_.Clear();
  return true;
}

bool ReliableConnection::FlushQueuedAcks(
  std::chrono::steady_clock::time_point now) {
  while (!ack_batcher_.Empty()) {
    const std::size_t count =
      std::min<std::size_t>(ack_batcher_.Size(), ack_batcher_.MaxCommands());
    if (count == 1) {
      const detail::PacketKey ack = ack_batcher_.Queued().front();
      if (!SendSinglePacket(detail::PacketType::kAck, ack.channel, nullptr, 0,
                            ack.sequence, detail::DeadlineMetadata{},
                            detail::FragmentMetadata{}, now)) {
        return false;
      }
      ack_batcher_.RemovePrefix(1);
      continue;
    }

    ResetBatchCommandScratch(count,
                             count * detail::PacketCodec::kBaseHeaderSize);
    for (std::size_t i = 0; i < count; ++i) {
      const detail::PacketKey ack = ack_batcher_.Queued().data()[i];
      if (!AppendAckBatchCommand(ack, now)) return false;
    }

    if (!EncodeAndSendCurrentBatch(now)) return false;
    ack_batcher_.RemovePrefix(count);
  }
  return true;
}

void ReliableConnection::ResetBatchCommandScratch(
  std::size_t command_count_hint, std::size_t command_bytes_hint) {
  batch_command_spans_.clear();
  batch_command_spans_.reserve(command_count_hint);
  batch_command_buffer_.clear();
  batch_command_buffer_.reserve(command_bytes_hint);
}

bool ReliableConnection::AppendAckBatchCommand(
  detail::PacketKey ack, std::chrono::steady_clock::time_point now) {
  const std::size_t offset = batch_command_buffer_.size();
  batch_command_buffer_.resize(offset + detail::PacketCodec::kBaseHeaderSize);

  const detail::PacketBuild packet{.type = detail::PacketType::kAck,
                             .channel = ack.channel,
                             .sequence = ack.sequence,
                             .payload = {}};
  auto out = std::span<std::uint8_t>(batch_command_buffer_).subspan(offset);
  const auto encoded = detail::PacketCodec::Encode(packet, now, out);
  if (!encoded.has_value()) {
    batch_command_buffer_.resize(offset);
    return false;
  }

  batch_command_spans_.emplace_back(batch_command_buffer_.data() + offset,
                                    *encoded);
  return true;
}

bool ReliableConnection::EncodeAndSendCurrentBatch(
  std::chrono::steady_clock::time_point now) {
  const auto batch_payload_size = detail::PacketCodec::EncodeBatchPayload(
    batch_command_spans_, ack_batcher_.MaxCommands(), batch_payload_buffer_);
  if (!batch_payload_size.has_value()) return false;
  if (*batch_payload_size + detail::PacketCodec::kBaseHeaderSize >
      config_.maxPacketSize) {
    return false;
  }

  std::size_t packet_size = 0;
  if (!BuildPacket(detail::PacketType::kBatch, 0, batch_payload_buffer_.data(),
                   *batch_payload_size, 0, detail::DeadlineMetadata{},
                   detail::FragmentMetadata{}, now, batch_buffer_,
                   packet_size)) {
    return false;
  }
  return SendRawDatagram(
    batch_buffer_.data(), packet_size, now,
    static_cast<std::uint32_t>(batch_command_spans_.size()));
}

void ReliableConnection::QueueAck(std::uint8_t channel, std::uint32_t sequence,
                                  std::chrono::steady_clock::time_point now) {
  if (!CanBatchPacket(detail::PacketType::kAck)) {
    (void)SendSinglePacket(detail::PacketType::kAck, channel, nullptr, 0,
                           sequence, detail::DeadlineMetadata{},
                           detail::FragmentMetadata{}, now);
    return;
  }

  ack_batcher_.Add(channel, sequence);
  if (ack_batcher_.ShouldFlush()) (void)FlushQueuedAcks(now);
}

void ReliableConnection::ProcessBatchPacket(const std::uint8_t* payload,
                                            std::size_t size,
                                            const SocketAddress& from,
                                            std::uint16_t from_port) {
  const auto commands = detail::PacketCodec::DecodeBatchPayload(
    AsBytes(payload, size), ack_batcher_.MaxCommands());
  if (!commands.has_value()) return;

  for (const auto command : *commands) {
    const auto decoded = detail::PacketCodec::Decode(command);
    if (!decoded.has_value() || decoded->type == detail::PacketType::kBatch) {
      return;
    }
    ProcessSinglePacket(command.data(), command.size(), *decoded, from,
                        from_port);
  }
}

bool ReliableConnection::SendFragmented(
  std::uint8_t channel, const void* data, std::size_t size,
  const detail::DeadlineMetadata& deadline) {
  if (channel >= next_fragment_group_id_.size() || data == nullptr ||
      size > config_.maxMessageSize) {
    return false;
  }

  const std::size_t max_frag_payload =
    MaxPayloadForPacket(deadline.hasDeadline, true);
  if (max_frag_payload == 0) return false;
  const std::size_t frag_total_size =
    (size + max_frag_payload - 1) / max_frag_payload;
  if (frag_total_size == 0 ||
      frag_total_size > config_.maxFragmentsPerMessage ||
      frag_total_size > std::numeric_limits<std::uint16_t>::max()) {
    return false;
  }

  const auto frag_total = static_cast<std::uint16_t>(frag_total_size);
  const std::uint16_t group_id = next_fragment_group_id_.at(channel)++;
  const auto* src = static_cast<const std::uint8_t*>(data);

  for (std::uint16_t i = 0; i < frag_total; ++i) {
    const auto now = clock_->Now();
    if (DeadlineExpired(deadline, now)) {
      ++stats_deadline_send_drops_;
      return false;
    }
    if (!congestion_.CanSend(send_queue_.ActiveCount())) return false;

    const std::size_t offset = i * max_frag_payload;
    const std::size_t frag_size = std::min(max_frag_payload, size - offset);
    const std::uint32_t seq = GetNextSequence(channel);
    auto handle_result = send_queue_.Allocate(channel, seq);
    if (!handle_result.has_value()) return false;

    detail::PendingPacket* pending = send_queue_.Get(*handle_result);
    if (pending == nullptr) return false;
    pending->data.Assign(src + offset, frag_size);
    pending->sendTime = now;
    pending->channel = channel;
    pending->type = detail::PacketType::kFragment;
    pending->fragment = detail::FragmentMetadata{.hasFragment = true,
                                                 .groupId = group_id,
                                                 .fragmentIndex = i,
                                                 .fragmentTotal = frag_total};
    CopyDeadlineToPending(*pending, deadline);

    if (!SendPacket(detail::PacketType::kFragment, channel,
                    pending->data.Data(), pending->data.Size(), seq, deadline,
                    pending->fragment, now)) {
      send_queue_.Erase(*handle_result);
      return false;
    }
    send_queue_.ScheduleRetry(*handle_result, now, config_.retryTimeoutMs);
  }
  return true;
}

void ReliableConnection::SendAck(std::uint8_t channel, std::uint32_t sequence) {
  (void)SendPacket(detail::PacketType::kAck, channel, nullptr, 0, sequence);
}

void ReliableConnection::SendAck(std::uint8_t channel, std::uint32_t sequence,
                                 std::chrono::steady_clock::time_point now) {
  (void)SendPacket(detail::PacketType::kAck, channel, nullptr, 0, sequence,
                   detail::DeadlineMetadata{}, now);
}

void ReliableConnection::SendPing() { SendPing(clock_->Now()); }

void ReliableConnection::SendPing(std::chrono::steady_clock::time_point now) {
  const std::uint32_t seq = GetNextSequence(0);
  if (!SendPacket(detail::PacketType::kPing, 0, nullptr, 0, seq,
                  detail::DeadlineMetadata{}, now)) {
    return;
  }

  auto handle_result = send_queue_.Allocate(0, seq);
  if (!handle_result.has_value()) return;
  detail::PendingPacket* pending = send_queue_.Get(*handle_result);
  if (pending == nullptr) return;
  pending->sendTime = now;
  pending->type = detail::PacketType::kPing;
  send_queue_.ScheduleRetry(*handle_result, now, config_.retryTimeoutMs);
}

void ReliableConnection::DeliverReliableMessages(
  const std::vector<detail::ReceiveSequencer::Message>& messages) {
  if (event_handler_ == nullptr) return;
  for (const auto& message : messages) {
    event_handler_->OnReliableReceived(message.channel, message.data.Data(),
                                       message.data.Size());
  }
}

void ReliableConnection::RetryPendingPackets(
  std::chrono::steady_clock::time_point now) {
  while (true) {
    const auto handle = send_queue_.PopDue(now);
    if (!handle.has_value()) break;

    detail::PendingPacket* pending = send_queue_.Get(*handle);
    if (pending == nullptr) continue;

    if (pending->hasDeadline && now >= pending->expireTime) {
      ++stats_deadline_retries_prevented_;
      send_queue_.Erase(*handle);
      continue;
    }

    if (pending->retries >= config_.maxRetries) {
      ++stats_lost_packets_;
      congestion_.OnLoss();
      send_queue_.Erase(*handle);
      continue;
    }

    detail::DeadlineMetadata deadline;
    deadline.hasDeadline = pending->hasDeadline;
    deadline.deadline_ms = pending->deadline_ms;
    deadline.createdTime = pending->createdTime;
    deadline.expireTime = pending->expireTime;

    const void* payload =
      pending->data.Empty() ? nullptr : pending->data.Data();
    if (SendPacket(pending->type, pending->channel, payload,
                   pending->data.Size(), pending->sequence, deadline,
                   pending->fragment, now)) {
      pending->sendTime = now;
      ++pending->retries;
    } else if (pending->hasDeadline && DeadlineExpired(deadline, now)) {
      ++stats_deadline_retries_prevented_;
      send_queue_.Erase(*handle);
      continue;
    }

    send_queue_.ScheduleRetry(*handle, now, config_.retryTimeoutMs);
  }
}

void ReliableConnection::EnsureReceiveBatchBuffers() {
  const std::size_t packet_size =
    std::max<std::size_t>(1, config_.maxPacketSize);
  const std::size_t storage_size = kReceiveBatchSize * packet_size;
  if (receive_batch_storage_.size() != storage_size) {
    receive_batch_storage_.resize(storage_size);
  }
  if (receive_batch_.size() != kReceiveBatchSize) {
    receive_batch_.resize(kReceiveBatchSize);
  }

  for (std::size_t i = 0; i < kReceiveBatchSize; ++i) {
    receive_batch_.at(i).data = receive_batch_storage_.data() + i * packet_size;
    receive_batch_.at(i).capacity = packet_size;
    receive_batch_.at(i).result = {};
  }
}

void ReliableConnection::CheckTimeout(
  std::chrono::steady_clock::time_point now) {
  if (state_ != ConnectionState::kConnected) return;
  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now - last_receive_time_)
                         .count();
  if (std::cmp_greater(elapsed, config_.disconnectTimeoutMs)) {
    if (event_handler_ != nullptr) event_handler_->OnTimeout();
    Disconnect();
  }
}

void ReliableConnection::ClearPendingPackets() {
  send_queue_.Clear();
  ack_batcher_.Clear();
}

bool ReliableConnection::CanUseCrypto() const {
  if (!SecureMode()) return true;

  const auto init_result = crypto::Initialize();
  return init_result.ok &&
         crypto::CipherSuiteSupported(
           crypto::CipherSuite::kXChaCha20Poly1305) &&
         config_.crypto.localKeyPair.Valid();
}

bool ReliableConnection::ShouldEncryptPacket(detail::PacketType type) const {
  return SecureMode() && crypto_ready_ &&
         type != detail::PacketType::kConnect &&
         type != detail::PacketType::kAccept;
}

std::size_t ReliableConnection::CryptoEnvelopeOverhead() const {
  return SecureMode() ? (crypto::kNonceSize + crypto::kMacSize) : 0;
}

std::size_t ReliableConnection::MaxPayloadForPacket(bool has_deadline,
                                                    bool has_fragment) const {
  const std::size_t overhead =
    detail::PacketCodec::kBaseHeaderSize +
    (has_deadline ? detail::PacketCodec::kDeadlineExtensionSize
                  : std::size_t{0}) +
    (has_fragment ? detail::PacketCodec::kFragmentExtensionSize
                  : std::size_t{0}) +
    CryptoEnvelopeOverhead();
  if (config_.maxPacketSize < overhead) return 0;
  return config_.maxPacketSize - overhead;
}

bool ReliableConnection::PrepareDeadline(
  std::uint32_t deadline_ms, detail::DeadlineMetadata& deadline,
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
  const detail::DeadlineMetadata& deadline,
  std::chrono::steady_clock::time_point now) {
  return deadline.hasDeadline && now >= deadline.expireTime;
}

void ReliableConnection::CopyDeadlineToPending(
  detail::PendingPacket& pending, const detail::DeadlineMetadata& deadline) {
  pending.hasDeadline = deadline.hasDeadline;
  pending.deadline_ms = deadline.deadline_ms;
  pending.createdTime = deadline.createdTime;
  pending.expireTime = deadline.expireTime;
}

void ReliableConnection::Tick() {
  while (true) {
    EnsureReceiveBatchBuffers();
    const std::size_t received = socket_->ReceiveMany(receive_batch_);
    if (received == 0) break;

    for (std::size_t i = 0; i < received; ++i) {
      const IncomingDatagram& datagram = receive_batch_.at(i);
      if (datagram.result.bytes > 0) {
        ProcessPacket(datagram.data,
                      static_cast<std::size_t>(datagram.result.bytes),
                      datagram.fromAddr, datagram.fromPort);
      }
    }
    if (received < receive_batch_.size()) break;
  }
  Update(clock_->Now());
}

}  // namespace socketwire
