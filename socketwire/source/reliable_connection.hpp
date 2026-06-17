#pragma once

/// Reliable UDP protocol implementation for SocketWire.
///
/// Provides reliable packet delivery, packet sequencing, connection state
/// management, keep-alives, and separate reliable/unreliable channels.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "bit_stream.hpp"
#include "crypto.hpp"
#include "i_socket.hpp"
#include "reliable_protocol.hpp"

namespace socketwire {

enum class ConnectionState : std::uint8_t {
  kDisconnected = 0,
  kDisconnecting = 1,
  kConnected = 2,
  kConnecting = 3
};

class IClock {
 public:
  using TimePoint = std::chrono::steady_clock::time_point;

  virtual ~IClock() = default;
  [[nodiscard]] virtual TimePoint Now() const = 0;
};

class SystemClock final : public IClock {
 public:
  [[nodiscard]] TimePoint Now() const override {
    return std::chrono::steady_clock::now();
  }

  [[nodiscard]] static SystemClock& Instance() {
    static SystemClock clock;
    return clock;
  }
};

class ManualClock final : public IClock {
 public:
  explicit ManualClock(TimePoint initial = TimePoint{}) : now_(initial) {}

  [[nodiscard]] TimePoint Now() const override { return now_; }

  void Set(TimePoint now) { now_ = now; }

  template <class Rep, class Period>
  void Advance(std::chrono::duration<Rep, Period> delta) {
    now_ += std::chrono::duration_cast<TimePoint::duration>(delta);
  }

 private:
  TimePoint now_;
};

/// Configuration for reliable connections.
struct ReliableConnectionConfig {
  struct CryptoConfig {
    bool enabled = false;
    crypto::KeyPair localKeyPair{};
    crypto::PublicKey expected_server_public_key{};
  };

  std::uint32_t maxRetries = 10;
  std::uint32_t retryTimeoutMs = 100;
  std::uint32_t pingIntervalMs = 1000;
  std::uint32_t disconnectTimeoutMs = 5000;
  std::uint32_t maxPacketSize = 1400;
  std::uint8_t numChannels = 2;
  /// How long (ms) to wait for all fragments before discarding an incomplete
  /// group.
  std::uint32_t fragmentTimeoutMs = 5000;
  /// Maximum application message size accepted before fragmentation/drop.
  std::uint32_t maxMessageSize = 64 * 1024;
  /// Maximum reliable/unsequenced packets awaiting ACK per connection.
  std::uint32_t maxPendingReliablePackets = 4096;
  /// Maximum incomplete fragment groups per channel.
  std::uint32_t maxFragmentGroupsPerChannel = 32;
  /// Maximum fragments accepted for one reassembled message.
  std::uint32_t maxFragmentsPerMessage = 512;
  /// Maximum simultaneous unACKed reliable packets (send-window size). 0 =
  /// unlimited. When > 0, enables packet-based AIMD congestion avoidance:
  /// window halves on packet loss and grows by 1 per ACK up to this maximum.
  std::uint32_t sendWindowSize = 0;
  CryptoConfig crypto{};
  /// Enable deadline-aware packets sent through the WithDeadline APIs.
  bool deadlinesEnabled = false;
  /// Maximum accepted deadline/TTL in milliseconds for deadline-aware sends.
  std::uint32_t maxdeadline_ms = 1000;
  /// ACK expired reliable-style packets so senders stop retransmitting them.
  bool ackExpiredReliable = true;
  /// Drop expired deadline-aware packets before delivering to the handler.
  bool dropExpiredOnReceive = true;
  /// Pack ACKs and small protocol packets into fewer UDP datagrams.
  bool enablePacketBatching = true;
  /// Maximum protocol commands in one batch datagram.
  std::uint16_t maxBatchCommands = 32;
  /// Ordered reliable receive window per channel.
  std::uint32_t receiveWindowSize = 1024;
};

/// Event callbacks for reliable connection state and payload delivery.
class IReliableConnectionHandler {
 public:
  virtual ~IReliableConnectionHandler() = default;

  /// Called when the connection is established.
  virtual void OnConnected() {}

  /// Called when the connection is closed.
  virtual void OnDisconnected() {}

  /// Called when a reliable packet is received in order.
  virtual void OnReliableReceived(std::uint8_t channel, const void* data,
                                  std::size_t size) {
    (void)channel;
    (void)data;
    (void)size;
  }

  /// Called when an unreliable packet is received.
  virtual void OnUnreliableReceived(std::uint8_t channel, const void* data,
                                    std::size_t size) {
    (void)channel;
    (void)data;
    (void)size;
  }

  /// Called when the connection times out.
  virtual void OnTimeout() {}
};

/// Manages a single reliable connection over UDP.
///
/// Threading contract: a ReliableConnection instance is owned by one network
/// loop thread. Calls to Tick/Update/ProcessPacket and Send* must happen on
/// that owner thread; cross-thread application sends should be marshalled into
/// that loop by the caller.
class ReliableConnection {
 public:
  explicit ReliableConnection(ISocket* socket,
                              const ReliableConnectionConfig& cfg = {},
                              IClock* clock = nullptr);
  ~ReliableConnection();

  /// Starts a client-side connection attempt.
  bool Connect(const SocketAddress& addr, std::uint16_t port);
  /// Sends a disconnect packet and clears local connection state.
  void Disconnect();
  [[nodiscard]] bool IsConnected() const {
    return state_ == ConnectionState::kConnected;
  }
  [[nodiscard]] ConnectionState GetState() const { return state_; }
  [[nodiscard]] bool IsCryptoReady() const { return crypto_ready_; }
  /// Sets the remote address for server-side demultiplexed connections.
  void SetRemoteAddress(const SocketAddress& addr, std::uint16_t port);
  // TODO: kabanya - убрать
#if defined(SOCKETWIRE_TESTING)
  void SetConnectedForTest() { state_ = ConnectionState::kConnected; }
#endif

  // Without deadline APIs
  /// Sends data reliably and in order on the selected channel.
  bool SendReliable(const std::uint8_t channel, const BitStream& stream);
  bool SendReliable(const std::uint8_t channel, const void* data,
                    std::size_t size);

  /// Sends data once without ACK/retry guarantees.
  bool SendUnreliable(const std::uint8_t channel, const BitStream& stream);
  bool SendUnreliable(const std::uint8_t channel, const void* data,
                      std::size_t size);

  /// Sends data unreliably, dropping older packets that arrive late.
  bool SendSequenced(const std::uint8_t channel, const BitStream& stream);
  bool SendSequenced(const std::uint8_t channel, const void* data,
                     std::size_t size);

  /// Sends data reliably, but delivery order is not enforced.
  bool SendUnsequenced(const std::uint8_t channel, const BitStream& stream);
  bool SendUnsequenced(const std::uint8_t channel, const void* data,
                       std::size_t size);

  // With deadline APIs
  /// Sends a reliable buffer with deadline_ms used as packet TTL.
  bool SendReliableWithDeadline(const std::uint8_t channel,
                                const void* data,
                                std::size_t size,
                                std::uint32_t deadline_ms);
  /// Sends a reliable BitStream with deadline_ms used as packet TTL.
  bool SendReliableWithDeadline(const std::uint8_t channel,
                                const BitStream& stream,
                                std::uint32_t deadline_ms);

  /// Sends an unreliable BitStream with deadline_ms used as packet TTL.
  bool SendUnreliableWithDeadline(const std::uint8_t channel,
                                  const BitStream& stream,
                                  std::uint32_t deadline_ms);
  /// Sends an unreliable buffer with deadline_ms used as packet TTL.
  bool SendUnreliableWithDeadline(const std::uint8_t channel,
                                  const void* data,
                                  std::size_t size,
                                  std::uint32_t deadline_ms);

  /// Sends a sequenced BitStream with deadline_ms used as packet TTL.
  bool SendSequencedWithDeadline(const std::uint8_t channel,
                                 const BitStream& stream,
                                 std::uint32_t deadline_ms);
  /// Sends a sequenced buffer with deadline_ms used as packet TTL.
  bool SendSequencedWithDeadline(const std::uint8_t channel,
                                 const void* data,
                                 std::size_t size,
                                 std::uint32_t deadline_ms);

  /// Sends an unsequenced BitStream with deadline_ms used as packet TTL.
  bool SendUnsequencedWithDeadline(const std::uint8_t channel,
                                   const BitStream& stream,
                                   std::uint32_t deadline_ms);
  /// Sends an unsequenced buffer with deadline_ms used as packet TTL.
  bool SendUnsequencedWithDeadline(const std::uint8_t channel,
                                   const void* data,
                                   std::size_t size,
                                   std::uint32_t deadline_ms);

  /// Processes retransmits, pings, timeouts, and pending ordered packets.
  void Update();
  /// Processes retransmits, pings, timeouts, and pending ordered packets using
  /// a caller-supplied tick timestamp.
  void Update(std::chrono::steady_clock::time_point now);

  void ProcessPacket(const void* data,
                     std::size_t size,
                     const SocketAddress& from,
                     std::uint16_t from_port);

  /// Returns true when the buffer contains a valid SocketWire connect packet.
  ///
  /// Intended for custom server-side demultiplexers that need to decide
  /// whether to allocate a new ReliableConnection for an unknown endpoint.
  [[nodiscard]] static bool IsConnectPacket(const void* data, std::size_t size);

  void SetHandler(IReliableConnectionHandler* handler);

  // Statistics
  [[nodiscard]] std::uint32_t GetSentPackets() const {
    return stats_sent_packets_;
  }
  [[nodiscard]] std::uint32_t GetReceivedPackets() const {
    return stats_received_packets_;
  }
  [[nodiscard]] std::uint32_t GetLostPackets() const {
    return stats_lost_packets_;
  }
  [[nodiscard]] float GetRtt() const { return rtt_; }
  /// Current adaptive send window (0 = unlimited).
  [[nodiscard]] std::uint32_t GetSendWindow() const {
    return congestion_.Window();
  }
  /// Number of reliable packets currently awaiting acknowledgment.
  [[nodiscard]] std::uint32_t GetInflightCount() const {
    return send_queue_.ActiveCount();
  }
  [[nodiscard]] std::uint32_t GetDeadlineSendDrops() const {
    return stats_deadline_send_drops_;
  }
  [[nodiscard]] std::uint32_t GetDeadlineReceiveDrops() const {
    return stats_deadline_receive_drops_;
  }
  [[nodiscard]] std::uint32_t GetDeadlineRetriesPrevented() const {
    return stats_deadline_retries_prevented_;
  }
  [[nodiscard]] std::uint32_t GetDeadlineExpiredFragmentGroups() const {
    return stats_deadline_expired_fragment_groups_;
  }

 private:
  ISocket* socket_ = nullptr;
  ReliableConnectionConfig config_;
  IClock* clock_ = nullptr;
  IReliableConnectionHandler* event_handler_ = nullptr;

  ConnectionState state_ = ConnectionState::kDisconnected;
  SocketAddress remote_addr_;
  std::uint16_t remote_port_ = 0;

  std::vector<std::uint8_t> send_buffer_;
  std::vector<std::uint8_t> batch_buffer_;
  std::vector<std::uint8_t> batch_scratch_buffer_;
  std::vector<std::uint8_t> batch_command_buffer_;
  std::vector<std::uint8_t> batch_payload_buffer_;
  std::vector<std::span<const std::uint8_t>> batch_command_spans_;

  // Sequence numbers per channel.
  std::vector<std::uint32_t> send_sequence_;

  detail::SendQueue send_queue_;
  detail::AckBatcher ack_batcher_;
  detail::CongestionController congestion_;
  detail::ReceiveSequencer receive_sequencer_;
  detail::FragmentReassembler fragment_reassembler_;

  // Timing
  std::chrono::steady_clock::time_point last_send_time_;
  std::chrono::steady_clock::time_point last_receive_time_;
  std::chrono::steady_clock::time_point last_ping_time_;

  // Round-trip time estimation
  float rtt_ = 100.0f;  // milliseconds

  // Statistics
  std::uint32_t stats_sent_packets_ = 0;
  std::uint32_t stats_received_packets_ = 0;
  std::uint32_t stats_lost_packets_ = 0;
  std::uint32_t stats_deadline_send_drops_ = 0;
  std::uint32_t stats_deadline_receive_drops_ = 0;
  std::uint32_t stats_deadline_retries_prevented_ = 0;
  std::uint32_t stats_deadline_expired_fragment_groups_ = 0;

  // Fragment state per channel.
  std::vector<std::uint16_t>
    next_fragment_group_id_;  ///< Rolling group-ID counter, per channel

  // Optional secure transport state.
  crypto::HandshakeState crypto_handshake_{};
  crypto::CryptoContext crypto_context_{};
  bool crypto_ready_ = false;

  // Internal methods
  bool SendReliableInternal(std::uint8_t channel, const void* data,
                            std::size_t size, std::uint32_t deadline_ms);
  bool SendUnreliableInternal(std::uint8_t channel, const void* data,
                              std::size_t size, std::uint32_t deadline_ms);
  bool SendSequencedInternal(std::uint8_t channel, const void* data,
                             std::size_t size, std::uint32_t deadline_ms);
  bool SendUnsequencedInternal(std::uint8_t channel, const void* data,
                               std::size_t size, std::uint32_t deadline_ms);
  bool SendPacket(detail::PacketType type, std::uint8_t channel,
                  const void* data, std::size_t size,
                  std::uint32_t sequence = 0);
  bool SendPacket(detail::PacketType type, std::uint8_t channel,
                  const void* data, std::size_t size, std::uint32_t sequence,
                  const detail::DeadlineMetadata& deadline);
  bool SendPacket(detail::PacketType type, std::uint8_t channel,
                  const void* data, std::size_t size, std::uint32_t sequence,
                  const detail::DeadlineMetadata& deadline,
                  std::chrono::steady_clock::time_point now);
  bool SendPacket(detail::PacketType type, std::uint8_t channel,
                  const void* data, std::size_t size, std::uint32_t sequence,
                  const detail::DeadlineMetadata& deadline,
                  const detail::FragmentMetadata& fragment,
                  std::chrono::steady_clock::time_point now);
  bool SendSinglePacket(detail::PacketType type, std::uint8_t channel,
                        const void* data, std::size_t size,
                        std::uint32_t sequence,
                        const detail::DeadlineMetadata& deadline,
                        const detail::FragmentMetadata& fragment,
                        std::chrono::steady_clock::time_point now);
  bool BuildPacket(detail::PacketType type, std::uint8_t channel,
                   const void* data, std::size_t size, std::uint32_t sequence,
                   const detail::DeadlineMetadata& deadline,
                   const detail::FragmentMetadata& fragment,
                   std::chrono::steady_clock::time_point now,
                   std::vector<std::uint8_t>& buffer, std::size_t& packet_size);
  bool SendRawDatagram(const std::uint8_t* data, std::size_t size,
                       std::chrono::steady_clock::time_point now,
                       std::uint32_t logical_packets = 1);
  [[nodiscard]] bool CanBatchPacket(detail::PacketType type) const;
  bool SendBatchWithCommand(const std::uint8_t* command,
                            std::size_t command_size,
                            std::chrono::steady_clock::time_point now);
  bool FlushQueuedAcks(std::chrono::steady_clock::time_point now);
  void ResetBatchCommandScratch(std::size_t command_count_hint,
                                std::size_t command_bytes_hint);
  bool AppendAckBatchCommand(detail::PacketKey ack,
                             std::chrono::steady_clock::time_point now);
  bool EncodeAndSendCurrentBatch(std::chrono::steady_clock::time_point now);
  void QueueAck(std::uint8_t channel, std::uint32_t sequence,
                std::chrono::steady_clock::time_point now);
  void ProcessBatchPacket(const std::uint8_t* payload, std::size_t size,
                          const SocketAddress& from, std::uint16_t from_port);
  void ProcessSinglePacket(const std::uint8_t* packet_data, std::size_t size,
                           const detail::DecodedPacket& packet,
                           const SocketAddress& from, std::uint16_t from_port);
  /// Split a large payload into Fragment packets and enqueue each for reliable
  /// delivery.
  bool SendFragmented(std::uint8_t channel, const void* data, std::size_t size,
                      const detail::DeadlineMetadata& deadline);
  void SendAck(std::uint8_t channel, std::uint32_t sequence);
  void SendAck(std::uint8_t channel, std::uint32_t sequence,
               std::chrono::steady_clock::time_point now);
  void SendPing();
  void SendPing(std::chrono::steady_clock::time_point now);
  void DeliverReliableMessages(
    const std::vector<detail::ReceiveSequencer::Message>& messages);
  void RetryPendingPackets(std::chrono::steady_clock::time_point now);
  void CheckTimeout(std::chrono::steady_clock::time_point now);
  /// Discard fragment groups that have been waiting longer than
  /// fragmentTimeoutMs.
  void CleanupFragments(std::chrono::steady_clock::time_point now);
  void ClearPendingPackets();
  [[nodiscard]] bool SecureMode() const { return config_.crypto.enabled; }
  [[nodiscard]] bool CanUseCrypto() const;
  [[nodiscard]] bool ShouldEncryptPacket(detail::PacketType type) const;
  [[nodiscard]] std::size_t CryptoEnvelopeOverhead() const;
  [[nodiscard]] std::size_t MaxPayloadForPacket(
    bool has_deadline = false, bool has_fragment = false) const;
  [[nodiscard]] bool PrepareDeadline(
    std::uint32_t deadline_ms, detail::DeadlineMetadata& deadline,
    std::chrono::steady_clock::time_point now) const;
  [[nodiscard]] static bool DeadlineExpired(
    const detail::DeadlineMetadata& deadline,
    std::chrono::steady_clock::time_point now);
  static void CopyDeadlineToPending(detail::PendingPacket& pending,
                                    const detail::DeadlineMetadata& deadline);

  std::uint32_t GetNextSequence(std::uint8_t channel) {
    if (channel >= send_sequence_.size()) return 0;
    return send_sequence_.at(channel)++;
  }
};

}  // namespace socketwire
