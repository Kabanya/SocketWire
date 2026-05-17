#pragma once

/// Reliable UDP protocol implementation for SocketWire.
///
/// Provides reliable packet delivery, packet sequencing, connection state
/// management, keep-alives, and separate reliable/unreliable channels.

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <unordered_map>
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
  /// Maximum accepted clients per ConnectionManager.
  std::uint32_t maxClients = 1024;
  /// Maximum new-connection handshakes accepted per second (0 = unlimited).
  std::uint32_t maxHandshakesPerSecond = 20;
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

  /// Sets the remote address for server-side connections that start connected.
  void SetRemoteAddress(const SocketAddress& addr, std::uint16_t port);
  void SetConnected() { state_ = ConnectionState::kConnected; }

  bool SendReliable(const std::uint8_t channel, const void* data,
                    std::size_t size);
  bool SendUnreliable(const std::uint8_t channel, const void* data,
                      std::size_t size);
  bool SendUnsequenced(const std::uint8_t channel, const void* data,
                       std::size_t size);
  bool SendReliableWithDeadline(const std::uint8_t channel, const void* data,
                                std::size_t size, std::uint32_t deadline_ms);
  bool SendUnreliableWithDeadline(const std::uint8_t channel, const void* data,
                                  std::size_t size, std::uint32_t deadline_ms);
  bool SendUnsequencedWithDeadline(const std::uint8_t channel, const void* data,
                                   std::size_t size, std::uint32_t deadline_ms);

  bool SendReliable(const std::uint8_t channel, const BitStream& stream);
  bool SendUnreliable(const std::uint8_t channel, const BitStream& stream);
  bool SendUnsequenced(const std::uint8_t channel, const BitStream& stream);
  bool SendReliableWithDeadline(const std::uint8_t channel,
                                const BitStream& stream,
                                std::uint32_t deadline_ms);
  bool SendUnreliableWithDeadline(const std::uint8_t channel,
                                  const BitStream& stream,
                                  std::uint32_t deadline_ms);
  bool SendUnsequencedWithDeadline(const std::uint8_t channel,
                                   const BitStream& stream,
                                   std::uint32_t deadline_ms);

  /// Processes retransmits, pings, timeouts, and pending ordered packets.
  void Update();

  /// Drains pending socket packets, then calls Update().
  ///
  /// Requires the socket to be in non-blocking mode.
  void Tick();

  void ProcessPacket(const void* data, std::size_t size,
                     const SocketAddress& from, std::uint16_t from_port);

  /// Returns true when the buffer contains a valid SocketWire connect packet.
  ///
  /// Intended for custom server-side demultiplexers that need to decide
  /// whether to allocate a new ReliableConnection for an unknown endpoint.
  [[nodiscard]] static bool IsConnectPacket(const void* data,
                                            std::size_t size);

  void SetHandler(IReliableConnectionHandler* handler) {
    event_handler_ = handler;
  }

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
  std::vector<std::uint8_t> receive_buffer_;
  std::vector<std::vector<std::uint8_t>> receive_batch_buffers_;
  std::vector<IncomingDatagram> receive_batch_;

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
  void EnsureReceiveBatchBuffers();
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

/// Manages multiple server-side reliable connections.
///
/// Threading contract: ConnectionManager has the same single-network-loop
/// ownership as ReliableConnection. It does not add internal locking.
class ConnectionManager {
 public:
  struct RemoteClient {
    SocketAddress address;
    std::uint16_t port = 0;
    std::unique_ptr<ReliableConnection> connection;
    void* userData = nullptr;  // For game-specific data (e.g., entity ID)
  };

  explicit ConnectionManager(ISocket* socket,
                             const ReliableConnectionConfig& cfg = {},
                             IClock* clock = nullptr);
  ~ConnectionManager();

  void Update();

  /// Drains pending socket packets, then updates all connections.
  ///
  /// Requires the socket to be in non-blocking mode.
  void Tick();

  void ProcessPacket(const void* data, std::size_t size,
                     const SocketAddress& from, std::uint16_t from_port);

  void BroadcastReliable(std::uint8_t channel, const void* data,
                         std::size_t size);
  void BroadcastUnreliable(std::uint8_t channel, const void* data,
                           std::size_t size);

  std::vector<RemoteClient*> GetConnections();
  RemoteClient* GetConnection(const SocketAddress& addr, std::uint16_t port);

  void SetHandler(IReliableConnectionHandler* handler) {
    event_handler_ = handler;
  }

  /// Optional server-side connection callbacks.
  /// Called once, after the client's connection reaches established state.
  std::function<void(RemoteClient*)> onClientConnected;
  /// Called when a disconnected client is removed from the manager.
  std::function<void(RemoteClient*)> onClientDisconnected;

 private:
  ISocket* socket_ = nullptr;
  ReliableConnectionConfig config_;
  IClock* clock_ = nullptr;
  IReliableConnectionHandler* event_handler_ = nullptr;

  std::vector<std::unique_ptr<RemoteClient>> clients_;

  struct ConnectionKey {
    bool isIPv6 = false;
    std::uint16_t port = 0;
    std::uint32_t ipv4 = 0;
    std::array<std::uint8_t, 16> ipv6{};
    std::uint32_t scopeId = 0;

    [[nodiscard]] bool operator==(const ConnectionKey& other) const {
      return isIPv6 == other.isIPv6 && port == other.port &&
             ipv4 == other.ipv4 && ipv6 == other.ipv6 &&
             scopeId == other.scopeId;
    }
  };

  struct ConnectionKeyHash {
    [[nodiscard]] std::size_t operator()(const ConnectionKey& key) const {
      std::size_t h = std::hash<std::uint16_t>{}(key.port);
      h ^= std::hash<bool>{}(key.isIPv6) + 0x9e3779b97f4a7c15ULL + (h << 6) +
           (h >> 2);
      if (key.isIPv6) {
        for (const auto byte : key.ipv6) {
          h ^= std::hash<std::uint8_t>{}(byte) + 0x9e3779b97f4a7c15ULL +
               (h << 6) + (h >> 2);
        }
        h ^= std::hash<std::uint32_t>{}(key.scopeId) + 0x9e3779b97f4a7c15ULL +
             (h << 6) + (h >> 2);
      } else {
        h ^= std::hash<std::uint32_t>{}(key.ipv4) + 0x9e3779b97f4a7c15ULL +
             (h << 6) + (h >> 2);
      }
      return h;
    }
  };

  RemoteClient* FindOrCreateClient(const SocketAddress& addr,
                                   std::uint16_t port);
  void RemoveClient(RemoteClient* client);

  static ConnectionKey MakeAddressKey(const SocketAddress& addr,
                                      std::uint16_t port);
  std::unordered_map<ConnectionKey, RemoteClient*, ConnectionKeyHash>
    client_map_;
  std::vector<std::uint8_t> receive_buffer_;
  std::vector<std::vector<std::uint8_t>> receive_batch_buffers_;
  std::vector<IncomingDatagram> receive_batch_;

  // Handshake rate-limiting state.
  std::uint32_t connect_window_count_ = 0;
  std::chrono::steady_clock::time_point connect_window_start_{};
  bool HandshakeAllowed();  ///< Returns true if a new connection may be
                            ///< accepted right now.
  void EmitClientConnected(RemoteClient* client);
  std::unordered_map<RemoteClient*, bool> connected_notified_;
};

}  // namespace socketwire
