#pragma once

/// Reliable UDP protocol implementation for SocketWire.
///
/// Provides reliable packet delivery, packet sequencing, connection state
/// management, keep-alives, and separate reliable/unreliable channels.

#include <array>
#include <bitset>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <unordered_map>
#include <vector>

#include "bit_stream.hpp"
#include "crypto.hpp"
#include "i_socket.hpp"

using Clock = std::chrono::steady_clock;

namespace socketwire {

enum class PacketType : std::uint8_t {
  kUnreliable = 0,   ///< No delivery guarantees.
  kReliable = 1,     ///< Guaranteed delivery, ordered.
  kUnsequenced = 2,  ///< Guaranteed delivery, unordered.
  kConnect = 3,      ///< Connection request.
  kAccept = 4,       ///< Connection accepted.
  kDisconnect = 5,   ///< Graceful disconnect.
  kPing = 6,         ///< Keep-alive request.
  kPong = 7,         ///< Keep-alive response.
  kAck = 8,          ///< Acknowledgment.
  kFragment = 9,     ///< Fragment of a large message.
  kBatch = 10        ///< Internal container for multiple protocol packets.
};

enum class ConnectionState : std::uint8_t {
  kDisconnected = 0,
  kDisconnecting = 1,
  kConnected = 2,
  kConnecting = 3
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
  /// Maximum new-connection handshakes accepted per second (0 = unlimited).
  std::uint32_t maxHandshakesPerSecond = 20;
  /// How long (ms) to wait for all fragments before discarding an incomplete
  /// group.
  std::uint32_t fragmentTimeoutMs = 5000;
  /// Maximum simultaneous unACKed reliable packets (send-window size). 0 =
  /// unlimited. When > 0, enables AIMD congestion avoidance: window halves on
  /// packet loss, grows by 1 per ACK up to this maximum.
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
  /// Reserved for delayed batching; 0 keeps application sends immediate.
  std::uint32_t maxBatchDelayUs = 0;
  /// Ordered reliable receive window per channel.
  std::uint32_t receiveWindowSize = 1024;
};

/// Small reusable payload buffer for pending packets. Most game/ACK-sized
/// reliable payloads avoid heap storage; large messages still use a vector and
/// keep its capacity for reuse.
class PendingPayloadBuffer {
 public:
  static constexpr std::size_t kInlineCapacity = 256;

  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }

  [[nodiscard]] std::uint8_t* data() noexcept {
    return using_heap_ ? heap_.data() : inline_.data();
  }
  [[nodiscard]] const std::uint8_t* data() const noexcept {
    return using_heap_ ? heap_.data() : inline_.data();
  }

  void clear() noexcept {
    size_ = 0;
    using_heap_ = false;
    heap_.clear();
  }

  void resize(std::size_t size) {
    size_ = size;
    if (size > kInlineCapacity) {
      using_heap_ = true;
      heap_.resize(size);
      return;
    }
    using_heap_ = false;
    heap_.clear();
  }

  void assign(const std::uint8_t* first, const std::uint8_t* last) {
    if (first == nullptr || last == nullptr || last <= first) {
      clear();
      return;
    }
    assign(first, static_cast<std::size_t>(last - first));
  }

  void assign(const std::uint8_t* src, std::size_t size) {
    resize(size);
    if (size > 0 && src != nullptr) {
      std::memcpy(data(), src, size);
    }
  }

 private:
  std::array<std::uint8_t, kInlineCapacity> inline_{};
  std::vector<std::uint8_t> heap_;
  std::size_t size_ = 0;
  bool using_heap_ = false;
};

/// Packet waiting for acknowledgment.
struct PendingPacket {
  std::uint32_t sequence = 0;
  PendingPayloadBuffer data;
  std::chrono::steady_clock::time_point sendTime;
  std::uint32_t retries = 0;
  std::uint8_t channel = 0;
  PacketType type =
      PacketType::kReliable;  ///< Original type for retransmission
  std::chrono::steady_clock::time_point createdTime;
  std::uint32_t deadline_ms = 0;
  std::chrono::steady_clock::time_point expireTime;
  bool hasDeadline = false;
};

/// Received packet queued for ordered delivery.
struct ReceivedPacket {
  std::uint32_t sequence = 0;
  PendingPayloadBuffer data;
  std::uint8_t channel = 0;
};

/// State for accumulating fragments of a single fragmented message.
struct FragmentGroup {
  std::uint16_t total = 0;  ///< Total number of fragments
  std::vector<std::optional<std::vector<std::uint8_t>>>
      pieces;  ///< Indexed by fragmentIndex
  std::uint16_t receivedCount = 0;
  std::chrono::steady_clock::time_point firstReceived;
  std::chrono::steady_clock::time_point expireTime;
  bool hasDeadline = false;
  std::uint8_t channel = 0;
};

/// Event callbacks for reliable connection state and payload delivery.
class IReliableConnectionHandler {
 public:
  virtual ~IReliableConnectionHandler() = default;

  /// Called when the connection is established.
  virtual void OnConnected() { onConnected(); }
  virtual void onConnected() {}

  /// Called when the connection is closed.
  virtual void OnDisconnected() { onDisconnected(); }
  virtual void onDisconnected() {}

  /// Called when a reliable packet is received in order.
  virtual void OnReliableReceived(std::uint8_t channel, const void* data,
                                  std::size_t size) {
    onReliableReceived(channel, data, size);
  }
  virtual void onReliableReceived(std::uint8_t channel, const void* data,
                                  std::size_t size) {
    (void)channel;
    (void)data;
    (void)size;
  }

  /// Called when an unreliable packet is received.
  virtual void OnUnreliableReceived(std::uint8_t channel, const void* data,
                                    std::size_t size) {
    onUnreliableReceived(channel, data, size);
  }
  virtual void onUnreliableReceived(std::uint8_t channel, const void* data,
                                    std::size_t size) {
    (void)channel;
    (void)data;
    (void)size;
  }

  /// Called when the connection times out.
  virtual void OnTimeout() { onTimeout(); }
  virtual void onTimeout() {}
};

/// Manages a single reliable connection over UDP.
class ReliableConnection {
 public:
  explicit ReliableConnection(ISocket* socket,
                              const ReliableConnectionConfig& cfg = {});
  ~ReliableConnection();

  /// Starts a client-side connection attempt.
  bool Connect(const SocketAddress& addr, std::uint16_t port);
  bool connect(const SocketAddress& addr, std::uint16_t port) {
    return Connect(addr, port);
  }
  /// Sends a disconnect packet and clears local connection state.
  void Disconnect();
  void disconnect() { Disconnect(); }
  [[nodiscard]] bool IsConnected() const {
    return state_ == ConnectionState::kConnected;
  }
  [[nodiscard]] bool isConnected() const { return IsConnected(); }
  [[nodiscard]] ConnectionState GetState() const { return state_; }
  [[nodiscard]] ConnectionState getState() const { return GetState(); }
  [[nodiscard]] bool IsCryptoReady() const { return crypto_ready_; }
  [[nodiscard]] bool isCryptoReady() const { return IsCryptoReady(); }

  /// Sets the remote address for server-side connections that start connected.
  void SetRemoteAddress(const SocketAddress& addr, std::uint16_t port);
  void setRemoteAddress(const SocketAddress& addr, std::uint16_t port) {
    SetRemoteAddress(addr, port);
  }
  void SetConnected() { state_ = ConnectionState::kConnected; }
  void setConnected() { SetConnected(); }

  bool SendReliable(const std::uint8_t channel, const void* data,
                    std::size_t size);
  bool sendReliable(const std::uint8_t channel, const void* data,
                    std::size_t size) {
    return SendReliable(channel, data, size);
  }
  bool SendUnreliable(const std::uint8_t channel, const void* data,
                      std::size_t size);
  bool sendUnreliable(const std::uint8_t channel, const void* data,
                      std::size_t size) {
    return SendUnreliable(channel, data, size);
  }
  bool SendUnsequenced(const std::uint8_t channel, const void* data,
                       std::size_t size);
  bool sendUnsequenced(const std::uint8_t channel, const void* data,
                       std::size_t size) {
    return SendUnsequenced(channel, data, size);
  }
  bool SendReliableWithDeadline(const std::uint8_t channel, const void* data,
                                std::size_t size, std::uint32_t deadline_ms);
  bool SendUnreliableWithDeadline(const std::uint8_t channel, const void* data,
                                  std::size_t size, std::uint32_t deadline_ms);
  bool SendUnsequencedWithDeadline(const std::uint8_t channel, const void* data,
                                   std::size_t size, std::uint32_t deadline_ms);

  bool SendReliable(const std::uint8_t channel, const BitStream& stream);
  bool sendReliable(const std::uint8_t channel, const BitStream& stream) {
    return SendReliable(channel, stream);
  }
  bool SendUnreliable(const std::uint8_t channel, const BitStream& stream);
  bool sendUnreliable(const std::uint8_t channel, const BitStream& stream) {
    return SendUnreliable(channel, stream);
  }
  bool SendUnsequenced(const std::uint8_t channel, const BitStream& stream);
  bool sendUnsequenced(const std::uint8_t channel, const BitStream& stream) {
    return SendUnsequenced(channel, stream);
  }
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
  void update() { Update(); }

  /// Drains pending socket packets, then calls Update().
  ///
  /// Requires the socket to be in non-blocking mode.
  void Tick();
  void tick() { Tick(); }

  void ProcessPacket(const void* data, std::size_t size,
                     const SocketAddress& from, std::uint16_t from_port);
  void processPacket(const void* data, std::size_t size,
                     const SocketAddress& from, std::uint16_t from_port) {
    ProcessPacket(data, size, from, from_port);
  }

  void SetHandler(IReliableConnectionHandler* handler) {
    event_handler_ = handler;
  }
  void setHandler(IReliableConnectionHandler* handler) { SetHandler(handler); }

  // Statistics
  [[nodiscard]] std::uint32_t GetSentPackets() const {
    return stats_sent_packets_;
  }
  [[nodiscard]] std::uint32_t getSentPackets() const { return GetSentPackets(); }
  [[nodiscard]] std::uint32_t GetReceivedPackets() const {
    return stats_received_packets_;
  }
  [[nodiscard]] std::uint32_t getReceivedPackets() const {
    return GetReceivedPackets();
  }
  [[nodiscard]] std::uint32_t GetLostPackets() const {
    return stats_lost_packets_;
  }
  [[nodiscard]] std::uint32_t getLostPackets() const { return GetLostPackets(); }
  [[nodiscard]] float GetRtt() const { return rtt_; }
  [[nodiscard]] float GetRTT() const { return GetRtt(); }
  [[nodiscard]] float getRtt() const { return GetRtt(); }
  [[nodiscard]] float getRTT() const { return GetRtt(); }
  /// Current adaptive send window (0 = unlimited).
  [[nodiscard]] std::uint32_t GetSendWindow() const {
    return current_send_window_;
  }
  [[nodiscard]] std::uint32_t getSendWindow() const {
    return GetSendWindow();
  }
  /// Number of reliable packets currently awaiting acknowledgment.
  [[nodiscard]] std::uint32_t GetInflightCount() const {
    return pending_active_count_;
  }
  [[nodiscard]] std::uint32_t getInflightCount() const {
    return GetInflightCount();
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
  struct DeadlineMetadata {
    bool hasDeadline = false;
    std::uint32_t deadline_ms = 0;
    std::chrono::steady_clock::time_point createdTime;
    std::chrono::steady_clock::time_point expireTime;
  };

  
  struct PendingHandle {
    std::size_t index = std::numeric_limits<std::size_t>::max();
    std::uint32_t generation = 0;
  };
  struct PendingSlot {
    PendingPacket packet;
    std::uint32_t generation = 0;
    bool active = false;
  };
  struct ReceivedSlot {
    ReceivedPacket packet;
    bool occupied = false;
  };
  struct RetryEntry {
    std::chrono::steady_clock::time_point dueTime{};
    PendingHandle handle;
    std::uint32_t retryGeneration = 0;

    [[nodiscard]] bool operator>(const RetryEntry& other) const {
      return dueTime > other.dueTime;
    }
  };

  ISocket* socket_ = nullptr;
  ReliableConnectionConfig config_;
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
  std::vector<std::uint32_t> queued_acks_;

  // Sequence numbers per channel.
  std::vector<std::uint32_t> send_sequence_;
  std::vector<std::uint32_t> receive_sequence_;

  // Pending packets waiting for ACK.
  std::vector<PendingSlot> pending_packets_;
  std::deque<PendingHandle> pending_order_;
  std::deque<PendingHandle> pending_retry_order_;
  std::vector<std::size_t> free_pending_slots_;
  std::unordered_map<std::uint32_t, PendingHandle> pending_by_sequence_;
  std::unordered_map<std::uint32_t, std::uint32_t> pending_sequence_counts_;
  std::priority_queue<RetryEntry, std::vector<RetryEntry>,
                      std::greater<RetryEntry>>
      retry_heap_;
  std::uint32_t pending_active_count_ = 0;

  // Per-channel duplicate detection window with bounded memory.
  static constexpr std::uint32_t kSeqWindowSize = 1024;
  std::vector<std::uint32_t>
      seq_window_high_;  // per-channel highest_seen_sequence + 1
  std::vector<std::bitset<1024>>
      seq_window_bits_;  // per-channel bit[seq % 1024]

  // Reliable packets pending ordered processing per channel.
  std::vector<std::vector<ReceivedSlot>> pending_received_;

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

  // Congestion control (AIMD)
  std::uint32_t current_send_window_ =
      0;                         ///< Adaptive send window; 0 = unlimited
  std::uint32_t ssthresh_ = 32;  ///< Slow-start threshold

  // Fragment state per channel.
  static constexpr std::size_t kFragmentHeaderExtra =
      6;  ///< groupId(2) + fragIdx(2) + fragTotal(2)
  std::vector<std::uint16_t>
      next_fragment_group_id_;  ///< Rolling group-ID counter, per channel
  /// Incomplete fragment groups indexed by [channel][groupId]
  std::vector<std::unordered_map<std::uint16_t, FragmentGroup>>
      fragment_groups_;

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
  bool SendPacket(PacketType type, std::uint8_t channel, const void* data,
                  std::size_t size, std::uint32_t sequence = 0);
  bool SendPacket(PacketType type, std::uint8_t channel, const void* data,
                  std::size_t size, std::uint32_t sequence,
                  const DeadlineMetadata& deadline);
  bool SendPacket(PacketType type, std::uint8_t channel, const void* data,
                  std::size_t size, std::uint32_t sequence,
                  const DeadlineMetadata& deadline, Clock::time_point now);
  bool SendSinglePacket(PacketType type, std::uint8_t channel,
                        const void* data, std::size_t size,
                        std::uint32_t sequence,
                        const DeadlineMetadata& deadline,
                        Clock::time_point now);
  bool BuildPacket(PacketType type, std::uint8_t channel, const void* data,
                   std::size_t size, std::uint32_t sequence,
                   const DeadlineMetadata& deadline, Clock::time_point now,
                   std::vector<std::uint8_t>& buffer,
                   std::size_t& packet_size);
  bool SendRawDatagram(const std::uint8_t* data, std::size_t size,
                       Clock::time_point now,
                       std::uint32_t logical_packets = 1);
  bool CanBatchPacket(PacketType type) const;
  bool SendBatchWithCommand(const std::uint8_t* command,
                            std::size_t command_size, Clock::time_point now);
  bool FlushQueuedAcks(Clock::time_point now);
  void QueueAck(std::uint32_t sequence, Clock::time_point now);
  void ProcessBatchPacket(const std::uint8_t* payload, std::size_t size,
                          const SocketAddress& from, std::uint16_t from_port);
  /// Split a large payload into Fragment packets and enqueue each for reliable
  /// delivery.
  bool SendFragmented(std::uint8_t channel, const void* data, std::size_t size,
                      const DeadlineMetadata& deadline);
  void SendAck(std::uint32_t sequence);
  void SendAck(std::uint32_t sequence, Clock::time_point now);
  void SendPing();
  void SendPing(Clock::time_point now);
  void ProcessPendingReliable(Clock::time_point now);
  void ProcessPendingReliableChannel(std::uint8_t channel,
                                     Clock::time_point now);
  void RetryPendingPackets(Clock::time_point now);
  void CheckTimeout(Clock::time_point now);
  /// Discard fragment groups that have been waiting longer than
  /// fragmentTimeoutMs.
  void CleanupFragments(Clock::time_point now);
  void ScheduleRetry(PendingHandle handle, Clock::time_point now);
  void EnsureReceiveBatchBuffers();
  PendingHandle AllocatePendingPacket(std::uint32_t sequence);
  void ResetPendingPacketForReuse(PendingPacket& pending,
                                  std::uint32_t sequence);
  void ErasePendingPacket(PendingHandle handle);
  [[nodiscard]] PendingPacket* GetPendingPacket(PendingHandle handle);
  [[nodiscard]] const PendingPacket* GetPendingPacket(
      PendingHandle handle) const;
  [[nodiscard]] PendingHandle FindPendingPacket(std::uint32_t sequence) const;
  [[nodiscard]] bool IsPendingHandleValid(PendingHandle handle) const;
  void ClearPendingPackets();
  [[nodiscard]] bool SecureMode() const { return config_.crypto.enabled; }
  [[nodiscard]] bool CanUseCrypto() const;
  [[nodiscard]] bool ShouldEncryptPacket(PacketType type) const;
  [[nodiscard]] std::size_t CryptoEnvelopeOverhead() const;
  [[nodiscard]] std::size_t MaxPayloadForPacket(
      bool has_deadline = false, std::size_t header_extra = 0) const;
  [[nodiscard]] bool PrepareDeadline(std::uint32_t deadline_ms,
                                     DeadlineMetadata& deadline,
                                     Clock::time_point now) const;
  [[nodiscard]] static bool DeadlineExpired(
      const DeadlineMetadata& deadline,
      std::chrono::steady_clock::time_point now);
  static void CopyDeadlineToPending(PendingPacket& pending,
                                    const DeadlineMetadata& deadline);

  [[nodiscard]] bool IsDuplicateSequence(std::uint8_t channel,
                                         std::uint32_t seq) const;
  void MarkSequenceReceived(std::uint8_t channel, std::uint32_t seq);

  std::uint32_t GetNextSequence(std::uint8_t channel) {
    if (channel >= send_sequence_.size()) return 0;
    return send_sequence_.at(channel)++;
  }
  static bool IsSequenceNewer(std::uint32_t s1, std::uint32_t s2);
};

/// Manages multiple server-side reliable connections.
class ConnectionManager {
 public:
  struct RemoteClient {
    SocketAddress address;
    std::uint16_t port = 0;
    std::unique_ptr<ReliableConnection> connection;
    void* userData = nullptr;  // For game-specific data (e.g., entity ID)
  };

  explicit ConnectionManager(ISocket* socket,
                             const ReliableConnectionConfig& cfg = {});
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
  std::function<void(RemoteClient*)> onClientConnected;
  std::function<void(RemoteClient*)> onClientDisconnected;

 private:
  ISocket* socket_ = nullptr;
  ReliableConnectionConfig config_;
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
};

// Helper function to create connection key from IPv4 address and port
inline std::string MakeConnectionKey(const SocketAddress& addr,
                                     std::uint16_t port) {
  std::string key;
  if (addr.isIPv6) {
    // 16 bytes IPv6 + 4 bytes scopeId + 2 bytes port
    key.resize(22);
    std::memcpy(key.data(), addr.ipv6.bytes.data(), 16);
    std::memcpy(key.data() + 16, &addr.ipv6.scopeId, 4);
    std::memcpy(key.data() + 20, &port, 2);
  } else {
    // 4 bytes IPv4 + 2 bytes port
    key.resize(6);
    std::memcpy(key.data(), &addr.ipv4.hostOrderAddress, 4);
    std::memcpy(key.data() + 4, &port, 2);
  }
  return key;
}

}  // namespace socketwire
