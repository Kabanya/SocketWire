#pragma once

/*
  ReliableConnection — reliable UDP protocol implementation for SocketWire

  Provides:
  - Reliable packet delivery with acknowledgments
  - Packet sequencing and ordering
  - Connection state management
  - Keep-alive mechanism
  - Multiple channels (reliable/unreliable)
*/

#include <bitset>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "bit_stream.hpp"
#include "crypto.hpp"
#include "i_socket.hpp"

namespace socketwire {

// Packet types for internal protocol
enum class PacketType : std::uint8_t {
  kUnreliable = 0,   // No guarantees
  kReliable = 1,     // Guaranteed delivery, ordered
  kUnsequenced = 2,  // Guaranteed delivery, unordered
  kConnect = 3,      // Connection request
  kAccept = 4,       // Connection accepted
  kDisconnect = 5,   // Graceful disconnect
  kPing = 6,         // Keep-alive
  kPong = 7,         // Keep-alive response
  kAck = 8,          // Acknowledgment
  kFragment = 9      // Fragment of a large message
};

// Connection states
enum class ConnectionState : std::uint8_t {
  kDisconnected = 0,
  kDisconnecting = 1,
  kConnected = 2,
  kConnecting = 3
};

// Configuration for reliable connection
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
};

// Pending packet waiting for acknowledgment
struct PendingPacket {
  std::uint32_t sequence = 0;
  std::vector<std::uint8_t> data;
  std::chrono::steady_clock::time_point sendTime;
  std::uint32_t retries = 0;
  std::uint8_t channel = 0;
  PacketType type =
      PacketType::kReliable;  ///< Original type for retransmission
};

// Received packet info
struct ReceivedPacket {
  std::uint32_t sequence = 0;
  std::vector<std::uint8_t> data;
  std::uint8_t channel = 0;
};

/// State for accumulating fragments of a single fragmented message.
struct FragmentGroup {
  std::uint16_t total = 0;  ///< Total number of fragments
  std::vector<std::optional<std::vector<std::uint8_t>>>
      pieces;  ///< Indexed by fragmentIndex
  std::uint16_t receivedCount = 0;
  std::chrono::steady_clock::time_point firstReceived;
  std::uint8_t channel = 0;
};

// Event callbacks
class IReliableConnectionHandler {
 public:
  virtual ~IReliableConnectionHandler() = default;  // disconect();

  // Called when connection is established
  virtual void OnConnected() {}

  // Called when connection is closed
  virtual void OnDisconnected() {}

  // Called when reliable packet is received (in order)
  virtual void OnReliableReceived(std::uint8_t channel, const void* data,
                                  std::size_t size) = 0;

  // Called when unreliable packet is received
  virtual void OnUnreliableReceived(std::uint8_t channel, const void* data,
                                    std::size_t size) = 0;

  // Called on connection timeout
  virtual void OnTimeout() {}
};

// Manages a single reliable connection over UDP
class ReliableConnection {
 public:
  explicit ReliableConnection(ISocket* socket,
                              const ReliableConnectionConfig& cfg = {});
  ~ReliableConnection();

  // Connection management
  bool Connect(const SocketAddress& addr, std::uint16_t port);
  void Disconnect();
  [[nodiscard]] bool IsConnected() const {
    return state == ConnectionState::kConnected;
  }
  [[nodiscard]] ConnectionState GetState() const { return state; }
  [[nodiscard]] bool IsCryptoReady() const { return cryptoReady; }

  // Set remote address (for server-side connections that start connected)
  void SetRemoteAddress(const SocketAddress& addr, std::uint16_t port);
  void SetConnected() { state = ConnectionState::kConnected; }

  // Send packets
  bool SendReliable(const std::uint8_t channel, const void* data,
                    std::size_t size);
  bool SendUnreliable(const std::uint8_t channel, const void* data,
                      std::size_t size);
  bool SendUnsequenced(const std::uint8_t channel, const void* data,
                       std::size_t size);

  // BitStream convenience methods
  bool SendReliable(const std::uint8_t channel, const BitStream& stream);
  bool SendUnreliable(const std::uint8_t channel, const BitStream& stream);
  bool SendUnsequenced(const std::uint8_t channel, const BitStream& stream);

  // Update - call regularly (e.g., every frame)
  void Update();

  // Convenience: drain all pending packets from socket, then call update().
  // Requires the socket to be in non-blocking mode.
  void Tick();

  // Process incoming packet
  void ProcessPacket(const void* data, std::size_t size,
                     const SocketAddress& from, std::uint16_t from_port);

  // Set event handler
  void SetHandler(IReliableConnectionHandler* handler) {
    eventHandler = handler;
  }

  // Statistics
  [[nodiscard]] std::uint32_t GetSentPackets() const {
    return statsSentPackets;
  }
  [[nodiscard]] std::uint32_t GetReceivedPackets() const {
    return statsReceivedPackets;
  }
  [[nodiscard]] std::uint32_t GetLostPackets() const {
    return statsLostPackets;
  }
  [[nodiscard]] float GetRtt() const { return rtt; }
  /// Current adaptive send window (0 = unlimited).
  [[nodiscard]] std::uint32_t GetSendWindow() const {
    return currentSendWindow;
  }
  /// Number of reliable packets currently awaiting acknowledgment.
  [[nodiscard]] std::uint32_t GetInflightCount() const {
    return static_cast<std::uint32_t>(pendingPackets.size());
  }

 private:
  ISocket* socket;
  ReliableConnectionConfig config;
  IReliableConnectionHandler* eventHandler = nullptr;

  ConnectionState state = ConnectionState::kDisconnected;
  SocketAddress remoteAddr;
  std::uint16_t remotePort = 0;

  // Sequence numbers — per channel
  std::vector<std::uint32_t> sendSequence;
  std::vector<std::uint32_t> receiveSequence;

  // Pending packets waiting for ACK
  std::deque<PendingPacket> pendingPackets;

  // Sliding window for duplicate sequence detection — per channel (O(1) lookup,
  // bounded memory)
  static constexpr std::uint32_t kSeqWindowSize = 1024;
  std::vector<std::uint32_t>
      seqWindowHigh;  // per-channel highest_seen_sequence + 1
  std::vector<std::bitset<1024>> seqWindowBits;  // per-channel bit[seq % 1024]

  // Reliable packets pending ordered processing — per channel
  std::vector<std::unordered_map<std::uint32_t, ReceivedPacket>>
      pendingReceived;

  // Timing
  std::chrono::steady_clock::time_point lastSendTime;
  std::chrono::steady_clock::time_point lastReceiveTime;
  std::chrono::steady_clock::time_point lastPingTime;

  // Round-trip time estimation
  float rtt = 100.0f;  // milliseconds

  // Statistics
  std::uint32_t statsSentPackets = 0;
  std::uint32_t statsReceivedPackets = 0;
  std::uint32_t statsLostPackets = 0;

  // Congestion control (AIMD)
  std::uint32_t currentSendWindow = 0;  ///< Adaptive send window; 0 = unlimited
  std::uint32_t ssthresh = 32;          ///< Slow-start threshold

  // Fragment state — per channel
  static constexpr std::size_t kFragmentHeaderExtra =
      6;  ///< groupId(2) + fragIdx(2) + fragTotal(2)
  std::vector<std::uint16_t>
      nextFragmentGroupId;  ///< Rolling group-ID counter, per channel
  /// Incomplete fragment groups indexed by [channel][groupId]
  std::vector<std::unordered_map<std::uint16_t, FragmentGroup>> fragmentGroups;

  // Optional secure transport state
  crypto::HandshakeState cryptoHandshake{};
  crypto::CryptoContext cryptoContext{};
  bool cryptoReady = false;

  // Internal methods
  bool SendPacket(PacketType type, std::uint8_t channel, const void* data,
                  std::size_t size, std::uint32_t sequence = 0);
  /// Split a large payload into Fragment packets and enqueue each for reliable
  /// delivery.
  bool SendFragmented(std::uint8_t channel, const void* data, std::size_t size);
  void SendAck(std::uint32_t sequence);
  void SendPing();
  void ProcessPendingReliable();
  void RetryPendingPackets();
  void CheckTimeout();
  /// Discard fragment groups that have been waiting longer than
  /// fragmentTimeoutMs.
  void CleanupFragments();
  [[nodiscard]] bool SecureMode() const { return config.crypto.enabled; }
  [[nodiscard]] bool CanUseCrypto() const;
  [[nodiscard]] bool ShouldEncryptPacket(PacketType type) const;
  [[nodiscard]] std::size_t CryptoEnvelopeOverhead() const;
  [[nodiscard]] std::size_t MaxPayloadForPacket(
      std::size_t header_extra = 0) const;

  [[nodiscard]] bool IsDuplicateSequence(std::uint8_t channel,
                                         std::uint32_t seq) const;
  void MarkSequenceReceived(std::uint8_t channel, std::uint32_t seq);

  std::uint32_t GetNextSequence(std::uint8_t channel) {
    if (channel >= sendSequence.size()) return 0;
    return sendSequence.at(channel)++;
  }
  static bool IsSequenceNewer(std::uint32_t s1, std::uint32_t s2);
};

/*
  ConnectionManager - manages multiple connections (for server)
*/
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

  // Update all connections
  void Update();

  // Convenience: drain all pending packets from socket, then update all
  // connections. Requires the socket to be in non-blocking mode.
  void Tick();

  // Process incoming packet - automatically routes to correct connection
  void ProcessPacket(const void* data, std::size_t size,
                     const SocketAddress& from, std::uint16_t from_port);

  // Broadcast to all connections
  void BroadcastReliable(std::uint8_t channel, const void* data,
                         std::size_t size);
  void BroadcastUnreliable(std::uint8_t channel, const void* data,
                           std::size_t size);

  // Get connections
  std::vector<RemoteClient*> GetConnections();
  RemoteClient* GetConnection(const SocketAddress& addr, std::uint16_t port);

  // Set handler for all connections
  void SetHandler(IReliableConnectionHandler* handler) {
    eventHandler = handler;
  }

  // Connection events (can be overridden)
  std::function<void(RemoteClient*)> onClientConnected;
  std::function<void(RemoteClient*)> onClientDisconnected;

 private:
  ISocket* socket;
  ReliableConnectionConfig config;
  IReliableConnectionHandler* eventHandler = nullptr;

  std::vector<std::unique_ptr<RemoteClient>> clients;

  RemoteClient* FindOrCreateClient(const SocketAddress& addr,
                                   std::uint16_t port);
  void RemoveClient(RemoteClient* client);

  std::string MakeAddressKey(const SocketAddress& addr, std::uint16_t port);
  std::unordered_map<std::string, RemoteClient*> clientMap;

  // Handshake rate-limiting state
  std::uint32_t connectWindowCount = 0;
  std::chrono::steady_clock::time_point connectWindowStart{};
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
