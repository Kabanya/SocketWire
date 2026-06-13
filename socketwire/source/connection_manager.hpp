#pragma once

/// Server-side manager for SocketWire reliable UDP connections.

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

#include "reliable_connection.hpp"

namespace socketwire {

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
  void Update(std::chrono::steady_clock::time_point now);

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
  std::vector<std::uint8_t> receive_batch_storage_;
  std::vector<IncomingDatagram> receive_batch_;

  // Handshake rate-limiting state.
  std::uint32_t connect_window_count_ = 0;
  std::chrono::steady_clock::time_point connect_window_start_{};
  void EnsureReceiveBatchBuffers();
  bool HandshakeAllowed(std::chrono::steady_clock::time_point now);
  void EmitClientConnected(RemoteClient* client);
  std::unordered_map<RemoteClient*, bool> connected_notified_;
};

}  // namespace socketwire
