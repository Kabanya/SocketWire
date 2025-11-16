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

#include "i_socket.hpp"
#include "bit_stream.hpp"
#include <cstdint>
#include <vector>
#include <deque>
#include <unordered_map>
#include <functional>
#include <chrono>

namespace socketwire
{

// Packet types for internal protocol
enum class PacketType : std::uint8_t
{
  Unreliable = 0,      // No guarantees
  Reliable = 1,        // Guaranteed delivery, ordered
  Unsequenced = 2,     // Guaranteed delivery, unordered
  Connect = 3,         // Connection request
  Accept = 4,          // Connection accepted
  Disconnect = 5,      // Graceful disconnect
  Ping = 6,            // Keep-alive
  Pong = 7,            // Keep-alive response
  Ack = 8              // Acknowledgment
};

// Connection states
enum class ConnectionState : std::uint8_t
{
  Disconnected = 0,
  Disconnecting = 1,
  Connected = 2,
  Connecting = 3
};

// Configuration for reliable connection
struct ReliableConnectionConfig
{
  std::uint32_t maxRetries = 10;
  std::uint32_t retryTimeoutMs = 100;
  std::uint32_t pingIntervalMs = 1000;
  std::uint32_t disconnectTimeoutMs = 5000;
  std::uint32_t maxPacketSize = 1400;
  std::uint8_t numChannels = 2;
};

// Pending packet waiting for acknowledgment
struct PendingPacket
{
  std::uint32_t sequence;
  std::vector<std::uint8_t> data;
  std::chrono::steady_clock::time_point sendTime;
  std::uint32_t retries = 0;
  std::uint8_t channel = 0;
};

// Received packet info
struct ReceivedPacket
{
  std::uint32_t sequence;
  std::vector<std::uint8_t> data;
  std::uint8_t channel = 0;
};

// Event callbacks
class IReliableConnectionHandler
{
public:
  virtual ~IReliableConnectionHandler() = default; // disconect();

  // Called when connection is established
  virtual void onConnected() {}

  // Called when connection is closed
  virtual void onDisconnected() {}

  // Called when reliable packet is received (in order)
  virtual void onReliableReceived(std::uint8_t channel, const void* data, std::size_t size) = 0;

  // Called when unreliable packet is received
  virtual void onUnreliableReceived(std::uint8_t channel, const void* data, std::size_t size) = 0;

  // Called on connection timeout
  virtual void onTimeout() {}
};


// Manages a single reliable connection over UDP
class ReliableConnection
{
public:
  explicit ReliableConnection(ISocket* socket, const ReliableConnectionConfig& cfg = {});
  ~ReliableConnection();

  // Connection management
  void connect(const SocketAddress& addr, std::uint16_t port);
  void disconnect();
  bool isConnected() const { return state == ConnectionState::Connected; }
  ConnectionState getState() const { return state; }

  // Set remote address (for server-side connections that start connected)
  void setRemoteAddress(const SocketAddress& addr, std::uint16_t port);
  void setConnected() { state = ConnectionState::Connected; }

  // Send packets
  bool sendReliable(const std::uint8_t channel, const void* data, std::size_t size);
  bool sendUnreliable(const std::uint8_t channel, const void* data, std::size_t size);
  bool sendUnsequenced(const std::uint8_t channel, const void* data, std::size_t size);

  // BitStream convenience methods
  bool sendReliable(const std::uint8_t channel, const BitStream& stream);
  bool sendUnreliable(const std::uint8_t channel, const BitStream& stream);
  bool sendUnsequenced(const std::uint8_t channel, const BitStream& stream);

  // Update - call regularly (e.g., every frame)
  void update();

  // Process incoming packet
  void processPacket(const void* data, std::size_t size,
                    const SocketAddress& from, std::uint16_t fromPort);

  // Set event handler
  void setHandler(IReliableConnectionHandler* handler) { eventHandler = handler; }

  // Statistics
  std::uint32_t getSentPackets() const { return statsSentPackets; }
  std::uint32_t getReceivedPackets() const { return statsReceivedPackets; }
  std::uint32_t getLostPackets() const { return statsLostPackets; }
  float getRTT() const { return rtt; }

private:
  ISocket* socket;
  ReliableConnectionConfig config;
  IReliableConnectionHandler* eventHandler = nullptr;

  ConnectionState state = ConnectionState::Disconnected;
  SocketAddress remoteAddr;
  std::uint16_t remotePort = 0;

  // Sequence numbers
  std::uint32_t sendSequence = 0;
  std::uint32_t receiveSequence = 0;

  // Pending packets waiting for ACK
  std::deque<PendingPacket> pendingPackets;

  // Received sequences (for duplicate detection)
  std::unordered_map<std::uint32_t, bool> receivedSequences;

  // Reliable packets pending processing (out of order)
  std::unordered_map<std::uint32_t, ReceivedPacket> pendingReceived;

  // Timing
  std::chrono::steady_clock::time_point lastSendTime;
  std::chrono::steady_clock::time_point lastReceiveTime;
  std::chrono::steady_clock::time_point lastPingTime;

  // Round-trip time estimation
  float rtt = 100.0f; // milliseconds

  // Statistics
  std::uint32_t statsSentPackets = 0;
  std::uint32_t statsReceivedPackets = 0;
  std::uint32_t statsLostPackets = 0;

  // Internal methods
  void sendPacket(PacketType type, std::uint8_t channel,
                 const void* data, std::size_t size,
                 std::uint32_t sequence = 0);
  void sendAck(std::uint32_t sequence);
  void sendPing();
  void processPendingReliable();
  void retryPendingPackets();
  void checkTimeout();
  void cleanupOldSequences();

  std::uint32_t getNextSequence() { return sendSequence++; }
  static bool isSequenceNewer(std::uint32_t s1, std::uint32_t s2);
};

/*
  ConnectionManager - manages multiple connections (for server)
*/
class ConnectionManager
{
public:
  struct RemoteClient
  {
    SocketAddress address;
    std::uint16_t port;
    ReliableConnection* connection;
    void* userData = nullptr; // For game-specific data (e.g., entity ID)
  };

  explicit ConnectionManager(ISocket* socket, const ReliableConnectionConfig& cfg = {});
  ~ConnectionManager();

  // Update all connections
  void update();

  // Process incoming packet - automatically routes to correct connection
  void processPacket(const void* data, std::size_t size,
                    const SocketAddress& from, std::uint16_t fromPort);

  // Broadcast to all connections
  void broadcastReliable(std::uint8_t channel, const void* data, std::size_t size);
  void broadcastUnreliable(std::uint8_t channel, const void* data, std::size_t size);

  // Get connections
  std::vector<RemoteClient*> getConnections();
  RemoteClient* getConnection(const SocketAddress& addr, std::uint16_t port);

  // Set handler for all connections
  void setHandler(IReliableConnectionHandler* handler) { eventHandler = handler; }

  // Connection events (can be overridden)
  std::function<void(RemoteClient*)> onClientConnected;
  std::function<void(RemoteClient*)> onClientDisconnected;

private:
  ISocket* socket;
  ReliableConnectionConfig config;
  IReliableConnectionHandler* eventHandler = nullptr;

  std::vector<RemoteClient*> clients;

  RemoteClient* findOrCreateClient(const SocketAddress& addr, std::uint16_t port);
  void removeClient(RemoteClient* client);

  std::uint64_t makeAddressKey(const SocketAddress& addr, std::uint16_t port);
  std::unordered_map<std::uint64_t, RemoteClient*> clientMap;
};

// Helper function to create connection key
inline std::uint64_t makeConnectionKey(std::uint32_t address, std::uint16_t port)
{
  return (static_cast<std::uint64_t>(address) << 16) | port;
}

} // namespace socketwire