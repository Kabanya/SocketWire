#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "connection_manager.hpp"
#include "i_socket.hpp"

namespace socketwire {

struct ShardedConnectionManagerConfig {
  std::uint16_t port = 0;
  std::uint32_t workerCount = 1;
  ConnectionManagerConfig connection{};
  SocketConfig socket{};
};

struct ShardedClientHandle {
  std::uint32_t workerIndex = 0;
  std::uint64_t clientId = 0;
};

enum class ShardedEventType : std::uint8_t {
  kConnected = 1,
  kDisconnected = 2,
};

struct ShardedConnectionEvent {
  ShardedEventType type = ShardedEventType::kConnected;
  ShardedClientHandle client{};
};

struct ShardedConnectionStats {
  std::uint32_t workerCount = 0;
  std::uint32_t connectedClients = 0;
  std::uint32_t totalClients = 0;
  std::uint32_t workerConnectedMin = 0;
  std::uint32_t workerConnectedMax = 0;
  double workerUpdateMsAvg = 0.0;
  double workerUpdateMsMax = 0.0;
  double rttMs = 0.0;
  std::uint64_t lostPackets = 0;
  std::uint64_t inflightPackets = 0;
  std::uint64_t sendWindow = 0;
  std::uint64_t deadlineSendDrops = 0;
  std::uint64_t deadlineReceiveDrops = 0;
  std::uint64_t deadlineRetriesPrevented = 0;
  std::uint64_t deadlineExpiredFragmentGroups = 0;
};

class ShardedConnectionManager {
public:
  using PacketCallback =
    std::function<void(ShardedClientHandle, ConnectionManager::RemoteClient&,
                       std::uint8_t, const void*, std::size_t, bool)>;

  explicit ShardedConnectionManager(ShardedConnectionManagerConfig config);
  ~ShardedConnectionManager();

  ShardedConnectionManager(const ShardedConnectionManager&) = delete;
  ShardedConnectionManager& operator=(const ShardedConnectionManager&) = delete;

  void SetPacketCallback(PacketCallback callback);
  bool Start();
  void Stop();

  [[nodiscard]] bool IsRunning() const;
  [[nodiscard]] std::uint16_t LocalPort() const;
  [[nodiscard]] bool ReusePortEnabled() const;
  [[nodiscard]] ShardedConnectionStats SnapshotStats() const;

  bool SendReliable(ShardedClientHandle client, std::uint8_t channel,
                    const void* data, std::size_t size);
  bool SendUnreliable(ShardedClientHandle client, std::uint8_t channel,
                      const void* data, std::size_t size);
  bool SendSequenced(ShardedClientHandle client, std::uint8_t channel,
                     const void* data, std::size_t size);
  bool SendUnsequenced(ShardedClientHandle client, std::uint8_t channel,
                       const void* data, std::size_t size);

  std::vector<ShardedConnectionEvent> DrainEvents();

private:
  enum class SendMode : std::uint8_t {
    kReliable = 1,
    kUnreliable = 2,
    kSequenced = 3,
    kUnsequenced = 4,
  };

  struct OutgoingCommand {
    SendMode mode = SendMode::kReliable;
    ShardedClientHandle client{};
    std::uint8_t channel = 0;
    std::vector<std::uint8_t> payload;
  };

  struct IncomingPacket {
    SocketAddress from{};
    std::uint16_t port = 0;
    std::vector<std::uint8_t> payload;
  };

  struct WorkerStats {
    std::atomic<std::uint32_t> connectedClients{0};
    std::atomic<std::uint32_t> totalClients{0};
    std::atomic<std::uint64_t> updateUsAvg{0};
    std::atomic<std::uint64_t> updateUsMax{0};
    std::atomic<std::uint64_t> rttUs{0};
    std::atomic<std::uint64_t> lostPackets{0};
    std::atomic<std::uint64_t> inflightPackets{0};
    std::atomic<std::uint64_t> sendWindow{0};
    std::atomic<std::uint64_t> deadlineSendDrops{0};
    std::atomic<std::uint64_t> deadlineReceiveDrops{0};
    std::atomic<std::uint64_t> deadlineRetriesPrevented{0};
    std::atomic<std::uint64_t> deadlineExpiredFragmentGroups{0};
  };

  struct Worker {
    std::uint32_t index = 0;
    std::unique_ptr<ISocket> socket;
    std::unique_ptr<ISocket> sendSocket;
    std::unique_ptr<ConnectionManager> manager;
    WorkerStats stats;
    std::mutex incomingMutex;
    std::vector<IncomingPacket> incoming;
    std::mutex outgoingMutex;
    std::vector<OutgoingCommand> outgoing;
    std::thread thread;
  };

  bool StartReusePort(std::uint32_t worker_count, ISocketFactory& factory);
  bool StartDispatcher(std::uint32_t worker_count, ISocketFactory& factory);
  void AttachWorkerCallbacks(Worker& worker);
  bool UseReusePortBackend(std::uint32_t worker_count) const;
  bool QueueSend(SendMode mode, ShardedClientHandle client,
                 std::uint8_t channel, const void* data, std::size_t size);
  void QueueIncoming(IncomingPacket packet);
  std::size_t DrainIncoming(Worker& worker);
  void DrainOutgoing(Worker& worker);
  void DispatcherLoop();
  void WorkerLoop(Worker& worker);
  void PushEvent(ShardedConnectionEvent event);
  [[nodiscard]] std::size_t WorkerIndexFor(const SocketAddress& address,
                                           std::uint16_t port) const;

  ShardedConnectionManagerConfig config_;
  std::vector<std::unique_ptr<Worker>> workers_;
  PacketCallback packetCallback_{};
  std::unique_ptr<ISocket> dispatcherSocket_;
  std::mutex dispatcherSocketMutex_;
  std::thread dispatcherThread_;
  mutable std::mutex eventsMutex_;
  std::vector<ShardedConnectionEvent> events_;
  std::atomic<bool> running_{false};
  std::uint16_t localPort_ = 0;
  bool reusePortEnabled_ = false;
};

}  // namespace socketwire
