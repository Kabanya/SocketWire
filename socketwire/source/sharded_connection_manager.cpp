#include "sharded_connection_manager.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <utility>

#include "socket_constants.hpp"
#include "socket_init.hpp"

namespace socketwire {
namespace {

using Clock = std::chrono::steady_clock;

class SharedSendSocket final : public ISocket {
 public:
  SharedSendSocket(ISocket& socket, std::mutex& mutex)
      : socket_(&socket), mutex_(&mutex) {}

  SocketError Bind(const SocketAddress&, std::uint16_t) override {
    return SocketError::kUnsupported;
  }

  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr,
                      std::uint16_t to_port) override {
    const std::scoped_lock lock(*mutex_);
    return socket_->SendTo(data, length, to_addr, to_port);
  }

  std::size_t SendMany(std::span<const OutgoingDatagram> datagrams) override {
    const std::scoped_lock lock(*mutex_);
    return socket_->SendMany(datagrams);
  }

  SocketResult Receive(void*, std::size_t, SocketAddress&,
                       std::uint16_t&) override {
    return {.bytes = -1, .error = SocketError::kWouldBlock};
  }

  std::size_t ReceiveMany(std::span<IncomingDatagram>) override { return 0; }

  SocketError SetBlocking(bool) override { return SocketError::kUnsupported; }
  [[nodiscard]] bool IsBlocking() const override {
    return socket_->IsBlocking();
  }
  [[nodiscard]] std::uint16_t LocalPort() const override {
    return socket_->LocalPort();
  }
  [[nodiscard]] int NativeHandle() const override {
    return socket_->NativeHandle();
  }
  void Close() override {}

 private:
  ISocket* socket_ = nullptr;
  std::mutex* mutex_ = nullptr;
};

}  // namespace

ShardedConnectionManager::ShardedConnectionManager(
  ShardedConnectionManagerConfig config)
    : config_(std::move(config)) {
  if (config_.workerCount == 0) config_.workerCount = 1;
}

ShardedConnectionManager::~ShardedConnectionManager() { Stop(); }

void ShardedConnectionManager::SetPacketCallback(PacketCallback callback) {
  packetCallback_ = std::move(callback);
}

bool ShardedConnectionManager::Start() {
  if (running_.load()) return false;

  InitializeSockets();
  ISocketFactory* factory = SocketFactoryRegistry::GetFactory();
  if (factory == nullptr) return false;

  const std::uint32_t worker_count =
    std::max<std::uint32_t>(1, config_.workerCount);

  workers_.clear();
  workers_.reserve(worker_count);
  dispatcherSocket_.reset();
  localPort_ = 0;
  reusePortEnabled_ = false;

  const bool started = UseReusePortBackend(worker_count)
                         ? StartReusePort(worker_count, *factory)
                         : StartDispatcher(worker_count, *factory);
  if (!started) return false;

  running_.store(true);
  if (dispatcherSocket_ != nullptr) {
    dispatcherThread_ = std::thread([this] { DispatcherLoop(); });
  }
  for (auto& worker : workers_) {
    worker->thread =
      std::thread([this, raw = worker.get()] { WorkerLoop(*raw); });
  }
  return true;
}

bool ShardedConnectionManager::StartReusePort(std::uint32_t worker_count,
                                              ISocketFactory& factory) {
  const bool need_reuse_port = worker_count > 1;
  std::uint16_t bind_port = config_.port;
  reusePortEnabled_ = need_reuse_port;

  for (std::uint32_t i = 0; i < worker_count; ++i) {
    auto worker = std::make_unique<Worker>();
    worker->index = i;

    SocketConfig socket_config = config_.socket;
    socket_config.nonBlocking = true;
    socket_config.reuseAddress = true;
    socket_config.reusePort = need_reuse_port;

    worker->socket = factory.CreateUdpSocket(socket_config);
    if (worker->socket == nullptr) {
      Stop();
      return false;
    }

    const SocketError bind_error =
      worker->socket->Bind(SocketConstants::Any(), bind_port);
    if (bind_error != SocketError::kNone) {
      Stop();
      return false;
    }

    if (i == 0) {
      localPort_ = worker->socket->LocalPort();
      bind_port = localPort_;
    }

    worker->manager = std::make_unique<ConnectionManager>(worker->socket.get(),
                                                          config_.connection);
    AttachWorkerCallbacks(*worker);

    workers_.push_back(std::move(worker));
  }

  return true;
}

bool ShardedConnectionManager::StartDispatcher(std::uint32_t worker_count,
                                               ISocketFactory& factory) {
  SocketConfig socket_config = config_.socket;
  socket_config.nonBlocking = true;
  socket_config.reuseAddress = true;
  socket_config.reusePort = false;

  dispatcherSocket_ = factory.CreateUdpSocket(socket_config);
  if (dispatcherSocket_ == nullptr) return false;

  const SocketError bind_error =
    dispatcherSocket_->Bind(SocketConstants::Any(), config_.port);
  if (bind_error != SocketError::kNone) {
    dispatcherSocket_.reset();
    return false;
  }
  localPort_ = dispatcherSocket_->LocalPort();

  for (std::uint32_t i = 0; i < worker_count; ++i) {
    auto worker = std::make_unique<Worker>();
    worker->index = i;
    worker->sendSocket = std::make_unique<SharedSendSocket>(
      *dispatcherSocket_, dispatcherSocketMutex_);
    worker->manager = std::make_unique<ConnectionManager>(
      worker->sendSocket.get(), config_.connection);
    AttachWorkerCallbacks(*worker);
    workers_.push_back(std::move(worker));
  }

  return true;
}

void ShardedConnectionManager::AttachWorkerCallbacks(Worker& worker) {
  worker.manager->onClientConnected =
    [this, raw = &worker](ConnectionManager::RemoteClient* client) {
      if (client == nullptr) return;
      PushEvent(
        {.type = ShardedEventType::kConnected,
         .client = {.workerIndex = raw->index, .clientId = client->id}});
    };
  worker.manager->onClientDisconnected =
    [this, raw = &worker](ConnectionManager::RemoteClient* client) {
      if (client == nullptr) return;
      PushEvent(
        {.type = ShardedEventType::kDisconnected,
         .client = {.workerIndex = raw->index, .clientId = client->id}});
    };
  worker.manager->onPacketReceived = [this, raw = &worker](
                                       ConnectionManager::RemoteClient* client,
                                       std::uint8_t channel, const void* data,
                                       std::size_t size, bool reliable) {
    if (client != nullptr && packetCallback_ != nullptr) {
      packetCallback_({.workerIndex = raw->index, .clientId = client->id},
                      *client, channel, data, size, reliable);
    }
  };
}

bool ShardedConnectionManager::UseReusePortBackend(
  std::uint32_t worker_count) const {
  if (worker_count <= 1) return true;
#if defined(__linux__)
  return true;
#else
  return false;
#endif
}

void ShardedConnectionManager::Stop() {
  running_.store(false);
  if (dispatcherThread_.joinable()) dispatcherThread_.join();
  for (auto& worker : workers_) {
    if (worker != nullptr && worker->thread.joinable()) worker->thread.join();
  }
  workers_.clear();
  dispatcherSocket_.reset();
  localPort_ = 0;
  reusePortEnabled_ = false;
}

bool ShardedConnectionManager::IsRunning() const { return running_.load(); }

std::uint16_t ShardedConnectionManager::LocalPort() const { return localPort_; }

bool ShardedConnectionManager::ReusePortEnabled() const {
  return reusePortEnabled_;
}

ShardedConnectionStats ShardedConnectionManager::SnapshotStats() const {
  ShardedConnectionStats stats;
  stats.workerCount = static_cast<std::uint32_t>(workers_.size());
  stats.workerConnectedMin =
    stats.workerCount == 0 ? 0 : std::numeric_limits<std::uint32_t>::max();

  std::uint64_t update_us_avg_sum = 0;
  std::uint64_t rtt_us_sum = 0;
  std::uint32_t rtt_workers = 0;

  for (const auto& worker : workers_) {
    const auto connected = worker->stats.connectedClients.load();
    stats.connectedClients += connected;
    stats.totalClients += worker->stats.totalClients.load();
    stats.workerConnectedMin = std::min(stats.workerConnectedMin, connected);
    stats.workerConnectedMax = std::max(stats.workerConnectedMax, connected);
    update_us_avg_sum += worker->stats.updateUsAvg.load();
    stats.workerUpdateMsMax =
      std::max(stats.workerUpdateMsMax,
               static_cast<double>(worker->stats.updateUsMax.load()) / 1000.0);
    const auto worker_rtt = worker->stats.rttUs.load();
    if (worker_rtt > 0) {
      rtt_us_sum += worker_rtt;
      rtt_workers += 1;
    }
    stats.lostPackets += worker->stats.lostPackets.load();
    stats.inflightPackets += worker->stats.inflightPackets.load();
    stats.sendWindow += worker->stats.sendWindow.load();
    stats.deadlineSendDrops += worker->stats.deadlineSendDrops.load();
    stats.deadlineReceiveDrops += worker->stats.deadlineReceiveDrops.load();
    stats.deadlineRetriesPrevented +=
      worker->stats.deadlineRetriesPrevented.load();
    stats.deadlineExpiredFragmentGroups +=
      worker->stats.deadlineExpiredFragmentGroups.load();
  }

  if (stats.workerCount > 0) {
    stats.workerUpdateMsAvg = static_cast<double>(update_us_avg_sum) /
                              static_cast<double>(stats.workerCount) / 1000.0;
  }
  if (rtt_workers > 0) {
    stats.rttMs = static_cast<double>(rtt_us_sum) /
                  static_cast<double>(rtt_workers) / 1000.0;
  }
  if (stats.workerConnectedMin == std::numeric_limits<std::uint32_t>::max()) {
    stats.workerConnectedMin = 0;
  }
  return stats;
}

bool ShardedConnectionManager::SendReliable(ShardedClientHandle client,
                                            std::uint8_t channel,
                                            const void* data,
                                            std::size_t size) {
  return QueueSend(SendMode::kReliable, client, channel, data, size);
}

bool ShardedConnectionManager::SendUnreliable(ShardedClientHandle client,
                                              std::uint8_t channel,
                                              const void* data,
                                              std::size_t size) {
  return QueueSend(SendMode::kUnreliable, client, channel, data, size);
}

bool ShardedConnectionManager::SendSequenced(ShardedClientHandle client,
                                             std::uint8_t channel,
                                             const void* data,
                                             std::size_t size) {
  return QueueSend(SendMode::kSequenced, client, channel, data, size);
}

bool ShardedConnectionManager::SendUnsequenced(ShardedClientHandle client,
                                               std::uint8_t channel,
                                               const void* data,
                                               std::size_t size) {
  return QueueSend(SendMode::kUnsequenced, client, channel, data, size);
}

std::vector<ShardedConnectionEvent> ShardedConnectionManager::DrainEvents() {
  const std::scoped_lock lock(eventsMutex_);
  std::vector<ShardedConnectionEvent> out;
  out.swap(events_);
  return out;
}

bool ShardedConnectionManager::QueueSend(SendMode mode,
                                         ShardedClientHandle client,
                                         std::uint8_t channel, const void* data,
                                         std::size_t size) {
  if (data == nullptr || size == 0 || !running_.load()) return false;
  if (client.workerIndex >= workers_.size()) return false;

  auto& worker = *workers_.at(client.workerIndex);
  auto* bytes = static_cast<const std::uint8_t*>(data);
  OutgoingCommand command;
  command.mode = mode;
  command.client = client;
  command.channel = channel;
  command.payload.assign(bytes, bytes + size);

  const std::scoped_lock lock(worker.outgoingMutex);
  worker.outgoing.push_back(std::move(command));
  return true;
}

void ShardedConnectionManager::QueueIncoming(IncomingPacket packet) {
  if (workers_.empty()) return;
  auto& worker = *workers_.at(WorkerIndexFor(packet.from, packet.port));
  const std::scoped_lock lock(worker.incomingMutex);
  worker.incoming.push_back(std::move(packet));
}

std::size_t ShardedConnectionManager::DrainIncoming(Worker& worker) {
  std::vector<IncomingPacket> packets;
  {
    const std::scoped_lock lock(worker.incomingMutex);
    packets.swap(worker.incoming);
  }

  for (const auto& packet : packets) {
    if (!packet.payload.empty()) {
      worker.manager->ProcessPacket(
        packet.payload.data(), packet.payload.size(), packet.from, packet.port);
    }
  }

  return packets.size();
}

void ShardedConnectionManager::DrainOutgoing(Worker& worker) {
  std::vector<OutgoingCommand> commands;
  {
    const std::scoped_lock lock(worker.outgoingMutex);
    commands.swap(worker.outgoing);
  }

  for (const auto& command : commands) {
    auto* client = worker.manager->GetConnection(command.client.clientId);
    if (client == nullptr || client->connection == nullptr ||
        !client->connection->IsConnected()) {
      continue;
    }

    switch (command.mode) {
      case SendMode::kReliable:
        (void)client->connection->SendReliable(
          command.channel, command.payload.data(), command.payload.size());
        break;
      case SendMode::kUnreliable:
        (void)client->connection->SendUnreliable(
          command.channel, command.payload.data(), command.payload.size());
        break;
      case SendMode::kSequenced:
        (void)client->connection->SendSequenced(
          command.channel, command.payload.data(), command.payload.size());
        break;
      case SendMode::kUnsequenced:
        (void)client->connection->SendUnsequenced(
          command.channel, command.payload.data(), command.payload.size());
        break;
    }
  }
}

void ShardedConnectionManager::DispatcherLoop() {
  constexpr std::size_t kBatchSize = 64;
  const std::size_t packet_size =
    std::max<std::size_t>(1, config_.connection.connection.maxPacketSize);
  std::vector<std::uint8_t> storage(kBatchSize * packet_size);
  std::vector<IncomingDatagram> datagrams(kBatchSize);

  while (running_.load()) {
    for (std::size_t i = 0; i < kBatchSize; ++i) {
      datagrams.at(i).data = storage.data() + i * packet_size;
      datagrams.at(i).capacity = packet_size;
      datagrams.at(i).result = {};
    }

    std::size_t received = 0;
    {
      const std::scoped_lock lock(dispatcherSocketMutex_);
      if (dispatcherSocket_ != nullptr) {
        received = dispatcherSocket_->ReceiveMany(datagrams);
      }
    }

    if (received == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      continue;
    }

    for (std::size_t i = 0; i < received; ++i) {
      const auto& datagram = datagrams.at(i);
      if (datagram.result.bytes <= 0) continue;
      auto* begin = static_cast<const std::uint8_t*>(datagram.data);
      const auto size = static_cast<std::size_t>(datagram.result.bytes);
      IncomingPacket packet;
      packet.from = datagram.fromAddr;
      packet.port = datagram.fromPort;
      packet.payload.assign(begin, begin + size);
      QueueIncoming(std::move(packet));
    }
  }
}

void ShardedConnectionManager::WorkerLoop(Worker& worker) {
  auto next_stats = Clock::now();
  std::uint64_t update_us_sum = 0;
  std::uint64_t update_us_max = 0;
  std::uint64_t update_samples = 0;

  while (running_.load()) {
    const auto loop_start = Clock::now();
    DrainOutgoing(worker);
    const std::size_t incoming = DrainIncoming(worker);
    if (worker.socket != nullptr) {
      worker.manager->Tick();
    } else {
      worker.manager->Update();
    }
    const auto loop_end = Clock::now();

    const auto update_us = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(loop_end -
                                                            loop_start)
        .count());
    update_us_sum += update_us;
    update_us_max = std::max(update_us_max, update_us);
    update_samples += 1;

    if (loop_end >= next_stats) {
      auto clients = worker.manager->GetConnections();
      std::uint32_t connected = 0;
      std::uint64_t rtt_us = 0;
      std::uint64_t lost = 0;
      std::uint64_t inflight = 0;
      std::uint64_t send_window = 0;
      std::uint64_t deadline_send_drops = 0;
      std::uint64_t deadline_receive_drops = 0;
      std::uint64_t deadline_retries_prevented = 0;
      std::uint64_t deadline_expired_fragment_groups = 0;

      for (const auto* client : clients) {
        if (client == nullptr || client->connection == nullptr ||
            !client->connection->IsConnected()) {
          continue;
        }
        connected += 1;
        rtt_us +=
          static_cast<std::uint64_t>(client->connection->GetRtt() * 1000.0f);
        lost += client->connection->GetLostPackets();
        inflight += client->connection->GetInflightCount();
        send_window += client->connection->GetSendWindow();
        deadline_send_drops += client->connection->GetDeadlineSendDrops();
        deadline_receive_drops += client->connection->GetDeadlineReceiveDrops();
        deadline_retries_prevented +=
          client->connection->GetDeadlineRetriesPrevented();
        deadline_expired_fragment_groups +=
          client->connection->GetDeadlineExpiredFragmentGroups();
      }

      worker.stats.connectedClients.store(connected);
      worker.stats.totalClients.store(
        static_cast<std::uint32_t>(clients.size()));
      worker.stats.updateUsAvg.store(
        update_samples == 0 ? 0 : update_us_sum / update_samples);
      worker.stats.updateUsMax.store(update_us_max);
      worker.stats.rttUs.store(connected == 0 ? 0 : rtt_us / connected);
      worker.stats.lostPackets.store(lost);
      worker.stats.inflightPackets.store(inflight);
      worker.stats.sendWindow.store(send_window);
      worker.stats.deadlineSendDrops.store(deadline_send_drops);
      worker.stats.deadlineReceiveDrops.store(deadline_receive_drops);
      worker.stats.deadlineRetriesPrevented.store(deadline_retries_prevented);
      worker.stats.deadlineExpiredFragmentGroups.store(
        deadline_expired_fragment_groups);

      update_us_sum = 0;
      update_us_max = 0;
      update_samples = 0;
      next_stats = loop_end + std::chrono::milliseconds(100);
    }

    if (worker.stats.totalClients.load() == 0 && incoming == 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    } else {
      std::this_thread::yield();
    }
  }
}

void ShardedConnectionManager::PushEvent(ShardedConnectionEvent event) {
  const std::scoped_lock lock(eventsMutex_);
  events_.push_back(event);
}

std::size_t ShardedConnectionManager::WorkerIndexFor(
  const SocketAddress& address, std::uint16_t port) const {
  if (workers_.empty()) return 0;
  std::size_t hash = std::hash<SocketAddress>{}(address);
  hash ^= std::hash<std::uint16_t>{}(port) + 0x9e3779b97f4a7c15ULL +
          (hash << 6) + (hash >> 2);
  return hash % workers_.size();
}

}  // namespace socketwire
