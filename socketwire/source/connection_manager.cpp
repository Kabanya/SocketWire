#include "connection_manager.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

namespace socketwire {
namespace {

constexpr std::size_t kReceiveBatchSize = 32;

std::size_t DefaultHandlerWorkerCount() {
  const auto hardware_threads = std::thread::hardware_concurrency();
  if (hardware_threads <= 1) return 1;
  return static_cast<std::size_t>(hardware_threads - 1);
}

}  // namespace

ConnectionManager::ConnectionManager(ISocket* socket,
                                     const ReliableConnectionConfig& cfg,
                                     IClock* clock)
    : socket_(socket),
      config_(cfg),
      clock_(clock != nullptr ? clock : &SystemClock::Instance()) {
  if (config_.handlerDispatchMode == HandlerDispatchMode::kAsyncPayload) {
    const std::size_t worker_count =
      config_.handlerWorkerThreads == 0 ? DefaultHandlerWorkerCount()
                                        : config_.handlerWorkerThreads;
    owned_handler_pool_ = std::make_unique<ThreadPool>(worker_count);
    owned_handler_pool_->Start();
    handler_pool_ = owned_handler_pool_.get();
  }
  EnsureReceiveBatchBuffers();
}

ConnectionManager::~ConnectionManager() {
  if (owned_handler_pool_ != nullptr) owned_handler_pool_->Stop();
  (void)DrainPostedTasks();
  clients_.clear();
  client_map_.clear();
  connected_notified_.clear();
}

void ConnectionManager::Update() {
  Update(clock_->Now());
}

void ConnectionManager::Update(std::chrono::steady_clock::time_point now) {
  (void)DrainPostedTasks(config_.maxNetworkTasksPerDrain);

  for (auto& client : clients_) {
    if (client->connection != nullptr) {
      client->connection->Update(now);
      if (client->connection->IsConnected()) EmitClientConnected(client.get());
    }
  }

  std::erase_if(clients_, [this](const std::unique_ptr<RemoteClient>& client) {
    if (client->connection->GetState() == ConnectionState::kDisconnected) {
      if (onClientDisconnected != nullptr) onClientDisconnected(client.get());
      client_map_.erase(MakeAddressKey(client->address, client->port));
      connected_notified_.erase(client.get());
      return true;
    }
    return false;
  });

  (void)DrainPostedTasks(config_.maxNetworkTasksPerDrain);
}

void ConnectionManager::ProcessPacket(const void* data, std::size_t size,
                                      const SocketAddress& from,
                                      std::uint16_t from_port) {
  const auto key = MakeAddressKey(from, from_port);
  const auto known_it = client_map_.find(key);
  const bool is_known = known_it != client_map_.end();

  if (!is_known) {
    if (!ReliableConnection::IsConnectPacket(data, size)) return;
    if (clients_.size() >= config_.maxClients) return;
    if (!HandshakeAllowed(clock_->Now())) return;
  }

  RemoteClient* client =
    is_known ? known_it->second : FindOrCreateClient(from, from_port);
  if (client != nullptr && client->connection != nullptr) {
    client->connection->ProcessPacket(data, size, from, from_port);
    if (client->connection->IsConnected()) EmitClientConnected(client);
    if (!is_known &&
        client->connection->GetState() == ConnectionState::kDisconnected) {
      RemoveClient(client);
    }
  }
}

bool ConnectionManager::HandshakeAllowed(
  std::chrono::steady_clock::time_point now) {
  if (config_.maxHandshakesPerSecond == 0) return true;

  const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                         now - connect_window_start_)
                         .count();
  if (elapsed >= 1000) {
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
      (void)client->connection->SendReliable(channel, data, size);
    }
  }
}

void ConnectionManager::BroadcastUnreliable(std::uint8_t channel,
                                            const void* data,
                                            std::size_t size) {
  for (auto& client : clients_) {
    if (client->connection != nullptr && client->connection->IsConnected()) {
      (void)client->connection->SendUnreliable(channel, data, size);
    }
  }
}

void ConnectionManager::SetHandler(IReliableConnectionHandler* handler) {
  event_handler_ = handler;
  for (auto& client : clients_) {
    if (client->connection != nullptr) {
      client->connection->SetHandlerThreadPool(handler_pool_);
      client->connection->SetHandler(event_handler_);
    }
  }
}

bool ConnectionManager::Post(std::function<void()> task) {
  return posted_network_tasks_.Post(std::move(task));
}

std::size_t ConnectionManager::DrainPostedTasks(std::size_t max_tasks) {
  return posted_network_tasks_.Drain(max_tasks);
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
  const auto it = client_map_.find(MakeAddressKey(addr, port));
  return it != client_map_.end() ? it->second : nullptr;
}

ConnectionManager::RemoteClient* ConnectionManager::FindOrCreateClient(
  const SocketAddress& addr, std::uint16_t port) {
  const auto key = MakeAddressKey(addr, port);
  const auto it = client_map_.find(key);
  if (it != client_map_.end()) return it->second;

  auto client = std::make_unique<RemoteClient>();
  client->address = addr;
  client->port = port;
  client->connection =
    std::make_unique<ReliableConnection>(socket_, config_, clock_);
  client->connection->SetRemoteAddress(addr, port);
  client->connection->SetHandlerThreadPool(handler_pool_);
  client->connection->SetHandler(event_handler_);

  RemoteClient* raw = client.get();
  clients_.push_back(std::move(client));
  client_map_[key] = raw;
  connected_notified_[raw] = false;
  return raw;
}

void ConnectionManager::RemoveClient(RemoteClient* client) {
  if (client == nullptr) return;
  client_map_.erase(MakeAddressKey(client->address, client->port));
  connected_notified_.erase(client);
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

void ConnectionManager::EmitClientConnected(RemoteClient* client) {
  if (client == nullptr) return;
  auto [it, inserted] = connected_notified_.emplace(client, false);
  (void)inserted;
  if (it->second) return;
  it->second = true;
  if (onClientConnected != nullptr) onClientConnected(client);
}

void ConnectionManager::EnsureReceiveBatchBuffers() {
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

void ConnectionManager::Tick() {
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
