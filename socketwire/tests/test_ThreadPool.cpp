#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <span>
#include <thread>
#include <vector>

#include "connection_manager.hpp"
#include "i_socket.hpp"
#include "reliable_connection.hpp"
#include "socket_init.hpp"
#include "task_queue.hpp"
#include "thread_pool.hpp"

using namespace std::chrono_literals;
using namespace socketwire;  // NOLINT

namespace {

template <typename Predicate>
bool WaitUntil(Predicate predicate, std::chrono::milliseconds timeout,
               std::chrono::milliseconds step = 2ms) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    if (predicate()) return true;
    std::this_thread::sleep_for(step);
  }
  return predicate();
}

class AsyncEchoServerHandler final : public IReliableConnectionHandler {
 public:
  AsyncEchoServerHandler(ThreadPool& workers, TaskQueue& network_queue)
      : workers_(workers), network_queue_(network_queue) {}

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    const auto callback_thread = std::this_thread::get_id();
    callbacks.fetch_add(1);

    std::vector<std::uint8_t> payload(
      static_cast<const std::uint8_t*>(data),
      static_cast<const std::uint8_t*>(data) + size);

    const bool posted = workers_.Submit(
      [this, channel, payload = std::move(payload), callback_thread]() mutable {
        worker_thread_distinct.store(std::this_thread::get_id() !=
                                     callback_thread);
        for (auto& byte : payload) {
          byte = static_cast<std::uint8_t>(byte + 1);
        }

        const bool queued =
          manager != nullptr &&
          network_queue_.Post([this, channel, payload = std::move(payload)] {
            network_tasks.fetch_add(1);
            if (manager != nullptr) {
              manager->BroadcastReliable(channel, payload.data(),
                                         payload.size());
            }
          });
        if (!queued) network_post_failed.store(true);
      });
    if (!posted) worker_post_failed.store(true);
  }

  ConnectionManager* manager = nullptr;
  std::atomic<int> callbacks{0};
  std::atomic<int> network_tasks{0};
  std::atomic<bool> worker_thread_distinct{false};
  std::atomic<bool> worker_post_failed{false};
  std::atomic<bool> network_post_failed{false};

 private:
  ThreadPool& workers_;
  TaskQueue& network_queue_;
};

class CollectingClientHandler final : public IReliableConnectionHandler {
 public:
  void OnConnected() override { connected.store(true); }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    (void)channel;
    reliable_received.fetch_add(1);

    const std::scoped_lock lock(mutex_);
    messages_.emplace_back(static_cast<const std::uint8_t*>(data),
                           static_cast<const std::uint8_t*>(data) + size);
  }

  [[nodiscard]] std::vector<std::vector<std::uint8_t>> Messages() const {
    const std::scoped_lock lock(mutex_);
    return messages_;
  }

  std::atomic<bool> connected{false};
  std::atomic<int> reliable_received{0};

 private:
  mutable std::mutex mutex_;
  std::vector<std::vector<std::uint8_t>> messages_;
};

class DiscardSocket final : public ISocket {
 public:
  SocketError Bind(const SocketAddress& address, std::uint16_t port) override {
    (void)address;
    bound_port_ = port;
    return SocketError::kNone;
  }

  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr,
                      std::uint16_t to_port) override {
    (void)data;
    (void)to_addr;
    (void)to_port;
    return {.bytes = static_cast<std::ptrdiff_t>(length),
            .error = SocketError::kNone};
  }

  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr,
                       std::uint16_t& from_port) override {
    (void)buffer;
    (void)capacity;
    from_addr = {};
    from_port = 0;
    return {.bytes = -1, .error = SocketError::kWouldBlock};
  }

  void Poll(ISocketEventHandler* handler) override { (void)handler; }
  SocketError SetBlocking(bool enable) override {
    blocking_ = enable;
    return SocketError::kNone;
  }
  [[nodiscard]] bool IsBlocking() const override { return blocking_; }
  [[nodiscard]] std::uint16_t LocalPort() const override { return bound_port_; }
  [[nodiscard]] int NativeHandle() const override { return 1; }
  void Close() override {}

 private:
  bool blocking_ = false;
  std::uint16_t bound_port_ = 0;
};

std::vector<std::uint8_t> MakeReliablePacket(std::uint32_t sequence,
                                             const void* payload,
                                             std::size_t payload_size) {
  std::vector<std::uint8_t> packet(1400);
  const auto encoded = detail::PacketCodec::Encode(
    detail::PacketBuild{
      .type = detail::PacketType::kReliable,
      .channel = 0,
      .sequence = sequence,
      .payload =
        std::span<const std::uint8_t>{static_cast<const std::uint8_t*>(payload),
                                      payload_size}},
    std::chrono::steady_clock::time_point{}, packet);
  EXPECT_TRUE(encoded.has_value());
  packet.resize(encoded.value_or(0));
  return packet;
}

class ThreadRecordingHandler final : public IReliableConnectionHandler {
 public:
  explicit ThreadRecordingHandler(std::thread::id expected_thread)
      : expected_thread_(expected_thread) {}

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    (void)channel;
    (void)data;
    (void)size;
    callback_count.fetch_add(1);
    if (std::this_thread::get_id() == expected_thread_) {
      expected_thread_callbacks.fetch_add(1);
    }
  }

  std::atomic<int> callback_count{0};
  std::atomic<int> expected_thread_callbacks{0};

 private:
  std::thread::id expected_thread_;
};

class ClientSideAsyncHandler final : public IReliableConnectionHandler {
 public:
  ClientSideAsyncHandler(ThreadPool& workers, TaskQueue& network_queue,
                         std::thread::id& network_thread)
      : workers_(workers),
        network_queue_(network_queue),
        network_thread_(network_thread) {}

  void OnConnected() override { connected.store(true); }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    (void)channel;
    (void)data;
    (void)size;
    if (std::this_thread::get_id() == network_thread_) {
      callback_on_network.store(true);
    }

    const bool submitted = workers_.Submit([this] {
      if (std::this_thread::get_id() != network_thread_) {
        worker_thread_distinct.store(true);
      }
      if (connection == nullptr) return;

      const std::array<std::uint8_t, 3> response{9, 8, 7};
      const bool posted = network_queue_.Post([this, response] {
        if (std::this_thread::get_id() == network_thread_) {
          post_ran_on_network.store(true);
        }
        (void)connection->SendUnreliable(0, response.data(), response.size());
      });
      if (!posted) post_failed.store(true);
    });
    if (!submitted) worker_post_failed.store(true);
  }

  ReliableConnection* connection = nullptr;
  std::atomic<bool> connected{false};
  std::atomic<bool> callback_on_network{false};
  std::atomic<bool> worker_thread_distinct{false};
  std::atomic<bool> worker_post_failed{false};
  std::atomic<bool> post_ran_on_network{false};
  std::atomic<bool> post_failed{false};

 private:
  ThreadPool& workers_;
  TaskQueue& network_queue_;
  std::thread::id& network_thread_;
};

class EchoAndCountServerHandler final : public IReliableConnectionHandler {
 public:
  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    reliable_received.fetch_add(1);
    if (manager != nullptr) manager->BroadcastReliable(channel, data, size);
  }

  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            std::size_t size) override {
    (void)channel;
    (void)data;
    (void)size;
    unreliable_received.fetch_add(1);
  }

  ConnectionManager* manager = nullptr;
  std::atomic<int> reliable_received{0};
  std::atomic<int> unreliable_received{0};
};

}  // namespace

TEST(ThreadPoolTest, StartRequiredBeforeSubmit) {
  ThreadPool pool(1);

  EXPECT_FALSE(pool.Submit([] {}));
}

TEST(ThreadPoolTest, ExecutesSubmittedTasks) {
  ThreadPool pool(4);
  std::atomic<int> count{0};

  pool.Start();
  for (int i = 0; i < 100; ++i) {
    EXPECT_TRUE(pool.Submit([&count] { count.fetch_add(1); }));
  }

  EXPECT_TRUE(WaitUntil([&] { return count.load() == 100; }, 1s));
  EXPECT_EQ(count.load(), 100);
  pool.Stop();
}

TEST(ThreadPoolTest, RejectsSubmitAfterStop) {
  ThreadPool pool(1);

  pool.Start();
  pool.Stop();

  EXPECT_FALSE(pool.Submit([] {}));
  pool.Stop();
}

TEST(ThreadPoolTest, StopDrainsAlreadySubmittedTasks) {
  ThreadPool pool(1);
  std::atomic<int> count{0};

  pool.Start();
  for (int i = 0; i < 32; ++i) {
    EXPECT_TRUE(pool.Submit([&count] { count.fetch_add(1); }));
  }
  pool.Stop();

  EXPECT_EQ(count.load(), 32);
}

TEST(ThreadPoolTest, StopWaitsForActiveTasks) {
  ThreadPool pool(1);
  std::atomic<bool> completed{false};

  pool.Start();
  EXPECT_TRUE(pool.Submit([&] {
    std::this_thread::sleep_for(20ms);
    completed.store(true);
  }));
  pool.Stop();

  EXPECT_TRUE(completed.load());
}

TEST(ThreadPoolTest, DestructorStopsWorkers) {
  std::atomic<bool> completed{false};

  {
    ThreadPool pool(1);
    pool.Start();
    ASSERT_TRUE(pool.Submit([&] { completed.store(true); }));
  }

  EXPECT_TRUE(completed.load());
}

TEST(TaskQueueTest, DrainsOnCallingThread) {
  TaskQueue queue;
  const auto caller_thread = std::this_thread::get_id();
  std::thread::id task_thread;

  EXPECT_TRUE(queue.Post([&] { task_thread = std::this_thread::get_id(); }));

  EXPECT_EQ(queue.Drain(), 1u);
  EXPECT_EQ(task_thread, caller_thread);
}

TEST(TaskQueueTest, PreservesFifoOrder) {
  TaskQueue queue;
  std::vector<int> order;

  EXPECT_TRUE(queue.Post([&] { order.push_back(1); }));
  EXPECT_TRUE(queue.Post([&] { order.push_back(2); }));
  EXPECT_TRUE(queue.Post([&] { order.push_back(3); }));

  EXPECT_EQ(queue.Drain(), 3u);
  EXPECT_EQ(order, std::vector<int>({1, 2, 3}));
}

TEST(TaskQueueTest, DefersTasksPostedDuringDrain) {
  TaskQueue queue;
  std::vector<int> order;

  EXPECT_TRUE(queue.Post([&] {
    order.push_back(1);
    EXPECT_TRUE(queue.Post([&] { order.push_back(3); }));
  }));
  EXPECT_TRUE(queue.Post([&] { order.push_back(2); }));

  EXPECT_EQ(queue.Drain(), 2u);
  EXPECT_EQ(order, std::vector<int>({1, 2}));
  EXPECT_EQ(queue.PendingCount(), 1u);

  EXPECT_EQ(queue.Drain(), 1u);
  EXPECT_EQ(order, std::vector<int>({1, 2, 3}));
}

TEST(TaskQueueTest, ClearDropsPendingTasks) {
  TaskQueue queue;
  std::atomic<int> count{0};

  EXPECT_TRUE(queue.Post([&] { count.fetch_add(1); }));
  EXPECT_TRUE(queue.Post([&] { count.fetch_add(1); }));
  queue.Clear();

  EXPECT_EQ(queue.PendingCount(), 0u);
  EXPECT_EQ(queue.Drain(), 0u);
  EXPECT_EQ(count.load(), 0);
}

TEST(HandlerDispatchTest, CallbacksRunInline) {
  DiscardSocket socket;
  ReliableConnection conn(&socket);
  ThreadRecordingHandler handler(std::this_thread::get_id());
  conn.SetHandler(&handler);
  conn.SetRemoteAddress(SocketAddress::FromIPv4(0x7F000001), 12345);
  conn.SetConnected();

  const std::array<std::uint8_t, 4> payload{1, 2, 3, 4};
  const auto packet = MakeReliablePacket(0, payload.data(), payload.size());
  conn.ProcessPacket(packet.data(), packet.size(),
                     SocketAddress::FromIPv4(0x7F000001), 12345);

  EXPECT_EQ(handler.callback_count.load(), 1);
  EXPECT_EQ(handler.expected_thread_callbacks.load(), 1);
}

TEST(ThreadPoolIntegrationTest, ClientWorkerPostsNetworkSend) {
  InitializeSockets();
  auto* factory = SocketFactoryRegistry::GetFactory();
  ASSERT_NE(factory, nullptr);

  SocketConfig cfg;
  cfg.nonBlocking = true;

  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);
  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), 0),
            SocketError::kNone);
  const std::uint16_t server_port = server_socket->LocalPort();
  ASSERT_GT(server_port, 0);

  auto client_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(client_socket, nullptr);

  ReliableConnectionConfig server_cfg;
  server_cfg.retryTimeoutMs = 50;
  server_cfg.disconnectTimeoutMs = 1000;

  ReliableConnectionConfig client_cfg;
  client_cfg.retryTimeoutMs = 50;
  client_cfg.disconnectTimeoutMs = 1000;

  EchoAndCountServerHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get(), server_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  std::thread::id network_thread_id;
  ThreadPool workers(2);
  TaskQueue network_queue;
  ClientSideAsyncHandler client_handler(workers, network_queue,
                                        network_thread_id);
  auto client_conn =
    std::make_unique<ReliableConnection>(client_socket.get(), client_cfg);
  client_handler.connection = client_conn.get();
  client_conn->SetHandler(&client_handler);

  std::atomic<bool> running{true};
  std::atomic<bool> network_ready{false};
  std::thread network_thread([&] {
    network_thread_id = std::this_thread::get_id();
    network_ready.store(true);
    while (running.load()) {
      network_queue.Drain();
      server_manager->Tick();
      client_conn->Tick();
      network_queue.Drain();
      std::this_thread::sleep_for(1ms);
    }
    network_queue.Drain();
  });
  ASSERT_TRUE(WaitUntil([&] { return network_ready.load(); }, 1s));

  std::atomic<int> connect_result{-1};
  ASSERT_TRUE(network_queue.Post([&] {
    connect_result.store(
      client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port)
        ? 1
        : 0);
  }));
  ASSERT_TRUE(WaitUntil([&] { return connect_result.load() != -1; }, 1s));
  ASSERT_EQ(connect_result.load(), 1);
  ASSERT_TRUE(WaitUntil([&] { return client_handler.connected.load(); }, 2s));

  workers.Start();
  const std::array<std::uint8_t, 4> payload{5, 6, 7, 8};
  std::atomic<int> send_result{-1};
  EXPECT_TRUE(network_queue.Post([&] {
    send_result.store(
      client_conn->SendReliable(0, payload.data(), payload.size()) ? 1 : 0);
  }));
  EXPECT_TRUE(WaitUntil([&] { return send_result.load() != -1; }, 1s));
  EXPECT_EQ(send_result.load(), 1);

  EXPECT_TRUE(WaitUntil(
    [&] { return server_handler.unreliable_received.load() > 0; }, 3s));

  running.store(false);
  network_thread.join();
  workers.Stop();

  EXPECT_TRUE(client_handler.callback_on_network.load());
  EXPECT_TRUE(client_handler.worker_thread_distinct.load());
  EXPECT_TRUE(client_handler.post_ran_on_network.load());
  EXPECT_FALSE(client_handler.worker_post_failed.load());
  EXPECT_FALSE(client_handler.post_failed.load());
  EXPECT_GT(server_handler.reliable_received.load(), 0);
}

TEST(ThreadPoolIntegrationTest, WorkerPostsResultBackToNetworkThread) {
  InitializeSockets();
  auto* factory = SocketFactoryRegistry::GetFactory();
  ASSERT_NE(factory, nullptr);

  SocketConfig cfg;
  cfg.nonBlocking = true;

  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);
  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), 0),
            SocketError::kNone);
  const std::uint16_t server_port = server_socket->LocalPort();
  ASSERT_GT(server_port, 0);

  auto client_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(client_socket, nullptr);

  ReliableConnectionConfig conn_cfg;
  conn_cfg.retryTimeoutMs = 50;
  conn_cfg.pingIntervalMs = 100;
  conn_cfg.disconnectTimeoutMs = 1000;

  ThreadPool workers(2);
  workers.Start();
  TaskQueue network_queue;

  AsyncEchoServerHandler server_handler(workers, network_queue);
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get(), conn_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  CollectingClientHandler client_handler;
  auto client_conn =
    std::make_unique<ReliableConnection>(client_socket.get(), conn_cfg);
  client_conn->SetHandler(&client_handler);
  client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

  std::atomic<bool> running{true};
  std::thread network_thread([&] {
    while (running.load()) {
      network_queue.Drain();
      server_manager->Tick();
      client_conn->Tick();
      network_queue.Drain();
      std::this_thread::sleep_for(1ms);
    }
    network_queue.Drain();
  });

  const bool connected =
    WaitUntil([&] { return client_handler.connected.load(); }, 2s);
  EXPECT_TRUE(connected);

  std::array<std::uint8_t, 5> payload{1, 2, 3, 4, 5};
  std::atomic<int> send_result{-1};
  if (connected) {
    EXPECT_TRUE(network_queue.Post([&] {
      send_result.store(
        client_conn->SendReliable(0, payload.data(), payload.size()) ? 1 : 0);
    }));
    EXPECT_TRUE(WaitUntil([&] { return send_result.load() != -1; }, 1s));
    EXPECT_EQ(send_result.load(), 1);
  }

  const bool delivered =
    WaitUntil([&] { return client_handler.reliable_received.load() > 0; }, 3s);
  EXPECT_TRUE(delivered);

  running.store(false);
  network_thread.join();
  workers.Stop();

  EXPECT_FALSE(server_handler.worker_post_failed.load());
  EXPECT_FALSE(server_handler.network_post_failed.load());
  EXPECT_GT(server_handler.callbacks.load(), 0);
  EXPECT_GT(server_handler.network_tasks.load(), 0);
  EXPECT_TRUE(server_handler.worker_thread_distinct.load());

  const std::vector<std::uint8_t> expected{2, 3, 4, 5, 6};
  const auto messages = client_handler.Messages();
  EXPECT_NE(std::ranges::find(messages, expected), messages.end());
}
