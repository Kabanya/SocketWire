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

    const bool posted =
      workers_.Post([this, channel, payload = std::move(payload),
                     callback_thread]() mutable {
        worker_thread_distinct.store(std::this_thread::get_id() !=
                                     callback_thread);
        for (auto& byte : payload) {
          byte = static_cast<std::uint8_t>(byte + 1);
        }

        const bool queued =
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
  [[nodiscard]] std::uint16_t LocalPort() const override {
    return bound_port_;
  }
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
        std::span<const std::uint8_t>{static_cast<const std::uint8_t*>(
                                        payload),
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

class BlockingFallbackHandler final : public IReliableConnectionHandler {
 public:
  explicit BlockingFallbackHandler(std::thread::id network_thread)
      : network_thread_(network_thread) {}

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    (void)channel;
    (void)data;
    (void)size;

    const int index = callbacks.fetch_add(1);
    if (std::this_thread::get_id() == network_thread_) {
      inline_callbacks.fetch_add(1);
    } else {
      worker_callbacks.fetch_add(1);
    }

    if (index == 0) {
      first_worker_started.store(true);
      while (!release_first_worker.load()) {
        std::this_thread::sleep_for(1ms);
      }
    }
  }

  std::atomic<int> callbacks{0};
  std::atomic<int> inline_callbacks{0};
  std::atomic<int> worker_callbacks{0};
  std::atomic<bool> first_worker_started{false};
  std::atomic<bool> release_first_worker{false};

 private:
  std::thread::id network_thread_;
};

class HighLevelAsyncServerHandler final : public IReliableConnectionHandler {
 public:
  explicit HighLevelAsyncServerHandler(std::thread::id& network_thread)
      : network_thread_(network_thread) {}

  void OnConnected() override {
    if (std::this_thread::get_id() == network_thread_) {
      control_on_network.store(true);
    }
  }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    if (std::this_thread::get_id() != network_thread_) {
      payload_off_network.store(true);
    }

    std::this_thread::sleep_for(5ms);
    std::vector<std::uint8_t> payload(
      static_cast<const std::uint8_t*>(data),
      static_cast<const std::uint8_t*>(data) + size);
    payload_callbacks.fetch_add(1);

    if (manager != nullptr) {
      const bool posted = manager->Post(
        [this, channel, payload = std::move(payload)]() mutable {
          if (std::this_thread::get_id() == network_thread_) {
            post_ran_on_network.store(true);
          }
          manager->BroadcastReliable(channel, payload.data(), payload.size());
        });
      if (!posted) post_failed.store(true);
    }
  }

  ConnectionManager* manager = nullptr;
  std::atomic<bool> control_on_network{false};
  std::atomic<bool> payload_off_network{false};
  std::atomic<bool> post_ran_on_network{false};
  std::atomic<bool> post_failed{false};
  std::atomic<int> payload_callbacks{0};

 private:
  std::thread::id& network_thread_;
};

class ClientSideAsyncHandler final : public IReliableConnectionHandler {
 public:
  explicit ClientSideAsyncHandler(std::thread::id& network_thread)
      : network_thread_(network_thread) {}

  void OnConnected() override { connected.store(true); }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    (void)channel;
    (void)data;
    (void)size;
    if (std::this_thread::get_id() != network_thread_) {
      payload_off_network.store(true);
    }

    if (connection != nullptr) {
      const std::array<std::uint8_t, 3> response{9, 8, 7};
      const bool posted = connection->Post([this, response] {
        if (std::this_thread::get_id() == network_thread_) {
          post_ran_on_network.store(true);
        }
        (void)connection->SendUnreliable(0, response.data(),
                                         response.size());
      });
      if (!posted) post_failed.store(true);
    }
  }

  ReliableConnection* connection = nullptr;
  std::atomic<bool> connected{false};
  std::atomic<bool> payload_off_network{false};
  std::atomic<bool> post_ran_on_network{false};
  std::atomic<bool> post_failed{false};

 private:
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

TEST(ThreadPoolTest, ExecutesAllPostedTasks) {
  ThreadPool pool(4, 128);
  std::atomic<int> count{0};

  for (int i = 0; i < 100; ++i) {
    EXPECT_TRUE(pool.Post([&count] { count.fetch_add(1); }));
  }

  pool.WaitIdle();
  EXPECT_EQ(count.load(), 100);
}

TEST(ThreadPoolTest, RejectsPostsAfterShutdown) {
  ThreadPool pool(1, 1);
  pool.Shutdown();

  EXPECT_FALSE(pool.Post([] {}));
}

TEST(ThreadPoolTest, RespectsBoundedQueue) {
  ThreadPool pool(1, 1);
  std::atomic<bool> first_started{false};
  std::atomic<bool> release_first{false};

  EXPECT_TRUE(pool.Post([&] {
    first_started.store(true);
    while (!release_first.load()) {
      std::this_thread::sleep_for(1ms);
    }
  }));

  const bool started = WaitUntil([&] { return first_started.load(); }, 1s);
  EXPECT_TRUE(started);

  bool second_posted = false;
  bool third_posted = false;
  if (started) {
    second_posted = pool.Post([] {});
    third_posted = pool.Post([] {});
  }

  release_first.store(true);
  pool.WaitIdle();

  EXPECT_TRUE(second_posted);
  EXPECT_FALSE(third_posted);
}

TEST(ThreadPoolTest, WaitIdleWaitsForActiveTasks) {
  ThreadPool pool(1, 8);
  std::atomic<bool> completed{false};

  EXPECT_TRUE(pool.Post([&] {
    std::this_thread::sleep_for(20ms);
    completed.store(true);
  }));

  pool.WaitIdle();
  EXPECT_TRUE(completed.load());
}

TEST(ThreadPoolTest, DestructorDrainsQueuedTasks) {
  std::atomic<int> count{0};

  {
    ThreadPool pool(1, 8);
    EXPECT_TRUE(pool.Post([&] { count.fetch_add(1); }));
  }

  EXPECT_EQ(count.load(), 1);
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

TEST(AsyncHandlerDispatchTest, DefaultConfigKeepsPayloadCallbacksInline) {
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

TEST(AsyncHandlerDispatchTest, QueueFullFallbackPreservesCallbackInline) {
  ReliableConnectionConfig cfg;
  cfg.handlerDispatchMode = HandlerDispatchMode::kAsyncPayload;
  cfg.handlerWorkerThreads = 1;
  cfg.handlerMaxQueueSize = 1;

  DiscardSocket socket;
  ReliableConnection conn(&socket, cfg);
  BlockingFallbackHandler handler(std::this_thread::get_id());
  conn.SetHandler(&handler);
  conn.SetRemoteAddress(SocketAddress::FromIPv4(0x7F000001), 12345);
  conn.SetConnected();

  const std::array<std::uint8_t, 4> payload{1, 2, 3, 4};
  const auto packet0 = MakeReliablePacket(0, payload.data(), payload.size());
  const auto packet1 = MakeReliablePacket(1, payload.data(), payload.size());
  const auto packet2 = MakeReliablePacket(2, payload.data(), payload.size());

  conn.ProcessPacket(packet0.data(), packet0.size(),
                     SocketAddress::FromIPv4(0x7F000001), 12345);
  ASSERT_TRUE(WaitUntil([&] { return handler.first_worker_started.load(); },
                        1s));

  conn.ProcessPacket(packet1.data(), packet1.size(),
                     SocketAddress::FromIPv4(0x7F000001), 12345);
  conn.ProcessPacket(packet2.data(), packet2.size(),
                     SocketAddress::FromIPv4(0x7F000001), 12345);

  handler.release_first_worker.store(true);
  EXPECT_TRUE(WaitUntil([&] { return handler.callbacks.load() == 3; }, 1s));
  EXPECT_GE(handler.worker_callbacks.load(), 1);
  EXPECT_GE(handler.inline_callbacks.load(), 1);
}

TEST(AsyncHandlerDispatchTest, ConnectionManagerAsyncPayloadEchoesViaPost) {
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
  server_cfg.handlerDispatchMode = HandlerDispatchMode::kAsyncPayload;
  server_cfg.handlerWorkerThreads = 2;
  server_cfg.handlerMaxQueueSize = 16;
  server_cfg.retryTimeoutMs = 50;
  server_cfg.disconnectTimeoutMs = 1000;

  ReliableConnectionConfig client_cfg;
  client_cfg.retryTimeoutMs = 50;
  client_cfg.disconnectTimeoutMs = 1000;

  std::thread::id network_thread_id;
  HighLevelAsyncServerHandler server_handler(network_thread_id);
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get(), server_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  CollectingClientHandler client_handler;
  auto client_conn =
    std::make_unique<ReliableConnection>(client_socket.get(), client_cfg);
  client_conn->SetHandler(&client_handler);

  std::atomic<bool> running{true};
  std::atomic<bool> network_ready{false};
  std::thread network_thread([&] {
    network_thread_id = std::this_thread::get_id();
    network_ready.store(true);
    while (running.load()) {
      server_manager->Tick();
      client_conn->Tick();
      std::this_thread::sleep_for(1ms);
    }
  });
  ASSERT_TRUE(WaitUntil([&] { return network_ready.load(); }, 1s));

  std::atomic<int> connect_result{-1};
  ASSERT_TRUE(client_conn->Post([&] {
    connect_result.store(
      client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port)
        ? 1
        : 0);
  }));
  ASSERT_TRUE(WaitUntil([&] { return connect_result.load() != -1; }, 1s));
  ASSERT_EQ(connect_result.load(), 1);
  ASSERT_TRUE(WaitUntil([&] { return client_handler.connected.load(); }, 2s));

  const std::array<std::uint8_t, 6> payload{1, 2, 3, 4, 5, 6};
  std::atomic<int> send_result{-1};
  ASSERT_TRUE(client_conn->Post([&] {
    send_result.store(client_conn->SendReliable(0, payload.data(),
                                                payload.size())
                        ? 1
                        : 0);
  }));
  ASSERT_TRUE(WaitUntil([&] { return send_result.load() != -1; }, 1s));
  ASSERT_EQ(send_result.load(), 1);

  ASSERT_TRUE(WaitUntil(
    [&] { return client_handler.reliable_received.load() > 0; }, 3s));

  running.store(false);
  network_thread.join();

  EXPECT_TRUE(server_handler.control_on_network.load());
  EXPECT_TRUE(server_handler.payload_off_network.load());
  EXPECT_TRUE(server_handler.post_ran_on_network.load());
  EXPECT_FALSE(server_handler.post_failed.load());
  EXPECT_GT(server_handler.payload_callbacks.load(), 0);

  const auto messages = client_handler.Messages();
  const std::vector<std::uint8_t> expected(payload.begin(), payload.end());
  EXPECT_NE(std::ranges::find(messages, expected), messages.end());
}

TEST(AsyncHandlerDispatchTest, ClientAsyncPayloadCanPostNetworkSend) {
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
  client_cfg.handlerDispatchMode = HandlerDispatchMode::kAsyncPayload;
  client_cfg.handlerWorkerThreads = 2;
  client_cfg.handlerMaxQueueSize = 16;
  client_cfg.retryTimeoutMs = 50;
  client_cfg.disconnectTimeoutMs = 1000;

  EchoAndCountServerHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get(), server_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  std::thread::id network_thread_id;
  ClientSideAsyncHandler client_handler(network_thread_id);
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
      server_manager->Tick();
      client_conn->Tick();
      std::this_thread::sleep_for(1ms);
    }
  });
  ASSERT_TRUE(WaitUntil([&] { return network_ready.load(); }, 1s));

  std::atomic<int> connect_result{-1};
  ASSERT_TRUE(client_conn->Post([&] {
    connect_result.store(
      client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port)
        ? 1
        : 0);
  }));
  ASSERT_TRUE(WaitUntil([&] { return connect_result.load() != -1; }, 1s));
  ASSERT_EQ(connect_result.load(), 1);
  ASSERT_TRUE(WaitUntil([&] { return client_handler.connected.load(); }, 2s));

  const std::array<std::uint8_t, 4> payload{5, 6, 7, 8};
  std::atomic<int> send_result{-1};
  ASSERT_TRUE(client_conn->Post([&] {
    send_result.store(client_conn->SendReliable(0, payload.data(),
                                                payload.size())
                        ? 1
                        : 0);
  }));
  ASSERT_TRUE(WaitUntil([&] { return send_result.load() != -1; }, 1s));
  ASSERT_EQ(send_result.load(), 1);

  ASSERT_TRUE(WaitUntil(
    [&] { return server_handler.unreliable_received.load() > 0; }, 3s));

  running.store(false);
  network_thread.join();

  EXPECT_TRUE(client_handler.payload_off_network.load());
  EXPECT_TRUE(client_handler.post_ran_on_network.load());
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

  ThreadPool workers(2, 16);
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
      send_result.store(client_conn->SendReliable(0, payload.data(),
                                                  payload.size())
                          ? 1
                          : 0);
    }));
    EXPECT_TRUE(WaitUntil([&] { return send_result.load() != -1; }, 1s));
    EXPECT_EQ(send_result.load(), 1);
  }

  const bool delivered = WaitUntil(
    [&] { return client_handler.reliable_received.load() > 0; }, 3s);
  EXPECT_TRUE(delivered);

  running.store(false);
  network_thread.join();
  workers.Shutdown(true);

  EXPECT_FALSE(server_handler.worker_post_failed.load());
  EXPECT_FALSE(server_handler.network_post_failed.load());
  EXPECT_GT(server_handler.callbacks.load(), 0);
  EXPECT_GT(server_handler.network_tasks.load(), 0);
  EXPECT_TRUE(server_handler.worker_thread_distinct.load());

  const std::vector<std::uint8_t> expected{2, 3, 4, 5, 6};
  const auto messages = client_handler.Messages();
  EXPECT_NE(std::ranges::find(messages, expected), messages.end());
}
