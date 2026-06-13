#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "bit_stream.hpp"
#include "connection_manager.hpp"
#include "i_socket.hpp"
#include "reliable_connection.hpp"
#include "socket_init.hpp"
#include "task_queue.hpp"
#include "thread_pool.hpp"

using namespace std::chrono;  // NOLINT
using namespace socketwire;   // NOLINT
using socketwire::SocketAddress;

class ReliableConnectionPerformanceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    socketwire::InitializeSockets();

    auto factory = SocketFactoryRegistry::GetFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be available";
  }

  // Helper to measure throughput
  struct ThroughputResult {
    double packetsPerSecond;
    double bytesPerSecond;
    double averageLatencyMs;
    double maxLatencyMs;
    uint32_t totalPackets;
    uint32_t lostPackets;
  };

  static void AppendPerfMetric(const std::string& operation_name,
                               double total_ms, double throughput,
                               const std::string& unit) {
    const char* results_path = std::getenv("SOCKETWIRE_PERF_RESULTS");
    if (results_path == nullptr || results_path[0] == '\0') return;

    std::ofstream out(results_path, std::ios::app);
    if (!out) return;

    out << operation_name << " total_ms=" << total_ms
        << " throughput=" << throughput << " " << unit << "\n";
  }
};

// Simple packet counter handler
class CounterHandler : public IReliableConnectionHandler {
 public:
  std::atomic<uint32_t> reliableCount{0};
  std::atomic<uint32_t> unreliableCount{0};
  std::atomic<bool> connected{false};

  void OnConnected() override { connected = true; }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          size_t size) override {
    (void)channel;
    (void)data;
    (void)size;
    reliableCount++;
  }

  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            size_t size) override {
    (void)channel;
    (void)data;
    (void)size;
    unreliableCount++;
  }
};

class PerfNullSocket final : public ISocket {
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
    ++send_count_;
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

  bool IsBlocking() const override { return blocking_; }
  std::uint16_t LocalPort() const override { return bound_port_; }
  int NativeHandle() const override { return 1; }
  void Close() override {}

  std::uint32_t SendCount() const { return send_count_; }

 private:
  bool blocking_ = false;
  std::uint16_t bound_port_ = 0;
  std::uint32_t send_count_ = 0;
};

template <typename Predicate>
bool SpinUntil(Predicate predicate, milliseconds timeout) {
  const auto deadline = steady_clock::now() + timeout;
  while (!predicate()) {
    if (steady_clock::now() >= deadline) return predicate();
    std::this_thread::yield();
  }
  return true;
}

namespace {

enum class ApplicationWorkloadMode : std::uint8_t { kInline, kThreadPool };

struct ApplicationWorkloadResult {
  std::string mode;
  bool ok = false;
  std::string error;
  double totalMs = 0.0;
  double messagesPerSecond = 0.0;
  double averageLatencyMs = 0.0;
  double maxLatencyMs = 0.0;
  double maxNetworkTickMs = 0.0;
  std::size_t workerCount = 0;
};

constexpr std::size_t kApplicationWorkloadMessages = 1000;
constexpr std::size_t kApplicationWorkloadPayloadSize = 256;
constexpr std::size_t kApplicationWorkloadSendBatch = 16;
constexpr std::uint32_t kApplicationWorkloadRounds = 96;

void StoreMessageId(std::vector<std::uint8_t>& payload, std::uint32_t id) {
  payload.at(0) = static_cast<std::uint8_t>((id >> 24) & 0xFFu);
  payload.at(1) = static_cast<std::uint8_t>((id >> 16) & 0xFFu);
  payload.at(2) = static_cast<std::uint8_t>((id >> 8) & 0xFFu);
  payload.at(3) = static_cast<std::uint8_t>(id & 0xFFu);
}

std::uint32_t LoadMessageId(const void* data, std::size_t size) {
  if (data == nullptr || size < 4) return UINT32_MAX;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  return (static_cast<std::uint32_t>(bytes[0]) << 24) |
         (static_cast<std::uint32_t>(bytes[1]) << 16) |
         (static_cast<std::uint32_t>(bytes[2]) << 8) |
         static_cast<std::uint32_t>(bytes[3]);
}

std::vector<std::uint8_t> MakeApplicationPayload(std::uint32_t id) {
  std::vector<std::uint8_t> payload(kApplicationWorkloadPayloadSize);
  StoreMessageId(payload, id);
  for (std::size_t i = 4; i < payload.size(); ++i) {
    payload.at(i) =
      static_cast<std::uint8_t>((id * 131u + i * 17u + 0x5Au) & 0xFFu);
  }
  return payload;
}

std::uint64_t RunDeterministicWorkload(
  const std::vector<std::uint8_t>& payload) {
  std::uint64_t hash = 1469598103934665603ULL;
  for (std::uint32_t round = 0; round < kApplicationWorkloadRounds; ++round) {
    for (const std::uint8_t byte : payload) {
      hash ^= static_cast<std::uint64_t>(byte) + round;
      hash *= 1099511628211ULL;
      hash ^= hash >> 32;
    }
  }
  return hash;
}

std::vector<std::uint8_t> BuildApplicationResponse(
  std::vector<std::uint8_t> payload) {
  const std::uint64_t hash = RunDeterministicWorkload(payload);
  for (std::size_t i = 0; i < 8 && payload.size() >= 12; ++i) {
    payload.at(payload.size() - 1 - i) =
      static_cast<std::uint8_t>((hash >> (i * 8)) & 0xFFu);
  }
  return payload;
}

void UpdateAtomicMax(std::atomic<std::int64_t>& target, std::int64_t value) {
  std::int64_t current = target.load();
  while (current < value &&
         !target.compare_exchange_weak(current, value)) {
  }
}

double NanosecondsToMilliseconds(std::int64_t ns) {
  return static_cast<double>(ns) / 1000000.0;
}

class ApplicationWorkloadClientHandler final
    : public IReliableConnectionHandler {
 public:
  explicit ApplicationWorkloadClientHandler(
    std::vector<steady_clock::time_point>& send_times)
      : send_times_(send_times) {}

  void OnConnected() override { connected.store(true); }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    (void)channel;
    const std::uint32_t id = LoadMessageId(data, size);
    if (id >= send_times_.size()) return;

    const auto sent_at = send_times_.at(id);
    if (sent_at == steady_clock::time_point{}) return;

    const auto latency_ns =
      duration_cast<nanoseconds>(steady_clock::now() - sent_at).count();
    total_latency_ns_.fetch_add(latency_ns);
    UpdateAtomicMax(max_latency_ns_, latency_ns);
    received.fetch_add(1);
  }

  [[nodiscard]] std::int64_t TotalLatencyNs() const {
    return total_latency_ns_.load();
  }

  [[nodiscard]] std::int64_t MaxLatencyNs() const {
    return max_latency_ns_.load();
  }

  std::atomic<bool> connected{false};
  std::atomic<std::uint32_t> received{0};

 private:
  std::vector<steady_clock::time_point>& send_times_;
  std::atomic<std::int64_t> total_latency_ns_{0};
  std::atomic<std::int64_t> max_latency_ns_{0};
};

class ApplicationWorkloadServerHandler final
    : public IReliableConnectionHandler {
 public:
  ApplicationWorkloadServerHandler(ApplicationWorkloadMode mode,
                                   TaskQueue& network_queue,
                                   ThreadPool* workers)
      : mode_(mode), network_queue_(network_queue), workers_(workers) {}

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    std::vector<std::uint8_t> payload(
      static_cast<const std::uint8_t*>(data),
      static_cast<const std::uint8_t*>(data) + size);

    if (mode_ == ApplicationWorkloadMode::kInline) {
      auto response = BuildApplicationResponse(std::move(payload));
      ++processed;
      if (manager != nullptr) {
        manager->BroadcastReliable(channel, response.data(), response.size());
      }
      return;
    }

    if (workers_ == nullptr) {
      worker_post_failed.store(true);
      return;
    }

    const bool posted =
      workers_->Post([this, channel, payload = std::move(payload)]() mutable {
        auto response = BuildApplicationResponse(std::move(payload));
        ++processed;
        const bool queued =
          network_queue_.Post([this, channel, response = std::move(response)] {
            if (manager != nullptr) {
              manager->BroadcastReliable(channel, response.data(),
                                         response.size());
            }
          });
        if (!queued) network_post_failed.store(true);
      });
    if (!posted) worker_post_failed.store(true);
  }

  ConnectionManager* manager = nullptr;
  std::atomic<std::uint32_t> processed{0};
  std::atomic<bool> worker_post_failed{false};
  std::atomic<bool> network_post_failed{false};

 private:
  ApplicationWorkloadMode mode_;
  TaskQueue& network_queue_;
  ThreadPool* workers_ = nullptr;
};

ApplicationWorkloadResult RunApplicationWorkloadScenario(
  ApplicationWorkloadMode mode) {
  ApplicationWorkloadResult result;
  result.mode =
    mode == ApplicationWorkloadMode::kInline ? "inline" : "thread_pool";

  auto* factory = SocketFactoryRegistry::GetFactory();
  if (factory == nullptr) {
    result.error = "Socket factory is unavailable";
    return result;
  }

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  auto client_socket = factory->CreateUdpSocket(cfg);
  if (server_socket == nullptr || client_socket == nullptr) {
    result.error = "Failed to create UDP sockets";
    return result;
  }

  if (server_socket->Bind(SocketAddress::FromIPv4(0), 0) !=
      SocketError::kNone) {
    result.error = "Failed to bind server socket";
    return result;
  }
  const std::uint16_t server_port = server_socket->LocalPort();
  if (server_port == 0) {
    result.error = "Server socket did not get a local port";
    return result;
  }

  ReliableConnectionConfig conn_cfg;
  conn_cfg.retryTimeoutMs = 20;
  conn_cfg.pingIntervalMs = 1000;
  conn_cfg.disconnectTimeoutMs = 5000;
  conn_cfg.maxPendingReliablePackets = 4096;

  TaskQueue network_queue;
  std::unique_ptr<ThreadPool> workers;
  if (mode == ApplicationWorkloadMode::kThreadPool) {
    workers = std::make_unique<ThreadPool>(
      ThreadPool::DefaultWorkerCount(), kApplicationWorkloadMessages * 2);
    result.workerCount = workers->WorkerCount();
  }

  ApplicationWorkloadServerHandler server_handler(
    mode, network_queue, workers.get());
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get(), conn_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  std::vector<steady_clock::time_point> send_times(
    kApplicationWorkloadMessages);
  ApplicationWorkloadClientHandler client_handler(send_times);
  auto client_conn =
    std::make_unique<ReliableConnection>(client_socket.get(), conn_cfg);
  client_conn->SetHandler(&client_handler);

  std::atomic<bool> running{true};
  std::atomic<std::int64_t> max_tick_ns{0};
  std::thread network_thread([&] {
    while (running.load()) {
      const auto tick_start = steady_clock::now();
      network_queue.Drain();
      server_manager->Tick();
      client_conn->Tick();
      network_queue.Drain();
      const auto tick_ns =
        duration_cast<nanoseconds>(steady_clock::now() - tick_start).count();
      UpdateAtomicMax(max_tick_ns, tick_ns);
      std::this_thread::yield();
    }
    network_queue.Drain();
  });

  const bool connect_queued = network_queue.Post([&] {
    client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);
  });
  if (!connect_queued ||
      !SpinUntil([&] { return client_handler.connected.load(); },
                 milliseconds(2000))) {
    running.store(false);
    network_thread.join();
    if (workers != nullptr) workers->Shutdown(false);
    result.error = "Connection failed to establish";
    return result;
  }

  std::atomic<bool> send_failed{false};
  std::atomic<std::uint32_t> next_to_send{0};
  auto send_more = std::make_shared<std::function<void()>>();
  std::weak_ptr<std::function<void()>> weak_send_more = send_more;
  *send_more = [&, weak_send_more] {
    for (std::size_t i = 0; i < kApplicationWorkloadSendBatch; ++i) {
      const std::uint32_t id = next_to_send.fetch_add(1);
      if (id >= kApplicationWorkloadMessages) return;

      auto payload = MakeApplicationPayload(id);
      send_times.at(id) = steady_clock::now();
      const bool sent =
        client_conn->SendReliable(0, payload.data(), payload.size());
      if (!sent) send_failed.store(true);
    }

    if (next_to_send.load() < kApplicationWorkloadMessages) {
      if (const auto next = weak_send_more.lock(); next != nullptr) {
        if (!network_queue.Post(*next)) send_failed.store(true);
      }
    }
  };

  const auto start = high_resolution_clock::now();
  if (!network_queue.Post(*send_more)) {
    running.store(false);
    network_thread.join();
    if (workers != nullptr) workers->Shutdown(false);
    result.error = "Failed to queue send task";
    return result;
  }

  const bool delivered = SpinUntil(
    [&] {
      return client_handler.received.load() >= kApplicationWorkloadMessages;
    },
    milliseconds(15000));
  const auto end = high_resolution_clock::now();

  running.store(false);
  network_thread.join();
  if (workers != nullptr) workers->Shutdown(true);

  if (!delivered) {
    result.error = "Timed out waiting for echoed workload messages";
    return result;
  }
  if (send_failed.load()) {
    result.error = "One or more reliable sends failed";
    return result;
  }
  if (server_handler.worker_post_failed.load() ||
      server_handler.network_post_failed.load()) {
    result.error = "Worker or network queue post failed";
    return result;
  }

  auto duration_us = duration_cast<microseconds>(end - start).count();
  if (duration_us == 0) duration_us = 1;
  const auto received = client_handler.received.load();
  result.ok = true;
  result.totalMs = static_cast<double>(duration_us) / 1000.0;
  result.messagesPerSecond =
    (static_cast<double>(received) * 1000000.0) /
    static_cast<double>(duration_us);
  result.averageLatencyMs = NanosecondsToMilliseconds(
    client_handler.TotalLatencyNs() / static_cast<std::int64_t>(received));
  result.maxLatencyMs = NanosecondsToMilliseconds(
    client_handler.MaxLatencyNs());
  result.maxNetworkTickMs = NanosecondsToMilliseconds(max_tick_ns.load());
  return result;
}

}  // namespace

TEST_F(ReliableConnectionPerformanceTest, SmallPacketThroughput) {
  const uint16_t server_port = 16001;
  const int packet_count = 1000;
  const size_t packet_size = 64;  // Small packets

  auto factory = SocketFactoryRegistry::GetFactory();

  // Server
  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);
  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), server_port),
            SocketError::kNone);

  CounterHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get());
  server_manager->SetHandler(&server_handler);

  // Client
  auto client_socket = factory->CreateUdpSocket(cfg);
  CounterHandler client_handler;
  auto client_conn = std::make_unique<ReliableConnection>(client_socket.get());
  client_conn->SetHandler(&client_handler);

  client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

  // Network thread
  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    while (running) {
      server_manager->Tick();
      client_conn->Tick();
      std::this_thread::yield();
    }
  });

  // Wait for connection
  ASSERT_TRUE(SpinUntil([&]() { return client_handler.connected.load(); },
                        milliseconds(1000)));

  // Prepare data
  std::vector<std::uint8_t> test_data(packet_size, 0xAB);

  // Benchmark
  auto start_time = high_resolution_clock::now();

  for (int i = 0; i < packet_count; i++) {
    client_conn->SendReliable(0, test_data.data(), test_data.size());
  }

  // Wait for all packets to be received
  EXPECT_TRUE(SpinUntil(
    [&]() { return server_handler.reliableCount.load() >= packet_count; },
    milliseconds(5000)));

  auto end_time = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(end_time - start_time).count();

  EXPECT_EQ(server_handler.reliableCount, packet_count)
    << "All packets should be received";

  const double packets_per_sec =
    (packet_count * 1000.0) / static_cast<double>(duration);
  const double bytes_per_sec =
    (packet_count * packet_size * 1000.0) / static_cast<double>(duration);

  std::cout << "\n=== Small Packet Throughput ===" << "\n";
  std::cout << "Packets: " << packet_count << "\n";
  std::cout << "Packet size: " << packet_size << " bytes" << "\n";
  std::cout << "Duration: " << duration << " ms" << "\n";
  std::cout << "Throughput: " << packets_per_sec << " packets/sec" << "\n";
  std::cout << "Throughput: " << (bytes_per_sec / 1024.0) << " KB/sec"
            << "\n";
  std::cout << "Lost packets: " << client_conn->GetLostPackets() << "\n";
  std::cout << "RTT: " << client_conn->GetRtt() << " ms" << "\n";
  AppendPerfMetric("Reliable small packet throughput",
                   static_cast<double>(duration), packets_per_sec,
                   "packets/sec");

  running = false;
  network_thread.join();
}

TEST_F(ReliableConnectionPerformanceTest, MediumPacketThroughput) {
  const uint16_t server_port = 16002;
  const int packet_count = 500;
  const size_t packet_size = 1024;  // Larger packets

  auto factory = SocketFactoryRegistry::GetFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);
  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), server_port),
            SocketError::kNone);

  CounterHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get());
  server_manager->SetHandler(&server_handler);

  auto client_socket = factory->CreateUdpSocket(cfg);
  CounterHandler client_handler;
  auto client_conn = std::make_unique<ReliableConnection>(client_socket.get());
  client_conn->SetHandler(&client_handler);

  client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    while (running) {
      server_manager->Tick();
      client_conn->Tick();
      std::this_thread::yield();
    }
  });

  ASSERT_TRUE(SpinUntil([&]() { return client_handler.connected.load(); },
                        milliseconds(1000)));

  std::vector<std::uint8_t> test_data(packet_size, 0xCD);

  auto start_time = high_resolution_clock::now();

  for (int i = 0; i < packet_count; i++) {
    client_conn->SendReliable(0, test_data.data(), test_data.size());
  }

  EXPECT_TRUE(SpinUntil(
    [&]() { return server_handler.reliableCount.load() >= packet_count; },
    milliseconds(5000)));

  auto end_time = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(end_time - start_time).count();

  EXPECT_EQ(server_handler.reliableCount, packet_count);

  const double packets_per_sec =
    (packet_count * 1000.0) / static_cast<double>(duration);
  const double bytes_per_sec =
    (packet_count * packet_size * 1000.0) / static_cast<double>(duration);

  std::cout << "\n=== Large Packet Throughput ===" << "\n";
  std::cout << "Packets: " << packet_count << "\n";
  std::cout << "Packet size: " << packet_size << " bytes" << "\n";
  std::cout << "Duration: " << duration << " ms" << "\n";
  std::cout << "Throughput: " << packets_per_sec << " packets/sec" << "\n";
  std::cout << "Throughput: " << (bytes_per_sec / 1024.0) << " KB/sec"
            << "\n";
  std::cout << "Lost packets: " << client_conn->GetLostPackets() << "\n";
  std::cout << "RTT: " << client_conn->GetRtt() << " ms" << "\n";
  AppendPerfMetric("Reliable medium packet throughput",
                   static_cast<double>(duration), packets_per_sec,
                   "packets/sec");

  running = false;
  network_thread.join();
}

TEST_F(ReliableConnectionPerformanceTest, LargePacketThroughput) {
  const uint16_t server_port = 16003;
  const int packet_count = 500;
  const size_t packet_size = 128;

  auto factory = SocketFactoryRegistry::GetFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);
  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), server_port),
            SocketError::kNone);

  CounterHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get());
  server_manager->SetHandler(&server_handler);

  auto client_socket = factory->CreateUdpSocket(cfg);
  CounterHandler client_handler;
  auto client_conn = std::make_unique<ReliableConnection>(client_socket.get());
  client_conn->SetHandler(&client_handler);

  client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    while (running) {
      server_manager->Tick();
      client_conn->Tick();
      std::this_thread::yield();
    }
  });

  // Wait for connection with timeout
  const bool connected =
    SpinUntil([&]() { return client_handler.connected.load(); },
              milliseconds(5000));

  if (!connected) {
    running = false;
    network_thread.join();
    FAIL() << "Connection failed to establish within timeout";
  }

  std::vector<std::uint8_t> test_data(packet_size, 0xEF);

  auto start_time = high_resolution_clock::now();

  // Send unreliable packets
  for (int i = 0; i < packet_count; i++) {
    client_conn->SendUnreliable(1, test_data.data(), test_data.size());
  }

  const bool all_unreliable_received = SpinUntil(
    [&]() { return server_handler.unreliableCount.load() >= packet_count; },
    milliseconds(10000));

  auto end_time = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(end_time - start_time).count();

  const uint32_t received = server_handler.unreliableCount;
  const double delivery_rate = (received * 100.0) / packet_count;
  const double packets_per_sec =
    (received * 1000.0) / static_cast<double>(duration);
  const double bytes_per_sec = (static_cast<double>(received) *
                                static_cast<double>(packet_size) * 1000.0) /
                               static_cast<double>(duration);

  std::cout << "\n=== Unreliable Packet Throughput ===" << "\n";
  std::cout << "Packets sent: " << packet_count << "\n";
  std::cout << "Packets received: " << received << "\n";
  std::cout << "Delivery rate: " << delivery_rate << "%" << "\n";
  std::cout << "Duration: " << duration << " ms" << "\n";
  std::cout << "Throughput: " << packets_per_sec << " packets/sec" << "\n";
  std::cout << "Throughput: " << (bytes_per_sec / 1024.0) << " KB/sec"
            << "\n";
  std::cout << "Received all before timeout: "
            << (all_unreliable_received ? "yes" : "no") << "\n";
  AppendPerfMetric("Reliable unreliable-packet throughput",
                   static_cast<double>(duration), packets_per_sec,
                   "packets/sec");

  // Unreliable should be faster and have high delivery rate on localhost
  // Use a more realistic threshold for unreliable packets, especially under
  // load
  EXPECT_GT(delivery_rate, 70.0)
    << "Delivery rate should be reasonable on localhost, got " << delivery_rate
    << "%";

  running = false;
  network_thread.join();
}

TEST_F(ReliableConnectionPerformanceTest, ConnectionScalability) {
  const uint16_t server_port = 16004;
  const int num_clients = 10;
  const int messages_per_client = 50;

  auto factory = SocketFactoryRegistry::GetFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);
  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), server_port),
            SocketError::kNone);

  CounterHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get());
  server_manager->SetHandler(&server_handler);

  // Create multiple clients
  std::vector<std::unique_ptr<ISocket>> client_sockets;
  std::vector<std::unique_ptr<ReliableConnection>> client_conns;
  std::vector<std::unique_ptr<CounterHandler>> client_handlers;

  for (int i = 0; i < num_clients; i++) {
    auto socket = factory->CreateUdpSocket(cfg);
    auto handler = std::make_unique<CounterHandler>();
    auto conn = std::make_unique<ReliableConnection>(socket.get());
    conn->SetHandler(handler.get());
    conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

    client_sockets.push_back(std::move(socket));
    client_conns.push_back(std::move(conn));
    client_handlers.push_back(std::move(handler));
  }

  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    while (running) {
      server_manager->Tick();
      for (const auto& client_conn : client_conns) {
        client_conn->Tick();
      }
      std::this_thread::yield();
    }
  });

  // Wait for all connections
  const bool all_connected = SpinUntil(
    [&]() {
      for (const auto& handler : client_handlers) {
        if (!handler->connected.load()) return false;
      }
      return true;
    },
    milliseconds(2000));
  ASSERT_TRUE(all_connected);

  auto start_time = high_resolution_clock::now();

  // Each client sends messages
  std::vector<std::uint8_t> test_data(100, 0x42);
  for (const auto& client_conn : client_conns) {
    for (int j = 0; j < messages_per_client; j++) {
      client_conn->SendReliable(0, test_data.data(), test_data.size());
    }
  }

  // Wait for all messages
  const uint32_t expected_total = num_clients * messages_per_client;
  EXPECT_TRUE(SpinUntil(
    [&]() { return server_handler.reliableCount.load() >= expected_total; },
    milliseconds(10000)));

  auto end_time = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(end_time - start_time).count();

  std::cout << "\n=== Connection Scalability ===" << "\n";
  std::cout << "Clients: " << num_clients << "\n";
  std::cout << "Messages per client: " << messages_per_client << "\n";
  std::cout << "Total messages: " << expected_total << "\n";
  std::cout << "Received: " << server_handler.reliableCount.load() << "\n";
  std::cout << "Duration: " << duration << " ms" << "\n";
  std::cout << "Average per client: " << (duration / num_clients) << " ms"
            << "\n";
  AppendPerfMetric("Reliable 10-client scalability",
                   static_cast<double>(duration),
                   (expected_total * 1000.0) / static_cast<double>(duration),
                   "messages/sec");

  EXPECT_EQ(server_handler.reliableCount, expected_total);

  running = false;
  network_thread.join();
}

TEST_F(ReliableConnectionPerformanceTest,
       ApplicationWorkloadInlineVsThreadPool) {
  const ApplicationWorkloadResult inline_result =
    RunApplicationWorkloadScenario(ApplicationWorkloadMode::kInline);
  ASSERT_TRUE(inline_result.ok) << inline_result.error;

  const ApplicationWorkloadResult thread_pool_result =
    RunApplicationWorkloadScenario(ApplicationWorkloadMode::kThreadPool);
  ASSERT_TRUE(thread_pool_result.ok) << thread_pool_result.error;

  const double duration_speedup =
    inline_result.totalMs / thread_pool_result.totalMs;
  const double throughput_speedup =
    thread_pool_result.messagesPerSecond / inline_result.messagesPerSecond;

  std::cout << "\n=== Application Workload: Inline vs ThreadPool ===\n";
  std::cout << "Messages: " << kApplicationWorkloadMessages << "\n";
  std::cout << "Payload size: " << kApplicationWorkloadPayloadSize
            << " bytes\n";
  std::cout << "Workload rounds: " << kApplicationWorkloadRounds << "\n";
  std::cout << std::left << std::setw(14) << "mode" << std::right
            << std::setw(12) << "total_ms" << std::setw(16)
            << "messages/sec" << std::setw(18) << "avg_latency_ms"
            << std::setw(17) << "max_latency_ms" << std::setw(14)
            << "max_tick_ms" << std::setw(10) << "workers" << "\n";

  const auto print_result = [](const ApplicationWorkloadResult& result) {
    std::cout << std::left << std::setw(14) << result.mode << std::right
              << std::fixed << std::setprecision(2) << std::setw(12)
              << result.totalMs << std::setw(16) << result.messagesPerSecond
              << std::setw(18) << result.averageLatencyMs << std::setw(17)
              << result.maxLatencyMs << std::setw(14)
              << result.maxNetworkTickMs << std::setw(10)
              << result.workerCount << "\n";
  };

  print_result(inline_result);
  print_result(thread_pool_result);

  std::cout << "duration speedup: " << std::fixed << std::setprecision(2)
            << duration_speedup << "x\n";
  std::cout << "throughput speedup: " << std::fixed << std::setprecision(2)
            << throughput_speedup << "x\n";

  AppendPerfMetric("Application workload inline", inline_result.totalMs,
                   inline_result.messagesPerSecond, "messages/sec");
  AppendPerfMetric("Application workload thread_pool",
                   thread_pool_result.totalMs,
                   thread_pool_result.messagesPerSecond, "messages/sec");

  EXPECT_GT(inline_result.messagesPerSecond, 0.0);
  EXPECT_GT(thread_pool_result.messagesPerSecond, 0.0);
}

TEST_F(ReliableConnectionPerformanceTest, ConnectionManagerUpdateScalability) {
  constexpr std::array<int, 3> kClientCounts = {100, 500, 1000};
  constexpr int kIterations = 1000;

  const auto now = steady_clock::time_point{};
  std::array<std::uint8_t, 64> packet_storage{};
  const auto encoded = detail::PacketCodec::Encode(
    detail::PacketBuild{.type = detail::PacketType::kConnect}, now,
    packet_storage);
  ASSERT_TRUE(encoded.has_value());
  const std::vector<std::uint8_t> connect_packet(
    packet_storage.begin(), packet_storage.begin() +
                              static_cast<std::ptrdiff_t>(*encoded));

  std::cout << "\n=== ConnectionManager Update Scalability ===" << "\n";

  for (const int client_count : kClientCounts) {
    PerfNullSocket socket;
    ReliableConnectionConfig cfg;
    cfg.maxClients = static_cast<std::uint32_t>(client_count);
    cfg.maxHandshakesPerSecond = 0;
    cfg.maxPacketSize = 256;
    cfg.pingIntervalMs = 60000;
    cfg.disconnectTimeoutMs = 60000;

    ManualClock clock(now);
    ConnectionManager manager(&socket, cfg, &clock);
    const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

    for (int i = 0; i < client_count; ++i) {
      manager.ProcessPacket(connect_packet.data(), connect_packet.size(), addr,
                            static_cast<std::uint16_t>(20000 + i));
    }
    ASSERT_EQ(manager.GetConnections().size(),
              static_cast<std::size_t>(client_count));

    const auto start = high_resolution_clock::now();
    for (int i = 0; i < kIterations; ++i) {
      manager.Update(now);
    }
    const auto end = high_resolution_clock::now();

    auto duration_us = duration_cast<microseconds>(end - start).count();
    if (duration_us == 0) duration_us = 1;
    const double duration_ms = static_cast<double>(duration_us) / 1000.0;
    const double updates_per_sec =
      (kIterations * 1000000.0) / static_cast<double>(duration_us);
    const double us_per_update =
      static_cast<double>(duration_us) / static_cast<double>(kIterations);

    std::cout << "Clients: " << client_count << "\n"
              << "Iterations: " << kIterations << "\n"
              << "Total time: " << duration_ms << " ms\n"
              << "Avg update: " << us_per_update << " μs\n"
              << "Throughput: " << updates_per_sec << " updates/sec\n";

    AppendPerfMetric("ConnectionManager update " +
                       std::to_string(client_count) + " clients",
                     duration_ms, updates_per_sec, "updates/sec");
    EXPECT_GT(updates_per_sec, 0.0);
  }
}

TEST_F(ReliableConnectionPerformanceTest, BitStreamSerializationPerformance) {
  const int iterations = 100000;

  std::cout << "\n=== BitStream Serialization Performance ===" << "\n";

  // Write performance
  auto write_start = high_resolution_clock::now();

  for (int i = 0; i < iterations; i++) {
    BitStream bs;
    bs.Write<std::uint8_t>(42);
    bs.Write<uint16_t>(1234);
    bs.Write<uint32_t>(123456);
    bs.Write<float>(3.14f);
    bs.Write<double>(2.718);
    bs.Write<bool>(true);
  }

  auto write_end = high_resolution_clock::now();
  auto write_duration =
    duration_cast<microseconds>(write_end - write_start).count();

  std::cout << "Write operations: " << iterations << "\n";
  std::cout << "Write time: " << write_duration << " μs" << "\n";
  std::cout << "Writes per second: "
            << (iterations * 1000000.0 / static_cast<double>(write_duration))
            << "\n";
  AppendPerfMetric(
    "Reliable BitStream write serialization",
    static_cast<double>(write_duration) / 1000.0,
    iterations * 1000000.0 / static_cast<double>(write_duration), "ops/sec");

  // Read performance
  BitStream bs;
  bs.Write<std::uint8_t>(42);
  bs.Write<uint16_t>(1234);
  bs.Write<uint32_t>(123456);
  bs.Write<float>(3.14f);
  bs.Write<double>(2.718);
  bs.Write<bool>(true);

  auto read_start = high_resolution_clock::now();

  for (int i = 0; i < iterations; i++) {
    bs.ResetRead();
    std::uint8_t v1 = 0;
    uint16_t v2 = 0;
    uint32_t v3 = 0;
    float v4 = NAN;
    double v5 = NAN;
    bool v6 = false;

    bs.Read<std::uint8_t>(v1);
    bs.Read<uint16_t>(v2);
    bs.Read<uint32_t>(v3);
    bs.Read<float>(v4);
    bs.Read<double>(v5);
    bs.Read<bool>(v6);
  }

  auto read_end = high_resolution_clock::now();
  auto read_duration =
    duration_cast<microseconds>(read_end - read_start).count();

  std::cout << "Read operations: " << iterations << "\n";
  std::cout << "Read time: " << read_duration << " μs" << "\n";
  std::cout << "Reads per second: "
            << (iterations * 1000000.0 / static_cast<double>(read_duration))
            << "\n";
  AppendPerfMetric(
    "Reliable BitStream read serialization",
    static_cast<double>(read_duration) / 1000.0,
    iterations * 1000000.0 / static_cast<double>(read_duration), "ops/sec");
}
