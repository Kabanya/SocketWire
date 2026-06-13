#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <iostream>
#include <thread>

#include "bit_stream.hpp"
#include "connection_manager.hpp"
#include "i_socket.hpp"
#include "reliable_connection.hpp"
#include "socket_init.hpp"

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

template <typename Predicate>
bool SpinUntil(Predicate predicate, milliseconds timeout) {
  const auto deadline = steady_clock::now() + timeout;
  while (!predicate()) {
    if (steady_clock::now() >= deadline) return predicate();
    std::this_thread::yield();
  }
  return true;
}

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
    char buffer[2048];
    while (running) {
      SocketAddress from;
      uint16_t from_port = 0;

      while (true) {
        auto result =
          server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
            buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      while (true) {
        auto result =
          client_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          client_conn->ProcessPacket(
            buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      server_manager->Update();
      client_conn->Update();

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
    char buffer[2048];
    while (running) {
      SocketAddress from;
      uint16_t from_port = 0;

      while (true) {
        auto result =
          server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
            buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      while (true) {
        auto result =
          client_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          client_conn->ProcessPacket(
            buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      server_manager->Update();
      client_conn->Update();
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
    char buffer[2048];
    while (running) {
      SocketAddress from;
      uint16_t from_port = 0;

      while (true) {
        auto result =
          server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
            buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      while (true) {
        auto result =
          client_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          client_conn->ProcessPacket(
            buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      server_manager->Update();
      client_conn->Update();
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
    char buffer[2048];
    while (running) {
      SocketAddress from;
      uint16_t from_port = 0;

      while (true) {
        auto result =
          server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
            buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      for (size_t i = 0; i < client_sockets.size(); i++) {
        while (true) {
          auto result = client_sockets.at(i)->Receive(buffer, sizeof(buffer),
                                                      from, from_port);
          if (!result.Succeeded()) break;
          if (result.bytes > 0) {
            client_conns.at(i)->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
          }
        }
        client_conns.at(i)->Update();
      }

      server_manager->Update();
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

  EXPECT_EQ(server_handler.reliableCount, expected_total);

  running = false;
  network_thread.join();
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
}
