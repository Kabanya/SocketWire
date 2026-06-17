// Tests for SocketPoller construction, registration, polling, and caller reads.

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "i_socket.hpp"
#include "socket_init.hpp"
#include "socket_poller.hpp"

using namespace socketwire;  // NOLINT

class SocketPollerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    InitializeSockets();
    factory = SocketFactoryRegistry::GetFactory();
    ASSERT_NE(factory, nullptr);
  }

  ISocketFactory* factory = nullptr;

  std::unique_ptr<ISocket> CreateUdpSocket() {
    const SocketConfig config;
    return factory->CreateUdpSocket(config);
  }
};

TEST_F(SocketPollerTest, ConstructorDefaultConfig) {
  const SocketPoller poller;
#if defined(_WIN32) || defined(_WIN64)
  EXPECT_EQ(poller.BackendType(), PollBackend::kWsaPoll);
#elif defined(__linux__)
  EXPECT_EQ(poller.BackendType(), PollBackend::kEpoll);
#elif defined(__APPLE__)
  EXPECT_EQ(poller.BackendType(), PollBackend::kKqueue);
#else
  EXPECT_EQ(poller.BackendType(), PollBackend::kSelect);
#endif
}

TEST_F(SocketPollerTest, ConstructorCustomConfig) {
  const SocketPollerConfig cfg{128};
  const SocketPoller poller(cfg);
#if defined(_WIN32) || defined(_WIN64)
  EXPECT_EQ(poller.BackendType(), PollBackend::kWsaPoll);
#elif defined(__linux__)
  EXPECT_EQ(poller.BackendType(), PollBackend::kEpoll);
#elif defined(__APPLE__)
  EXPECT_EQ(poller.BackendType(), PollBackend::kKqueue);
#else
  EXPECT_EQ(poller.BackendType(), PollBackend::kSelect);
#endif
}

TEST_F(SocketPollerTest, AddRemoveSocket) {
  SocketPoller poller;
  auto socket = CreateUdpSocket();
  ASSERT_TRUE(socket != nullptr);

  // Bind the socket first
  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  EXPECT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  // Add socket
  const bool add_result = poller.AddSocket(socket.get(), false);
  EXPECT_TRUE(add_result);

  // Try to add again (should succeed, as it's idempotent)
  EXPECT_TRUE(poller.AddSocket(socket.get(), false));

  // Remove socket
  poller.RemoveSocket(socket.get());

  // Remove again (should not crash)
  poller.RemoveSocket(socket.get());
}

TEST_F(SocketPollerTest, AddNullSocket) {
  SocketPoller poller;
  EXPECT_FALSE(poller.AddSocket(nullptr, false));
}

TEST_F(SocketPollerTest, PollEmptyPoller) {
  SocketPoller poller;
  auto events = poller.Poll(0);  // Non-blocking
  EXPECT_TRUE(events.empty());
}

TEST_F(SocketPollerTest, PollIntoUsesCallerStorage) {
  SocketPoller poller;
  std::vector<SocketEvent> events;
  events.reserve(8);

  poller.PollInto(events, 0);

  EXPECT_TRUE(events.empty());
  EXPECT_GE(events.capacity(), 8U);
}

TEST_F(SocketPollerTest, PollWithTimeout) {
  SocketPoller poller;
  auto socket = CreateUdpSocket();
  ASSERT_TRUE(socket != nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  EXPECT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  poller.AddSocket(socket.get(), false);

  // Poll with timeout (should return empty if no events)
  auto events = poller.Poll(10);  // 10ms timeout
  EXPECT_TRUE(events.empty());
}

TEST_F(SocketPollerTest, PollInfiniteTimeout) {
  SocketPoller poller;
  auto socket = CreateUdpSocket();
  ASSERT_TRUE(socket != nullptr);
  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  EXPECT_EQ(socket->Bind(addr, 0), SocketError::kNone);
  poller.AddSocket(socket.get(), false);

  // For testing, we can't really test infinite timeout without hanging.
  // Instead, test that poll with large timeout works (but interrupt it)
  // For now, skip this test or use a reasonable timeout
  auto events = poller.Poll(100);  // 100ms instead of infinite
  EXPECT_TRUE(events.empty());
}

TEST_F(SocketPollerTest, CallerReceivesManyPacketsAfterReadiness) {
  auto sender_socket = CreateUdpSocket();
  auto receiver_socket = CreateUdpSocket();
  ASSERT_TRUE(sender_socket != nullptr);
  ASSERT_TRUE(receiver_socket != nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(receiver_socket->Bind(addr, 0), SocketError::kNone);
  ASSERT_EQ(sender_socket->Bind(addr, 0), SocketError::kNone);

  const std::uint16_t receiver_port = receiver_socket->LocalPort();
  const std::uint16_t sender_port = sender_socket->LocalPort();

  SocketPoller poller;
  ASSERT_TRUE(poller.AddSocket(receiver_socket.get(), false));

  constexpr std::array<const char*, 3> messages = {"one", "two", "three"};
  for (const char* message : messages) {
    const SocketResult result =
      sender_socket->SendTo(message, std::strlen(message), addr, receiver_port);
    ASSERT_TRUE(result.Succeeded());
  }

  std::array<std::array<std::uint8_t, 64>, 4> storage{};
  std::array<IncomingDatagram, 4> datagrams{};
  for (std::size_t i = 0; i < datagrams.size(); ++i) {
    datagrams.at(i).data = storage.at(i).data();
    datagrams.at(i).capacity = storage.at(i).size();
  }

  std::size_t received = 0;
  std::vector<SocketEvent> events;
  const auto deadline =
    std::chrono::steady_clock::now() + std::chrono::milliseconds(500);

  while (received < messages.size() &&
         std::chrono::steady_clock::now() < deadline) {
    poller.PollInto(events, 100);
    for (const SocketEvent& event : events) {
      EXPECT_EQ(event.socket, receiver_socket.get());
      EXPECT_TRUE(event.readable);
      const std::size_t batch_received = event.socket->ReceiveMany(datagrams);
      for (std::size_t i = 0; i < batch_received; ++i) {
        EXPECT_EQ(datagrams.at(i).fromPort, sender_port);
        EXPECT_GT(datagrams.at(i).result.bytes, 0);
      }
      received += batch_received;
    }
  }

  EXPECT_EQ(received, messages.size());
}

TEST_F(SocketPollerTest, BackendType) {
  const SocketPoller poller;
  auto backend = poller.BackendType();
#if defined(_WIN32) || defined(_WIN64)
  EXPECT_EQ(backend, PollBackend::kWsaPoll);
#elif defined(__linux__)
  EXPECT_EQ(backend, PollBackend::kEpoll);
#elif defined(__APPLE__)
  EXPECT_EQ(backend, PollBackend::kKqueue);
#else
  EXPECT_EQ(backend, PollBackend::kSelect);
#endif
}

// Integration test: Send and receive with poller
TEST_F(SocketPollerTest, IntegrationSendReceive) {
  auto sender_socket = CreateUdpSocket();
  auto receiver_socket = CreateUdpSocket();
  ASSERT_TRUE(sender_socket != nullptr);
  ASSERT_TRUE(receiver_socket != nullptr);

  // Bind receiver to a port
  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  EXPECT_EQ(receiver_socket->Bind(addr, 0),
            SocketError::kNone);  // Bind to any available port
  const uint16_t receiver_port = receiver_socket->LocalPort();

  // Bind sender (optional for UDP)
  EXPECT_EQ(sender_socket->Bind(addr, 0), SocketError::kNone);
  const uint16_t sender_port = sender_socket->LocalPort();

  SocketPoller poller;
  poller.AddSocket(receiver_socket.get(), false);

  // Send data from sender to receiver
  const char* test_data = "Hello, SocketPoller!";
  const std::size_t data_size = strlen(test_data) + 1;
  const SocketResult send_result =
    sender_socket->SendTo(test_data, data_size, addr, receiver_port);
  ASSERT_TRUE(send_result.Succeeded());

  // Poll for events
  auto events = poller.Poll(100);  // 100ms timeout
  ASSERT_FALSE(events.empty());
  EXPECT_TRUE(events.at(0).readable);
  EXPECT_EQ(events.at(0).socket, receiver_socket.get());

  std::array<char, 128> buffer{};
  SocketAddress from;
  std::uint16_t from_port = 0;
  const SocketResult receive_result =
    receiver_socket->Receive(buffer.data(), buffer.size(), from, from_port);
  ASSERT_TRUE(receive_result.Succeeded());
  EXPECT_EQ(from_port, sender_port);
  EXPECT_EQ(receive_result.bytes, static_cast<std::ptrdiff_t>(data_size));
  EXPECT_EQ(std::memcmp(buffer.data(), test_data, data_size), 0);
}
