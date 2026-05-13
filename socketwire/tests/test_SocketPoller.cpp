// Tests for SocketPoller construction, registration, polling, and dispatch.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstring>
#include <memory>

#include "i_socket.hpp"
#include "socket_init.hpp"
#include "socket_poller.hpp"

using namespace socketwire;  // NOLINT

class MockSocketEventHandler : public ISocketEventHandler {
 public:
  MOCK_METHOD(void, OnDataReceived,
              (const SocketAddress& from, std::uint16_t from_port,
               const void* data, std::size_t bytes_read),
              (override));
  MOCK_METHOD(void, OnSocketError, (SocketError error), (override));
  MOCK_METHOD(void, OnSocketClosed, (), (override));
};

class SocketPollerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const bool result = InitializeSockets();
    ASSERT_TRUE(result) << "Socket initialization should succeed";
    factory = SocketFactoryRegistry::GetFactory();
    ASSERT_NE(factory, nullptr);
  }

  void TearDown() override { ShutdownSockets(); }

  ISocketFactory* factory = nullptr;

  std::unique_ptr<ISocket> CreateUdpSocket() {
    const SocketConfig config;
    return factory->CreateSocket(SocketType::kUdp, config);
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

TEST_F(SocketPollerTest, DispatchReadableNoHandler) {
  SocketPoller poller;
  SocketEvent ev;
  ev.readable = true;
  poller.DispatchReadable(ev, nullptr);  // Should not crash
}

TEST_F(SocketPollerTest, DispatchReadableNoEvent) {
  SocketPoller poller;
  MockSocketEventHandler handler;
  SocketEvent ev;
  ev.readable = false;
  poller.DispatchReadable(ev, &handler);  // Should not call anything
}

TEST_F(SocketPollerTest, DispatchAllEmptyEvents) {
  SocketPoller poller;
  MockSocketEventHandler handler;
  const std::vector<SocketEvent> events;
  poller.DispatchAll(events, &handler);  // Should not crash
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

  // Dispatch to handler
  MockSocketEventHandler handler;
  EXPECT_CALL(handler,
              OnDataReceived(testing::_, sender_port, testing::_, data_size))
      .Times(1);

  poller.DispatchReadable(events.at(0), &handler);
}
