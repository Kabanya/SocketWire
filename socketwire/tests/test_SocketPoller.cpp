/*
  Test suite for SocketPoller implementation
  This file contains comprehensive unit tests for the SocketPoller class,
  which provides cross-platform I/O multiplexing for sockets.

  Test Categories:
  - Constructor and Configuration Tests: Poller creation and backend selection
  - Add/Remove Socket Tests: Managing sockets in the poller
  - Poll Tests: Event polling with different timeouts
  - Dispatch Tests: Event dispatching to handlers
  - Backend Tests: Verification of backend types

  Note: These tests use Google Test and Google Mock frameworks.
*/

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "socket_poller.hpp"
#include "i_socket.hpp"

#include <cstring>
#include <memory>

using namespace socketwire; //NOLINT

// Mock event handler for testing
class MockSocketEventHandler : public ISocketEventHandler
{
public:
  MOCK_METHOD(void, onDataReceived,
              (const SocketAddress& from, std::uint16_t fromPort,
               const void* data, std::size_t bytesRead),
              (override));
  MOCK_METHOD(void, onSocketError, (SocketError error), (override));
  MOCK_METHOD(void, onSocketClosed, (), (override));
};

// Forward declaration of registration function
namespace socketwire {
  void register_posix_socket_factory();
}

class SocketPollerTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    register_posix_socket_factory();
    factory = SocketFactoryRegistry::getFactory();
    ASSERT_NE(factory, nullptr);
  }

  void TearDown() override
  {
    // Cleanup if needed
  }

  ISocketFactory* factory = nullptr;

  std::unique_ptr<ISocket> createUDPSocket()
  {
    SocketConfig config;
    return factory->createSocket(SocketType::UDP, config);
  }
};

TEST_F(SocketPollerTest, Constructor_DefaultConfig)
{
  SocketPoller poller;
  EXPECT_NE(poller.backendType(), PollBackend::Stub);
}

TEST_F(SocketPollerTest, Constructor_CustomConfig)
{
  SocketPollerConfig cfg{128};
  SocketPoller poller(cfg);
  EXPECT_NE(poller.backendType(), PollBackend::Stub);
}

TEST_F(SocketPollerTest, AddRemoveSocket)
{
  SocketPoller poller;
  auto socket = createUDPSocket();
  ASSERT_TRUE(socket != nullptr);

  // Bind the socket first
  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
  EXPECT_EQ(socket->bind(addr, 0), SocketError::None);

  // Add socket
  EXPECT_TRUE(poller.addSocket(socket.get(), false));

  // Try to add again (should succeed, as it's idempotent)
  EXPECT_TRUE(poller.addSocket(socket.get(), false));

  // Remove socket
  poller.removeSocket(socket.get());

  // Remove again (should not crash)
  poller.removeSocket(socket.get());
}

TEST_F(SocketPollerTest, AddNullSocket)
{
  SocketPoller poller;
  EXPECT_FALSE(poller.addSocket(nullptr, false));
}

TEST_F(SocketPollerTest, Poll_EmptyPoller)
{
  SocketPoller poller;
  auto events = poller.poll(0); // Non-blocking
  EXPECT_TRUE(events.empty());
}

TEST_F(SocketPollerTest, Poll_WithTimeout)
{
  SocketPoller poller;
  auto socket = createUDPSocket();
  ASSERT_TRUE(socket != nullptr);
  poller.addSocket(socket.get(), false);

  // Poll with timeout (should return empty if no events)
  auto events = poller.poll(10); // 10ms timeout
  EXPECT_TRUE(events.empty());
}

TEST_F(SocketPollerTest, Poll_InfiniteTimeout)
{
  SocketPoller poller;
  auto socket = createUDPSocket();
  ASSERT_TRUE(socket != nullptr);
  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  EXPECT_EQ(socket->bind(addr, 0), SocketError::None);
  poller.addSocket(socket.get(), false);

  // For testing, we can't really test infinite timeout without hanging.
  // Instead, test that poll with large timeout works (but interrupt it)
  // For now, skip this test or use a reasonable timeout
  auto events = poller.poll(100); // 100ms instead of infinite
  EXPECT_TRUE(events.empty());
}

TEST_F(SocketPollerTest, DispatchReadable_NoHandler)
{
  SocketPoller poller;
  SocketEvent ev;
  ev.readable = true;
  poller.dispatchReadable(ev, nullptr); // Should not crash
}

TEST_F(SocketPollerTest, DispatchReadable_NoEvent)
{
  SocketPoller poller;
  MockSocketEventHandler handler;
  SocketEvent ev;
  ev.readable = false;
  poller.dispatchReadable(ev, &handler); // Should not call anything
}

TEST_F(SocketPollerTest, DispatchAll_EmptyEvents)
{
  SocketPoller poller;
  MockSocketEventHandler handler;
  std::vector<SocketEvent> events;
  poller.dispatchAll(events, &handler); // Should not crash
}

TEST_F(SocketPollerTest, BackendType)
{
  SocketPoller poller;
  auto backend = poller.backendType();
#if defined(__linux__)
  EXPECT_EQ(backend, PollBackend::Epoll);
#elif defined(__APPLE__)
  EXPECT_EQ(backend, PollBackend::Kqueue);
#else
  EXPECT_EQ(backend, PollBackend::Select);
#endif
}

// Integration test: Send and receive with poller
TEST_F(SocketPollerTest, Integration_SendReceive)
{
  auto senderSocket = createUDPSocket();
  auto receiverSocket = createUDPSocket();
  ASSERT_TRUE(senderSocket != nullptr);
  ASSERT_TRUE(receiverSocket != nullptr);

  // Bind receiver to a port
  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
  EXPECT_EQ(receiverSocket->bind(addr, 0), SocketError::None); // Bind to any available port
  uint16_t receiverPort = receiverSocket->localPort();

  // Bind sender (optional for UDP)
  EXPECT_EQ(senderSocket->bind(addr, 0), SocketError::None);
  uint16_t senderPort = senderSocket->localPort();

  SocketPoller poller;
  poller.addSocket(receiverSocket.get(), false);

  // Send data from sender to receiver
  const char* testData = "Hello, SocketPoller!";
  size_t dataSize = strlen(testData) + 1;
  SocketResult sendResult = senderSocket->sendTo(testData, dataSize, addr, receiverPort);
  ASSERT_TRUE(sendResult.succeeded());

  // Poll for events
  auto events = poller.poll(100); // 100ms timeout
  ASSERT_FALSE(events.empty());
  EXPECT_TRUE(events[0].readable);
  EXPECT_EQ(events[0].socket, receiverSocket.get());

  // Dispatch to handler
  MockSocketEventHandler handler;
  EXPECT_CALL(handler, onDataReceived(testing::_, senderPort, testing::_, dataSize))
      .Times(1);

  poller.dispatchReadable(events[0], &handler);
}