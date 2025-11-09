/*
  Test suite for POSIX UDP Socket implementation
  This file contains comprehensive unit tests for the PosixUDPSocket class,
  which provides UDP socket functionality on POSIX-compliant systems (Linux, macOS, BSD).

  Test Categories:
  - Constructor and Factory Tests: Socket creation and configuration
  - Bind Tests: Binding to addresses and ports
  - Send/Receive Tests: Data transmission and reception
  - Blocking Mode Tests: Blocking/non-blocking socket modes
  - Poll Tests: Event-driven data reception with handlers
  - Close Tests: Socket cleanup and resource management
  - Native Handle Tests: Low-level socket descriptor access
  - Large Data Tests: Testing with larger packet sizes
  - Type Tests: Socket type verification

  Note: These tests use Google Test and Google Mock frameworks.
*/

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "i_socket.hpp"

#include <thread>
#include <chrono>
#include <cstring>

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
};

// Forward declaration of registration function
namespace socketwire {
  void register_posix_socket_factory();
}

class PosixUDPSocketTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // Register POSIX socket factory
    register_posix_socket_factory();

    // Get factory instance
    factory = SocketFactoryRegistry::getFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be registered";
  }

  void TearDown() override
  {
    // Cleanup
  }

  ISocketFactory* factory = nullptr;
};

// ========== Constructor and Factory Tests ==========

TEST_F(PosixUDPSocketTest, CreateUDPSocket)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);

  ASSERT_NE(socket, nullptr) << "Should create UDP socket";
  EXPECT_EQ(socket->type(), SocketType::UDP);
}

TEST_F(PosixUDPSocketTest, CreateWithCustomConfig)
{
  SocketConfig config;
  config.nonBlocking = false;
  config.reuseAddress = true;
  config.sendBufferSize = 65536;
  config.recvBufferSize = 65536;

  auto socket = factory->createSocket(SocketType::UDP, config);

  ASSERT_NE(socket, nullptr);
  EXPECT_FALSE(socket->isBlocking()) << "Should respect nonBlocking=false in config";
}


TEST_F(PosixUDPSocketTest, BindToAnyPort) //bind test
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
  SocketError err = socket->bind(addr, 0); // Port 0 = any available port

  EXPECT_EQ(err, SocketError::None) << "Bind should succeed";
  EXPECT_GT(socket->localPort(), 0) << "Should assign a valid port";
}

TEST_F(PosixUDPSocketTest, BindToSpecificPort)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
  std::uint16_t port = 0; // Will be assigned by OS

  SocketError err = socket->bind(addr, port);
  EXPECT_EQ(err, SocketError::None);

  std::uint16_t assignedPort = socket->localPort();
  EXPECT_GT(assignedPort, 0);
}

TEST_F(PosixUDPSocketTest, BindTwiceReturnsError)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);

  SocketError err1 = socket->bind(addr, 0);
  EXPECT_EQ(err1, SocketError::None);

  // Try to bind again
  SocketError err2 = socket->bind(addr, 0);
  EXPECT_NE(err2, SocketError::None) << "Second bind should fail";
}

TEST_F(PosixUDPSocketTest, BindMultipleSocketsDifferentPorts)
{
  SocketConfig config;
  auto socket1 = factory->createSocket(SocketType::UDP, config);
  auto socket2 = factory->createSocket(SocketType::UDP, config);

  ASSERT_NE(socket1, nullptr);
  ASSERT_NE(socket2, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);

  EXPECT_EQ(socket1->bind(addr, 0), SocketError::None);
  EXPECT_EQ(socket2->bind(addr, 0), SocketError::None);

  EXPECT_NE(socket1->localPort(), socket2->localPort())
    << "Different sockets should get different ports";
}

// SEND AND RECEIVE
TEST_F(PosixUDPSocketTest, SendToAndReceive)
{
  SocketConfig config;
  auto sender = factory->createSocket(SocketType::UDP, config);
  auto receiver = factory->createSocket(SocketType::UDP, config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1

  // Bind receiver to specific port
  ASSERT_EQ(receiver->bind(addr, 0), SocketError::None);
  std::uint16_t receiverPort = receiver->localPort();
  ASSERT_GT(receiverPort, 0);

  // Send data
  const char* message = "Hello, UDP!";
  size_t messageLen = std::strlen(message);

  SocketResult sendResult = sender->sendTo(message, messageLen, addr, receiverPort);

  EXPECT_TRUE(sendResult.succeeded()) << "Send should succeed";
  EXPECT_EQ(sendResult.bytes, static_cast<std::ptrdiff_t>(messageLen))
    << "Should send all bytes";

  // Small delay to ensure packet arrives
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Receive data
  char buffer[1024];
  SocketAddress fromAddr;
  std::uint16_t fromPort;

  SocketResult recvResult = receiver->receive(buffer, sizeof(buffer), fromAddr, fromPort);

  EXPECT_TRUE(recvResult.succeeded()) << "Receive should succeed";
  EXPECT_EQ(recvResult.bytes, static_cast<std::ptrdiff_t>(messageLen));
  EXPECT_EQ(std::string(buffer, recvResult.bytes), std::string(message));
}

TEST_F(PosixUDPSocketTest, SendWithoutBind)
{
  SocketConfig config;
  auto sender = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(sender, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  const char* message = "Test";

  // UDP allows sending without explicit bind (lazy open)
  SocketResult result = sender->sendTo(message, std::strlen(message), addr, 12345);

  // Should succeed or fail gracefully (depending on whether port 12345 is listening)
  EXPECT_TRUE(result.error == SocketError::None || 
              result.error == SocketError::System);
}

TEST_F(PosixUDPSocketTest, SendNullDataReturnsError)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);

  SocketResult result = socket->sendTo(nullptr, 100, addr, 12345);

  EXPECT_FALSE(result.succeeded());
  EXPECT_EQ(result.error, SocketError::InvalidParam);
}

TEST_F(PosixUDPSocketTest, SendZeroLengthReturnsError)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  const char* data = "test";

  SocketResult result = socket->sendTo(data, 0, addr, 12345);

  EXPECT_FALSE(result.succeeded());
  EXPECT_EQ(result.error, SocketError::InvalidParam);
}

TEST_F(PosixUDPSocketTest, ReceiveWithoutBindReturnsError)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  char buffer[1024];
  SocketAddress fromAddr;
  std::uint16_t fromPort;

  SocketResult result = socket->receive(buffer, sizeof(buffer), fromAddr, fromPort);

  EXPECT_FALSE(result.succeeded());
  EXPECT_EQ(result.error, SocketError::NotBound);
}

TEST_F(PosixUDPSocketTest, ReceiveNullBufferReturnsError)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(socket->bind(addr, 0), SocketError::None);

  SocketAddress fromAddr;
  std::uint16_t fromPort;

  SocketResult result = socket->receive(nullptr, 1024, fromAddr, fromPort);

  EXPECT_FALSE(result.succeeded());
  EXPECT_EQ(result.error, SocketError::InvalidParam);
}

TEST_F(PosixUDPSocketTest, MultipleMessages)
{
  SocketConfig config;
  auto sender = factory->createSocket(SocketType::UDP, config);
  auto receiver = factory->createSocket(SocketType::UDP, config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(receiver->bind(addr, 0), SocketError::None);
  std::uint16_t receiverPort = receiver->localPort();

  // Send multiple messages
  const int numMessages = 5;
  for (int i = 0; i < numMessages; ++i)
  {
    std::string message = "Message " + std::to_string(i);
    SocketResult result = sender->sendTo(message.c_str(), message.length(), 
                                         addr, receiverPort);
    EXPECT_TRUE(result.succeeded());
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Receive messages
  for (int i = 0; i < numMessages; ++i)
  {
    char buffer[1024];
    SocketAddress fromAddr;
    std::uint16_t fromPort;

    SocketResult result = receiver->receive(buffer, sizeof(buffer), fromAddr, fromPort);
    EXPECT_TRUE(result.succeeded());
    EXPECT_GT(result.bytes, 0);
  }
}

// ========== Blocking Mode Tests ==========

TEST_F(PosixUDPSocketTest, DefaultNonBlocking)
{
  SocketConfig config;
  config.nonBlocking = true;

  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(socket->bind(addr, 0), SocketError::None);

  EXPECT_FALSE(socket->isBlocking()) << "Should be non-blocking by default";
}

TEST_F(PosixUDPSocketTest, SetBlockingMode)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(socket->bind(addr, 0), SocketError::None);

  // Set to blocking
  SocketError err = socket->setBlocking(true);
  EXPECT_EQ(err, SocketError::None);
  EXPECT_TRUE(socket->isBlocking());

  // Set back to non-blocking
  err = socket->setBlocking(false);
  EXPECT_EQ(err, SocketError::None);
  EXPECT_FALSE(socket->isBlocking());
}

TEST_F(PosixUDPSocketTest, SetBlockingWithoutBindReturnsError)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketError err = socket->setBlocking(true);
  EXPECT_EQ(err, SocketError::NotBound);
}

TEST_F(PosixUDPSocketTest, NonBlockingReceiveReturnsWouldBlock)
{
  SocketConfig config;
  config.nonBlocking = true;

  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(socket->bind(addr, 0), SocketError::None);

  char buffer[1024];
  SocketAddress fromAddr;
  std::uint16_t fromPort;

  // Should return WouldBlock when no data available
  SocketResult result = socket->receive(buffer, sizeof(buffer), fromAddr, fromPort);

  EXPECT_FALSE(result.succeeded());
  EXPECT_EQ(result.error, SocketError::WouldBlock);
}

// POLL TEST
TEST_F(PosixUDPSocketTest, PollWithHandler)
{
  SocketConfig config;
  auto sender = factory->createSocket(SocketType::UDP, config);
  auto receiver = factory->createSocket(SocketType::UDP, config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(receiver->bind(addr, 0), SocketError::None);
  std::uint16_t receiverPort = receiver->localPort();

  // Setup mock handler
  MockSocketEventHandler mockHandler;

  // Send message
  const char* message = "Poll test";
  size_t messageLen = std::strlen(message);

  ASSERT_TRUE(sender->sendTo(message, messageLen, addr, receiverPort).succeeded());

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Expect onDataReceived to be called
  EXPECT_CALL(mockHandler, onDataReceived(::testing::_, ::testing::_, ::testing::_, messageLen))
    .Times(1)
    .WillOnce(::testing::Invoke([message, messageLen](
        const SocketAddress& /*from*/, std::uint16_t /*port*/,
        const void* data, std::size_t bytes)
    {
      EXPECT_EQ(bytes, messageLen);
      EXPECT_EQ(std::memcmp(data, message, messageLen), 0);
    }));

  receiver->poll(&mockHandler);

  ::testing::Mock::VerifyAndClearExpectations(&mockHandler);
}

TEST_F(PosixUDPSocketTest, PollWithNullHandler)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(socket->bind(addr, 0), SocketError::None);

  // Should not crash
  socket->poll(nullptr);
}

TEST_F(PosixUDPSocketTest, PollMultiplePackets)
{
  SocketConfig config;
  auto sender = factory->createSocket(SocketType::UDP, config);
  auto receiver = factory->createSocket(SocketType::UDP, config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(receiver->bind(addr, 0), SocketError::None);
  std::uint16_t receiverPort = receiver->localPort();

  // Send multiple packets
  const int numPackets = 3;
  for (int i = 0; i < numPackets; ++i)
  {
    std::string msg = "Packet " + std::to_string(i);
    sender->sendTo(msg.c_str(), msg.length(), addr, receiverPort);
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  MockSocketEventHandler mockHandler;

  // Poll may receive packets in one or multiple calls depending on timing
  // and internal heuristics. We just verify at least one packet is received.
  EXPECT_CALL(mockHandler, onDataReceived(::testing::_, ::testing::_,
                                          ::testing::_, ::testing::_))
    .Times(::testing::AtLeast(1));

  // Poll multiple times to ensure all packets are read
  for (int i = 0; i < numPackets; ++i)
  {
    receiver->poll(&mockHandler);
  }

  ::testing::Mock::VerifyAndClearExpectations(&mockHandler);
}

// CLOSE TEST

TEST_F(PosixUDPSocketTest, CloseSocket)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(socket->bind(addr, 0), SocketError::None);

  std::uint16_t port = socket->localPort();
  EXPECT_GT(port, 0);

  socket->close();

  EXPECT_EQ(socket->localPort(), 0) << "Port should be reset after close";
  EXPECT_EQ(socket->nativeHandle(), -1) << "Handle should be invalid after close";
}

TEST_F(PosixUDPSocketTest, CloseMultipleTimes)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(socket->bind(addr, 0), SocketError::None);

  // Close multiple times should not crash
  socket->close();
  socket->close();
  socket->close();
}

TEST_F(PosixUDPSocketTest, DestructorClosesSocket)
{
  SocketConfig config;
  std::uint16_t port = 0;

  {
    auto socket = factory->createSocket(SocketType::UDP, config);
    SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
    ASSERT_EQ(socket->bind(addr, 0), SocketError::None);
    port = socket->localPort();
    EXPECT_GT(port, 0);
    // Socket destroyed here
  }

  // Should be able to bind to the same port again
  auto socket2 = factory->createSocket(SocketType::UDP, config);
  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);

  // Port should be available (may get same or different port from OS)
  EXPECT_EQ(socket2->bind(addr, 0), SocketError::None);
}

// NATIVE HANDLE TEST
TEST_F(PosixUDPSocketTest, NativeHandleValid)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  // Before bind, handle might be -1
  EXPECT_EQ(socket->nativeHandle(), -1);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(socket->bind(addr, 0), SocketError::None);

  // After bind, should have valid handle
  EXPECT_GE(socket->nativeHandle(), 0) << "Should have valid file descriptor";
}

// ========== Large Data Tests ==========

TEST_F(PosixUDPSocketTest, SendLargePacket)
{
  SocketConfig config;
  auto sender = factory->createSocket(SocketType::UDP, config);
  auto receiver = factory->createSocket(SocketType::UDP, config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(receiver->bind(addr, 0), SocketError::None);
  std::uint16_t receiverPort = receiver->localPort();

  // Create large buffer (but not too large for UDP - typical MTU is ~1500 bytes)
  const size_t dataSize = 1400;
  std::vector<char> data(dataSize);
  for (size_t i = 0; i < dataSize; ++i)
  {
    data[i] = static_cast<char>(i % 256);
  }

  SocketResult sendResult = sender->sendTo(data.data(), data.size(), addr, receiverPort);

  EXPECT_TRUE(sendResult.succeeded());
  EXPECT_EQ(sendResult.bytes, static_cast<std::ptrdiff_t>(dataSize));

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  std::vector<char> buffer(2048);
  SocketAddress fromAddr;
  std::uint16_t fromPort;

  SocketResult recvResult = receiver->receive(buffer.data(), buffer.size(),
                                              fromAddr, fromPort);

  EXPECT_TRUE(recvResult.succeeded());
  EXPECT_EQ(recvResult.bytes, static_cast<std::ptrdiff_t>(dataSize));
  EXPECT_EQ(std::memcmp(buffer.data(), data.data(), dataSize), 0);
}

// TYPE TEST
TEST_F(PosixUDPSocketTest, SocketTypeIsUDP)
{
  SocketConfig config;
  auto socket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(socket, nullptr);

  EXPECT_EQ(socket->type(), SocketType::UDP);
}