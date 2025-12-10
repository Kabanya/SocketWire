/*
 Test suite for ISocket interface and implementations

 Migrated from legacy net_socket tests to use the new ISocket architecture
 with factory pattern and POSIX UDP socket implementation.
*/

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "i_socket.hpp"
#include "socket_init.hpp"
#include "socket_constants.hpp"

#include <cstring>
#include <thread>
#include <chrono>

using namespace socketwire; //NOLINT

// Forward declaration of registration function


namespace {

// Mock event handler for testing
class MockEventHandler : public ISocketEventHandler
{
public:
  MOCK_METHOD(void, onDataReceived,
              (const SocketAddress& from, std::uint16_t fromPort,
               const void* data, std::size_t bytesRead),
              (override));
  MOCK_METHOD(void, onSocketError, (SocketError error), (override));
};

class NetSocketTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // Initialize platform-specific socket factory
    bool result = initialize_sockets();
    ASSERT_TRUE(result) << "Socket initialization should succeed";

    // Get factory instance
    factory = SocketFactoryRegistry::getFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be registered";
  }

  void TearDown() override
  {
    // Cleanup
    shutdown_sockets();
  }

  ISocketFactory* factory = nullptr;
};

TEST_F(NetSocketTest, CreateSocket)
{
  // Test creating and binding socket
  SocketConfig config;
  auto sock = factory->createUDPSocket(config);
  ASSERT_NE(sock, nullptr) << "Socket creation should succeed";

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
  SocketError bindResult = sock->bind(addr, 0);  // Bind to any available port
  EXPECT_EQ(bindResult, SocketError::None) << "Socket bind should succeed";

  // Verify port was assigned
  int port = sock->localPort();
  EXPECT_NE(port, 0) << "Socket should be assigned a non-zero port";
  EXPECT_GT(port, 0) << "Port number should be positive";
  EXPECT_LE(port, 65535) << "Port number should be within valid range (1-65535)";

  // Test creating multiple sockets
  auto sock2 = factory->createUDPSocket(config);
  ASSERT_NE(sock2, nullptr);
  EXPECT_EQ(sock2->bind(addr, 0), SocketError::None) << "Second socket bind should succeed";

  int port2 = sock2->localPort();
  EXPECT_NE(port2, 0) << "Second socket should have a valid port";
  EXPECT_NE(port, port2) << "Two sockets should have different ports";

  // Test binding to specific port (OS-assigned)
  auto sock3 = factory->createUDPSocket(config);
  ASSERT_NE(sock3, nullptr);
  SocketError specificResult = sock3->bind(addr, 0);
  EXPECT_EQ(specificResult, SocketError::None) << "Binding to available port should succeed";
  EXPECT_GT(sock3->localPort(), 0) << "Socket should have valid port after binding";
}

TEST_F(NetSocketTest, GetLocalIPs)
{
  // Note: This functionality would need to be added to ISocket interface
  // For now, we'll test that we can create sockets on loopback
  SocketConfig config;
  auto sock = factory->createUDPSocket(config);
  ASSERT_NE(sock, nullptr);

  // Test binding to loopback
  SocketAddress loopback = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
  EXPECT_EQ(sock->bind(loopback, 0), SocketError::None)
    << "Should be able to bind to loopback interface";

  // Test binding to any interface
  auto sock2 = factory->createUDPSocket(config);
  ASSERT_NE(sock2, nullptr);
  SocketAddress any = SocketAddress::fromIPv4(0x00000000); // 0.0.0.0
  EXPECT_EQ(sock2->bind(any, 0), SocketError::None)
    << "Should be able to bind to any interface (0.0.0.0)";
}

TEST_F(NetSocketTest, IsPortInUse)
{
  SocketConfig config;

  // Bind to a port
  auto sock = factory->createUDPSocket(config);
  ASSERT_NE(sock, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(sock->bind(addr, 0), SocketError::None);

  int usedPort = sock->localPort();
  EXPECT_GT(usedPort, 0) << "Bound socket should have valid port";

  // Try to bind another socket to the same port (with SO_REUSEADDR it might succeed)
  // This tests that ports are properly managed
  auto sock2 = factory->createUDPSocket(config);
  ASSERT_NE(sock2, nullptr);

  // Binding to port 0 should give a different port
  EXPECT_EQ(sock2->bind(addr, 0), SocketError::None);
  int newPort = sock2->localPort();

  // With SO_REUSEADDR, we might get the same port, but typically we get different ones
  // The important thing is that bind succeeds
  EXPECT_GT(newPort, 0);
}

TEST_F(NetSocketTest, SendAndReceive)
{
  SocketConfig config;

  // Create sender socket
  auto sender = factory->createUDPSocket(config);
  ASSERT_NE(sender, nullptr) << "Sender socket creation should succeed";

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  EXPECT_EQ(sender->bind(addr, 0), SocketError::None)
    << "Sender should bind successfully";
  int senderPort = sender->localPort();
  EXPECT_GT(senderPort, 0) << "Sender should have valid port";

  // Create receiver socket
  auto receiver = factory->createUDPSocket(config);
  ASSERT_NE(receiver, nullptr) << "Receiver socket creation should succeed";
  EXPECT_EQ(receiver->bind(addr, 0), SocketError::None)
    << "Receiver should bind successfully";
  int receiverPort = receiver->localPort();
  EXPECT_GT(receiverPort, 0) << "Receiver should have valid port";

  // Ensure they have different ports
  EXPECT_NE(senderPort, receiverPort)
    << "Sender and receiver should have different ports";

  // Send message
  const char* message = "Hello";
  size_t messageLen = std::strlen(message);

  SocketResult sent = sender->sendTo(message, messageLen, addr, receiverPort);
  EXPECT_EQ(sent.error, SocketError::None)
    << "Should send successfully";
  EXPECT_EQ(sent.bytes, static_cast<std::ptrdiff_t>(messageLen))
    << "Should send all " << messageLen << " bytes";
  EXPECT_GT(sent.bytes, 0) << "Send should return positive byte count";

  // Small delay to ensure packet arrives
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Receive message
  char buffer[1024];
  SocketAddress fromAddr;
  std::uint16_t fromPort;

  SocketResult received = receiver->receive(buffer, sizeof(buffer), fromAddr, fromPort);

  EXPECT_EQ(received.error, SocketError::None) << "Receive should succeed";
  EXPECT_EQ(received.bytes, static_cast<std::ptrdiff_t>(messageLen))
    << "Should receive " << messageLen << " bytes";
  EXPECT_EQ(std::string(buffer, received.bytes), std::string(message))
    << "Received data should match sent data";
  EXPECT_EQ(fromPort, senderPort) << "Should know sender's port";
}

TEST_F(NetSocketTest, SendAndReceiveWithMock)
{
  SocketConfig config;

  // Create sender socket
  auto sender = factory->createUDPSocket(config);
  ASSERT_NE(sender, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  EXPECT_EQ(sender->bind(addr, 0), SocketError::None)
    << "Sender should bind successfully";
  int senderPort = sender->localPort();
  EXPECT_GT(senderPort, 0) << "Sender port should be valid";

  // Create receiver socket
  auto receiver = factory->createUDPSocket(config);
  ASSERT_NE(receiver, nullptr);
  EXPECT_EQ(receiver->bind(addr, 0), SocketError::None)
    << "Receiver should bind successfully";
  int receiverPort = receiver->localPort();
  EXPECT_GT(receiverPort, 0) << "Receiver port should be valid";

  // Setup mock event handler
  MockEventHandler mockHandler;

  // Send test message
  const char* message = "Hello";
  size_t messageLen = std::strlen(message);

  SocketResult sent = sender->sendTo(message, messageLen, addr, receiverPort);
  EXPECT_EQ(sent.error, SocketError::None)
    << "Should send exactly " << messageLen << " bytes";
  EXPECT_EQ(sent.bytes, static_cast<std::ptrdiff_t>(messageLen));
  EXPECT_GT(sent.bytes, 0) << "Bytes sent should be positive";

  // Small delay
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Setup expectation for mock - expect onDataReceived to be called
  EXPECT_CALL(mockHandler, onDataReceived(::testing::_, senderPort, ::testing::_, messageLen))
    .Times(1)
    .WillOnce(::testing::Invoke([message, messageLen](
        const SocketAddress& /*from*/, std::uint16_t /*port*/,
        const void* data, std::size_t bytesRead)
    {
      // Verify received data matches sent data
      EXPECT_EQ(bytesRead, messageLen)
        << "Received bytes should match sent size";
      EXPECT_GT(bytesRead, 0)
        << "Should receive positive number of bytes";
      EXPECT_EQ(std::memcmp(data, message, messageLen), 0)
        << "Received data should match sent message";
    }));

  // Poll to receive the data
  receiver->poll(&mockHandler);

  // Verify mock was called as expected
  ::testing::Mock::VerifyAndClearExpectations(&mockHandler);
}

TEST_F(NetSocketTest, NonBlockingBehavior)
{
  SocketConfig config;
  config.nonBlocking = true;

  auto sock = factory->createUDPSocket(config);
  ASSERT_NE(sock, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(sock->bind(addr, 0), SocketError::None);

  // Verify non-blocking mode
  EXPECT_FALSE(sock->isBlocking()) << "Socket should be in non-blocking mode";

  // Try to receive without data - should return WouldBlock
  char buffer[1024];
  SocketAddress fromAddr;
  std::uint16_t fromPort;

  SocketResult result = sock->receive(buffer, sizeof(buffer), fromAddr, fromPort);
  EXPECT_EQ(result.error, SocketError::WouldBlock)
    << "Non-blocking receive with no data should return WouldBlock";
}

TEST_F(NetSocketTest, SocketType)
{
  SocketConfig config;

  auto udpSocket = factory->createSocket(SocketType::UDP, config);
  ASSERT_NE(udpSocket, nullptr);

  EXPECT_EQ(udpSocket->type(), SocketType::UDP)
    << "Socket type should be UDP";
}

TEST_F(NetSocketTest, MultipleMessagesSequential)
{
  SocketConfig config;

  auto sender = factory->createUDPSocket(config);
  auto receiver = factory->createUDPSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  ASSERT_EQ(receiver->bind(addr, 0), SocketError::None);
  int receiverPort = receiver->localPort();

  // Send and receive multiple messages
  const int numMessages = 5;
  for (int i = 0; i < numMessages; ++i)
  {
    std::string message = "Message " + std::to_string(i);

    // Send
    SocketResult sendResult = sender->sendTo(message.c_str(), message.length(), 
                                              addr, receiverPort);
    EXPECT_EQ(sendResult.error, SocketError::None);
    EXPECT_EQ(sendResult.bytes, static_cast<std::ptrdiff_t>(message.length()));

    // Small delay
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    // Receive
    char buffer[1024];
    SocketAddress fromAddr;
    std::uint16_t fromPort;

    SocketResult recvResult = receiver->receive(buffer, sizeof(buffer),
                                                 fromAddr, fromPort);
    EXPECT_EQ(recvResult.error, SocketError::None);
    EXPECT_EQ(recvResult.bytes, static_cast<std::ptrdiff_t>(message.length()));

    std::string received(buffer, recvResult.bytes);
    EXPECT_EQ(received, message) << "Message " << i << " should match";
  }
}

TEST_F(NetSocketTest, SendAndReceiveIPv6Loopback)
{
  SocketConfig config;
  config.enableIPv6 = true;

  auto sender = factory->createUDPSocket(config);
  auto receiver = factory->createUDPSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress v6Loop = SocketConstants::loopbackIPv6();

  ASSERT_EQ(receiver->bind(v6Loop, 0), SocketError::None);
  std::uint16_t receiverPort = receiver->localPort();
  ASSERT_GT(receiverPort, 0);

  ASSERT_EQ(sender->bind(v6Loop, 0), SocketError::None);
  std::uint16_t senderPort = sender->localPort();

  const char* msg = "HiIPv6";
  std::size_t msgLen = std::strlen(msg);

  SocketResult sent = sender->sendTo(msg, msgLen, v6Loop, receiverPort);
  EXPECT_TRUE(sent.succeeded());

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  char buffer[64];
  SocketAddress fromAddr;
  std::uint16_t fromPort = 0;

  SocketResult received = receiver->receive(buffer, sizeof(buffer), fromAddr, fromPort);
  EXPECT_TRUE(received.succeeded());
  EXPECT_EQ(received.bytes, static_cast<std::ptrdiff_t>(msgLen));
  EXPECT_EQ(std::string(buffer, received.bytes), std::string(msg));
  EXPECT_EQ(fromPort, senderPort);
  EXPECT_TRUE(fromAddr.isIPv6);
}

TEST_F(NetSocketTest, DualStackIPv4ToIPv6Mapped)
{
  SocketConfig recvCfg;
  recvCfg.enableIPv6 = true; // allow dual-stack
  auto receiver = factory->createUDPSocket(recvCfg);
  ASSERT_NE(receiver, nullptr);

  SocketAddress any6 = SocketConstants::anyIPv6();
  ASSERT_EQ(receiver->bind(any6, 0), SocketError::None);
  std::uint16_t receiverPort = receiver->localPort();

  SocketConfig sendCfg; // IPv4-only is fine
  auto sender = factory->createUDPSocket(sendCfg);
  ASSERT_NE(sender, nullptr);
  ASSERT_EQ(sender->bind(SocketConstants::loopback(), 0), SocketError::None);
  std::uint16_t senderPort = sender->localPort();

  const char* payload = "dual";
  std::size_t payloadLen = std::strlen(payload);

  SocketResult sent = sender->sendTo(payload, payloadLen, SocketConstants::loopback(), receiverPort);
  EXPECT_TRUE(sent.succeeded());

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  char buffer[64];
  SocketAddress fromAddr;
  std::uint16_t fromPort = 0;
  SocketResult recv = receiver->receive(buffer, sizeof(buffer), fromAddr, fromPort);
  EXPECT_TRUE(recv.succeeded());
  EXPECT_EQ(recv.bytes, static_cast<std::ptrdiff_t>(payloadLen));
  EXPECT_FALSE(fromAddr.isIPv6); // mapped IPv4 returned as IPv4
  EXPECT_EQ(fromAddr.ipv4.hostOrderAddress, SocketConstants::IPV4_LOOPBACK);
  EXPECT_EQ(fromPort, senderPort);
}

TEST(NetSocketStandalone, ParseAndFormatIPv6)
{
  std::array<std::uint8_t, 16> bytes{};
  std::uint32_t scopeId = 0;
  ASSERT_TRUE(SocketConstants::parseIPv6("::1", bytes, scopeId));
  EXPECT_EQ(scopeId, 0u);

  char buf[64];
  ASSERT_TRUE(SocketConstants::formatIPv6(bytes, scopeId, buf, sizeof(buf)));
  EXPECT_STREQ(buf, "::1");

  SocketAddress addr = SocketConstants::fromString("::1");
  EXPECT_TRUE(addr.isIPv6);
  EXPECT_EQ(addr.ipv6.bytes[15], 1);
}
} // anonymous namespace
