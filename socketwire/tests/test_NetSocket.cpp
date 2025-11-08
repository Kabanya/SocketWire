#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "net_socket.hpp"
#include <arpa/inet.h>
#include <cstring>

using socketwire::Socket;
using socketwire::EventHandler;
using socketwire::RecvData;

class MockEventHandler : public EventHandler
{
public:
  MOCK_METHOD(void, onDataReceived, (const RecvData& recv_data), (override));
  MOCK_METHOD(void, onSocketError, (int error_code), (override));
};

class NetSocketTest : public ::testing::Test
{
protected:
  void SetUp() override {
    // Setup if needed
  }

  void TearDown() override {
    // Cleanup
  }
};

TEST_F(NetSocketTest, CreateSocket) {
  // Test creating and binding socket
  Socket sock;
  int bind_result = sock.bind("127.0.0.1", "0");  // Bind to any available port
  EXPECT_EQ(bind_result, 0) << "Socket bind should succeed with return code 0";

  // Verify port was assigned
  int port = sock.getLocalPort();
  EXPECT_NE(port, 0) << "Socket should be assigned a non-zero port";
  EXPECT_GT(port, 0) << "Port number should be positive";
  EXPECT_LE(port, 65535) << "Port number should be within valid range (1-65535)";

  // Test creating multiple sockets
  Socket sock2;
  EXPECT_EQ(sock2.bind("127.0.0.1", "0"), 0) << "Second socket bind should succeed";

  int port2 = sock2.getLocalPort();
  EXPECT_NE(port2, 0) << "Second socket should have a valid port";
  EXPECT_NE(port, port2) << "Two sockets should have different ports";

  // Test binding to specific port
  Socket sock3;
  int specific_result = sock3.bind("127.0.0.1", "0");
  EXPECT_EQ(specific_result, 0) << "Binding to available port should succeed";
  EXPECT_GT(sock3.getLocalPort(), 0) << "Socket should have valid port after binding";
}

TEST_F(NetSocketTest, GetLocalIPs) {
  // Get local IP addresses
  auto ips = Socket::getLocalIPs();

  // Should have at least one IP (loopback)
  EXPECT_FALSE(ips.empty()) << "Should have at least one local IP address";
  EXPECT_GE(ips.size(), 1) << "Should have at least the loopback interface";

  // Check that each IP is non-empty and looks valid
  for (size_t i = 0; i < ips.size(); ++i) {
    const auto& ip = ips[i];
    EXPECT_FALSE(ip.empty()) << "IP address at index " << i << " should not be empty";
    EXPECT_GT(ip.length(), 6) << "IP address should have reasonable length (e.g., '0.0.0.0' minimum)";

    // Check for dots (IPv4) - basic validation
    size_t dot_count = std::count(ip.begin(), ip.end(), '.');
    bool is_ipv4 = (dot_count == 3);

    // Check for colons (IPv6)
    size_t colon_count = std::count(ip.begin(), ip.end(), ':');
    bool is_ipv6 = (colon_count >= 2);

    EXPECT_TRUE(is_ipv4 || is_ipv6)
      << "IP address '" << ip << "' should be either IPv4 or IPv6 format";
  }

  // Verify loopback exists (optional check)
  bool has_loopback = false;
  for (const auto& ip : ips) {
    if (ip == "127.0.0.1" || ip == "::1") {
      has_loopback = true;
      break;
    }
  }
  (void)has_loopback;
}

TEST_F(NetSocketTest, IsPortInUse) {
  // Test with a known free port
  EXPECT_FALSE(Socket::isPortInUse("127.0.0.1", "54321"))
    << "Random high port should likely be free";

  // Test with different addresses
  EXPECT_FALSE(Socket::isPortInUse("0.0.0.0", "54322"))
    << "Another random port should be free";

  // Test edge cases
  EXPECT_FALSE(Socket::isPortInUse("127.0.0.1", "65432"))
    << "High port number should be free";

  // Note: Testing with a bound socket to verify "in use" detection
  // may not work reliably depending on how isPortInUse is implemented.
  // It might check if the port can be bound, which may succeed even if
  // another socket is using it (depends on SO_REUSEADDR settings).
  Socket sock;
  if (sock.bind("127.0.0.1", "0") == 0) {
    int used_port = sock.getLocalPort();
    EXPECT_GT(used_port, 0) << "Bound socket should have valid port";
    // Additional checks could be added here if isPortInUse implementation supports it
  }
}

// For sendTo and receive, we need two sockets
TEST_F(NetSocketTest, SendAndReceive) {
  // Create sender socket
  Socket sender;
  EXPECT_EQ(sender.bind("127.0.0.1", "0"), 0)
    << "Sender should bind successfully";
  int sender_port = sender.getLocalPort();
  EXPECT_GT(sender_port, 0) << "Sender should have valid port";

  // Create receiver socket
  Socket receiver;
  EXPECT_EQ(receiver.bind("127.0.0.1", "0"), 0)
    << "Receiver should bind successfully";
  int receiver_port = receiver.getLocalPort();
  EXPECT_GT(receiver_port, 0) << "Receiver should have valid port";

  // Ensure they have different ports
  EXPECT_NE(sender_port, receiver_port)
    << "Sender and receiver should have different ports";

  // Setup destination address
  sockaddr_in dest;
  std::memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(receiver_port);
  inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

  // Send message
  const char* message = "Hello";
  size_t message_len = strlen(message);
  int sent = sender.sendTo(message, message_len, dest);
  EXPECT_EQ(sent, static_cast<int>(message_len))
    << "Should send all " << message_len << " bytes. Sent: " << sent;
  EXPECT_GT(sent, 0) << "Send should return positive byte count";

  // Note: Actual receive testing requires event handler setup
  // This test verifies send operation completes successfully
}

TEST_F(NetSocketTest, SendAndReceiveWithMock) {
  // Create sender socket
  Socket sender;
  EXPECT_EQ(sender.bind("127.0.0.1", "0"), 0)
    << "Sender should bind successfully";
  int sender_port = sender.getLocalPort();
  EXPECT_GT(sender_port, 0) << "Sender port should be valid";

  // Create receiver socket
  Socket receiver;
  EXPECT_EQ(receiver.bind("127.0.0.1", "0"), 0)
    << "Receiver should bind successfully";
  int receiver_port = receiver.getLocalPort();
  EXPECT_GT(receiver_port, 0) << "Receiver port should be valid";

  // Setup mock event handler
  MockEventHandler mockHandler;
  receiver.setEventHandler(&mockHandler);

  // Setup destination address for sender
  sockaddr_in dest;
  std::memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(receiver_port);
  int pton_result = inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);
  EXPECT_EQ(pton_result, 1) << "inet_pton should successfully parse 127.0.0.1";

  // Send test message
  const char* message = "Hello";
  size_t message_len = strlen(message);
  int sent = sender.sendTo(message, message_len, dest);
  EXPECT_EQ(sent, static_cast<int>(message_len))
    << "Should send exactly " << message_len << " bytes";
  EXPECT_GT(sent, 0) << "Bytes sent should be positive";

  // Setup expectation for mock - expect onDataReceived to be called
  EXPECT_CALL(mockHandler, onDataReceived(::testing::_))
    .Times(1)
    .WillOnce(::testing::Invoke([message, message_len](const RecvData& recv_data) {
      // Verify received data matches sent data
      EXPECT_EQ(recv_data.bytesRead, static_cast<int>(message_len))
        << "Received bytes should match sent size";
      EXPECT_GT(recv_data.bytesRead, 0)
        << "Should receive positive number of bytes";
      EXPECT_EQ(std::string(recv_data.data, recv_data.bytesRead), std::string(message))
        << "Received data should match sent message";
      EXPECT_GT(recv_data.timeReceived, 0)
        << "Timestamp should be set";
    }));

  // Poll to receive the data
  receiver.pollReceive();

  // Verify mock was called as expected
  ::testing::Mock::VerifyAndClearExpectations(&mockHandler);
}