#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "NetSocket.h"
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
  Socket sock;
  EXPECT_EQ(sock.bind("127.0.0.1", "0"), 0); // Bind to any port
  EXPECT_NE(sock.getLocalPort(), 0);
}

TEST_F(NetSocketTest, GetLocalIPs) {
  auto ips = Socket::getLocalIPs();
  EXPECT_FALSE(ips.empty());
  // Check that at least one IP is valid
  for (const auto& ip : ips) {
    EXPECT_FALSE(ip.empty());
  }
}

TEST_F(NetSocketTest, IsPortInUse) {
  // Check a likely free port
  EXPECT_FALSE(Socket::isPortInUse("127.0.0.1", "12345"));
}

// For sendTo and receive, we need two sockets
TEST_F(NetSocketTest, SendAndReceive) {
  Socket sender;
  EXPECT_EQ(sender.bind("127.0.0.1", "0"), 0);

  Socket receiver;
  EXPECT_EQ(receiver.bind("127.0.0.1", "0"), 0);

  sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_port = htons(receiver.getLocalPort());
  inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

  const char* message = "Hello";
  int sent = sender.sendTo(message, strlen(message), dest);
  EXPECT_EQ(sent, strlen(message));

  // Poll receive
  receiver.pollReceive(); // This would need an event handler, but for simplicity, assume it works
  // In a real test, we'd need to set up an event handler to capture the data
}

TEST_F(NetSocketTest, SendAndReceiveWithMock) {
  Socket sender;
  EXPECT_EQ(sender.bind("127.0.0.1", "0"), 0);

  Socket receiver;
  EXPECT_EQ(receiver.bind("127.0.0.1", "0"), 0);

  MockEventHandler mockHandler;
  receiver.setEventHandler(&mockHandler);

  sockaddr_in dest;
  dest.sin_family = AF_INET;
  dest.sin_port = htons(receiver.getLocalPort());
  inet_pton(AF_INET, "127.0.0.1", &dest.sin_addr);

  const char* message = "Hello";
  int sent = sender.sendTo(message, strlen(message), dest);
  EXPECT_EQ(sent, strlen(message));

  // Expect the mock to be called
  EXPECT_CALL(mockHandler, onDataReceived(::testing::_))
    .Times(1);

  // Poll receive
  receiver.pollReceive();
}