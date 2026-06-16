// Tests for UDP socket creation, binding, I/O, polling, and cleanup.

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <thread>

#if !defined(_WIN32) && !defined(_WIN64)
#include <sys/socket.h>
#endif

#include "i_socket.hpp"
#include "socket_init.hpp"

using namespace socketwire;  // NOLINT

class UDPSocketTest : public ::testing::Test {
 protected:
  void SetUp() override {
    InitializeSockets();

    factory = SocketFactoryRegistry::GetFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be registered";
  }

  ISocketFactory* factory = nullptr;
};

// Constructor and factory tests.

TEST_F(UDPSocketTest, CreateUDPSocket) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);

  ASSERT_NE(socket, nullptr) << "Should create UDP socket";
}

TEST_F(UDPSocketTest, CreateWithCustomConfig) {
  SocketConfig config;
  config.nonBlocking = false;
  config.reuseAddress = true;
  config.sendBufferSize = 65536;
  config.recvBufferSize = 65536;

  auto socket = factory->CreateUdpSocket(config);

  ASSERT_NE(socket, nullptr);
  EXPECT_FALSE(socket->IsBlocking())
    << "Should respect nonBlocking=false in config";
}

TEST_F(UDPSocketTest, BindToAnyPort)  // bind test
{
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  const SocketError err = socket->Bind(addr, 0);  // Port 0 = any available port

  EXPECT_EQ(err, SocketError::kNone) << "Bind should succeed";
  EXPECT_GT(socket->LocalPort(), 0) << "Should assign a valid port";
}

TEST_F(UDPSocketTest, BindToSpecificPort) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  std::uint16_t port = 0;  // Will be assigned by OS

  const SocketError err = socket->Bind(addr, port);
  EXPECT_EQ(err, SocketError::kNone);

  std::uint16_t assigned_port = socket->LocalPort();
  EXPECT_GT(assigned_port, 0);
}

TEST_F(UDPSocketTest, BindTwiceReturnsError) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  const SocketError err1 = socket->Bind(addr, 0);
  EXPECT_EQ(err1, SocketError::kNone);

  // Try to bind again
  const SocketError err2 = socket->Bind(addr, 0);
  EXPECT_NE(err2, SocketError::kNone) << "Second bind should fail";
}

TEST_F(UDPSocketTest, BindMultipleSocketsDifferentPorts) {
  const SocketConfig config;
  auto socket1 = factory->CreateUdpSocket(config);
  auto socket2 = factory->CreateUdpSocket(config);

  ASSERT_NE(socket1, nullptr);
  ASSERT_NE(socket2, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  EXPECT_EQ(socket1->Bind(addr, 0), SocketError::kNone);
  EXPECT_EQ(socket2->Bind(addr, 0), SocketError::kNone);

  EXPECT_NE(socket1->LocalPort(), socket2->LocalPort())
    << "Different sockets should get different ports";
}

TEST_F(UDPSocketTest, ReusePortAllowsSamePortBind) {
  SocketConfig config;
  config.reuseAddress = true;
  config.reusePort = true;

  auto socket1 = factory->CreateUdpSocket(config);
  auto socket2 = factory->CreateUdpSocket(config);

  ASSERT_NE(socket1, nullptr);
  ASSERT_NE(socket2, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket1->Bind(addr, 0), SocketError::kNone);

  const SocketError second_bind = socket2->Bind(addr, socket1->LocalPort());
#if defined(SO_REUSEPORT)
  EXPECT_EQ(second_bind, SocketError::kNone);
#else
  EXPECT_EQ(second_bind, SocketError::kUnsupported);
#endif
}

// SEND AND RECEIVE
TEST_F(UDPSocketTest, SendAndReceive) {
  const SocketConfig config;
  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1

  // Bind receiver to specific port
  ASSERT_EQ(receiver->Bind(addr, 0), SocketError::kNone);
  std::uint16_t receiver_port = receiver->LocalPort();
  ASSERT_GT(receiver_port, 0);

  // Send data
  const char* message = "Hello, UDP!";
  const std::size_t message_len = std::strlen(message);

  const SocketResult send_result =
    sender->SendTo(message, message_len, addr, receiver_port);

  EXPECT_TRUE(send_result.Succeeded()) << "Send should succeed";
  EXPECT_EQ(send_result.bytes, static_cast<std::ptrdiff_t>(message_len))
    << "Should send all bytes";

  // Small delay to ensure packet arrives
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Receive data
  char buffer[1024];
  SocketAddress from_addr;
  std::uint16_t from_port = 0;

  const SocketResult recv_result =
    receiver->Receive(buffer, sizeof(buffer), from_addr, from_port);

  EXPECT_TRUE(recv_result.Succeeded()) << "Receive should succeed";
  EXPECT_EQ(recv_result.bytes, static_cast<std::ptrdiff_t>(message_len));
  EXPECT_EQ(std::string(buffer, static_cast<std::size_t>(recv_result.bytes)),
            std::string(message));
}

TEST_F(UDPSocketTest, SendWithoutBind) {
  const SocketConfig config;
  auto sender = factory->CreateUdpSocket(config);
  ASSERT_NE(sender, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  const char* message = "Test";

  // UDP allows sending without explicit bind (lazy open)
  const SocketResult result =
    sender->SendTo(message, std::strlen(message), addr, 12345);

  // Should succeed or fail gracefully (depending on whether port 12345 is
  // listening)
  EXPECT_TRUE(result.error == SocketError::kNone ||
              result.error == SocketError::kSystem);
}

TEST_F(UDPSocketTest, SendNullDataReturnsError) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  const SocketResult result = socket->SendTo(nullptr, 100, addr, 12345);

  EXPECT_FALSE(result.Succeeded());
  EXPECT_EQ(result.error, SocketError::kInvalidParam);
}

TEST_F(UDPSocketTest, SendZeroLengthReturnsError) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  const char* data = "test";

  const SocketResult result = socket->SendTo(data, 0, addr, 12345);

  EXPECT_FALSE(result.Succeeded());
  EXPECT_EQ(result.error, SocketError::kInvalidParam);
}

TEST_F(UDPSocketTest, ReceiveWithoutBindReturnsError) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  char buffer[1024];
  SocketAddress from_addr;
  std::uint16_t from_port = 0;

  const SocketResult result =
    socket->Receive(buffer, sizeof(buffer), from_addr, from_port);

  EXPECT_FALSE(result.Succeeded());
  EXPECT_EQ(result.error, SocketError::kNotBound);
}

TEST_F(UDPSocketTest, ReceiveNullBufferReturnsError) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  SocketAddress from_addr;
  std::uint16_t from_port = 0;

  const SocketResult result =
    socket->Receive(nullptr, 1024, from_addr, from_port);

  EXPECT_FALSE(result.Succeeded());
  EXPECT_EQ(result.error, SocketError::kInvalidParam);
}

TEST_F(UDPSocketTest, MultipleMessages) {
  const SocketConfig config;
  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(receiver->Bind(addr, 0), SocketError::kNone);
  std::uint16_t receiver_port = receiver->LocalPort();

  // Send multiple messages
  const int num_messages = 5;
  for (int i = 0; i < num_messages; ++i) {
    const std::string message = "Message " + std::to_string(i);
    const SocketResult result =
      sender->SendTo(message.c_str(), message.length(), addr, receiver_port);
    EXPECT_TRUE(result.Succeeded());
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(50));

  // Receive messages
  for (int i = 0; i < num_messages; ++i) {
    char buffer[1024];
    SocketAddress from_addr;
    std::uint16_t from_port = 0;

    const SocketResult result =
      receiver->Receive(buffer, sizeof(buffer), from_addr, from_port);
    EXPECT_TRUE(result.Succeeded());
    EXPECT_GT(result.bytes, 0);
  }
}

// Blocking mode tests.

TEST_F(UDPSocketTest, DefaultNonBlocking) {
  SocketConfig config;
  config.nonBlocking = true;

  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  EXPECT_FALSE(socket->IsBlocking()) << "Should be non-blocking by default";
}

TEST_F(UDPSocketTest, NonBlockingReceive) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  // Set to blocking
  SocketError err = socket->SetBlocking(true);
  EXPECT_EQ(err, SocketError::kNone);
  EXPECT_TRUE(socket->IsBlocking());

  // Set back to non-blocking
  err = socket->SetBlocking(false);
  EXPECT_EQ(err, SocketError::kNone);
  EXPECT_FALSE(socket->IsBlocking());
}

TEST_F(UDPSocketTest, SetBlockingWithoutBindReturnsError) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketError err = socket->SetBlocking(true);
  EXPECT_EQ(err, SocketError::kNotBound);
}

TEST_F(UDPSocketTest, NonBlockingReceiveReturnsWouldBlock) {
  SocketConfig config;
  config.nonBlocking = true;

  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  char buffer[1024];
  SocketAddress from_addr;
  std::uint16_t from_port = 0;

  // Should return WouldBlock when no data available
  const SocketResult result =
    socket->Receive(buffer, sizeof(buffer), from_addr, from_port);

  EXPECT_FALSE(result.Succeeded());
  EXPECT_EQ(result.error, SocketError::kWouldBlock);
}

TEST_F(UDPSocketTest, ReceiveAfterSend) {
  const SocketConfig config;
  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(receiver->Bind(addr, 0), SocketError::kNone);
  std::uint16_t receiver_port = receiver->LocalPort();

  const char* message = "Poll test";
  const std::size_t message_len = std::strlen(message);

  ASSERT_TRUE(
    sender->SendTo(message, message_len, addr, receiver_port).Succeeded());

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  char buffer[128]{};
  SocketAddress from;
  std::uint16_t from_port = 0;
  const SocketResult result =
    receiver->Receive(buffer, sizeof(buffer), from, from_port);
  ASSERT_TRUE(result.Succeeded());
  ASSERT_EQ(result.bytes, static_cast<std::ptrdiff_t>(message_len));
  EXPECT_EQ(std::memcmp(buffer, message, message_len), 0);
}

TEST_F(UDPSocketTest, ReceiveWithoutData) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  char buffer[128]{};
  SocketAddress from;
  std::uint16_t from_port = 0;
  const SocketResult result =
    socket->Receive(buffer, sizeof(buffer), from, from_port);
  EXPECT_EQ(result.error, SocketError::kWouldBlock);
}

TEST_F(UDPSocketTest, ReceiveMultiplePackets) {
  const SocketConfig config;
  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(receiver->Bind(addr, 0), SocketError::kNone);
  std::uint16_t receiver_port = receiver->LocalPort();

  // Send multiple packets
  const int num_packets = 3;
  for (int i = 0; i < num_packets; ++i) {
    const std::string msg = "Packet " + std::to_string(i);
    sender->SendTo(msg.c_str(), msg.length(), addr, receiver_port);
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(20));

  int received = 0;
  for (int i = 0; i < num_packets; ++i) {
    char buffer[128]{};
    SocketAddress from;
    std::uint16_t from_port = 0;
    const SocketResult result =
      receiver->Receive(buffer, sizeof(buffer), from, from_port);
    if (result.Succeeded()) ++received;
  }

  EXPECT_GE(received, 1);
}

// CLOSE TEST

TEST_F(UDPSocketTest, CloseSocket) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  std::uint16_t port = socket->LocalPort();
  EXPECT_GT(port, 0);

  socket->Close();

  EXPECT_EQ(socket->LocalPort(), 0) << "Port should be reset after close";
  EXPECT_EQ(socket->NativeHandle(), -1)
    << "Handle should be invalid after close";
}

TEST_F(UDPSocketTest, CloseMultipleTimes) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  // Close multiple times should not crash
  socket->Close();
  socket->Close();
  socket->Close();
}

TEST_F(UDPSocketTest, DestructorClosesSocket) {
  const SocketConfig config;
  std::uint16_t port = 0;

  {
    auto socket = factory->CreateUdpSocket(config);
    const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
    ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);
    port = socket->LocalPort();
    EXPECT_GT(port, 0);
    // Socket destroyed here
  }

  // Should be able to bind to the same port again
  auto socket2 = factory->CreateUdpSocket(config);
  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  // Port should be available (may get same or different port from OS)
  EXPECT_EQ(socket2->Bind(addr, 0), SocketError::kNone);
}

// NATIVE HANDLE TEST
TEST_F(UDPSocketTest, NativeHandle) {
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  ASSERT_NE(socket, nullptr);

  // Before bind, handle might be -1
  EXPECT_EQ(socket->NativeHandle(), -1);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(socket->Bind(addr, 0), SocketError::kNone);

  // After bind, should have valid handle
  EXPECT_GE(socket->NativeHandle(), 0) << "Should have valid file descriptor";
}

// Large data tests.

TEST_F(UDPSocketTest, LargePacket) {
  const SocketConfig config;
  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(receiver->Bind(addr, 0), SocketError::kNone);
  std::uint16_t receiver_port = receiver->LocalPort();

  // Create large buffer (but not too large for UDP - typical MTU is ~1500
  // bytes)
  const std::size_t data_size = 1400;
  std::vector<char> data(data_size);
  for (size_t i = 0; i < data_size; ++i) {
    data.at(i) = static_cast<char>(i % 256);
  }

  const SocketResult send_result =
    sender->SendTo(data.data(), data.size(), addr, receiver_port);

  EXPECT_TRUE(send_result.Succeeded());
  EXPECT_EQ(send_result.bytes, static_cast<std::ptrdiff_t>(data_size));

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  std::vector<char> buffer(2048);
  SocketAddress from_addr;
  std::uint16_t from_port = 0;

  const SocketResult recv_result =
    receiver->Receive(buffer.data(), buffer.size(), from_addr, from_port);

  EXPECT_TRUE(recv_result.Succeeded());
  EXPECT_EQ(recv_result.bytes, static_cast<std::ptrdiff_t>(data_size));
  EXPECT_EQ(std::memcmp(buffer.data(), data.data(), data_size), 0);
}
