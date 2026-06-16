// Tests for the ISocket interface and concrete socket implementations.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

#include "i_socket.hpp"
#include "socket_constants.hpp"
#include "socket_init.hpp"

using namespace socketwire;  // NOLINT

namespace {

TEST(SocketInitTest, ConcurrentInitializeSockets) {
  std::atomic<bool> start{false};
  std::array<std::thread, 8> threads;

  for (auto& thread : threads) {
    thread = std::thread([&] {
      while (!start.load()) std::this_thread::yield();
      InitializeSockets();
    });
  }

  start.store(true);
  for (auto& thread : threads) thread.join();

  EXPECT_NE(SocketFactoryRegistry::GetFactory(), nullptr);
}

class NetSocketTest : public ::testing::Test {
 protected:
  void SetUp() override {
    InitializeSockets();

    factory = SocketFactoryRegistry::GetFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be registered";
  }

  ISocketFactory* factory = nullptr;
};

TEST_F(NetSocketTest, CreateSocket) {
  // Test creating and binding socket
  const SocketConfig config;
  auto sock = factory->CreateUdpSocket(config);
  ASSERT_NE(sock, nullptr) << "Socket creation should succeed";

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  const SocketError bind_result =
    sock->Bind(addr, 0);  // Bind to any available port
  EXPECT_EQ(bind_result, SocketError::kNone) << "Socket bind should succeed";

  // Verify port was assigned
  const int port = sock->LocalPort();
  EXPECT_NE(port, 0) << "Socket should be assigned a non-zero port";
  EXPECT_GT(port, 0) << "Port number should be positive";
  EXPECT_LE(port, 65535)
    << "Port number should be within valid range (1-65535)";

  // Test creating multiple sockets
  auto sock2 = factory->CreateUdpSocket(config);
  ASSERT_NE(sock2, nullptr);
  EXPECT_EQ(sock2->Bind(addr, 0), SocketError::kNone)
    << "Second socket bind should succeed";

  const int port2 = sock2->LocalPort();
  EXPECT_NE(port2, 0) << "Second socket should have a valid port";
  EXPECT_NE(port, port2) << "Two sockets should have different ports";

  // Test binding to specific port (OS-assigned)
  auto sock3 = factory->CreateUdpSocket(config);
  ASSERT_NE(sock3, nullptr);
  const SocketError specific_result = sock3->Bind(addr, 0);
  EXPECT_EQ(specific_result, SocketError::kNone)
    << "Binding to available port should succeed";
  EXPECT_GT(sock3->LocalPort(), 0)
    << "Socket should have valid port after binding";
}

TEST_F(NetSocketTest, GetLocalIPs) {
  // Note: This functionality would need to be added to ISocket interface
  // For now, we'll test that we can create sockets on loopback
  const SocketConfig config;
  auto sock = factory->CreateUdpSocket(config);
  ASSERT_NE(sock, nullptr);

  // Test binding to loopback
  const SocketAddress loopback =
    SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  EXPECT_EQ(sock->Bind(loopback, 0), SocketError::kNone)
    << "Should be able to bind to loopback interface";

  // Test binding to any interface
  auto sock2 = factory->CreateUdpSocket(config);
  ASSERT_NE(sock2, nullptr);
  const SocketAddress any = SocketAddress::FromIPv4(0x00000000);  // 0.0.0.0
  EXPECT_EQ(sock2->Bind(any, 0), SocketError::kNone)
    << "Should be able to bind to any interface (0.0.0.0)";
}

TEST_F(NetSocketTest, IsPortInUse) {
  const SocketConfig config;

  // Bind to a port
  auto sock = factory->CreateUdpSocket(config);
  ASSERT_NE(sock, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(sock->Bind(addr, 0), SocketError::kNone);

  const int used_port = sock->LocalPort();
  EXPECT_GT(used_port, 0) << "Bound socket should have valid port";

  // Try to bind another socket to the same port (with SO_REUSEADDR it might
  // succeed) This tests that ports are properly managed
  auto sock2 = factory->CreateUdpSocket(config);
  ASSERT_NE(sock2, nullptr);

  // Binding to port 0 should give a different port
  EXPECT_EQ(sock2->Bind(addr, 0), SocketError::kNone);
  const int new_port = sock2->LocalPort();

  // With SO_REUSEADDR, we might get the same port, but typically we get
  // different ones The important thing is that bind succeeds
  EXPECT_GT(new_port, 0);
}

TEST_F(NetSocketTest, SendAndReceive) {
  const SocketConfig config;

  // Create sender socket
  auto sender = factory->CreateUdpSocket(config);
  ASSERT_NE(sender, nullptr) << "Sender socket creation should succeed";

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  EXPECT_EQ(sender->Bind(addr, 0), SocketError::kNone)
    << "Sender should bind successfully";
  std::uint16_t sender_port = sender->LocalPort();
  EXPECT_GT(sender_port, 0) << "Sender should have valid port";

  // Create receiver socket
  auto receiver = factory->CreateUdpSocket(config);
  ASSERT_NE(receiver, nullptr) << "Receiver socket creation should succeed";
  EXPECT_EQ(receiver->Bind(addr, 0), SocketError::kNone)
    << "Receiver should bind successfully";
  std::uint16_t receiver_port = receiver->LocalPort();
  EXPECT_GT(receiver_port, 0) << "Receiver should have valid port";

  // Ensure they have different ports
  EXPECT_NE(sender_port, receiver_port)
    << "Sender and receiver should have different ports";

  // Send message
  const char* message = "Hello";
  const std::size_t message_len = std::strlen(message);

  const SocketResult sent =
    sender->SendTo(message, message_len, addr, receiver_port);
  EXPECT_EQ(sent.error, SocketError::kNone) << "Should send successfully";
  EXPECT_EQ(sent.bytes, static_cast<std::ptrdiff_t>(message_len))
    << "Should send all " << message_len << " bytes";
  EXPECT_GT(sent.bytes, 0) << "Send should return positive byte count";

  // Small delay to ensure packet arrives
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  // Receive message
  char buffer[1024];
  SocketAddress from_addr;
  std::uint16_t from_port = 0;

  const SocketResult received =
    receiver->Receive(buffer, sizeof(buffer), from_addr, from_port);

  EXPECT_EQ(received.error, SocketError::kNone) << "Receive should succeed";
  EXPECT_EQ(received.bytes, static_cast<std::ptrdiff_t>(message_len))
    << "Should receive " << message_len << " bytes";
  EXPECT_EQ(std::string(buffer, static_cast<std::size_t>(received.bytes)),
            std::string(message))
    << "Received data should match sent data";
  EXPECT_EQ(from_port, sender_port) << "Should know sender's port";
}

TEST_F(NetSocketTest, SendAndReceiveDirectly) {
  const SocketConfig config;

  // Create sender socket
  auto sender = factory->CreateUdpSocket(config);
  ASSERT_NE(sender, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  EXPECT_EQ(sender->Bind(addr, 0), SocketError::kNone)
    << "Sender should bind successfully";
  std::uint16_t sender_port = sender->LocalPort();
  EXPECT_GT(sender_port, 0) << "Sender port should be valid";

  // Create receiver socket
  auto receiver = factory->CreateUdpSocket(config);
  ASSERT_NE(receiver, nullptr);
  EXPECT_EQ(receiver->Bind(addr, 0), SocketError::kNone)
    << "Receiver should bind successfully";
  std::uint16_t receiver_port = receiver->LocalPort();
  EXPECT_GT(receiver_port, 0) << "Receiver port should be valid";

  const char* message = "Hello";
  const size_t message_len = std::strlen(message);

  const SocketResult sent =
    sender->SendTo(message, message_len, addr, receiver_port);
  EXPECT_EQ(sent.error, SocketError::kNone)
    << "Should send exactly " << message_len << " bytes";
  EXPECT_EQ(sent.bytes, static_cast<std::ptrdiff_t>(message_len));
  EXPECT_GT(sent.bytes, 0) << "Bytes sent should be positive";

  // Small delay
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  char buffer[1024]{};
  SocketAddress from_addr;
  std::uint16_t from_port = 0;
  const SocketResult received =
    receiver->Receive(buffer, sizeof(buffer), from_addr, from_port);

  ASSERT_TRUE(received.Succeeded());
  EXPECT_EQ(received.bytes, static_cast<std::ptrdiff_t>(message_len));
  EXPECT_EQ(from_port, sender_port);
  EXPECT_EQ(std::memcmp(buffer, message, message_len), 0);
}

TEST_F(NetSocketTest, NonBlockingBehavior) {
  SocketConfig config;
  config.nonBlocking = true;

  auto sock = factory->CreateUdpSocket(config);
  ASSERT_NE(sock, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(sock->Bind(addr, 0), SocketError::kNone);

  // Verify non-blocking mode
  EXPECT_FALSE(sock->IsBlocking()) << "Socket should be in non-blocking mode";

  // Try to receive without data - should return WouldBlock
  char buffer[1024];
  SocketAddress from_addr;
  std::uint16_t from_port = 0;

  const SocketResult result =
    sock->Receive(buffer, sizeof(buffer), from_addr, from_port);
  EXPECT_EQ(result.error, SocketError::kWouldBlock)
    << "Non-blocking receive with no data should return WouldBlock";
}

TEST_F(NetSocketTest, MultipleMessagesSequential) {
  const SocketConfig config;

  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ASSERT_EQ(receiver->Bind(addr, 0), SocketError::kNone);
  std::uint16_t receiver_port = receiver->LocalPort();

  // Send and receive multiple messages
  const int num_messages = 5;
  for (int i = 0; i < num_messages; ++i) {
    const std::string message = "Message " + std::to_string(i);

    // Send
    const SocketResult send_result =
      sender->SendTo(message.c_str(), message.length(), addr, receiver_port);
    EXPECT_EQ(send_result.error, SocketError::kNone);
    EXPECT_EQ(send_result.bytes, static_cast<std::ptrdiff_t>(message.length()));

    // Small delay
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    // Receive
    char buffer[1024];
    SocketAddress from_addr;
    std::uint16_t from_port = 0;

    const SocketResult recv_result =
      receiver->Receive(buffer, sizeof(buffer), from_addr, from_port);
    EXPECT_EQ(recv_result.error, SocketError::kNone);
    EXPECT_EQ(recv_result.bytes, static_cast<std::ptrdiff_t>(message.length()));

    const std::string received(buffer,
                               static_cast<std::size_t>(recv_result.bytes));
    EXPECT_EQ(received, message) << "Message " << i << " should match";
  }
}

TEST_F(NetSocketTest, SendAndReceiveIPv6Loopback) {
  SocketConfig config;
  config.enableIPv6 = true;

  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  const SocketAddress v6_loop = SocketConstants::LoopbackIPv6();

  ASSERT_EQ(receiver->Bind(v6_loop, 0), SocketError::kNone);
  std::uint16_t receiver_port = receiver->LocalPort();
  ASSERT_GT(receiver_port, 0);

  ASSERT_EQ(sender->Bind(v6_loop, 0), SocketError::kNone);
  std::uint16_t sender_port = sender->LocalPort();

  const char* msg = "HiIPv6";
  const std::size_t msg_len = std::strlen(msg);

  const SocketResult sent =
    sender->SendTo(msg, msg_len, v6_loop, receiver_port);
  EXPECT_TRUE(sent.Succeeded());

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  char buffer[64];
  SocketAddress from_addr;
  std::uint16_t from_port = 0;

  const SocketResult received =
    receiver->Receive(buffer, sizeof(buffer), from_addr, from_port);
  EXPECT_TRUE(received.Succeeded());
  EXPECT_EQ(received.bytes, static_cast<std::ptrdiff_t>(msg_len));
  EXPECT_EQ(std::string(buffer, static_cast<std::size_t>(received.bytes)),
            std::string(msg));
  EXPECT_EQ(from_port, sender_port);
  EXPECT_TRUE(from_addr.isIPv6);
}

TEST_F(NetSocketTest, DualStackIPv4ToIPv6Mapped) {
  SocketConfig recv_cfg;
  recv_cfg.enableIPv6 = true;  // allow dual-stack
  auto receiver = factory->CreateUdpSocket(recv_cfg);
  ASSERT_NE(receiver, nullptr);

  const SocketAddress any6 = SocketConstants::AnyIPv6();
  ASSERT_EQ(receiver->Bind(any6, 0), SocketError::kNone);
  std::uint16_t receiver_port = receiver->LocalPort();

  const SocketConfig send_cfg;  // IPv4-only is fine
  auto sender = factory->CreateUdpSocket(send_cfg);
  ASSERT_NE(sender, nullptr);
  ASSERT_EQ(sender->Bind(SocketConstants::Loopback(), 0), SocketError::kNone);
  std::uint16_t sender_port = sender->LocalPort();

  const char* payload = "dual";
  const std::size_t payload_len = std::strlen(payload);

  const SocketResult sent = sender->SendTo(
    payload, payload_len, SocketConstants::Loopback(), receiver_port);
  EXPECT_TRUE(sent.Succeeded());

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  char buffer[64];
  SocketAddress from_addr;
  std::uint16_t from_port = 0;
  const SocketResult recv =
    receiver->Receive(buffer, sizeof(buffer), from_addr, from_port);
  EXPECT_TRUE(recv.Succeeded());
  EXPECT_EQ(recv.bytes, static_cast<std::ptrdiff_t>(payload_len));
  EXPECT_FALSE(from_addr.isIPv6);  // mapped IPv4 returned as IPv4
  EXPECT_EQ(from_addr.ipv4.hostOrderAddress, SocketConstants::kIpV4Loopback);
  EXPECT_EQ(from_port, sender_port);
}

TEST(NetSocketStandalone, ParseAndFormatIPv6) {
  std::array<std::uint8_t, 16> bytes{};
  std::uint32_t scope_id = 0;
  ASSERT_TRUE(SocketConstants::ParseIPv6("::1", bytes, scope_id));
  EXPECT_EQ(scope_id, 0u);

  char buf[64];
  ASSERT_TRUE(SocketConstants::FormatIPv6(bytes, scope_id, buf, sizeof(buf)));
  EXPECT_STREQ(buf, "::1");

  SocketAddress addr = SocketConstants::FromString("::1");
  EXPECT_TRUE(addr.isIPv6);
  EXPECT_EQ(addr.ipv6.bytes.at(15), 1);
}
}  // anonymous namespace
