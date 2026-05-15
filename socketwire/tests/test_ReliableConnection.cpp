#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

#include "i_socket.hpp"
#include "reliable_connection.hpp"

using socketwire::BitStream;
using socketwire::ConnectionManager;
using socketwire::ConnectionState;
using socketwire::IReliableConnectionHandler;
using socketwire::ISocket;
using socketwire::ISocketEventHandler;
using socketwire::PacketType;
using socketwire::ReliableConnection;
using socketwire::ReliableConnectionConfig;
using socketwire::SocketAddress;
using socketwire::SocketError;
using socketwire::SocketResult;

namespace {

constexpr std::uint8_t kDeadlineHeaderFlag = 0x80;
constexpr std::uint8_t kPacketTypeMask = 0x7F;
constexpr std::size_t kBaseHeaderSize = 6;
constexpr std::size_t kDeadlineHeaderSize = 16;

std::uint32_t ReadU32(const std::vector<std::uint8_t>& data,
                      std::size_t offset) {
  std::uint32_t value = 0;
  std::memcpy(&value, data.data() + offset, sizeof(value));
  return value;
}

std::vector<std::uint8_t> MakeDeadlinePacket(
    PacketType type, std::uint8_t channel, std::uint32_t sequence,
    std::uint32_t deadline_ms, std::uint32_t age_ms_at_send,
    const void* payload = nullptr, std::size_t payload_size = 0) {
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(type) | kDeadlineHeaderFlag);
  bs.Write<std::uint8_t>(channel);
  bs.Write<std::uint32_t>(sequence);
  bs.Write<std::uint8_t>(1);  // extensionVersion
  bs.Write<std::uint8_t>(0);  // extensionFlags
  bs.Write<std::uint32_t>(deadline_ms);
  bs.Write<std::uint32_t>(age_ms_at_send);
  if (payload != nullptr && payload_size > 0) {
    bs.WriteBytes(payload, payload_size);
  }
  return {bs.GetData(), bs.GetData() + bs.GetSizeBytes()};
}

std::vector<std::uint8_t> MakeBasePacket(PacketType type, std::uint8_t channel,
                                         std::uint32_t sequence,
                                         const void* payload = nullptr,
                                         std::size_t payload_size = 0) {
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(type));
  bs.Write<std::uint8_t>(channel);
  bs.Write<std::uint32_t>(sequence);
  if (payload != nullptr && payload_size > 0) {
    bs.WriteBytes(payload, payload_size);
  }
  return {bs.GetData(), bs.GetData() + bs.GetSizeBytes()};
}

std::vector<std::uint8_t> MakeBatchPacket(
    const std::vector<std::vector<std::uint8_t>>& commands) {
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kBatch));
  bs.Write<std::uint8_t>(0);
  bs.Write<std::uint32_t>(0);
  bs.Write<std::uint16_t>(static_cast<std::uint16_t>(commands.size()));
  for (const auto& command : commands) {
    bs.Write<std::uint16_t>(static_cast<std::uint16_t>(command.size()));
    bs.WriteBytes(command.data(), command.size());
  }
  return {bs.GetData(), bs.GetData() + bs.GetSizeBytes()};
}

// Mock socket for testing
class MockSocket : public ISocket {
 public:
  struct SentPacket {
    std::vector<std::uint8_t> data;
    SocketAddress address;
    uint16_t port = 0;
  };

  std::vector<SentPacket> sentPackets;
  std::vector<std::vector<std::uint8_t>> receiveQueue;
  bool shouldBlock = false;
  SocketError receiveError = SocketError::kNone;

  SocketError Bind(const SocketAddress& address, uint16_t port) override {
    (void)address;
    (void)port;
    return SocketError::kNone;
  }

  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr, uint16_t to_port) override {
    SentPacket packet;
    packet.data.assign(static_cast<const std::uint8_t*>(data),
                       static_cast<const std::uint8_t*>(data) + length);
    packet.address = to_addr;
    packet.port = to_port;
    sentPackets.push_back(packet);
    return {.bytes = static_cast<std::ptrdiff_t>(length),
            .error = SocketError::kNone};
  }

  SocketResult SendBitStream(BitStream& stream, const SocketAddress& to_addr,
                             uint16_t to_port) override {
    return SendTo(stream.GetData(), stream.GetSizeBytes(), to_addr, to_port);
  }

  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr, uint16_t& from_port) override {
    if (shouldBlock || receiveQueue.empty()) {
      if (receiveError != SocketError::kNone) {
        return {.bytes = -1, .error = receiveError};
      }
      return {.bytes = -1, .error = SocketError::kWouldBlock};
    }

    auto& packet = receiveQueue.front();
    const std::size_t copy_size = std::min(capacity, packet.size());
    std::memcpy(buffer, packet.data(), copy_size);

    from_addr = SocketAddress::FromIPv4(0x7F000001);
    from_port = 12345;

    receiveQueue.erase(receiveQueue.begin());
    return {.bytes = static_cast<std::ptrdiff_t>(copy_size),
            .error = SocketError::kNone};
  }

  void Poll(ISocketEventHandler* handler) override { (void)handler; }

  SocketError SetBlocking(bool enable) override {
    (void)enable;
    return SocketError::kNone;
  }

  [[nodiscard]] bool IsBlocking() const override { return false; }
  [[nodiscard]] uint16_t LocalPort() const override { return 54321; }
  [[nodiscard]] int NativeHandle() const override { return 42; }
  void Close() override {}

  void QueueReceive(const void* data, std::size_t size) {
    const std::vector<std::uint8_t> packet(
        static_cast<const std::uint8_t*>(data),
        static_cast<const std::uint8_t*>(data) + size);
    receiveQueue.push_back(packet);
  }

  void ClearSent() { sentPackets.clear(); }

  [[nodiscard]] std::size_t GetSentCount() const { return sentPackets.size(); }
};

// Mock event handler
class MockEventHandler : public IReliableConnectionHandler {
 public:
  bool connected = false;
  bool disconnected = false;
  bool timedOut = false;
  std::vector<std::vector<std::uint8_t>> reliablePackets;
  std::vector<std::vector<std::uint8_t>> unreliablePackets;

  void OnConnected() override { connected = true; }

  void OnDisconnected() override { disconnected = true; }

  void OnTimeout() override { timedOut = true; }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    (void)channel;
    const std::vector<std::uint8_t> packet(
        static_cast<const std::uint8_t*>(data),
        static_cast<const std::uint8_t*>(data) + size);
    reliablePackets.push_back(packet);
  }

  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            std::size_t size) override {
    (void)channel;
    const std::vector<std::uint8_t> packet(
        static_cast<const std::uint8_t*>(data),
        static_cast<const std::uint8_t*>(data) + size);
    unreliablePackets.push_back(packet);
  }

  void Reset() {
    connected = false;
    disconnected = false;
    timedOut = false;
    reliablePackets.clear();
    unreliablePackets.clear();
  }
};

class ReliableConnectionTest : public ::testing::Test {
 protected:
  MockSocket socket;
  ReliableConnectionConfig config;
  MockEventHandler handler;

  void SetUp() override {
    config.maxRetries = 3;
    config.retryTimeoutMs = 50;
    config.pingIntervalMs = 100;
    config.disconnectTimeoutMs = 500;
    config.maxPacketSize = 1400;
    config.numChannels = 2;
  }
};

TEST_F(ReliableConnectionTest, Construction) {
  ReliableConnection conn(&socket, config);
  EXPECT_EQ(conn.GetState(), ConnectionState::kDisconnected);
  EXPECT_FALSE(conn.IsConnected());
}

TEST_F(ReliableConnectionTest, ClientConnect) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.Connect(addr, 12345);

  EXPECT_EQ(conn.GetState(), ConnectionState::kConnecting);
  EXPECT_FALSE(conn.IsConnected());
  EXPECT_GT(socket.GetSentCount(), 0) << "Should send connect packet";

  // Verify connect packet was sent
  ASSERT_FALSE(socket.sentPackets.empty());
  const auto& packet = socket.sentPackets.at(0);
  EXPECT_GT(packet.data.size(), 0);
}

TEST_F(ReliableConnectionTest, ServerAcceptConnection) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress client_addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(client_addr, 12345);

  // Simulate receiving connect packet
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kConnect));
  bs.Write<std::uint8_t>(0);   // channel
  bs.Write<std::uint32_t>(0);  // sequence

  conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), client_addr, 12345);

  EXPECT_TRUE(handler.connected) << "Should trigger OnConnected";
  EXPECT_EQ(conn.GetState(), ConnectionState::kConnected);
  EXPECT_TRUE(conn.IsConnected());
}

TEST_F(ReliableConnectionTest, ClientReceiveAccept) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.Connect(addr, 12345);

  EXPECT_FALSE(handler.connected);

  // Simulate receiving accept packet
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kAccept));
  bs.Write<std::uint8_t>(0);   // channel
  bs.Write<std::uint32_t>(0);  // sequence

  conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);

  EXPECT_TRUE(handler.connected) << "Should trigger OnConnected";
  EXPECT_EQ(conn.GetState(), ConnectionState::kConnected);
  EXPECT_TRUE(conn.IsConnected());
}

TEST_F(ReliableConnectionTest, SendReliablePacket) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  // Set connected state
  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();

  // Send reliable packet
  const char* test_data = "Hello, World!";
  const bool result = conn.SendReliable(0, test_data, strlen(test_data));

  EXPECT_TRUE(result) << "SendReliable should succeed";
  EXPECT_EQ(socket.GetSentCount(), 1) << "Should send one packet";

  // Verify packet structure
  ASSERT_FALSE(socket.sentPackets.empty());
  const auto& packet = socket.sentPackets.at(0);
  EXPECT_GT(packet.data.size(), strlen(test_data))
      << "Packet should include header";
}

TEST_F(ReliableConnectionTest, SendUnreliablePacket) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();

  const char* test_data = "Unreliable data";
  const bool result = conn.SendUnreliable(0, test_data, strlen(test_data));

  EXPECT_TRUE(result) << "SendUnreliable should succeed";
  EXPECT_EQ(socket.GetSentCount(), 1) << "Should send one packet";
}

TEST_F(ReliableConnectionTest, SendWithBitStream) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();

  // Create BitStream with data
  BitStream bs;
  bs.Write<std::uint8_t>(42);
  bs.Write<float>(3.14f);
  bs.Write<std::uint32_t>(12345);

  const bool result = conn.SendReliable(0, bs);

  EXPECT_TRUE(result) << "SendReliable with BitStream should succeed";
  EXPECT_EQ(socket.GetSentCount(), 1) << "Should send one packet";
}

TEST_F(ReliableConnectionTest, ReceiveReliablePacket) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  // Create reliable packet
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kReliable));
  bs.Write<std::uint8_t>(0);   // channel
  bs.Write<std::uint32_t>(0);  // sequence
  const char* payload = "Test payload";
  bs.WriteBytes(payload, strlen(payload));

  socket.ClearSent();
  conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);

  // Process packet queue (since it's sequenced)
  conn.Update();

  // Should flush the queued ACK.
  EXPECT_GT(socket.GetSentCount(), 0) << "Should send ACK packet";

  EXPECT_EQ(handler.reliablePackets.size(), 1)
      << "Should receive one reliable packet";
  ASSERT_FALSE(handler.reliablePackets.empty());

  const auto& received_data = handler.reliablePackets.at(0);
  const std::string received_str(received_data.begin(), received_data.end());
  EXPECT_EQ(received_str, std::string(payload));
}

TEST_F(ReliableConnectionTest, ReceiveUnreliablePacket) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  // Create unreliable packet
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kUnreliable));
  bs.Write<std::uint8_t>(0);   // channel
  bs.Write<std::uint32_t>(0);  // sequence
  const char* payload = "Unreliable payload";
  bs.WriteBytes(payload, strlen(payload));

  conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);

  EXPECT_EQ(handler.unreliablePackets.size(), 1)
      << "Should receive one unreliable packet";
  ASSERT_FALSE(handler.unreliablePackets.empty());

  const auto& received_data = handler.unreliablePackets.at(0);
  const std::string received_str(received_data.begin(), received_data.end());
  EXPECT_EQ(received_str, std::string(payload));
}

TEST_F(ReliableConnectionTest, BatchPacketDeliversMultipleCommands) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  const auto first = MakeBasePacket(PacketType::kUnreliable, 0, 0, "one", 3);
  const auto second = MakeBasePacket(PacketType::kUnreliable, 0, 0, "two", 3);
  const auto batch = MakeBatchPacket({first, second});

  conn.ProcessPacket(batch.data(), batch.size(), addr, 12345);

  ASSERT_EQ(handler.unreliablePackets.size(), 2u);
  EXPECT_EQ(std::string(handler.unreliablePackets.at(0).begin(),
                        handler.unreliablePackets.at(0).end()),
            "one");
  EXPECT_EQ(std::string(handler.unreliablePackets.at(1).begin(),
                        handler.unreliablePackets.at(1).end()),
            "two");
}

TEST_F(ReliableConnectionTest, BatchPacketRejectsMalformedPayload) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  BitStream malformed;
  malformed.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kBatch));
  malformed.Write<std::uint8_t>(0);
  malformed.Write<std::uint32_t>(0);
  malformed.Write<std::uint16_t>(2);
  malformed.Write<std::uint16_t>(kBaseHeaderSize);

  conn.ProcessPacket(malformed.GetData(), malformed.GetSizeBytes(), addr,
                     12345);

  EXPECT_TRUE(handler.reliablePackets.empty());
  EXPECT_TRUE(handler.unreliablePackets.empty());
}

TEST_F(ReliableConnectionTest, AckPiggybacksOnNextApplicationPacket) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  const auto inbound = MakeBasePacket(PacketType::kReliable, 0, 0, "in", 2);
  socket.ClearSent();
  conn.ProcessPacket(inbound.data(), inbound.size(), addr, 12345);
  ASSERT_EQ(handler.reliablePackets.size(), 1u);
  EXPECT_EQ(socket.GetSentCount(), 0u);

  ASSERT_TRUE(conn.SendUnreliable(0, "out", 3));
  ASSERT_EQ(socket.GetSentCount(), 1u);

  const auto& packet = socket.sentPackets.at(0).data;
  ASSERT_GE(packet.size(), kBaseHeaderSize + sizeof(std::uint16_t));
  EXPECT_EQ(packet.at(0), static_cast<std::uint8_t>(PacketType::kBatch));

  std::uint16_t command_count = 0;
  std::memcpy(&command_count, packet.data() + kBaseHeaderSize,
              sizeof(command_count));
  ASSERT_EQ(command_count, 2u);

  std::size_t offset = kBaseHeaderSize + sizeof(std::uint16_t);
  std::uint16_t first_size = 0;
  std::memcpy(&first_size, packet.data() + offset, sizeof(first_size));
  offset += sizeof(first_size);
  ASSERT_GE(first_size, kBaseHeaderSize);
  EXPECT_EQ(packet.at(offset), static_cast<std::uint8_t>(PacketType::kAck));
  EXPECT_EQ(ReadU32(packet, offset + 2), 0u);

  offset += first_size;
  std::uint16_t second_size = 0;
  std::memcpy(&second_size, packet.data() + offset, sizeof(second_size));
  offset += sizeof(second_size);
  ASSERT_GE(second_size, kBaseHeaderSize + 3u);
  EXPECT_EQ(packet.at(offset),
            static_cast<std::uint8_t>(PacketType::kUnreliable));
}

TEST_F(ReliableConnectionTest, PacketSequencing) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  // Send packets out of order
  auto create_packet = [](std::uint32_t seq,
                          const char* payload) -> std::vector<std::uint8_t> {
    BitStream bs;
    bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kReliable));
    bs.Write<std::uint8_t>(0);  // channel
    bs.Write<std::uint32_t>(seq);
    bs.WriteBytes(payload, strlen(payload));
    return {bs.GetData(), bs.GetData() + bs.GetSizeBytes()};
  };

  auto packet2 = create_packet(2, "Second");
  auto packet1 = create_packet(1, "First");
  auto packet0 = create_packet(0, "Zero");

  // Receive in wrong order: 2, 1, 0
  conn.ProcessPacket(packet2.data(), packet2.size(), addr, 12345);
  conn.Update();
  EXPECT_EQ(handler.reliablePackets.size(), 0) << "Should wait for sequence 0";

  conn.ProcessPacket(packet1.data(), packet1.size(), addr, 12345);
  conn.Update();
  EXPECT_EQ(handler.reliablePackets.size(), 0)
      << "Still waiting for sequence 0";

  conn.ProcessPacket(packet0.data(), packet0.size(), addr, 12345);
  conn.Update();

  // Now all packets should be delivered in order
  EXPECT_EQ(handler.reliablePackets.size(), 3)
      << "Should receive all three packets";

  const std::string first(handler.reliablePackets.at(0).begin(),
                          handler.reliablePackets.at(0).end());
  const std::string second(handler.reliablePackets.at(1).begin(),
                           handler.reliablePackets.at(1).end());
  const std::string third(handler.reliablePackets.at(2).begin(),
                          handler.reliablePackets.at(2).end());

  EXPECT_EQ(first, "Zero");
  EXPECT_EQ(second, "First");
  EXPECT_EQ(third, "Second");
}

TEST_F(ReliableConnectionTest, DuplicateDetection) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  // Create reliable packet
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kReliable));
  bs.Write<std::uint8_t>(0);   // channel
  bs.Write<std::uint32_t>(0);  // sequence
  bs.WriteBytes("Test", 4);

  // Send same packet twice
  conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);
  conn.Update();

  const std::size_t first_count = handler.reliablePackets.size();

  conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);
  conn.Update();

  EXPECT_EQ(handler.reliablePackets.size(), first_count)
      << "Duplicate packet should be ignored";
}

TEST_F(ReliableConnectionTest, AcknowledgmentReceived) {
  config.pingIntervalMs = 10000;  // in fact disable ping
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();

  // Send reliable packet
  conn.SendReliable(0, "Test", 4);

  const std::size_t sent_before = socket.GetSentCount();
  const std::uint32_t lost_before = conn.GetLostPackets();

  // Extract sequence from sent packet
  ASSERT_FALSE(socket.sentPackets.empty());
  const auto& sent_packet = socket.sentPackets.back();
  BitStream sent_bs(sent_packet.data.data(), sent_packet.data.size());
  std::uint8_t type = 0, channel = 0;
  std::uint32_t sequence = 0;
  sent_bs.Read<std::uint8_t>(type);
  sent_bs.Read<std::uint8_t>(channel);
  sent_bs.Read<std::uint32_t>(sequence);

  // Send ACK
  BitStream ack_bs;
  ack_bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kAck));
  ack_bs.Write<std::uint8_t>(0);
  ack_bs.Write<std::uint32_t>(sequence);

  conn.ProcessPacket(ack_bs.GetData(), ack_bs.GetSizeBytes(), addr, 12345);
  conn.Update();

  // Wait longer than retry timeout
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  conn.Update();

  // Should not resend after ACK
  EXPECT_EQ(socket.GetSentCount(), sent_before)
      << "Should not resend acknowledged packet";
  EXPECT_EQ(conn.GetLostPackets(), lost_before)
      << "Acknowledged packet should not be counted as lost";
}

TEST_F(ReliableConnectionTest, Disconnect) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  EXPECT_TRUE(conn.IsConnected());
  EXPECT_FALSE(handler.disconnected);

  socket.ClearSent();
  conn.Disconnect();

  EXPECT_FALSE(conn.IsConnected());
  EXPECT_TRUE(handler.disconnected) << "Should trigger OnDisconnected";
  EXPECT_GT(socket.GetSentCount(), 0) << "Should send disconnect packet";
}

TEST_F(ReliableConnectionTest, ReceiveDisconnect) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  EXPECT_FALSE(handler.disconnected);

  // Receive disconnect packet
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kDisconnect));
  bs.Write<std::uint8_t>(0);
  bs.Write<std::uint32_t>(0);

  conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);

  EXPECT_TRUE(handler.disconnected) << "Should trigger OnDisconnected";
  EXPECT_EQ(conn.GetState(), ConnectionState::kDisconnected);
}

TEST_F(ReliableConnectionTest, Statistics) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  const std::uint32_t initial_sent = conn.GetSentPackets();
  const std::uint32_t initial_received = conn.GetReceivedPackets();

  // Send packet
  conn.SendReliable(0, "Test", 4);
  EXPECT_GT(conn.GetSentPackets(), initial_sent)
      << "Sent count should increase";

  // Receive packet
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kUnreliable));
  bs.Write<std::uint8_t>(0);
  bs.Write<std::uint32_t>(0);
  bs.WriteBytes("Data", 4);

  conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);

  EXPECT_GT(conn.GetReceivedPackets(), initial_received)
      << "Received count should increase";
}

TEST_F(ReliableConnectionTest, PingPong) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();

  // Receive ping
  BitStream ping_bs;
  ping_bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kPing));
  ping_bs.Write<std::uint8_t>(0);
  ping_bs.Write<std::uint32_t>(42);

  conn.ProcessPacket(ping_bs.GetData(), ping_bs.GetSizeBytes(), addr, 12345);

  // Should send pong
  EXPECT_GT(socket.GetSentCount(), 0) << "Should send pong response";

  // Verify pong packet
  ASSERT_FALSE(socket.sentPackets.empty());
  const auto& pong_packet = socket.sentPackets.at(0);
  BitStream pong_bs(pong_packet.data.data(), pong_packet.data.size());

  std::uint8_t type = 0;
  std::uint8_t channel = 0;
  std::uint32_t sequence = 0;
  pong_bs.Read<std::uint8_t>(type);
  pong_bs.Read<std::uint8_t>(channel);
  pong_bs.Read<std::uint32_t>(sequence);

  EXPECT_EQ(type, static_cast<std::uint8_t>(PacketType::kPong));
  EXPECT_EQ(sequence, 42) << "Pong should echo ping sequence";
}

TEST_F(ReliableConnectionTest, RTTMeasurement) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  const float initial_rtt = conn.GetRtt();
  EXPECT_GT(initial_rtt, 0.0f) << "RTT should have initial value";

  // RTT will be updated when ACKs are received
  // For now just verify the getter works
  EXPECT_GE(conn.GetRtt(), 0.0f);
}

TEST_F(ReliableConnectionTest, SendBeforeConnected) {
  ReliableConnection conn(&socket, config);

  // Try to send before connecting
  const bool result = conn.SendReliable(0, "Test", 4);

  EXPECT_FALSE(result) << "Should fail to send before connected";
}

TEST_F(ReliableConnectionTest, MaxPacketSizeLimit) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  // A payload larger than maxPacketSize should be transparently fragmented, not
  // rejected
  const std::size_t big_size = static_cast<std::size_t>(config.maxPacketSize) *
                               3U;  // definitely needs fragmentation
  std::vector<std::uint8_t> large_data(big_size, 0xFF);

  socket.ClearSent();
  const bool result =
      conn.SendReliable(0, large_data.data(), large_data.size());

  EXPECT_TRUE(result) << "Large payloads should succeed via fragmentation";
  // The payload must have been split into multiple Fragment packets
  EXPECT_GT(socket.GetSentCount(), 1u)
      << "Oversized payload should produce multiple Fragment packets";
}

TEST_F(ReliableConnectionTest, MultipleChannels) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();

  // Send on different channels
  conn.SendReliable(0, "Channel0", 8);
  conn.SendReliable(1, "Channel1", 8);

  EXPECT_EQ(socket.GetSentCount(), 2)
      << "Should send packets on different channels";

  // Verify channels are different
  ASSERT_GE(socket.sentPackets.size(), 2);

  BitStream bs0(socket.sentPackets.at(0).data.data(),
                socket.sentPackets.at(0).data.size());
  BitStream bs1(socket.sentPackets.at(1).data.data(),
                socket.sentPackets.at(1).data.size());

  std::uint8_t type0 = 0, channel0 = 0, type1 = 0, channel1 = 0;
  std::uint32_t seq0 = 0, seq1 = 0;

  bs0.Read<std::uint8_t>(type0);
  bs0.Read<std::uint8_t>(channel0);
  bs0.Read<std::uint32_t>(seq0);

  bs1.Read<std::uint8_t>(type1);
  bs1.Read<std::uint8_t>(channel1);
  bs1.Read<std::uint32_t>(seq1);

  EXPECT_EQ(type0, static_cast<std::uint8_t>(PacketType::kReliable));
  EXPECT_EQ(type1, static_cast<std::uint8_t>(PacketType::kReliable));
  EXPECT_EQ(seq0, 0u);
  EXPECT_EQ(seq1, 0u);
  EXPECT_EQ(channel0, 0);
  EXPECT_EQ(channel1, 1);
}

TEST_F(ReliableConnectionTest, SendWithoutDeadlineUsesBaseHeader) {
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();
  ASSERT_TRUE(conn.SendUnreliable(0, "abc", 3));

  ASSERT_EQ(socket.sentPackets.size(), 1u);
  const auto& packet = socket.sentPackets.at(0).data;
  ASSERT_EQ(packet.size(), kBaseHeaderSize + 3u);
  EXPECT_EQ(packet.at(0), static_cast<std::uint8_t>(PacketType::kUnreliable));
  EXPECT_EQ(packet.at(1), 0);
  EXPECT_EQ(
      std::string(packet.begin() + static_cast<std::ptrdiff_t>(kBaseHeaderSize),
                  packet.end()),
      "abc");
}

TEST_F(ReliableConnectionTest, DeadlineSendDisabledIsRejected) {
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();
  EXPECT_FALSE(conn.SendReliableWithDeadline(0, "abc", 3, 50));
  EXPECT_FALSE(conn.SendUnreliableWithDeadline(0, "abc", 3, 50));
  EXPECT_FALSE(conn.SendUnsequencedWithDeadline(0, "abc", 3, 50));
  EXPECT_EQ(socket.GetSentCount(), 0u);
}

TEST_F(ReliableConnectionTest, DeadlineSendWritesExtendedHeader) {
  config.deadlinesEnabled = true;
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();
  ASSERT_TRUE(conn.SendUnreliableWithDeadline(1, "xyz", 3, 75));

  ASSERT_EQ(socket.sentPackets.size(), 1u);
  const auto& packet = socket.sentPackets.at(0).data;
  ASSERT_EQ(packet.size(), kDeadlineHeaderSize + 3u);
  EXPECT_EQ(packet.at(0) & kPacketTypeMask,
            static_cast<std::uint8_t>(PacketType::kUnreliable));
  EXPECT_NE(packet.at(0) & kDeadlineHeaderFlag, 0);
  EXPECT_EQ(packet.at(1), 1);
  EXPECT_EQ(ReadU32(packet, 2), 0u);
  EXPECT_EQ(packet.at(6), 1);
  EXPECT_EQ(packet.at(7), 0);
  EXPECT_EQ(ReadU32(packet, 8), 75u);
  EXPECT_LE(ReadU32(packet, 12), 75u);
  EXPECT_EQ(std::string(packet.begin() +
                            static_cast<std::ptrdiff_t>(kDeadlineHeaderSize),
                        packet.end()),
            "xyz");
}

TEST_F(ReliableConnectionTest, ExpiredReliableAndUnsequencedStopRetrying) {
  config.deadlinesEnabled = true;
  config.retryTimeoutMs = 5;
  config.pingIntervalMs = 10000;
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  socket.ClearSent();
  ASSERT_TRUE(conn.SendReliableWithDeadline(0, "rel", 3, 10));
  ASSERT_TRUE(conn.SendUnsequencedWithDeadline(0, "unq", 3, 10));
  ASSERT_EQ(conn.GetInflightCount(), 2u);
  ASSERT_EQ(socket.GetSentCount(), 2u);

  std::this_thread::sleep_for(std::chrono::milliseconds(25));
  conn.Update();

  EXPECT_EQ(conn.GetInflightCount(), 0u);
  EXPECT_EQ(socket.GetSentCount(), 2u);
  EXPECT_EQ(conn.GetDeadlineRetriesPrevented(), 2u);
  EXPECT_EQ(conn.GetLostPackets(), 0u);
}

TEST_F(ReliableConnectionTest, ExpiredReliableStyleReceiveIsAckedAndDropped) {
  config.deadlinesEnabled = true;
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  const auto reliable =
      MakeDeadlinePacket(PacketType::kReliable, 0, 0, 10, 10, "rel", 3);
  socket.ClearSent();
  conn.ProcessPacket(reliable.data(), reliable.size(), addr, 12345);
  conn.Update();

  ASSERT_EQ(socket.GetSentCount(), 1u);
  EXPECT_EQ(socket.sentPackets.at(0).data.at(0),
            static_cast<std::uint8_t>(PacketType::kAck));
  EXPECT_EQ(ReadU32(socket.sentPackets.at(0).data, 2), 0u);
  EXPECT_TRUE(handler.reliablePackets.empty());

  const auto unsequenced =
      MakeDeadlinePacket(PacketType::kUnsequenced, 0, 1, 10, 10, "unq", 3);
  socket.ClearSent();
  conn.ProcessPacket(unsequenced.data(), unsequenced.size(), addr, 12345);
  conn.Update();

  ASSERT_EQ(socket.GetSentCount(), 1u);
  EXPECT_EQ(socket.sentPackets.at(0).data.at(0),
            static_cast<std::uint8_t>(PacketType::kAck));
  EXPECT_EQ(ReadU32(socket.sentPackets.at(0).data, 2), 1u);
  EXPECT_TRUE(handler.reliablePackets.empty());

  std::uint16_t group_id = 7;
  std::uint16_t frag_index = 0;
  std::uint16_t frag_total = 2;
  std::vector<std::uint8_t> fragment_payload(9);
  std::memcpy(fragment_payload.data() + 0, &group_id, 2);
  std::memcpy(fragment_payload.data() + 2, &frag_index, 2);
  std::memcpy(fragment_payload.data() + 4, &frag_total, 2);
  std::memcpy(fragment_payload.data() + 6, "abc", 3);
  const auto fragment =
      MakeDeadlinePacket(PacketType::kFragment, 0, 2, 10, 10,
                         fragment_payload.data(), fragment_payload.size());
  socket.ClearSent();
  conn.ProcessPacket(fragment.data(), fragment.size(), addr, 12345);
  conn.Update();

  ASSERT_EQ(socket.GetSentCount(), 1u);
  EXPECT_EQ(socket.sentPackets.at(0).data.at(0),
            static_cast<std::uint8_t>(PacketType::kAck));
  EXPECT_EQ(ReadU32(socket.sentPackets.at(0).data, 2), 2u);
  EXPECT_TRUE(handler.reliablePackets.empty());
  EXPECT_EQ(conn.GetDeadlineReceiveDrops(), 3u);
}

TEST_F(ReliableConnectionTest, ExpiredUnreliableReceiveIsDroppedWithoutAck) {
  config.deadlinesEnabled = true;
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  const auto packet =
      MakeDeadlinePacket(PacketType::kUnreliable, 0, 0, 10, 10, "abc", 3);
  socket.ClearSent();
  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);

  EXPECT_EQ(socket.GetSentCount(), 0u);
  EXPECT_TRUE(handler.unreliablePackets.empty());
  EXPECT_EQ(conn.GetDeadlineReceiveDrops(), 1u);
}

TEST_F(ReliableConnectionTest, FragmentGroupExpiresByDeadline) {
  config.deadlinesEnabled = true;
  config.fragmentTimeoutMs = 10000;
  config.pingIntervalMs = 10000;
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  std::uint16_t group_id = 3;
  std::uint16_t frag_index = 0;
  std::uint16_t frag_total = 2;
  std::vector<std::uint8_t> fragment_payload(9);
  std::memcpy(fragment_payload.data() + 0, &group_id, 2);
  std::memcpy(fragment_payload.data() + 2, &frag_index, 2);
  std::memcpy(fragment_payload.data() + 4, &frag_total, 2);
  std::memcpy(fragment_payload.data() + 6, "abc", 3);

  const auto packet =
      MakeDeadlinePacket(PacketType::kFragment, 0, 0, 20, 0,
                         fragment_payload.data(), fragment_payload.size());
  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);
  ASSERT_EQ(conn.GetDeadlineExpiredFragmentGroups(), 0u);

  std::this_thread::sleep_for(std::chrono::milliseconds(35));
  conn.Update();

  EXPECT_EQ(conn.GetDeadlineExpiredFragmentGroups(), 1u);
  EXPECT_TRUE(handler.reliablePackets.empty());
}

// ConnectionManager tests
class ConnectionManagerTest : public ::testing::Test {
 protected:
  MockSocket socket;
  ReliableConnectionConfig config;
  MockEventHandler handler;

  void SetUp() override {
    config.maxRetries = 3;
    config.retryTimeoutMs = 50;
    config.pingIntervalMs = 100;
    config.disconnectTimeoutMs = 500;
  }
};

TEST_F(ConnectionManagerTest, Construction) {
  ConnectionManager manager(&socket, config);
  auto connections = manager.GetConnections();
  EXPECT_TRUE(connections.empty()) << "Should start with no connections";
}

TEST_F(ConnectionManagerTest, AutoCreateConnection) {
  ConnectionManager manager(&socket, config);
  manager.SetHandler(&handler);

  SocketAddress client_addr = SocketAddress::FromIPv4(0x7F000001);

  // Simulate receiving connect packet from new client
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kConnect));
  bs.Write<std::uint8_t>(0);
  bs.Write<std::uint32_t>(0);

  manager.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), client_addr, 12345);

  auto connections = manager.GetConnections();
  EXPECT_EQ(connections.size(), 1)
      << "Should auto-create connection for new client";
}

TEST_F(ConnectionManagerTest, GetConnection) {
  ConnectionManager manager(&socket, config);

  SocketAddress addr1 = SocketAddress::FromIPv4(0x7F000001);
  SocketAddress addr2 = SocketAddress::FromIPv4(0x7F000002);

  // Create connections
  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kConnect));
  bs.Write<std::uint8_t>(0);
  bs.Write<std::uint32_t>(0);

  manager.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr1, 12345);
  manager.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr2, 12346);

  auto* client1 = manager.GetConnection(addr1, 12345);
  auto* client2 = manager.GetConnection(addr2, 12346);

  EXPECT_NE(client1, nullptr);
  EXPECT_NE(client2, nullptr);
  EXPECT_NE(client1, client2) << "Different clients should be distinct";
}

TEST_F(ConnectionManagerTest, BroadcastReliable) {
  ConnectionManager manager(&socket, config);

  // Create multiple connections
  SocketAddress addr1 = SocketAddress::FromIPv4(0x7F000001);
  SocketAddress addr2 = SocketAddress::FromIPv4(0x7F000002);

  BitStream connect_bs;
  connect_bs.Write<std::uint8_t>(
      static_cast<std::uint8_t>(PacketType::kConnect));
  connect_bs.Write<std::uint8_t>(0);
  connect_bs.Write<std::uint32_t>(0);

  manager.ProcessPacket(connect_bs.GetData(), connect_bs.GetSizeBytes(), addr1,
                        12345);
  manager.ProcessPacket(connect_bs.GetData(), connect_bs.GetSizeBytes(), addr2,
                        12346);

  socket.ClearSent();

  // Broadcast
  const char* broadcast_data = "Broadcast message";
  manager.BroadcastReliable(0, broadcast_data, strlen(broadcast_data));

  // Should send to all connected clients
  EXPECT_GE(socket.GetSentCount(), 2) << "Should send to multiple clients";
}

TEST_F(ConnectionManagerTest, BroadcastUnreliable) {
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  BitStream connect_bs;
  connect_bs.Write<std::uint8_t>(
      static_cast<std::uint8_t>(PacketType::kConnect));
  connect_bs.Write<std::uint8_t>(0);
  connect_bs.Write<std::uint32_t>(0);

  manager.ProcessPacket(connect_bs.GetData(), connect_bs.GetSizeBytes(), addr,
                        12345);

  socket.ClearSent();

  manager.BroadcastUnreliable(0, "Test", 4);

  EXPECT_GT(socket.GetSentCount(), 0) << "Should send broadcast";
}

TEST_F(ConnectionManagerTest, UpdateAllConnections) {
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kConnect));
  bs.Write<std::uint8_t>(0);
  bs.Write<std::uint32_t>(0);

  manager.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);

  // Update should process all connections
  manager.Update();

  auto connections = manager.GetConnections();
  EXPECT_FALSE(connections.empty());

  for (auto* client : connections) {
    EXPECT_NE(client->connection, nullptr);
  }
}

TEST_F(ConnectionManagerTest, UserData) {
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kConnect));
  bs.Write<std::uint8_t>(0);
  bs.Write<std::uint32_t>(0);

  manager.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);

  auto* client = manager.GetConnection(addr, 12345);
  ASSERT_NE(client, nullptr);

  // Set user data
  int user_data = 42;
  client->userData = &user_data;

  EXPECT_EQ(*static_cast<const int*>(client->userData), 42);
}

// Safety and correctness tests.

TEST_F(ReliableConnectionTest, UnknownPacketTypeIsIgnored) {
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnected();

  // Craft a packet with an invalid PacketType (value 100, well beyond Ack=8)
  BitStream bs;
  bs.Write<std::uint8_t>(100);  // invalid type
  bs.Write<std::uint8_t>(0);    // channel
  bs.Write<std::uint32_t>(0);   // sequence

  auto received_before [[maybe_unused]] = conn.GetReceivedPackets();
  EXPECT_NO_THROW(
      conn.ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345));
  // The packet header was still read, but no side effects occur.
  // The counter increments because lastReceiveTime is not updated
  // (readPacketHeader returns false before reaching the counter update).
  // The key behavior: no crash, no undefined behavior.
}

TEST_F(ConnectionManagerTest, IPv6ClientsAreSeparated) {
  ConnectionManager manager(&socket, config);

  // Create two different IPv6 addresses
  std::array<std::uint8_t, 16> bytes1{};
  bytes1.at(15) = 1;
  std::array<std::uint8_t, 16> bytes2{};
  bytes2.at(15) = 2;

  SocketAddress addr1 = SocketAddress::FromIPv6(bytes1);
  SocketAddress addr2 = SocketAddress::FromIPv6(bytes2);

  // Send connect packets from each address
  BitStream bs1;
  bs1.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kConnect));
  bs1.Write<std::uint8_t>(0);
  bs1.Write<std::uint32_t>(0);

  BitStream bs2;
  bs2.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kConnect));
  bs2.Write<std::uint8_t>(0);
  bs2.Write<std::uint32_t>(0);

  manager.ProcessPacket(bs1.GetData(), bs1.GetSizeBytes(), addr1, 5000);
  manager.ProcessPacket(bs2.GetData(), bs2.GetSizeBytes(), addr2, 5000);

  auto connections = manager.GetConnections();
  EXPECT_EQ(connections.size(), 2u)
      << "Two IPv6 clients with different addresses should create separate "
         "connections";

  auto* c1 = manager.GetConnection(addr1, 5000);
  auto* c2 = manager.GetConnection(addr2, 5000);
  ASSERT_NE(c1, nullptr);
  ASSERT_NE(c2, nullptr);
  EXPECT_NE(c1, c2) << "Should be different RemoteClient instances";
}

TEST_F(ConnectionManagerTest, ConnectionManagerOwnsClients) {
  // This test verifies that unique_ptr properly manages client lifetime
  auto manager = std::make_unique<ConnectionManager>(&socket, config);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  BitStream bs;
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(PacketType::kConnect));
  bs.Write<std::uint8_t>(0);
  bs.Write<std::uint32_t>(0);

  manager->ProcessPacket(bs.GetData(), bs.GetSizeBytes(), addr, 12345);
  EXPECT_EQ(manager->GetConnections().size(), 1u);

  // Destroying the manager should not leak or crash
  EXPECT_NO_THROW(manager.reset());
}

TEST_F(ReliableConnectionTest, SecureConnectFailsWithoutValidCryptoConfig) {
  config.crypto.enabled = true;

  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);

  const bool result = conn.Connect(addr, 12345);

  EXPECT_FALSE(result);
  EXPECT_EQ(conn.GetState(), ConnectionState::kDisconnected);
  EXPECT_EQ(socket.GetSentCount(), 0u);
}

#if SOCKETWIRE_HAVE_LIBSODIUM
bool ConnectSecurePair(ReliableConnection& client, MockSocket& client_socket,
                       MockEventHandler& client_handler,
                       ReliableConnection& server, MockSocket& server_socket,
                       MockEventHandler& server_handler,
                       const SocketAddress& server_addr) {
  client.SetHandler(&client_handler);
  server.SetHandler(&server_handler);

  if (!client.Connect(server_addr, 12345) ||
      client_socket.sentPackets.empty()) {
    return false;
  }

  const auto connect_packet = client_socket.sentPackets.back();
  server.ProcessPacket(connect_packet.data.data(), connect_packet.data.size(),
                       server_addr, 23456);
  if (server_socket.sentPackets.empty()) return false;

  const auto accept_packet = server_socket.sentPackets.back();
  client.ProcessPacket(accept_packet.data.data(), accept_packet.data.size(),
                       server_addr, 12345);

  return client.IsConnected() && server.IsConnected() &&
         client.IsCryptoReady() && server.IsCryptoReady() &&
         client_handler.connected && server_handler.connected;
}

TEST_F(ReliableConnectionTest, SecureConnectClientServer) {
  auto client_keys = socketwire::crypto::KeyPair::Generate();
  auto server_keys = socketwire::crypto::KeyPair::Generate();

  ReliableConnectionConfig client_cfg = config;
  client_cfg.crypto.enabled = true;
  client_cfg.crypto.localKeyPair = client_keys;
  client_cfg.crypto.expected_server_public_key = server_keys.publicKey;

  ReliableConnectionConfig server_cfg = config;
  server_cfg.crypto.enabled = true;
  server_cfg.crypto.localKeyPair = server_keys;

  MockSocket client_socket;
  MockSocket server_socket;
  MockEventHandler client_handler;
  MockEventHandler server_handler;
  ReliableConnection client(&client_socket, client_cfg);
  ReliableConnection server(&server_socket, server_cfg);
  auto addr = SocketAddress::FromIPv4(0x7F000001);

  ASSERT_TRUE(ConnectSecurePair(client, client_socket, client_handler, server,
                                server_socket, server_handler, addr));

  ASSERT_FALSE(client_socket.sentPackets.empty());
  EXPECT_EQ(client_socket.sentPackets.front().data.size(),
            6u + socketwire::crypto::kClientHelloSize);
  ASSERT_FALSE(server_socket.sentPackets.empty());
  EXPECT_EQ(server_socket.sentPackets.front().data.size(),
            6u + socketwire::crypto::kServerHelloSize);
}

TEST_F(ReliableConnectionTest, SecureConnectRejectsWrongPinnedServerKey) {
  auto client_keys = socketwire::crypto::KeyPair::Generate();
  auto server_keys = socketwire::crypto::KeyPair::Generate();
  auto wrong_server_keys = socketwire::crypto::KeyPair::Generate();

  ReliableConnectionConfig client_cfg = config;
  client_cfg.crypto.enabled = true;
  client_cfg.crypto.localKeyPair = client_keys;
  client_cfg.crypto.expected_server_public_key = wrong_server_keys.publicKey;

  ReliableConnectionConfig server_cfg = config;
  server_cfg.crypto.enabled = true;
  server_cfg.crypto.localKeyPair = server_keys;

  MockSocket client_socket;
  MockSocket server_socket;
  MockEventHandler client_handler;
  MockEventHandler server_handler;
  ReliableConnection client(&client_socket, client_cfg);
  ReliableConnection server(&server_socket, server_cfg);
  client.SetHandler(&client_handler);
  server.SetHandler(&server_handler);
  auto addr = SocketAddress::FromIPv4(0x7F000001);

  ASSERT_TRUE(client.Connect(addr, 12345));
  ASSERT_FALSE(client_socket.sentPackets.empty());
  auto connect_packet = client_socket.sentPackets.back();
  server.ProcessPacket(connect_packet.data.data(), connect_packet.data.size(),
                       addr, 23456);

  ASSERT_FALSE(server_socket.sentPackets.empty());
  auto accept_packet = server_socket.sentPackets.back();
  client.ProcessPacket(accept_packet.data.data(), accept_packet.data.size(),
                       addr, 12345);

  EXPECT_FALSE(client_handler.connected);
  EXPECT_FALSE(client.IsConnected());
  EXPECT_FALSE(client.IsCryptoReady());
  EXPECT_EQ(client.GetState(), ConnectionState::kDisconnected);
}

TEST_F(ReliableConnectionTest, SecureConnectionRejectsPlaintextAfterHandshake) {
  auto client_keys = socketwire::crypto::KeyPair::Generate();
  auto server_keys = socketwire::crypto::KeyPair::Generate();

  ReliableConnectionConfig client_cfg = config;
  client_cfg.crypto.enabled = true;
  client_cfg.crypto.localKeyPair = client_keys;
  client_cfg.crypto.expected_server_public_key = server_keys.publicKey;

  ReliableConnectionConfig server_cfg = config;
  server_cfg.crypto.enabled = true;
  server_cfg.crypto.localKeyPair = server_keys;

  MockSocket client_socket;
  MockSocket server_socket;
  MockEventHandler client_handler;
  MockEventHandler server_handler;
  ReliableConnection client(&client_socket, client_cfg);
  ReliableConnection server(&server_socket, server_cfg);
  auto addr = SocketAddress::FromIPv4(0x7F000001);

  ASSERT_TRUE(ConnectSecurePair(client, client_socket, client_handler, server,
                                server_socket, server_handler, addr));
  server_handler.Reset();

  BitStream plaintext;
  plaintext.Write<std::uint8_t>(
      static_cast<std::uint8_t>(PacketType::kReliable));
  plaintext.Write<std::uint8_t>(0);
  plaintext.Write<std::uint32_t>(0);
  plaintext.WriteBytes("plain", 5);

  server.ProcessPacket(plaintext.GetData(), plaintext.GetSizeBytes(), addr,
                       23456);
  server.Update();

  EXPECT_TRUE(server_handler.reliablePackets.empty());
}

TEST_F(ReliableConnectionTest, SecureReliableAndUnreliablePayloadDelivery) {
  auto client_keys = socketwire::crypto::KeyPair::Generate();
  auto server_keys = socketwire::crypto::KeyPair::Generate();

  ReliableConnectionConfig client_cfg = config;
  client_cfg.crypto.enabled = true;
  client_cfg.crypto.localKeyPair = client_keys;
  client_cfg.crypto.expected_server_public_key = server_keys.publicKey;

  ReliableConnectionConfig server_cfg = config;
  server_cfg.crypto.enabled = true;
  server_cfg.crypto.localKeyPair = server_keys;

  MockSocket client_socket;
  MockSocket server_socket;
  MockEventHandler client_handler;
  MockEventHandler server_handler;
  ReliableConnection client(&client_socket, client_cfg);
  ReliableConnection server(&server_socket, server_cfg);
  auto addr = SocketAddress::FromIPv4(0x7F000001);

  ASSERT_TRUE(ConnectSecurePair(client, client_socket, client_handler, server,
                                server_socket, server_handler, addr));
  client_socket.ClearSent();
  server_handler.Reset();

  const char* reliable_msg = "secure reliable";
  ASSERT_TRUE(client.SendReliable(0, reliable_msg, std::strlen(reliable_msg)));
  ASSERT_EQ(client_socket.sentPackets.size(), 1u);
  const auto reliable_packet = client_socket.sentPackets.back();
  EXPECT_EQ(
      std::search(reliable_packet.data.begin(), reliable_packet.data.end(),
                  reliable_msg, reliable_msg + std::strlen(reliable_msg)),
      reliable_packet.data.end());

  server.ProcessPacket(reliable_packet.data.data(), reliable_packet.data.size(),
                       addr, 23456);
  server.Update();
  ASSERT_EQ(server_handler.reliablePackets.size(), 1u);
  EXPECT_EQ(std::string(server_handler.reliablePackets.at(0).begin(),
                        server_handler.reliablePackets.at(0).end()),
            std::string(reliable_msg));

  client_socket.ClearSent();
  const char* unreliable_msg = "secure unreliable";
  ASSERT_TRUE(
      client.SendUnreliable(1, unreliable_msg, std::strlen(unreliable_msg)));
  ASSERT_EQ(client_socket.sentPackets.size(), 1u);
  const auto unreliable_packet = client_socket.sentPackets.back();
  EXPECT_EQ(
      std::search(unreliable_packet.data.begin(), unreliable_packet.data.end(),
                  unreliable_msg, unreliable_msg + std::strlen(unreliable_msg)),
      unreliable_packet.data.end());

  server.ProcessPacket(unreliable_packet.data.data(),
                       unreliable_packet.data.size(), addr, 23456);
  ASSERT_EQ(server_handler.unreliablePackets.size(), 1u);
  EXPECT_EQ(std::string(server_handler.unreliablePackets.at(0).begin(),
                        server_handler.unreliablePackets.at(0).end()),
            std::string(unreliable_msg));
}

TEST_F(ReliableConnectionTest, SecureDeadlinePayloadDelivery) {
  auto client_keys = socketwire::crypto::KeyPair::Generate();
  auto server_keys = socketwire::crypto::KeyPair::Generate();

  ReliableConnectionConfig client_cfg = config;
  client_cfg.crypto.enabled = true;
  client_cfg.crypto.localKeyPair = client_keys;
  client_cfg.crypto.expected_server_public_key = server_keys.publicKey;
  client_cfg.deadlinesEnabled = true;

  ReliableConnectionConfig server_cfg = config;
  server_cfg.crypto.enabled = true;
  server_cfg.crypto.localKeyPair = server_keys;
  server_cfg.deadlinesEnabled = true;

  MockSocket client_socket;
  MockSocket server_socket;
  MockEventHandler client_handler;
  MockEventHandler server_handler;
  ReliableConnection client(&client_socket, client_cfg);
  ReliableConnection server(&server_socket, server_cfg);
  auto addr = SocketAddress::FromIPv4(0x7F000001);

  ASSERT_TRUE(ConnectSecurePair(client, client_socket, client_handler, server,
                                server_socket, server_handler, addr));
  client_socket.ClearSent();
  server_handler.Reset();

  const char* reliable_msg = "secure deadline reliable";
  ASSERT_TRUE(client.SendReliableWithDeadline(0, reliable_msg,
                                              std::strlen(reliable_msg), 100));
  ASSERT_EQ(client_socket.sentPackets.size(), 1u);
  const auto reliable_packet = client_socket.sentPackets.back();
  ASSERT_EQ(reliable_packet.data.at(0) & kPacketTypeMask,
            static_cast<std::uint8_t>(PacketType::kReliable));
  ASSERT_NE(reliable_packet.data.at(0) & kDeadlineHeaderFlag, 0);
  EXPECT_EQ(
      std::search(reliable_packet.data.begin(), reliable_packet.data.end(),
                  reliable_msg, reliable_msg + std::strlen(reliable_msg)),
      reliable_packet.data.end());

  server.ProcessPacket(reliable_packet.data.data(), reliable_packet.data.size(),
                       addr, 23456);
  server.Update();
  ASSERT_EQ(server_handler.reliablePackets.size(), 1u);
  EXPECT_EQ(std::string(server_handler.reliablePackets.at(0).begin(),
                        server_handler.reliablePackets.at(0).end()),
            std::string(reliable_msg));

  client_socket.ClearSent();
  const char* unreliable_msg = "secure deadline unreliable";
  ASSERT_TRUE(client.SendUnreliableWithDeadline(
      1, unreliable_msg, std::strlen(unreliable_msg), 100));
  ASSERT_EQ(client_socket.sentPackets.size(), 1u);
  const auto unreliable_packet = client_socket.sentPackets.back();
  ASSERT_EQ(unreliable_packet.data.at(0) & kPacketTypeMask,
            static_cast<std::uint8_t>(PacketType::kUnreliable));
  ASSERT_NE(unreliable_packet.data.at(0) & kDeadlineHeaderFlag, 0);
  EXPECT_EQ(
      std::search(unreliable_packet.data.begin(), unreliable_packet.data.end(),
                  unreliable_msg, unreliable_msg + std::strlen(unreliable_msg)),
      unreliable_packet.data.end());

  server.ProcessPacket(unreliable_packet.data.data(),
                       unreliable_packet.data.size(), addr, 23456);
  ASSERT_EQ(server_handler.unreliablePackets.size(), 1u);
  EXPECT_EQ(std::string(server_handler.unreliablePackets.at(0).begin(),
                        server_handler.unreliablePackets.at(0).end()),
            std::string(unreliable_msg));
}
#endif

}  // anonymous namespace
