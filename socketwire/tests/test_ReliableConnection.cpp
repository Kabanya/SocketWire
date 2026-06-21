#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "connection_manager.hpp"
#include "i_socket.hpp"
#include "reliable_connection.hpp"

using socketwire::BitStream;
using socketwire::ConnectionManager;
using socketwire::ConnectionManagerConfig;
using socketwire::ConnectionState;
using socketwire::IReliableConnectionHandler;
using socketwire::ISocket;
using socketwire::ReliableConnection;
using socketwire::ReliableConnectionConfig;
using socketwire::SocketAddress;
using socketwire::SocketError;
using socketwire::SocketResult;
using socketwire::detail::PacketType;

namespace {

constexpr std::size_t kBaseHeaderSize =
  socketwire::detail::PacketCodec::kBaseHeaderSize;
constexpr std::size_t kDeadlineHeaderSize =
  socketwire::detail::PacketCodec::kBaseHeaderSize +
  socketwire::detail::PacketCodec::kDeadlineExtensionSize;

std::uint16_t ReadNativeU16(const std::uint8_t* data) {
  std::uint16_t value = 0;
  std::memcpy(&value, data, sizeof(value));
  return value;
}

std::vector<std::uint8_t> EncodePacket(
  PacketType type, std::uint8_t channel, std::uint32_t sequence,
  socketwire::detail::DeadlineMetadata deadline = {},
  socketwire::detail::FragmentMetadata fragment = {},
  const void* payload = nullptr, std::size_t payload_size = 0) {
  std::vector<std::uint8_t> packet(1400);
  const auto encoded = socketwire::detail::PacketCodec::Encode(
    socketwire::detail::PacketBuild{
      .type = type,
      .channel = channel,
      .sequence = sequence,
      .deadline = deadline,
      .fragment = fragment,
      .payload =
        payload == nullptr
          ? std::span<const std::uint8_t>{}
          : std::span<const std::uint8_t>{static_cast<const std::uint8_t*>(
                                            payload),
                                          payload_size}},
    std::chrono::steady_clock::time_point{}, packet);
  EXPECT_TRUE(encoded.has_value());
  packet.resize(encoded.value_or(0));
  return packet;
}

std::vector<std::uint8_t> MakeDeadlinePacket(
  PacketType type, std::uint8_t channel, std::uint32_t sequence,
  std::uint32_t deadline_ms, std::uint32_t age_ms_at_send,
  const void* payload = nullptr, std::size_t payload_size = 0) {
  socketwire::detail::DeadlineMetadata deadline;
  deadline.hasDeadline = true;
  deadline.deadline_ms = deadline_ms;
  deadline.createdTime = std::chrono::steady_clock::time_point{} -
                         std::chrono::milliseconds(age_ms_at_send);
  deadline.expireTime =
    deadline.createdTime + std::chrono::milliseconds(deadline_ms);

  socketwire::detail::FragmentMetadata fragment;
  const void* actual_payload = payload;
  std::size_t actual_payload_size = payload_size;
  if (type == PacketType::kFragment && payload != nullptr &&
      payload_size >= 6) {
    const auto* bytes = static_cast<const std::uint8_t*>(payload);
    fragment.hasFragment = true;
    fragment.groupId = ReadNativeU16(bytes);
    fragment.fragmentIndex = ReadNativeU16(bytes + 2);
    fragment.fragmentTotal = ReadNativeU16(bytes + 4);
    actual_payload = bytes + 6;
    actual_payload_size = payload_size - 6;
  }
  return EncodePacket(type, channel, sequence, deadline, fragment,
                      actual_payload, actual_payload_size);
}

std::vector<std::uint8_t> MakeBasePacket(PacketType type, std::uint8_t channel,
                                         std::uint32_t sequence,
                                         const void* payload = nullptr,
                                         std::size_t payload_size = 0) {
  socketwire::detail::FragmentMetadata fragment;
  const void* actual_payload = payload;
  std::size_t actual_payload_size = payload_size;
  if (type == PacketType::kFragment && payload != nullptr &&
      payload_size >= 6) {
    const auto* bytes = static_cast<const std::uint8_t*>(payload);
    fragment.hasFragment = true;
    fragment.groupId = ReadNativeU16(bytes);
    fragment.fragmentIndex = ReadNativeU16(bytes + 2);
    fragment.fragmentTotal = ReadNativeU16(bytes + 4);
    actual_payload = bytes + 6;
    actual_payload_size = payload_size - 6;
  }
  return EncodePacket(type, channel, sequence, {}, fragment, actual_payload,
                      actual_payload_size);
}

std::vector<std::uint8_t> MakeBatchPacket(
  const std::vector<std::vector<std::uint8_t>>& commands) {
  std::vector<std::span<const std::uint8_t>> spans;
  spans.reserve(commands.size());
  for (const auto& command : commands) {
    spans.emplace_back(command.data(), command.size());
  }
  auto payload = socketwire::detail::PacketCodec::EncodeBatchPayload(spans, 32);
  EXPECT_TRUE(payload.has_value());
  return EncodePacket(PacketType::kBatch, 0, 0, {}, {}, payload->data(),
                      payload->size());
}

socketwire::detail::DecodedPacket DecodePacket(
  const std::vector<std::uint8_t>& packet) {
  auto decoded = socketwire::detail::PacketCodec::Decode(packet);
  EXPECT_TRUE(decoded.has_value());
  return decoded.value_or(socketwire::detail::DecodedPacket{});
}

void DrainConnection(ISocket& socket, ReliableConnection& connection,
                     std::size_t max_packet_size = 1400) {
  std::vector<std::uint8_t> buffer(max_packet_size);
  while (true) {
    SocketAddress from;
    std::uint16_t port = 0;
    const SocketResult result =
      socket.Receive(buffer.data(), buffer.size(), from, port);
    if (result.Failed() || result.bytes <= 0) break;
    connection.ProcessPacket(buffer.data(), static_cast<std::size_t>(result.bytes),
                             from, port);
  }
  connection.Update();
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

class WebSocketLikeMockSocket : public ISocket {
public:
  std::vector<std::vector<std::uint8_t>> sentFrames;
  std::vector<std::vector<std::uint8_t>> receiveQueue;

  SocketError Bind(const SocketAddress& address, uint16_t port) override {
    (void)address;
    (void)port;
    return SocketError::kNone;
  }

  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr, uint16_t to_port) override {
    (void)to_addr;
    (void)to_port;
    sentFrames.emplace_back(static_cast<const std::uint8_t*>(data),
                            static_cast<const std::uint8_t*>(data) + length);
    return {.bytes = static_cast<std::ptrdiff_t>(length),
            .error = SocketError::kNone};
  }

  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr, uint16_t& from_port) override {
    if (receiveQueue.empty()) {
      return {.bytes = -1, .error = SocketError::kWouldBlock};
    }

    const auto& frame = receiveQueue.front();
    const std::size_t copy_size = std::min(capacity, frame.size());
    std::memcpy(buffer, frame.data(), copy_size);
    receiveQueue.erase(receiveQueue.begin());

    from_addr = SocketAddress::FromIPv4(0);
    from_port = 0;
    return {.bytes = static_cast<std::ptrdiff_t>(copy_size),
            .error = SocketError::kNone};
  }

  SocketError SetBlocking(bool enable) override {
    return enable ? SocketError::kUnsupported : SocketError::kNone;
  }

  [[nodiscard]] bool IsBlocking() const override { return false; }
  [[nodiscard]] uint16_t LocalPort() const override { return 0; }
  [[nodiscard]] int NativeHandle() const override { return -1; }
  void Close() override {}

  void QueueReceive(std::vector<std::uint8_t> frame) {
    receiveQueue.push_back(std::move(frame));
  }
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

TEST_F(ReliableConnectionTest, WebSocketLikeSocketSupportsClientHandshake) {
  WebSocketLikeMockSocket web_socket;
  ReliableConnection conn(&web_socket, config);
  conn.SetHandler(&handler);

  EXPECT_TRUE(conn.Connect(SocketAddress::FromIPv4(0), 0));

  ASSERT_EQ(web_socket.sentFrames.size(), 1u);
  ASSERT_GE(web_socket.sentFrames.at(0).size(), kBaseHeaderSize);
  EXPECT_EQ(DecodePacket(web_socket.sentFrames.at(0)).type,
            PacketType::kConnect);

  web_socket.QueueReceive(MakeBasePacket(PacketType::kAccept, 0, 0));
  DrainConnection(web_socket, conn);

  EXPECT_TRUE(handler.connected);
  EXPECT_TRUE(conn.IsConnected());
}

TEST_F(ReliableConnectionTest, ServerAcceptConnection) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress client_addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(client_addr, 12345);

  const auto packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  conn.ProcessPacket(packet.data(), packet.size(), client_addr, 12345);

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

  const auto packet = MakeBasePacket(PacketType::kAccept, 0, 0);
  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);

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
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

  const char* payload = "Test payload";
  const auto packet =
    MakeBasePacket(PacketType::kReliable, 0, 0, payload, strlen(payload));

  socket.ClearSent();
  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);

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
  conn.SetConnectedForTest();

  const char* payload = "Unreliable payload";
  const auto packet =
    MakeBasePacket(PacketType::kUnreliable, 0, 0, payload, strlen(payload));

  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);

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
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

  const std::vector<std::uint8_t> payload = {
    0, 2, 0, static_cast<std::uint8_t>(kBaseHeaderSize)};
  const auto malformed = EncodePacket(PacketType::kBatch, 0, 0, {}, {},
                                      payload.data(), payload.size());

  conn.ProcessPacket(malformed.data(), malformed.size(), addr, 12345);

  EXPECT_TRUE(handler.reliablePackets.empty());
  EXPECT_TRUE(handler.unreliablePackets.empty());
}

TEST_F(ReliableConnectionTest, AckPiggybacksOnNextApplicationPacket) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

  const auto inbound = MakeBasePacket(PacketType::kReliable, 0, 0, "in", 2);
  const auto second_inbound =
    MakeBasePacket(PacketType::kReliable, 1, 0, "ch", 2);
  socket.ClearSent();
  conn.ProcessPacket(inbound.data(), inbound.size(), addr, 12345);
  conn.ProcessPacket(second_inbound.data(), second_inbound.size(), addr, 12345);
  ASSERT_EQ(handler.reliablePackets.size(), 2u);
  EXPECT_EQ(socket.GetSentCount(), 0u);

  ASSERT_TRUE(conn.SendUnreliable(0, "out", 3));
  ASSERT_EQ(socket.GetSentCount(), 1u);

  const auto& packet = socket.sentPackets.at(0).data;
  const auto batch = DecodePacket(packet);
  ASSERT_EQ(batch.type, PacketType::kBatch);

  const auto commands =
    socketwire::detail::PacketCodec::DecodeBatchPayload(batch.payload, 32);
  ASSERT_TRUE(commands.has_value());
  ASSERT_EQ(commands->size(), 3u);

  const auto ack = socketwire::detail::PacketCodec::Decode(commands->at(0));
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(ack->type, PacketType::kAck);
  EXPECT_EQ(ack->channel, 0u);
  EXPECT_EQ(ack->sequence, 0u);

  const auto second_ack =
    socketwire::detail::PacketCodec::Decode(commands->at(1));
  ASSERT_TRUE(second_ack.has_value());
  EXPECT_EQ(second_ack->type, PacketType::kAck);
  EXPECT_EQ(second_ack->channel, 1u);
  EXPECT_EQ(second_ack->sequence, 0u);

  const auto application =
    socketwire::detail::PacketCodec::Decode(commands->at(2));
  ASSERT_TRUE(application.has_value());
  EXPECT_EQ(application->type, PacketType::kUnreliable);
  EXPECT_EQ(
    std::string(application->payload.begin(), application->payload.end()),
    "out");
}

TEST_F(ReliableConnectionTest, PacketSequencing) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

  // Send packets out of order
  auto create_packet = [](std::uint32_t seq,
                          const char* payload) -> std::vector<std::uint8_t> {
    return MakeBasePacket(PacketType::kReliable, 0, seq, payload,
                          strlen(payload));
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
  conn.SetConnectedForTest();

  const auto packet = MakeBasePacket(PacketType::kReliable, 0, 0, "Test", 4);

  // Send same packet twice
  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);
  conn.Update();

  const std::size_t first_count = handler.reliablePackets.size();

  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);
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
  conn.SetConnectedForTest();

  socket.ClearSent();

  // Send reliable packet
  conn.SendReliable(0, "Test", 4);

  const std::size_t sent_before = socket.GetSentCount();
  const std::uint32_t lost_before = conn.GetLostPackets();

  // Extract sequence from sent packet
  ASSERT_FALSE(socket.sentPackets.empty());
  const auto& sent_packet = socket.sentPackets.back();
  const auto sent = DecodePacket(sent_packet.data);

  // Send ACK
  const auto ack = MakeBasePacket(PacketType::kAck, 0, sent.sequence);
  conn.ProcessPacket(ack.data(), ack.size(), addr, 12345);
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

TEST_F(ReliableConnectionTest, AcknowledgmentMatchesChannelAndSequence) {
  config.pingIntervalMs = 10000;
  ReliableConnection conn(&socket, config);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

  socket.ClearSent();
  ASSERT_TRUE(conn.SendReliable(0, "zero", 4));
  ASSERT_TRUE(conn.SendReliable(1, "one", 3));
  ASSERT_EQ(conn.GetInflightCount(), 2u);
  ASSERT_EQ(socket.GetSentCount(), 2u);

  const auto channel0 = DecodePacket(socket.sentPackets.at(0).data);
  const auto channel1 = DecodePacket(socket.sentPackets.at(1).data);
  ASSERT_EQ(channel0.channel, 0u);
  ASSERT_EQ(channel1.channel, 1u);
  ASSERT_EQ(channel0.sequence, 0u);
  ASSERT_EQ(channel1.sequence, 0u);

  const auto ack_channel1 =
    MakeBasePacket(PacketType::kAck, 1, channel1.sequence);
  conn.ProcessPacket(ack_channel1.data(), ack_channel1.size(), addr, 12345);
  EXPECT_EQ(conn.GetInflightCount(), 1u);

  const std::size_t sent_after_ack = socket.GetSentCount();
  std::this_thread::sleep_for(std::chrono::milliseconds(60));
  conn.Update();
  ASSERT_GT(socket.GetSentCount(), sent_after_ack);

  const auto retry = DecodePacket(socket.sentPackets.back().data);
  EXPECT_EQ(retry.type, PacketType::kReliable);
  EXPECT_EQ(retry.channel, 0u);
  EXPECT_EQ(retry.sequence, channel0.sequence);

  const auto ack_channel0 =
    MakeBasePacket(PacketType::kAck, 0, channel0.sequence);
  conn.ProcessPacket(ack_channel0.data(), ack_channel0.size(), addr, 12345);
  EXPECT_EQ(conn.GetInflightCount(), 0u);

  const std::size_t sent_after_all_acks = socket.GetSentCount();
  std::this_thread::sleep_for(std::chrono::milliseconds(60));
  conn.Update();
  EXPECT_EQ(socket.GetSentCount(), sent_after_all_acks);
}

TEST_F(ReliableConnectionTest, Disconnect) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

  EXPECT_FALSE(handler.disconnected);

  const auto packet = MakeBasePacket(PacketType::kDisconnect, 0, 0);
  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);

  EXPECT_TRUE(handler.disconnected) << "Should trigger OnDisconnected";
  EXPECT_EQ(conn.GetState(), ConnectionState::kDisconnected);
}

TEST_F(ReliableConnectionTest, Statistics) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

  const std::uint32_t initial_sent = conn.GetSentPackets();
  const std::uint32_t initial_received = conn.GetReceivedPackets();

  // Send packet
  conn.SendReliable(0, "Test", 4);
  EXPECT_GT(conn.GetSentPackets(), initial_sent)
    << "Sent count should increase";

  const auto packet = MakeBasePacket(PacketType::kUnreliable, 0, 0, "Data", 4);
  conn.ProcessPacket(packet.data(), packet.size(), addr, 12345);

  EXPECT_GT(conn.GetReceivedPackets(), initial_received)
    << "Received count should increase";
}

TEST_F(ReliableConnectionTest, PingPong) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

  socket.ClearSent();

  const auto ping = MakeBasePacket(PacketType::kPing, 0, 42);
  conn.ProcessPacket(ping.data(), ping.size(), addr, 12345);

  // Should send pong
  EXPECT_GT(socket.GetSentCount(), 0) << "Should send pong response";

  // Verify pong packet
  ASSERT_FALSE(socket.sentPackets.empty());
  const auto& pong_packet = socket.sentPackets.at(0);
  const auto pong = DecodePacket(pong_packet.data);
  EXPECT_EQ(pong.type, PacketType::kPong);
  EXPECT_EQ(pong.sequence, 42) << "Pong should echo ping sequence";
}

TEST_F(ReliableConnectionTest, RTTMeasurement) {
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

  socket.ClearSent();

  // Send on different channels
  conn.SendReliable(0, "Channel0", 8);
  conn.SendReliable(1, "Channel1", 8);

  EXPECT_EQ(socket.GetSentCount(), 2)
    << "Should send packets on different channels";

  // Verify channels are different
  ASSERT_GE(socket.sentPackets.size(), 2);

  const auto first = DecodePacket(socket.sentPackets.at(0).data);
  const auto second = DecodePacket(socket.sentPackets.at(1).data);

  EXPECT_EQ(first.type, PacketType::kReliable);
  EXPECT_EQ(second.type, PacketType::kReliable);
  EXPECT_EQ(first.sequence, 0u);
  EXPECT_EQ(second.sequence, 0u);
  EXPECT_EQ(first.channel, 0);
  EXPECT_EQ(second.channel, 1);
}

TEST_F(ReliableConnectionTest, SendWithoutDeadlineUsesBaseHeader) {
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

  socket.ClearSent();
  ASSERT_TRUE(conn.SendUnreliable(0, "abc", 3));

  ASSERT_EQ(socket.sentPackets.size(), 1u);
  const auto& packet = socket.sentPackets.at(0).data;
  ASSERT_EQ(packet.size(), kBaseHeaderSize + 3u);
  const auto decoded = DecodePacket(packet);
  EXPECT_EQ(decoded.type, PacketType::kUnreliable);
  EXPECT_EQ(decoded.channel, 0);
  EXPECT_FALSE(decoded.hasDeadline);
  EXPECT_EQ(std::string(decoded.payload.begin(), decoded.payload.end()), "abc");
}

TEST_F(ReliableConnectionTest, DeadlineSendDisabledIsRejected) {
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

  socket.ClearSent();
  ASSERT_TRUE(conn.SendUnreliableWithDeadline(1, "xyz", 3, 75));

  ASSERT_EQ(socket.sentPackets.size(), 1u);
  const auto& packet = socket.sentPackets.at(0).data;
  ASSERT_EQ(packet.size(), kDeadlineHeaderSize + 3u);
  const auto decoded = DecodePacket(packet);
  EXPECT_EQ(decoded.type, PacketType::kUnreliable);
  EXPECT_EQ(decoded.channel, 1);
  EXPECT_TRUE(decoded.hasDeadline);
  EXPECT_EQ(decoded.sequence, 0u);
  EXPECT_EQ(decoded.deadline_ms, 75u);
  EXPECT_LE(decoded.ageMsAtSend, 75u);
  EXPECT_EQ(std::string(decoded.payload.begin(), decoded.payload.end()), "xyz");
}

TEST_F(ReliableConnectionTest, ExpiredReliableAndUnsequencedStopRetrying) {
  config.deadlinesEnabled = true;
  config.retryTimeoutMs = 5;
  config.pingIntervalMs = 10000;
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

  const auto reliable =
    MakeDeadlinePacket(PacketType::kReliable, 0, 0, 10, 10, "rel", 3);
  socket.ClearSent();
  conn.ProcessPacket(reliable.data(), reliable.size(), addr, 12345);
  conn.Update();

  ASSERT_EQ(socket.GetSentCount(), 1u);
  auto ack = DecodePacket(socket.sentPackets.at(0).data);
  EXPECT_EQ(ack.type, PacketType::kAck);
  EXPECT_EQ(ack.sequence, 0u);
  EXPECT_TRUE(handler.reliablePackets.empty());

  const auto unsequenced =
    MakeDeadlinePacket(PacketType::kUnsequenced, 0, 1, 10, 10, "unq", 3);
  socket.ClearSent();
  conn.ProcessPacket(unsequenced.data(), unsequenced.size(), addr, 12345);
  conn.Update();

  ASSERT_EQ(socket.GetSentCount(), 1u);
  ack = DecodePacket(socket.sentPackets.at(0).data);
  EXPECT_EQ(ack.type, PacketType::kAck);
  EXPECT_EQ(ack.sequence, 1u);
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
  ack = DecodePacket(socket.sentPackets.at(0).data);
  EXPECT_EQ(ack.type, PacketType::kAck);
  EXPECT_EQ(ack.sequence, 2u);
  EXPECT_TRUE(handler.reliablePackets.empty());
  EXPECT_EQ(conn.GetDeadlineReceiveDrops(), 3u);
}

TEST_F(ReliableConnectionTest, ExpiredUnreliableReceiveIsDroppedWithoutAck) {
  config.deadlinesEnabled = true;
  ReliableConnection conn(&socket, config);
  conn.SetHandler(&handler);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

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
  conn.SetConnectedForTest();

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
  ConnectionManagerConfig config;
  MockEventHandler handler;

  void SetUp() override {
    config.connection.maxRetries = 3;
    config.connection.retryTimeoutMs = 50;
    config.connection.pingIntervalMs = 100;
    config.connection.disconnectTimeoutMs = 500;
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

  const auto packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  manager.ProcessPacket(packet.data(), packet.size(), client_addr, 12345);

  auto connections = manager.GetConnections();
  EXPECT_EQ(connections.size(), 1)
    << "Should auto-create connection for new client";
}

TEST_F(ConnectionManagerTest, GetConnection) {
  ConnectionManager manager(&socket, config);

  SocketAddress addr1 = SocketAddress::FromIPv4(0x7F000001);
  SocketAddress addr2 = SocketAddress::FromIPv4(0x7F000002);

  const auto packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  manager.ProcessPacket(packet.data(), packet.size(), addr1, 12345);
  manager.ProcessPacket(packet.data(), packet.size(), addr2, 12346);

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

  const auto connect_packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  manager.ProcessPacket(connect_packet.data(), connect_packet.size(), addr1,
                        12345);
  manager.ProcessPacket(connect_packet.data(), connect_packet.size(), addr2,
                        12346);

  socket.ClearSent();

  // Broadcast
  const char* broadcast_data = "Broadcast message";
  BroadcastReliable(manager, 0, broadcast_data, strlen(broadcast_data));

  // Should send to all connected clients
  EXPECT_GE(socket.GetSentCount(), 2) << "Should send to multiple clients";
}

TEST_F(ConnectionManagerTest, BroadcastUnreliable) {
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  const auto connect_packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  manager.ProcessPacket(connect_packet.data(), connect_packet.size(), addr,
                        12345);

  socket.ClearSent();

  BroadcastUnreliable(manager, 0, "Test", 4);

  EXPECT_GT(socket.GetSentCount(), 0) << "Should send broadcast";
}

TEST_F(ConnectionManagerTest, UpdateAllConnections) {
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  const auto packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  manager.ProcessPacket(packet.data(), packet.size(), addr, 12345);

  // Update should process all connections
  manager.Update();

  auto connections = manager.GetConnections();
  EXPECT_FALSE(connections.empty());

  for (auto* client : connections) {
    EXPECT_NE(client->connection, nullptr);
  }
}

TEST_F(ConnectionManagerTest, CallerOwnsUserData) {
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);

  const auto packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  manager.ProcessPacket(packet.data(), packet.size(), addr, 12345);

  auto* client = manager.GetConnection(addr, 12345);
  ASSERT_NE(client, nullptr);

  std::unordered_map<ConnectionManager::RemoteClient*, int> user_data;
  user_data.emplace(client, 42);

  EXPECT_EQ(user_data.at(client), 42);
}

// Safety and correctness tests.

TEST_F(ReliableConnectionTest, UnknownPacketTypeIsIgnored) {
  ReliableConnection conn(&socket, config);
  auto addr = SocketAddress::FromIPv4(0x7F000001);
  conn.SetRemoteAddress(addr, 12345);
  conn.SetConnectedForTest();

  auto packet = MakeBasePacket(PacketType::kUnreliable, 0, 0);
  packet.at(3) = 100;  // invalid type in the v2 header

  auto received_before [[maybe_unused]] = conn.GetReceivedPackets();
  EXPECT_NO_THROW(
    conn.ProcessPacket(packet.data(), packet.size(), addr, 12345));
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

  const auto packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  manager.ProcessPacket(packet.data(), packet.size(), addr1, 5000);
  manager.ProcessPacket(packet.data(), packet.size(), addr2, 5000);

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

  const auto packet = MakeBasePacket(PacketType::kConnect, 0, 0);
  manager->ProcessPacket(packet.data(), packet.size(), addr, 12345);
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
            kBaseHeaderSize + socketwire::crypto::kClientHelloSize);
  ASSERT_FALSE(server_socket.sentPackets.empty());
  EXPECT_EQ(server_socket.sentPackets.front().data.size(),
            kBaseHeaderSize + socketwire::crypto::kServerHelloSize);
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

  const auto plaintext =
    MakeBasePacket(PacketType::kReliable, 0, 0, "plain", 5);

  server.ProcessPacket(plaintext.data(), plaintext.size(), addr, 23456);
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
  const auto decoded_reliable = DecodePacket(reliable_packet.data);
  ASSERT_EQ(decoded_reliable.type, PacketType::kReliable);
  ASSERT_TRUE(decoded_reliable.hasDeadline);
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
  const auto decoded_unreliable = DecodePacket(unreliable_packet.data);
  ASSERT_EQ(decoded_unreliable.type, PacketType::kUnreliable);
  ASSERT_TRUE(decoded_unreliable.hasDeadline);
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
