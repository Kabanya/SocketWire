#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "connection_manager.hpp"
#include "i_socket.hpp"
#include "reliable_connection.hpp"
#include "reliable_protocol.hpp"

using namespace std::chrono_literals;

namespace {

using socketwire::ConnectionManager;
using socketwire::ConnectionState;
using socketwire::IReliableConnectionHandler;
using socketwire::ISocket;
using socketwire::ISocketEventHandler;
using socketwire::ManualClock;
using socketwire::ReliableConnection;
using socketwire::ReliableConnectionConfig;
using socketwire::SocketAddress;
using socketwire::SocketError;
using socketwire::SocketResult;
using socketwire::detail::CongestionController;
using socketwire::detail::FragmentMetadata;
using socketwire::detail::FragmentReassembler;
using socketwire::detail::PacketBuild;
using socketwire::detail::PacketCodec;
using socketwire::detail::PacketDecodeError;
using socketwire::detail::PacketType;

std::span<const std::uint8_t> Bytes(const char* text) {
  return {reinterpret_cast<const std::uint8_t*>(text), std::strlen(text)};
}

std::vector<std::uint8_t> EncodePacket(
  const PacketBuild& packet, std::chrono::steady_clock::time_point now = {}) {
  std::vector<std::uint8_t> out(256);
  const auto encoded = PacketCodec::Encode(packet, now, out);
  EXPECT_TRUE(encoded.has_value());
  out.resize(encoded.value_or(0));
  return out;
}

std::vector<std::uint8_t> MakeConnectPacket() {
  return EncodePacket(PacketBuild{.type = PacketType::kConnect});
}

class RecordingSocket : public ISocket {
 public:
  struct SentPacket {
    std::vector<std::uint8_t> data;
    SocketAddress address;
    std::uint16_t port = 0;
  };

  std::vector<SentPacket> sent;

  SocketError Bind(const SocketAddress& address, std::uint16_t port) override {
    (void)address;
    (void)port;
    return SocketError::kNone;
  }

  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr,
                      std::uint16_t to_port) override {
    SentPacket packet;
    packet.data.assign(static_cast<const std::uint8_t*>(data),
                       static_cast<const std::uint8_t*>(data) + length);
    packet.address = to_addr;
    packet.port = to_port;
    sent.push_back(std::move(packet));
    return {.bytes = static_cast<std::ptrdiff_t>(length),
            .error = SocketError::kNone};
  }

  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr,
                       std::uint16_t& from_port) override {
    (void)buffer;
    (void)capacity;
    (void)from_addr;
    (void)from_port;
    return {.bytes = 0, .error = SocketError::kWouldBlock};
  }

  void Poll(ISocketEventHandler* handler) override { (void)handler; }
  SocketError SetBlocking(bool enable) override {
    blocking_ = enable;
    return SocketError::kNone;
  }
  [[nodiscard]] bool IsBlocking() const override { return blocking_; }
  [[nodiscard]] std::uint16_t LocalPort() const override { return 0; }
  [[nodiscard]] int NativeHandle() const override { return -1; }
  void Close() override {}

 private:
  bool blocking_ = false;
};

class RecordingHandler : public IReliableConnectionHandler {
 public:
  void OnConnected() override { ++connected; }
  void OnDisconnected() override { ++disconnected; }
  void OnTimeout() override { ++timed_out; }

  int connected = 0;
  int disconnected = 0;
  int timed_out = 0;
};

TEST(PacketCodecTest, EncodesAndDecodesV2PacketByteForByte) {
  const auto now = std::chrono::steady_clock::time_point{};
  socketwire::detail::DeadlineMetadata deadline;
  deadline.hasDeadline = true;
  deadline.deadline_ms = 100;
  deadline.createdTime = now - 7ms;
  deadline.expireTime = now + 93ms;

  FragmentMetadata fragment;
  fragment.hasFragment = true;
  fragment.groupId = 0x1234;
  fragment.fragmentIndex = 1;
  fragment.fragmentTotal = 3;

  const auto packet = EncodePacket(PacketBuild{.type = PacketType::kFragment,
                                               .channel = 2,
                                               .sequence = 0x01020304,
                                               .deadline = deadline,
                                               .fragment = fragment,
                                               .payload = Bytes("abc")},
                                   now);

  const std::vector<std::uint8_t> expected = {
    0x53, 0x57, 0x02, 0x09, 0x02, 0x03, 0x01, 0x02, 0x03, 0x04,
    0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x07,
    0x12, 0x34, 0x00, 0x01, 0x00, 0x03, 'a',  'b',  'c'};
  EXPECT_EQ(packet, expected);

  const auto decoded = PacketCodec::Decode(packet);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->type, PacketType::kFragment);
  EXPECT_EQ(decoded->channel, 2);
  EXPECT_EQ(decoded->sequence, 0x01020304u);
  EXPECT_TRUE(decoded->hasDeadline);
  EXPECT_EQ(decoded->deadline_ms, 100u);
  EXPECT_EQ(decoded->ageMsAtSend, 7u);
  EXPECT_TRUE(decoded->fragment.hasFragment);
  EXPECT_EQ(decoded->fragment.groupId, 0x1234);
  EXPECT_EQ(decoded->fragment.fragmentIndex, 1);
  EXPECT_EQ(decoded->fragment.fragmentTotal, 3);
  EXPECT_EQ(std::string(decoded->payload.begin(), decoded->payload.end()),
            "abc");
}

TEST(PacketCodecTest, RejectsUnknownTypesFlagsAndMalformedExtensions) {
  auto packet = EncodePacket(PacketBuild{.type = PacketType::kUnreliable});
  packet.at(3) = 100;
  EXPECT_EQ(PacketCodec::Decode(packet).error(),
            PacketDecodeError::kUnknownType);

  packet = EncodePacket(PacketBuild{.type = PacketType::kUnreliable});
  packet.at(5) = 0x80;
  EXPECT_EQ(PacketCodec::Decode(packet).error(),
            PacketDecodeError::kUnknownFlags);

  packet = EncodePacket(PacketBuild{.type = PacketType::kUnreliable});
  packet.at(5) = 0x01;
  EXPECT_EQ(PacketCodec::Decode(packet).error(), PacketDecodeError::kTruncated);

  packet = EncodePacket(PacketBuild{.type = PacketType::kUnreliable});
  packet.at(5) = 0x02;
  EXPECT_EQ(PacketCodec::Decode(packet).error(),
            PacketDecodeError::kInvalidExtension);

  packet = EncodePacket(PacketBuild{.type = PacketType::kUnreliable});
  packet.at(11) = 1;
  EXPECT_EQ(PacketCodec::Decode(packet).error(),
            PacketDecodeError::kInvalidLength);
}

TEST(PacketCodecTest, BatchPayloadUsesBigEndianCountsAndLengths) {
  const auto first =
    EncodePacket(PacketBuild{.type = PacketType::kAck, .sequence = 7});
  const auto second = EncodePacket(
    PacketBuild{.type = PacketType::kUnreliable, .payload = Bytes("x")});
  const std::span<const std::uint8_t> commands[] = {
    {first.data(), first.size()}, {second.data(), second.size()}};

  const auto payload = PacketCodec::EncodeBatchPayload(commands, 4);
  ASSERT_TRUE(payload.has_value());
  ASSERT_GE(payload->size(), 6u);
  EXPECT_EQ(payload->at(0), 0);
  EXPECT_EQ(payload->at(1), 2);
  EXPECT_EQ(payload->at(2), 0);
  EXPECT_EQ(payload->at(3), first.size());

  const auto decoded = PacketCodec::DecodeBatchPayload(*payload, 4);
  ASSERT_TRUE(decoded.has_value());
  ASSERT_EQ(decoded->size(), 2u);
  EXPECT_EQ(decoded->at(0).size(), first.size());
  EXPECT_EQ(decoded->at(1).size(), second.size());

  const std::vector<std::uint8_t> malformed = {0, 2, 0, 12};
  EXPECT_FALSE(PacketCodec::DecodeBatchPayload(malformed, 4).has_value());
}

TEST(CongestionControllerTest, AckGrowsWindowLossHalvesAndInflightBlocks) {
  CongestionController controller;
  controller.Configure(8);

  EXPECT_EQ(controller.Window(), 4u);
  EXPECT_TRUE(controller.CanSend(3));
  EXPECT_FALSE(controller.CanSend(4));

  controller.OnAck();
  EXPECT_EQ(controller.Window(), 5u);
  EXPECT_TRUE(controller.CanSend(4));

  controller.OnLoss();
  EXPECT_EQ(controller.Window(), 2u);
  EXPECT_FALSE(controller.CanSend(2));
}

TEST(FragmentReassemblerTest, ReassemblesOutOfOrderAndSuppressesDuplicates) {
  FragmentReassembler reassembler;
  reassembler.Configure(1, 4, 8, 64, 1000);
  const auto now = std::chrono::steady_clock::time_point{};

  auto meta = FragmentMetadata{
    .hasFragment = true, .groupId = 3, .fragmentIndex = 1, .fragmentTotal = 3};
  auto result = reassembler.AddFragment(0, meta, Bytes("B"), now, false, {});
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kAccepted);

  result = reassembler.AddFragment(0, meta, Bytes("B"), now, false, {});
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kDuplicate);

  meta.fragmentIndex = 0;
  result = reassembler.AddFragment(0, meta, Bytes("A"), now, false, {});
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kAccepted);

  meta.fragmentIndex = 2;
  result = reassembler.AddFragment(0, meta, Bytes("C"), now, false, {});
  ASSERT_EQ(result.status, FragmentReassembler::AddStatus::kCompleted);
  ASSERT_TRUE(result.message.has_value());
  EXPECT_EQ(
    std::string(result.message->payload.begin(), result.message->payload.end()),
    "ABC");
}

TEST(FragmentReassemblerTest, EnforcesExpiryAndMemoryLimits) {
  FragmentReassembler reassembler;
  reassembler.Configure(1, 1, 2, 4, 10);
  const auto now = std::chrono::steady_clock::time_point{};

  FragmentMetadata meta{
    .hasFragment = true, .groupId = 1, .fragmentIndex = 0, .fragmentTotal = 2};
  auto result =
    reassembler.AddFragment(0, meta, Bytes("ab"), now, true, now + 5ms);
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kAccepted);
  EXPECT_EQ(reassembler.Cleanup(now + 6ms), 1u);

  result = reassembler.AddFragment(0, meta, Bytes("ab"), now, false, {});
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kAccepted);
  FragmentMetadata second_group = meta;
  second_group.groupId = 2;
  result =
    reassembler.AddFragment(0, second_group, Bytes("cd"), now, false, {});
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kDropped);

  reassembler.Reset();
  FragmentMetadata too_many = meta;
  too_many.fragmentTotal = 3;
  result = reassembler.AddFragment(0, too_many, Bytes("x"), now, false, {});
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kDropped);

  reassembler.Reset();
  result = reassembler.AddFragment(0, meta, Bytes("abc"), now, false, {});
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kAccepted);
  meta.fragmentIndex = 1;
  result = reassembler.AddFragment(0, meta, Bytes("de"), now, false, {});
  EXPECT_EQ(result.status, FragmentReassembler::AddStatus::kDropped);
}

TEST(ManualClockReliableConnectionTest, DrivesRetryTimeoutDeadlineAndPing) {
  ManualClock clock;
  RecordingSocket socket;
  ReliableConnectionConfig config;
  config.retryTimeoutMs = 10;
  config.maxRetries = 3;
  config.pingIntervalMs = 1000;
  config.maxPendingReliablePackets = 8;

  ReliableConnection conn(&socket, config, &clock);
  conn.SetRemoteAddress(SocketAddress::FromIPv4(0x7F000001), 7777);
  conn.SetConnectedForTest();

  ASSERT_TRUE(conn.SendReliable(0, "a", 1));
  ASSERT_EQ(socket.sent.size(), 1u);
  clock.Advance(9ms);
  conn.Update();
  EXPECT_EQ(socket.sent.size(), 1u);
  clock.Advance(1ms);
  conn.Update();
  EXPECT_EQ(socket.sent.size(), 2u);

  RecordingSocket deadline_socket;
  ReliableConnectionConfig deadline_config = config;
  deadline_config.deadlinesEnabled = true;
  ReliableConnection deadline_conn(&deadline_socket, deadline_config, &clock);
  deadline_conn.SetRemoteAddress(SocketAddress::FromIPv4(0x7F000001), 7777);
  deadline_conn.SetConnectedForTest();

  ASSERT_TRUE(deadline_conn.SendReliableWithDeadline(0, "b", 1, 5));
  clock.Advance(10ms);
  deadline_conn.Update();
  EXPECT_EQ(deadline_socket.sent.size(), 1u);
  EXPECT_EQ(deadline_conn.GetInflightCount(), 0u);
  EXPECT_EQ(deadline_conn.GetDeadlineRetriesPrevented(), 1u);

  RecordingSocket ping_socket;
  ReliableConnectionConfig ping_config = config;
  ping_config.pingIntervalMs = 10;
  ReliableConnection ping_conn(&ping_socket, ping_config, &clock);
  ping_conn.SetRemoteAddress(SocketAddress::FromIPv4(0x7F000001), 7777);
  ping_conn.SetConnectedForTest();

  clock.Advance(11ms);
  ping_conn.Update();
  ASSERT_EQ(ping_socket.sent.size(), 1u);
  const auto ping = PacketCodec::Decode(ping_socket.sent.front().data);
  ASSERT_TRUE(ping.has_value());
  EXPECT_EQ(ping->type, PacketType::kPing);
}

TEST(ManualClockReliableConnectionTest, DrivesDisconnectTimeout) {
  ManualClock clock;
  RecordingSocket socket;
  RecordingHandler handler;
  ReliableConnectionConfig config;
  config.disconnectTimeoutMs = 20;
  config.pingIntervalMs = 1000;

  ReliableConnection conn(&socket, config, &clock);
  conn.SetHandler(&handler);
  conn.SetRemoteAddress(SocketAddress::FromIPv4(0x7F000001), 7777);
  conn.SetConnectedForTest();

  clock.Advance(21ms);
  conn.Update();

  EXPECT_EQ(handler.timed_out, 1);
  EXPECT_EQ(handler.disconnected, 1);
  EXPECT_EQ(conn.GetState(), ConnectionState::kDisconnected);
}

TEST(BackpressureTest, PendingReliableAndMessageSizeLimitsRejectSends) {
  ManualClock clock;
  RecordingSocket socket;
  ReliableConnectionConfig config;
  config.maxPendingReliablePackets = 1;
  config.maxMessageSize = 4;
  config.pingIntervalMs = 1000;

  ReliableConnection conn(&socket, config, &clock);
  conn.SetRemoteAddress(SocketAddress::FromIPv4(0x7F000001), 7777);
  conn.SetConnectedForTest();

  EXPECT_TRUE(conn.SendReliable(0, "one", 3));
  EXPECT_FALSE(conn.SendReliable(0, "two", 3));
  EXPECT_FALSE(conn.SendUnreliable(0, "12345", 5));
}

TEST(ConnectionManagerArchitectureTest, ConnectionCallbacksAndLimits) {
  ManualClock clock;
  RecordingSocket socket;
  ReliableConnectionConfig config;
  config.maxClients = 1;
  config.maxHandshakesPerSecond = 1;
  config.pingIntervalMs = 1000;

  ConnectionManager manager(&socket, config, &clock);
  int connected = 0;
  int disconnected = 0;
  manager.onClientConnected = [&](ConnectionManager::RemoteClient*) {
    ++connected;
  };
  manager.onClientDisconnected = [&](ConnectionManager::RemoteClient*) {
    ++disconnected;
  };

  const auto connect = MakeConnectPacket();
  const auto addr1 = SocketAddress::FromIPv4(0x7F000001);
  const auto addr2 = SocketAddress::FromIPv4(0x7F000002);

  manager.ProcessPacket(connect.data(), connect.size(), addr1, 1000);
  EXPECT_EQ(manager.GetConnections().size(), 1u);
  EXPECT_EQ(connected, 1);
  manager.Update();
  EXPECT_EQ(connected, 1);

  manager.ProcessPacket(connect.data(), connect.size(), addr2, 1001);
  EXPECT_EQ(manager.GetConnections().size(), 1u);

  auto* client = manager.GetConnection(addr1, 1000);
  ASSERT_NE(client, nullptr);
  client->connection->Disconnect();
  manager.Update();
  EXPECT_EQ(disconnected, 1);
  EXPECT_TRUE(manager.GetConnections().empty());

  RecordingSocket rate_socket;
  ReliableConnectionConfig rate_config = config;
  rate_config.maxClients = 8;
  ConnectionManager rate_limited(&rate_socket, rate_config, &clock);
  rate_limited.ProcessPacket(connect.data(), connect.size(), addr1, 1000);
  rate_limited.ProcessPacket(connect.data(), connect.size(), addr2, 1001);
  EXPECT_EQ(rate_limited.GetConnections().size(), 1u);
  clock.Advance(1000ms);
  rate_limited.ProcessPacket(connect.data(), connect.size(), addr2, 1001);
  EXPECT_EQ(rate_limited.GetConnections().size(), 2u);
}

}  // namespace
