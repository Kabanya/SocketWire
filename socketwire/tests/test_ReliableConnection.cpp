#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "reliable_connection.hpp"
#include "i_socket.hpp"
#include <vector>
#include <thread>
#include <chrono>
#include <cstring>

using socketwire::ReliableConnection;
using socketwire::ConnectionManager;
using socketwire::ReliableConnectionConfig;
using socketwire::ConnectionState;
using socketwire::IReliableConnectionHandler;
using socketwire::ISocketEventHandler;
using socketwire::PacketType;
using socketwire::BitStream;
using socketwire::ISocket;
using socketwire::SocketAddress;
using socketwire::SocketError;
using socketwire::SocketResult;
using socketwire::SocketConfig;
using socketwire::SocketType;
using socketwire::SocketFactoryRegistry;

// Mock socket for testing
class MockSocket : public ISocket
{
public:
  struct SentPacket
  {
    std::vector<uint8_t> data;
    SocketAddress address;
    uint16_t port;
  };

  std::vector<SentPacket> sentPackets;
  std::vector<std::vector<uint8_t>> receiveQueue;
  bool shouldBlock = false;
  SocketError receiveError = SocketError::None;

  SocketError bind(const SocketAddress& address, uint16_t port) override
  {
    (void)address;
    (void)port;
    return SocketError::None;
  }

  SocketResult sendTo(const void* data, size_t length,
                     const SocketAddress& toAddr, uint16_t toPort) override
  {
    SentPacket packet;
    packet.data.assign(static_cast<const uint8_t*>(data),
                      static_cast<const uint8_t*>(data) + length);
    packet.address = toAddr;
    packet.port = toPort;
    sentPackets.push_back(packet);
    return {static_cast<std::ptrdiff_t>(length), SocketError::None};
  }

  SocketResult sendBitStream(BitStream& stream, const SocketAddress& toAddr,
                            uint16_t toPort) override
  {
    return sendTo(stream.getData(), stream.getSizeBytes(), toAddr, toPort);
  }

  SocketResult receive(void* buffer, size_t capacity,
                      SocketAddress& fromAddr, uint16_t& fromPort) override
  {
    if (shouldBlock || receiveQueue.empty())
    {
      if (receiveError != SocketError::None)
        return {-1, receiveError};
      return {-1, SocketError::WouldBlock};
    }

    auto& packet = receiveQueue.front();
    size_t copySize = std::min(capacity, packet.size());
    std::memcpy(buffer, packet.data(), copySize);

    fromAddr = SocketAddress::fromIPv4(0x7F000001);
    fromPort = 12345;

    receiveQueue.erase(receiveQueue.begin());
    return {static_cast<std::ptrdiff_t>(copySize), SocketError::None};
  }

  void poll(ISocketEventHandler* handler) override
  {
    (void)handler;
  }

  SocketError setBlocking(bool enable) override
  {
    (void)enable;
    return SocketError::None;
  }

  bool isBlocking() const override { return false; }
  uint16_t localPort() const override { return 54321; }
  SocketType type() const override { return SocketType::UDP; }
  int nativeHandle() const override { return 42; }
  void close() override {}

  void queueReceive(const void* data, size_t size)
  {
    std::vector<uint8_t> packet(static_cast<const uint8_t*>(data),
                                static_cast<const uint8_t*>(data) + size);
    receiveQueue.push_back(packet);
  }

  void clearSent()
  {
    sentPackets.clear();
  }

  size_t getSentCount() const
  {
    return sentPackets.size();
  }
};

// Mock event handler
class MockEventHandler : public IReliableConnectionHandler
{
public:
  bool connected = false;
  bool disconnected = false;
  bool timedOut = false;
  std::vector<std::vector<uint8_t>> reliablePackets;
  std::vector<std::vector<uint8_t>> unreliablePackets;

  void onConnected() override
  {
    connected = true;
  }

  void onDisconnected() override
  {
    disconnected = true;
  }

  void onTimeout() override
  {
    timedOut = true;
  }

  void onReliableReceived(uint8_t channel, const void* data, size_t size) override
  {
    (void)channel;
    std::vector<uint8_t> packet(static_cast<const uint8_t*>(data),
                               static_cast<const uint8_t*>(data) + size);
    reliablePackets.push_back(packet);
  }

  void onUnreliableReceived(uint8_t channel, const void* data, size_t size) override
  {
    (void)channel;
    std::vector<uint8_t> packet(static_cast<const uint8_t*>(data),
                               static_cast<const uint8_t*>(data) + size);
    unreliablePackets.push_back(packet);
  }

  void reset()
  {
    connected = false;
    disconnected = false;
    timedOut = false;
    reliablePackets.clear();
    unreliablePackets.clear();
  }
};

class ReliableConnectionTest : public ::testing::Test
{
protected:
  MockSocket socket;
  ReliableConnectionConfig config;
  MockEventHandler handler;

  void SetUp() override
  {
    config.maxRetries = 3;
    config.retryTimeoutMs = 50;
    config.pingIntervalMs = 100;
    config.disconnectTimeoutMs = 500;
    config.maxPacketSize = 1400;
    config.numChannels = 2;
  }
};

TEST_F(ReliableConnectionTest, Construction)
{
  ReliableConnection conn(&socket, config);
  EXPECT_EQ(conn.getState(), ConnectionState::Disconnected);
  EXPECT_FALSE(conn.isConnected());
}

TEST_F(ReliableConnectionTest, ClientConnect)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.connect(addr, 12345);

  EXPECT_EQ(conn.getState(), ConnectionState::Connecting);
  EXPECT_FALSE(conn.isConnected());
  EXPECT_GT(socket.getSentCount(), 0) << "Should send connect packet";

  // Verify connect packet was sent
  ASSERT_FALSE(socket.sentPackets.empty());
  auto& packet = socket.sentPackets[0];
  EXPECT_GT(packet.data.size(), 0);
}

TEST_F(ReliableConnectionTest, ServerAcceptConnection)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress clientAddr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(clientAddr, 12345);

  // Simulate receiving connect packet
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Connect));
  bs.write<uint8_t>(0); // channel
  bs.write<uint32_t>(0); // sequence

  conn.processPacket(bs.getData(), bs.getSizeBytes(), clientAddr, 12345);

  EXPECT_TRUE(handler.connected) << "Should trigger onConnected";
  EXPECT_EQ(conn.getState(), ConnectionState::Connected);
  EXPECT_TRUE(conn.isConnected());
}

TEST_F(ReliableConnectionTest, ClientReceiveAccept)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.connect(addr, 12345);

  EXPECT_FALSE(handler.connected);

  // Simulate receiving accept packet
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Accept));
  bs.write<uint8_t>(0); // channel
  bs.write<uint32_t>(0); // sequence

  conn.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);

  EXPECT_TRUE(handler.connected) << "Should trigger onConnected";
  EXPECT_EQ(conn.getState(), ConnectionState::Connected);
  EXPECT_TRUE(conn.isConnected());
}

TEST_F(ReliableConnectionTest, SendReliablePacket)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  // Set connected state
  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  socket.clearSent();

  // Send reliable packet
  const char* testData = "Hello, World!";
  bool result = conn.sendReliable(0, testData, strlen(testData));

  EXPECT_TRUE(result) << "sendReliable should succeed";
  EXPECT_EQ(socket.getSentCount(), 1) << "Should send one packet";

  // Verify packet structure
  ASSERT_FALSE(socket.sentPackets.empty());
  auto& packet = socket.sentPackets[0];
  EXPECT_GT(packet.data.size(), strlen(testData)) << "Packet should include header";
}

TEST_F(ReliableConnectionTest, SendUnreliablePacket)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  socket.clearSent();

  const char* testData = "Unreliable data";
  bool result = conn.sendUnreliable(0, testData, strlen(testData));

  EXPECT_TRUE(result) << "sendUnreliable should succeed";
  EXPECT_EQ(socket.getSentCount(), 1) << "Should send one packet";
}

TEST_F(ReliableConnectionTest, SendWithBitStream)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  socket.clearSent();

  // Create BitStream with data
  BitStream bs;
  bs.write<uint8_t>(42);
  bs.write<float>(3.14f);
  bs.write<uint32_t>(12345);

  bool result = conn.sendReliable(0, bs);

  EXPECT_TRUE(result) << "sendReliable with BitStream should succeed";
  EXPECT_EQ(socket.getSentCount(), 1) << "Should send one packet";
}

TEST_F(ReliableConnectionTest, ReceiveReliablePacket)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  // Create reliable packet
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Reliable));
  bs.write<uint8_t>(0); // channel
  bs.write<uint32_t>(0); // sequence
  const char* payload = "Test payload";
  bs.writeBytes(payload, strlen(payload));

  socket.clearSent();
  conn.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);

  // Should send ACK
  EXPECT_GT(socket.getSentCount(), 0) << "Should send ACK packet";

  // Process packet queue (since it's sequenced)
  conn.update();

  EXPECT_EQ(handler.reliablePackets.size(), 1) << "Should receive one reliable packet";
  ASSERT_FALSE(handler.reliablePackets.empty());

  auto& receivedData = handler.reliablePackets[0];
  std::string receivedStr(receivedData.begin(), receivedData.end());
  EXPECT_EQ(receivedStr, std::string(payload));
}

TEST_F(ReliableConnectionTest, ReceiveUnreliablePacket)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  // Create unreliable packet
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Unreliable));
  bs.write<uint8_t>(0); // channel
  bs.write<uint32_t>(0); // sequence
  const char* payload = "Unreliable payload";
  bs.writeBytes(payload, strlen(payload));

  conn.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);

  EXPECT_EQ(handler.unreliablePackets.size(), 1) << "Should receive one unreliable packet";
  ASSERT_FALSE(handler.unreliablePackets.empty());

  auto& receivedData = handler.unreliablePackets[0];
  std::string receivedStr(receivedData.begin(), receivedData.end());
  EXPECT_EQ(receivedStr, std::string(payload));
}

TEST_F(ReliableConnectionTest, PacketSequencing)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  // Send packets out of order
  auto createPacket = [](uint32_t seq, const char* payload) -> std::vector<uint8_t>
  {
    BitStream bs;
    bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Reliable));
    bs.write<uint8_t>(0); // channel
    bs.write<uint32_t>(seq);
    bs.writeBytes(payload, strlen(payload));
    return std::vector<uint8_t>(bs.getData(), bs.getData() + bs.getSizeBytes());
  };

  auto packet2 = createPacket(2, "Second");
  auto packet1 = createPacket(1, "First");
  auto packet0 = createPacket(0, "Zero");

  // Receive in wrong order: 2, 1, 0
  conn.processPacket(packet2.data(), packet2.size(), addr, 12345);
  conn.update();
  EXPECT_EQ(handler.reliablePackets.size(), 0) << "Should wait for sequence 0";

  conn.processPacket(packet1.data(), packet1.size(), addr, 12345);
  conn.update();
  EXPECT_EQ(handler.reliablePackets.size(), 0) << "Still waiting for sequence 0";

  conn.processPacket(packet0.data(), packet0.size(), addr, 12345);
  conn.update();

  // Now all packets should be delivered in order
  EXPECT_EQ(handler.reliablePackets.size(), 3) << "Should receive all three packets";

  std::string first(handler.reliablePackets[0].begin(), handler.reliablePackets[0].end());
  std::string second(handler.reliablePackets[1].begin(), handler.reliablePackets[1].end());
  std::string third(handler.reliablePackets[2].begin(), handler.reliablePackets[2].end());

  EXPECT_EQ(first, "Zero");
  EXPECT_EQ(second, "First");
  EXPECT_EQ(third, "Second");
}

TEST_F(ReliableConnectionTest, DuplicateDetection)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  // Create reliable packet
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Reliable));
  bs.write<uint8_t>(0); // channel
  bs.write<uint32_t>(0); // sequence
  bs.writeBytes("Test", 4);

  // Send same packet twice
  conn.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);
  conn.update();

  size_t firstCount = handler.reliablePackets.size();

  conn.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);
  conn.update();

  EXPECT_EQ(handler.reliablePackets.size(), firstCount)
    << "Duplicate packet should be ignored";
}

TEST_F(ReliableConnectionTest, AcknowledgmentReceived)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  socket.clearSent();

  // Send reliable packet
  conn.sendReliable(0, "Test", 4);

  size_t sentBefore = socket.getSentCount();
  uint32_t lostBefore = conn.getLostPackets();

  // Extract sequence from sent packet
  ASSERT_FALSE(socket.sentPackets.empty());
  auto& sentPacket = socket.sentPackets.back();
  BitStream sentBs(sentPacket.data.data(), sentPacket.data.size());
  uint8_t type, channel;
  uint32_t sequence;
  sentBs.read<uint8_t>(type);
  sentBs.read<uint8_t>(channel);
  sentBs.read<uint32_t>(sequence);

  // Send ACK
  BitStream ackBs;
  ackBs.write<uint8_t>(static_cast<uint8_t>(PacketType::Ack));
  ackBs.write<uint8_t>(0);
  ackBs.write<uint32_t>(sequence);

  conn.processPacket(ackBs.getData(), ackBs.getSizeBytes(), addr, 12345);
  conn.update();

  // Wait longer than retry timeout
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  conn.update();

  // Should not resend after ACK
  EXPECT_EQ(socket.getSentCount(), sentBefore)
    << "Should not resend acknowledged packet";
  EXPECT_EQ(conn.getLostPackets(), lostBefore)
    << "Acknowledged packet should not be counted as lost";
}

TEST_F(ReliableConnectionTest, Disconnect)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  EXPECT_TRUE(conn.isConnected());
  EXPECT_FALSE(handler.disconnected);

  socket.clearSent();
  conn.disconnect();

  EXPECT_FALSE(conn.isConnected());
  EXPECT_TRUE(handler.disconnected) << "Should trigger onDisconnected";
  EXPECT_GT(socket.getSentCount(), 0) << "Should send disconnect packet";
}

TEST_F(ReliableConnectionTest, ReceiveDisconnect)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  EXPECT_FALSE(handler.disconnected);

  // Receive disconnect packet
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Disconnect));
  bs.write<uint8_t>(0);
  bs.write<uint32_t>(0);

  conn.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);

  EXPECT_TRUE(handler.disconnected) << "Should trigger onDisconnected";
  EXPECT_EQ(conn.getState(), ConnectionState::Disconnected);
}

TEST_F(ReliableConnectionTest, Statistics)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  uint32_t initialSent = conn.getSentPackets();
  uint32_t initialReceived = conn.getReceivedPackets();

  // Send packet
  conn.sendReliable(0, "Test", 4);
  EXPECT_GT(conn.getSentPackets(), initialSent) << "Sent count should increase";

  // Receive packet
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Unreliable));
  bs.write<uint8_t>(0);
  bs.write<uint32_t>(0);
  bs.writeBytes("Data", 4);

  conn.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);

  EXPECT_GT(conn.getReceivedPackets(), initialReceived) << "Received count should increase";
}

TEST_F(ReliableConnectionTest, PingPong)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  socket.clearSent();

  // Receive ping
  BitStream pingBs;
  pingBs.write<uint8_t>(static_cast<uint8_t>(PacketType::Ping));
  pingBs.write<uint8_t>(0);
  pingBs.write<uint32_t>(42);

  conn.processPacket(pingBs.getData(), pingBs.getSizeBytes(), addr, 12345);

  // Should send pong
  EXPECT_GT(socket.getSentCount(), 0) << "Should send pong response";

  // Verify pong packet
  ASSERT_FALSE(socket.sentPackets.empty());
  auto& pongPacket = socket.sentPackets[0];
  BitStream pongBs(pongPacket.data.data(), pongPacket.data.size());

  uint8_t type;
  uint8_t channel;
  uint32_t sequence;
  pongBs.read<uint8_t>(type);
  pongBs.read<uint8_t>(channel);
  pongBs.read<uint32_t>(sequence);

  EXPECT_EQ(type, static_cast<uint8_t>(PacketType::Pong));
  EXPECT_EQ(sequence, 42) << "Pong should echo ping sequence";
}

TEST_F(ReliableConnectionTest, RTTMeasurement)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  float initialRTT = conn.getRTT();
  EXPECT_GT(initialRTT, 0.0f) << "RTT should have initial value";

  // RTT will be updated when ACKs are received
  // For now just verify the getter works
  EXPECT_GE(conn.getRTT(), 0.0f);
}

TEST_F(ReliableConnectionTest, SendBeforeConnected)
{
  ReliableConnection conn(&socket, config);

  // Try to send before connecting
  bool result = conn.sendReliable(0, "Test", 4);

  EXPECT_FALSE(result) << "Should fail to send before connected";
}

TEST_F(ReliableConnectionTest, MaxPacketSizeLimit)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  // Try to send packet larger than max size
  std::vector<uint8_t> largeData(config.maxPacketSize + 1, 0xFF);

  bool result = conn.sendReliable(0, largeData.data(), largeData.size());

  EXPECT_FALSE(result) << "Should fail to send packet exceeding max size";
}

TEST_F(ReliableConnectionTest, MultipleChannels)
{
  ReliableConnection conn(&socket, config);
  conn.setHandler(&handler);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);
  conn.setRemoteAddress(addr, 12345);
  conn.setConnected();

  socket.clearSent();

  // Send on different channels
  conn.sendReliable(0, "Channel0", 8);
  conn.sendReliable(1, "Channel1", 8);

  EXPECT_EQ(socket.getSentCount(), 2) << "Should send packets on different channels";

  // Verify channels are different
  ASSERT_GE(socket.sentPackets.size(), 2);

  BitStream bs0(socket.sentPackets[0].data.data(), socket.sentPackets[0].data.size());
  BitStream bs1(socket.sentPackets[1].data.data(), socket.sentPackets[1].data.size());

  uint8_t type0, channel0, type1, channel1;
  uint32_t seq0, seq1;

  bs0.read<uint8_t>(type0);
  bs0.read<uint8_t>(channel0);
  bs0.read<uint32_t>(seq0);

  bs1.read<uint8_t>(type1);
  bs1.read<uint8_t>(channel1);
  bs1.read<uint32_t>(seq1);

  EXPECT_EQ(channel0, 0);
  EXPECT_EQ(channel1, 1);
}

// ConnectionManager tests
class ConnectionManagerTest : public ::testing::Test
{
protected:
  MockSocket socket;
  ReliableConnectionConfig config;
  MockEventHandler handler;

  void SetUp() override
  {
    config.maxRetries = 3;
    config.retryTimeoutMs = 50;
    config.pingIntervalMs = 100;
    config.disconnectTimeoutMs = 500;
  }
};

TEST_F(ConnectionManagerTest, Construction)
{
  ConnectionManager manager(&socket, config);
  auto connections = manager.getConnections();
  EXPECT_TRUE(connections.empty()) << "Should start with no connections";
}

TEST_F(ConnectionManagerTest, AutoCreateConnection)
{
  ConnectionManager manager(&socket, config);
  manager.setHandler(&handler);

  SocketAddress clientAddr = SocketAddress::fromIPv4(0x7F000001);

  // Simulate receiving connect packet from new client
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Connect));
  bs.write<uint8_t>(0);
  bs.write<uint32_t>(0);

  manager.processPacket(bs.getData(), bs.getSizeBytes(), clientAddr, 12345);

  auto connections = manager.getConnections();
  EXPECT_EQ(connections.size(), 1) << "Should auto-create connection for new client";
}

TEST_F(ConnectionManagerTest, GetConnection)
{
  ConnectionManager manager(&socket, config);

  SocketAddress addr1 = SocketAddress::fromIPv4(0x7F000001);
  SocketAddress addr2 = SocketAddress::fromIPv4(0x7F000002);

  // Create connections
  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Connect));
  bs.write<uint8_t>(0);
  bs.write<uint32_t>(0);

  manager.processPacket(bs.getData(), bs.getSizeBytes(), addr1, 12345);
  manager.processPacket(bs.getData(), bs.getSizeBytes(), addr2, 12346);

  auto* client1 = manager.getConnection(addr1, 12345);
  auto* client2 = manager.getConnection(addr2, 12346);

  EXPECT_NE(client1, nullptr);
  EXPECT_NE(client2, nullptr);
  EXPECT_NE(client1, client2) << "Different clients should be distinct";
}

TEST_F(ConnectionManagerTest, BroadcastReliable)
{
  ConnectionManager manager(&socket, config);

  // Create multiple connections
  SocketAddress addr1 = SocketAddress::fromIPv4(0x7F000001);
  SocketAddress addr2 = SocketAddress::fromIPv4(0x7F000002);

  BitStream connectBs;
  connectBs.write<uint8_t>(static_cast<uint8_t>(PacketType::Connect));
  connectBs.write<uint8_t>(0);
  connectBs.write<uint32_t>(0);

  manager.processPacket(connectBs.getData(), connectBs.getSizeBytes(), addr1, 12345);
  manager.processPacket(connectBs.getData(), connectBs.getSizeBytes(), addr2, 12346);

  socket.clearSent();

  // Broadcast
  const char* broadcastData = "Broadcast message";
  manager.broadcastReliable(0, broadcastData, strlen(broadcastData));

  // Should send to all connected clients
  EXPECT_GE(socket.getSentCount(), 2) << "Should send to multiple clients";
}

TEST_F(ConnectionManagerTest, BroadcastUnreliable)
{
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);

  BitStream connectBs;
  connectBs.write<uint8_t>(static_cast<uint8_t>(PacketType::Connect));
  connectBs.write<uint8_t>(0);
  connectBs.write<uint32_t>(0);

  manager.processPacket(connectBs.getData(), connectBs.getSizeBytes(), addr, 12345);

  socket.clearSent();

  manager.broadcastUnreliable(0, "Test", 4);

  EXPECT_GT(socket.getSentCount(), 0) << "Should send broadcast";
}

TEST_F(ConnectionManagerTest, UpdateAllConnections)
{
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);

  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Connect));
  bs.write<uint8_t>(0);
  bs.write<uint32_t>(0);

  manager.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);

  // Update should process all connections
  manager.update();

  auto connections = manager.getConnections();
  EXPECT_FALSE(connections.empty());

  for (auto* client : connections)
  {
    EXPECT_NE(client->connection, nullptr);
  }
}

TEST_F(ConnectionManagerTest, UserData)
{
  ConnectionManager manager(&socket, config);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001);

  BitStream bs;
  bs.write<uint8_t>(static_cast<uint8_t>(PacketType::Connect));
  bs.write<uint8_t>(0);
  bs.write<uint32_t>(0);

  manager.processPacket(bs.getData(), bs.getSizeBytes(), addr, 12345);

  auto* client = manager.getConnection(addr, 12345);
  ASSERT_NE(client, nullptr);

  // Set user data
  int* userData = new int(42);
  client->userData = userData;

  EXPECT_EQ(*static_cast<int*>(client->userData), 42);

  delete userData;
}