#include <gtest/gtest.h>
#include "reliable_connection.hpp"
#include "i_socket.hpp"
#include "bit_stream.hpp"
#include <chrono>
#include <thread>
#include <atomic>
#include <iostream>

using socketwire::ReliableConnection;
using socketwire::ConnectionManager;
using socketwire::ReliableConnectionConfig;
using socketwire::IReliableConnectionHandler;
using socketwire::ISocket;
using socketwire::SocketAddress;
using socketwire::SocketError;
using socketwire::SocketConfig;
using socketwire::SocketFactoryRegistry;
using socketwire::BitStream;

using std::chrono::high_resolution_clock;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::microseconds;



class PerformanceTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    socketwire::register_posix_socket_factory();

    auto factory = SocketFactoryRegistry::getFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be available";
  }

  // Helper to measure throughput
  struct ThroughputResult
  {
    double packetsPerSecond;
    double bytesPerSecond;
    double averageLatencyMs;
    double maxLatencyMs;
    uint32_t totalPackets;
    uint32_t lostPackets;
  };
};

// Simple packet counter handler
class CounterHandler : public IReliableConnectionHandler
{
public:
  std::atomic<uint32_t> reliableCount{0};
  std::atomic<uint32_t> unreliableCount{0};
  std::atomic<bool> connected{false};

  void onConnected() override
  {
    connected = true;
  }

  void onReliableReceived(uint8_t channel, const void* data, size_t size) override
  {
    (void)channel;
    (void)data;
    (void)size;
    reliableCount++;
  }

  void onUnreliableReceived(uint8_t channel, const void* data, size_t size) override
  {
    (void)channel;
    (void)data;
    (void)size;
    unreliableCount++;
  }
};

TEST_F(PerformanceTest, DISABLED_SmallPacketThroughput)
{
  const uint16_t SERVER_PORT = 16001;
  const int PACKET_COUNT = 1000;
  const size_t PACKET_SIZE = 64; // Small packets

  auto factory = SocketFactoryRegistry::getFactory();

  // Server
  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);
  ASSERT_EQ(serverSocket->bind(SocketAddress::fromIPv4(0), SERVER_PORT), SocketError::None);

  CounterHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get());
  serverManager->setHandler(&serverHandler);

  // Client
  auto clientSocket = factory->createUDPSocket(cfg);
  CounterHandler clientHandler;
  auto clientConn = std::make_unique<ReliableConnection>(clientSocket.get());
  clientConn->setHandler(&clientHandler);

  clientConn->connect(SocketAddress::fromIPv4(0x7F000001), SERVER_PORT);

  // Network thread
  std::atomic<bool> running{true};
  std::thread networkThread([&]() {
    char buffer[2048];
    while (running)
    {
      SocketAddress from;
      uint16_t fromPort;

      while (true)
      {
        auto result = serverSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          serverManager->processPacket(buffer, result.bytes, from, fromPort);
      }

      while (true)
      {
        auto result = clientSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          clientConn->processPacket(buffer, result.bytes, from, fromPort);
      }

      serverManager->update();
      clientConn->update();

      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  // Wait for connection
  for (int i = 0; i < 100 && !clientHandler.connected; i++)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ASSERT_TRUE(clientHandler.connected);

  // Prepare data
  std::vector<uint8_t> testData(PACKET_SIZE, 0xAB);

  // Benchmark
  auto startTime = high_resolution_clock::now();

  for (int i = 0; i < PACKET_COUNT; i++)
  {
    clientConn->sendReliable(0, testData.data(), testData.size());
  }

  // Wait for all packets to be received
  for (int i = 0; i < 500 && serverHandler.reliableCount < PACKET_COUNT; i++)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto endTime = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(endTime - startTime).count();

  EXPECT_EQ(serverHandler.reliableCount, PACKET_COUNT) 
    << "All packets should be received";

  double packetsPerSec = (PACKET_COUNT * 1000.0) / duration;
  double bytesPerSec = (PACKET_COUNT * PACKET_SIZE * 1000.0) / duration;

  std::cout << "\n=== Small Packet Throughput ===" << std::endl;
  std::cout << "Packets: " << PACKET_COUNT << std::endl;
  std::cout << "Packet size: " << PACKET_SIZE << " bytes" << std::endl;
  std::cout << "Duration: " << duration << " ms" << std::endl;
  std::cout << "Throughput: " << packetsPerSec << " packets/sec" << std::endl;
  std::cout << "Throughput: " << (bytesPerSec / 1024.0) << " KB/sec" << std::endl;
  std::cout << "Lost packets: " << clientConn->getLostPackets() << std::endl;
  std::cout << "RTT: " << clientConn->getRTT() << " ms" << std::endl;

  running = false;
  networkThread.join();
}

TEST_F(PerformanceTest, DISABLED_LargePacketThroughput)
{
  const uint16_t SERVER_PORT = 16002;
  const int PACKET_COUNT = 500;
  const size_t PACKET_SIZE = 1024; // Larger packets

  auto factory = SocketFactoryRegistry::getFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);
  ASSERT_EQ(serverSocket->bind(SocketAddress::fromIPv4(0), SERVER_PORT), SocketError::None);

  CounterHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get());
  serverManager->setHandler(&serverHandler);

  auto clientSocket = factory->createUDPSocket(cfg);
  CounterHandler clientHandler;
  auto clientConn = std::make_unique<ReliableConnection>(clientSocket.get());
  clientConn->setHandler(&clientHandler);

  clientConn->connect(SocketAddress::fromIPv4(0x7F000001), SERVER_PORT);

  std::atomic<bool> running{true};
  std::thread networkThread([&]() {
    char buffer[2048];
    while (running)
    {
      SocketAddress from;
      uint16_t fromPort;

      while (true)
      {
        auto result = serverSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          serverManager->processPacket(buffer, result.bytes, from, fromPort);
      }

      while (true)
      {
        auto result = clientSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          clientConn->processPacket(buffer, result.bytes, from, fromPort);
      }

      serverManager->update();
      clientConn->update();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  for (int i = 0; i < 100 && !clientHandler.connected; i++)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ASSERT_TRUE(clientHandler.connected);

  std::vector<uint8_t> testData(PACKET_SIZE, 0xCD);

  auto startTime = high_resolution_clock::now();

  for (int i = 0; i < PACKET_COUNT; i++)
  {
    clientConn->sendReliable(0, testData.data(), testData.size());
  }

  for (int i = 0; i < 500 && serverHandler.reliableCount < PACKET_COUNT; i++)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto endTime = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(endTime - startTime).count();

  EXPECT_EQ(serverHandler.reliableCount, PACKET_COUNT);

  double packetsPerSec = (PACKET_COUNT * 1000.0) / duration;
  double bytesPerSec = (PACKET_COUNT * PACKET_SIZE * 1000.0) / duration;

  std::cout << "\n=== Large Packet Throughput ===" << std::endl;
  std::cout << "Packets: " << PACKET_COUNT << std::endl;
  std::cout << "Packet size: " << PACKET_SIZE << " bytes" << std::endl;
  std::cout << "Duration: " << duration << " ms" << std::endl;
  std::cout << "Throughput: " << packetsPerSec << " packets/sec" << std::endl;
  std::cout << "Throughput: " << (bytesPerSec / 1024.0) << " KB/sec" << std::endl;
  std::cout << "Lost packets: " << clientConn->getLostPackets() << std::endl;
  std::cout << "RTT: " << clientConn->getRTT() << " ms" << std::endl;

  running = false;
  networkThread.join();
}

TEST_F(PerformanceTest, DISABLED_UnreliablePacketThroughput)
{
  const uint16_t SERVER_PORT = 16003;
  const int PACKET_COUNT = 2000;
  const size_t PACKET_SIZE = 128;

  auto factory = SocketFactoryRegistry::getFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);
  ASSERT_EQ(serverSocket->bind(SocketAddress::fromIPv4(0), SERVER_PORT), SocketError::None);

  CounterHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get());
  serverManager->setHandler(&serverHandler);

  auto clientSocket = factory->createUDPSocket(cfg);
  CounterHandler clientHandler;
  auto clientConn = std::make_unique<ReliableConnection>(clientSocket.get());
  clientConn->setHandler(&clientHandler);

  clientConn->connect(SocketAddress::fromIPv4(0x7F000001), SERVER_PORT);

  std::atomic<bool> running{true};
  std::thread networkThread([&]() {
    char buffer[2048];
    while (running)
    {
      SocketAddress from;
      uint16_t fromPort;

      while (true)
      {
        auto result = serverSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          serverManager->processPacket(buffer, result.bytes, from, fromPort);
      }

      while (true)
      {
        auto result = clientSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          clientConn->processPacket(buffer, result.bytes, from, fromPort);
      }

      serverManager->update();
      clientConn->update();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  for (int i = 0; i < 100 && !clientHandler.connected; i++)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ASSERT_TRUE(clientHandler.connected);

  std::vector<uint8_t> testData(PACKET_SIZE, 0xEF);

  auto startTime = high_resolution_clock::now();

  // Send unreliable packets
  for (int i = 0; i < PACKET_COUNT; i++)
  {
    clientConn->sendUnreliable(1, testData.data(), testData.size());
  }

  // Give time for processing
  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  auto endTime = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(endTime - startTime).count();

  uint32_t received = serverHandler.unreliableCount;
  double deliveryRate = (received * 100.0) / PACKET_COUNT;
  double packetsPerSec = (received * 1000.0) / duration;
  double bytesPerSec = (received * PACKET_SIZE * 1000.0) / duration;

  std::cout << "\n=== Unreliable Packet Throughput ===" << std::endl;
  std::cout << "Packets sent: " << PACKET_COUNT << std::endl;
  std::cout << "Packets received: " << received << std::endl;
  std::cout << "Delivery rate: " << deliveryRate << "%" << std::endl;
  std::cout << "Duration: " << duration << " ms" << std::endl;
  std::cout << "Throughput: " << packetsPerSec << " packets/sec" << std::endl;
  std::cout << "Throughput: " << (bytesPerSec / 1024.0) << " KB/sec" << std::endl;

  // Unreliable should be faster and have high delivery rate on localhost
  EXPECT_GT(deliveryRate, 90.0) << "Delivery rate should be high on localhost";

  running = false;
  networkThread.join();
}

TEST_F(PerformanceTest, DISABLED_ConnectionScalability)
{
  const uint16_t SERVER_PORT = 16004;
  const int NUM_CLIENTS = 10;
  const int MESSAGES_PER_CLIENT = 50;

  auto factory = SocketFactoryRegistry::getFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);
  ASSERT_EQ(serverSocket->bind(SocketAddress::fromIPv4(0), SERVER_PORT), SocketError::None);

  CounterHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get());
  serverManager->setHandler(&serverHandler);

  // Create multiple clients
  std::vector<std::unique_ptr<ISocket>> clientSockets;
  std::vector<std::unique_ptr<ReliableConnection>> clientConns;
  std::vector<std::unique_ptr<CounterHandler>> clientHandlers;

  for (int i = 0; i < NUM_CLIENTS; i++)
  {
    auto socket = factory->createUDPSocket(cfg);
    auto handler = std::make_unique<CounterHandler>();
    auto conn = std::make_unique<ReliableConnection>(socket.get());
    conn->setHandler(handler.get());
    conn->connect(SocketAddress::fromIPv4(0x7F000001), SERVER_PORT);

    clientSockets.push_back(std::move(socket));
    clientConns.push_back(std::move(conn));
    clientHandlers.push_back(std::move(handler));
  }

  std::atomic<bool> running{true};
  std::thread networkThread([&]() {
    char buffer[2048];
    while (running)
    {
      SocketAddress from;
      uint16_t fromPort;

      while (true)
      {
        auto result = serverSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          serverManager->processPacket(buffer, result.bytes, from, fromPort);
      }

      for (size_t i = 0; i < clientSockets.size(); i++)
      {
        while (true)
        {
          auto result = clientSockets[i]->receive(buffer, sizeof(buffer), from, fromPort);
          if (!result.succeeded()) break;
          if (result.bytes > 0)
            clientConns[i]->processPacket(buffer, result.bytes, from, fromPort);
        }
        clientConns[i]->update();
      }

      serverManager->update();
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  });

  // Wait for all connections
  bool allConnected = false;
  for (int attempt = 0; attempt < 200 && !allConnected; attempt++)
  {
    allConnected = true;
    for (const auto& handler : clientHandlers)
    {
      if (!handler->connected)
      {
        allConnected = false;
        break;
      }
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  ASSERT_TRUE(allConnected);

  auto startTime = high_resolution_clock::now();

  // Each client sends messages
  std::vector<uint8_t> testData(100, 0x42);
  for (size_t i = 0; i < clientConns.size(); i++)
  {
    for (int j = 0; j < MESSAGES_PER_CLIENT; j++)
    {
      clientConns[i]->sendReliable(0, testData.data(), testData.size());
    }
  }

  // Wait for all messages
  uint32_t expectedTotal = NUM_CLIENTS * MESSAGES_PER_CLIENT;
  for (int i = 0; i < 1000 && serverHandler.reliableCount < expectedTotal; i++)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  auto endTime = high_resolution_clock::now();
  auto duration = duration_cast<milliseconds>(endTime - startTime).count();

  std::cout << "\n=== Connection Scalability ===" << std::endl;
  std::cout << "Clients: " << NUM_CLIENTS << std::endl;
  std::cout << "Messages per client: " << MESSAGES_PER_CLIENT << std::endl;
  std::cout << "Total messages: " << expectedTotal << std::endl;
  std::cout << "Received: " << serverHandler.reliableCount.load() << std::endl;
  std::cout << "Duration: " << duration << " ms" << std::endl;
  std::cout << "Average per client: " << (duration / NUM_CLIENTS) << " ms" << std::endl;

  EXPECT_EQ(serverHandler.reliableCount, expectedTotal);

  running = false;
  networkThread.join();
}

TEST_F(PerformanceTest, DISABLED_BitStreamSerializationPerformance)
{
  const int ITERATIONS = 100000;

  std::cout << "\n=== BitStream Serialization Performance ===" << std::endl;

  // Write performance
  auto writeStart = high_resolution_clock::now();

  for (int i = 0; i < ITERATIONS; i++)
  {
    BitStream bs;
    bs.write<uint8_t>(42);
    bs.write<uint16_t>(1234);
    bs.write<uint32_t>(123456);
    bs.write<float>(3.14f);
    bs.write<double>(2.718);
    bs.write<bool>(true);
  }

  auto writeEnd = high_resolution_clock::now();
  auto writeDuration = duration_cast<microseconds>(writeEnd - writeStart).count();

  std::cout << "Write operations: " << ITERATIONS << std::endl;
  std::cout << "Write time: " << writeDuration << " μs" << std::endl;
  std::cout << "Writes per second: " << (ITERATIONS * 1000000.0 / writeDuration) << std::endl;

  // Read performance
  BitStream bs;
  bs.write<uint8_t>(42);
  bs.write<uint16_t>(1234);
  bs.write<uint32_t>(123456);
  bs.write<float>(3.14f);
  bs.write<double>(2.718);
  bs.write<bool>(true);

  auto readStart = high_resolution_clock::now();

  for (int i = 0; i < ITERATIONS; i++)
  {
    bs.resetRead();
    uint8_t v1;
    uint16_t v2;
    uint32_t v3;
    float v4;
    double v5;
    bool v6;

    bs.read<uint8_t>(v1);
    bs.read<uint16_t>(v2);
    bs.read<uint32_t>(v3);
    bs.read<float>(v4);
    bs.read<double>(v5);
    bs.read<bool>(v6);
  }

  auto readEnd = high_resolution_clock::now();
  auto readDuration = duration_cast<microseconds>(readEnd - readStart).count();

  std::cout << "Read operations: " << ITERATIONS << std::endl;
  std::cout << "Read time: " << readDuration << " μs" << std::endl;
  std::cout << "Reads per second: " << (ITERATIONS * 1000000.0 / readDuration) << std::endl;
}