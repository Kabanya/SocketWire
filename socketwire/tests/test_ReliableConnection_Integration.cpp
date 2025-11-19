#include <gtest/gtest.h>
#include "reliable_connection.hpp"
#include "i_socket.hpp"
#include "socket_init.hpp"
#include <thread>
#include <atomic>
#include <memory>

using namespace std::chrono_literals;

using socketwire::ReliableConnection;
using socketwire::ConnectionManager;
using socketwire::ReliableConnectionConfig;
using socketwire::IReliableConnectionHandler;
using socketwire::ISocket;
using socketwire::SocketAddress;
using socketwire::SocketError;
using socketwire::SocketConfig;
using socketwire::SocketFactoryRegistry;

class IntegrationTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    bool result = socketwire::initialize_sockets();
    ASSERT_TRUE(result) << "Socket initialization should succeed";

    auto factory = SocketFactoryRegistry::getFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be available";
  }

  void TearDown() override
  {
    socketwire::shutdown_sockets();
  }
};

// Simple echo server handler
class EchoServerHandler : public IReliableConnectionHandler
{
public:
  ConnectionManager* manager = nullptr;
  std::atomic<int> messagesReceived{0};

  void onReliableReceived(uint8_t channel, const void* data, size_t size) override
  {
    messagesReceived++;

    // Echo back to all clients
    if (manager != nullptr)
    {
      manager->broadcastReliable(channel, data, size);
    }
  }

  void onUnreliableReceived(uint8_t channel, const void* data, size_t size) override
  {
    messagesReceived++;

    // Echo back unreliable
    if (manager != nullptr)
    {
      manager->broadcastUnreliable(channel, data, size);
    }
  }
};

// Client handler
class ClientHandler : public IReliableConnectionHandler
{
public:
  std::atomic<bool> connected{false};
  std::atomic<bool> disconnected{false};
  std::atomic<int> reliableReceived{0};
  std::atomic<int> unreliableReceived{0};
  std::vector<std::vector<uint8_t>> receivedMessages;
  std::mutex messagesMutex;

  void onConnected() override
  {
    connected = true;
  }

  void onDisconnected() override
  {
    disconnected = true;
  }

  void onReliableReceived(uint8_t channel, const void* data, size_t size) override
  {
    (void)channel;
    reliableReceived++;

    std::lock_guard<std::mutex> lock(messagesMutex);
    std::vector<uint8_t> msg(static_cast<const uint8_t*>(data),
                             static_cast<const uint8_t*>(data) + size);
    receivedMessages.push_back(msg);
  }

  void onUnreliableReceived(uint8_t channel, const void* data, size_t size) override
  {
    (void)channel;
    unreliableReceived++;

    std::lock_guard<std::mutex> lock(messagesMutex);
    std::vector<uint8_t> msg(static_cast<const uint8_t*>(data),
                             static_cast<const uint8_t*>(data) + size);
    receivedMessages.push_back(msg);
  }

  std::vector<std::vector<uint8_t>> getMessages()
  {
    std::lock_guard<std::mutex> lock(messagesMutex);
    return receivedMessages;
  }

  void clearMessages()
  {
    std::lock_guard<std::mutex> lock(messagesMutex);
    receivedMessages.clear();
  }
};

TEST_F(IntegrationTest, ClientServerConnect)
{
  const uint16_t SERVER_PORT = 15001;

  auto factory = SocketFactoryRegistry::getFactory();

  // Server setup
  SocketConfig serverCfg;
  serverCfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(serverCfg);
  ASSERT_NE(serverSocket, nullptr);

  SocketAddress serverAddr = SocketAddress::fromIPv4(0); // INADDR_ANY
  ASSERT_EQ(serverSocket->bind(serverAddr, SERVER_PORT), SocketError::None);

  ReliableConnectionConfig connCfg;
  connCfg.pingIntervalMs = 200;
  connCfg.disconnectTimeoutMs = 1000;

  EchoServerHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get(), connCfg);
  serverHandler.manager = serverManager.get();
  serverManager->setHandler(&serverHandler);

  // Client setup
  auto clientSocket = factory->createUDPSocket(serverCfg);
  ASSERT_NE(clientSocket, nullptr);

  ClientHandler clientHandler;
  auto clientConn = std::make_unique<ReliableConnection>(clientSocket.get(), connCfg);
  clientConn->setHandler(&clientHandler);

  // Connect
  SocketAddress connectAddr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
  clientConn->connect(connectAddr, SERVER_PORT);

  EXPECT_FALSE(clientHandler.connected);

  // Run network loop
  std::atomic<bool> running{true};
  std::thread networkThread([&]() {
    char buffer[2048];

    while (running)
    {
      // Server receive
      while (true)
      {
        SocketAddress from;
        uint16_t fromPort;
        auto result = serverSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded())
          break;

        if (result.bytes > 0)
          serverManager->processPacket(buffer, result.bytes, from, fromPort);
      }

      // Client receive
      while (true)
      {
        SocketAddress from;
        uint16_t fromPort;
        auto result = clientSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded())
          break;

        if (result.bytes > 0)
          clientConn->processPacket(buffer, result.bytes, from, fromPort);
      }

      serverManager->update();
      clientConn->update();

      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !clientHandler.connected; i++)
  {
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_TRUE(clientHandler.connected) << "Client should connect to server";

  auto connections = serverManager->getConnections();
  EXPECT_EQ(connections.size(), 1) << "Server should have one client";

  running = false;
  networkThread.join();
}

TEST_F(IntegrationTest, ClientServerReliableMessage)
{
  const uint16_t SERVER_PORT = 15002;

  auto factory = SocketFactoryRegistry::getFactory();

  // Server
  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);

  SocketAddress serverAddr = SocketAddress::fromIPv4(0);
  ASSERT_EQ(serverSocket->bind(serverAddr, SERVER_PORT), SocketError::None);

  ReliableConnectionConfig connCfg;
  connCfg.retryTimeoutMs = 100;

  EchoServerHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get(), connCfg);
  serverHandler.manager = serverManager.get();
  serverManager->setHandler(&serverHandler);

  // Client
  auto clientSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(clientSocket, nullptr);

  ClientHandler clientHandler;
  auto clientConn = std::make_unique<ReliableConnection>(clientSocket.get(), connCfg);
  clientConn->setHandler(&clientHandler);

  SocketAddress connectAddr = SocketAddress::fromIPv4(0x7F000001);
  clientConn->connect(connectAddr, SERVER_PORT);

  // Network loop
  std::atomic<bool> running{true};
  std::thread networkThread([&]()
  {
    char buffer[2048];

    while (running)
    {
      while (true)
      {
        SocketAddress from;
        uint16_t fromPort;
        auto result = serverSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          serverManager->processPacket(buffer, result.bytes, from, fromPort);
      }

      while (true)
      {
        SocketAddress from;
        uint16_t fromPort;
        auto result = clientSocket->receive(buffer, sizeof(buffer), from, fromPort);
        if (!result.succeeded()) break;
        if (result.bytes > 0)
          clientConn->processPacket(buffer, result.bytes, from, fromPort);
      }

      serverManager->update();
      clientConn->update();
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !clientHandler.connected; i++)
  {
    std::this_thread::sleep_for(50ms);
  }

  ASSERT_TRUE(clientHandler.connected);

  // Send message
  const char* testMessage = "Hello, Server!";
  clientConn->sendReliable(0, testMessage, strlen(testMessage));

  // Wait for echo
  for (int i = 0; i < 50 && clientHandler.reliableReceived == 0; i++)
  {
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_GT(clientHandler.reliableReceived, 0) << "Should receive echoed message";
  EXPECT_GT(serverHandler.messagesReceived, 0) << "Server should receive message";

  auto messages = clientHandler.getMessages();
  ASSERT_FALSE(messages.empty());

  std::string received(messages[0].begin(), messages[0].end());
  EXPECT_EQ(received, std::string(testMessage));

  running = false;
  networkThread.join();
}

TEST_F(IntegrationTest, ClientServerMultipleMessages)
{
  const uint16_t SERVER_PORT = 15003;

  auto factory = SocketFactoryRegistry::getFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);

  ASSERT_EQ(serverSocket->bind(SocketAddress::fromIPv4(0), SERVER_PORT), SocketError::None);

  ReliableConnectionConfig connCfg;
  EchoServerHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get(), connCfg);
  serverHandler.manager = serverManager.get();
  serverManager->setHandler(&serverHandler);

  auto clientSocket = factory->createUDPSocket(cfg);
  ClientHandler clientHandler;
  auto clientConn = std::make_unique<ReliableConnection>(clientSocket.get(), connCfg);
  clientConn->setHandler(&clientHandler);

  clientConn->connect(SocketAddress::fromIPv4(0x7F000001), SERVER_PORT);

  std::atomic<bool> running{true};
  std::thread networkThread([&]()
  {
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
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !clientHandler.connected; i++)
  {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(clientHandler.connected);

  // Send multiple messages
  const int MESSAGE_COUNT = 10;
  for (int i = 0; i < MESSAGE_COUNT; i++)
  {
    std::string msg = "Message #" + std::to_string(i);
    clientConn->sendReliable(0, msg.c_str(), msg.length());
    std::this_thread::sleep_for(20ms);
  }

  // Wait for all echoes
  for (int i = 0; i < 100 && clientHandler.reliableReceived < MESSAGE_COUNT; i++)
  {
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_GE(clientHandler.reliableReceived, MESSAGE_COUNT)
    << "Should receive all echoed messages";

  running = false;
  networkThread.join();
}

TEST_F(IntegrationTest, ClientServerUnreliableMessages)
{
  const uint16_t SERVER_PORT = 15004;

  auto factory = SocketFactoryRegistry::getFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);

  ASSERT_EQ(serverSocket->bind(SocketAddress::fromIPv4(0), SERVER_PORT), SocketError::None);

  EchoServerHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get());
  serverHandler.manager = serverManager.get();
  serverManager->setHandler(&serverHandler);

  auto clientSocket = factory->createUDPSocket(cfg);
  ClientHandler clientHandler;
  auto clientConn = std::make_unique<ReliableConnection>(clientSocket.get());
  clientConn->setHandler(&clientHandler);

  clientConn->connect(SocketAddress::fromIPv4(0x7F000001), SERVER_PORT);

  std::atomic<bool> running{true};
  std::thread networkThread([&]()
  {
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
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !clientHandler.connected; i++)
  {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(clientHandler.connected);

  // Send unreliable messages
  const char* msg = "Unreliable snapshot";
  for (int i = 0; i < 5; i++)
  {
    clientConn->sendUnreliable(1, msg, strlen(msg));
    std::this_thread::sleep_for(30ms);
  }

  // Give time for processing
  std::this_thread::sleep_for(300ms);

  EXPECT_GT(clientHandler.unreliableReceived, 0)
    << "Should receive some unreliable messages";

  running = false;
  networkThread.join();
}

TEST_F(IntegrationTest, MultipleClients)
{
  const uint16_t SERVER_PORT = 15005;
  const int NUM_CLIENTS = 3;

  auto factory = SocketFactoryRegistry::getFactory();

  // Server
  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);

  ASSERT_EQ(serverSocket->bind(SocketAddress::fromIPv4(0), SERVER_PORT), SocketError::None);

  EchoServerHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get());
  serverHandler.manager = serverManager.get();
  serverManager->setHandler(&serverHandler);

  // Multiple clients
  std::vector<std::unique_ptr<ISocket>> clientSockets;
  std::vector<std::unique_ptr<ReliableConnection>> clientConns;
  std::vector<std::unique_ptr<ClientHandler>> clientHandlers;

  for (int i = 0; i < NUM_CLIENTS; i++)
  {
    auto socket = factory->createUDPSocket(cfg);
    ASSERT_NE(socket, nullptr);

    auto handler = std::make_unique<ClientHandler>();
    auto conn = std::make_unique<ReliableConnection>(socket.get());
    conn->setHandler(handler.get());
    conn->connect(SocketAddress::fromIPv4(0x7F000001), SERVER_PORT);

    clientSockets.push_back(std::move(socket));
    clientConns.push_back(std::move(conn));
    clientHandlers.push_back(std::move(handler));
  }

  // Network loop
  std::atomic<bool> running{true};
  std::thread networkThread([&]()
  {
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
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for all clients to connect
  bool allConnected = false;
  for (int attempt = 0; attempt < 100 && !allConnected; attempt++)
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
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_TRUE(allConnected) << "All clients should connect";

  auto connections = serverManager->getConnections();
  EXPECT_EQ(connections.size(), NUM_CLIENTS)
    << "Server should have " << NUM_CLIENTS << " clients";

  // Each client sends a message
  for (size_t i = 0; i < clientConns.size(); i++)
  {
    std::string msg = "Client " + std::to_string(i);
    clientConns[i]->sendReliable(0, msg.c_str(), msg.length());
  }

  // Wait for broadcasts
  std::this_thread::sleep_for(1s);

  // Each client should receive messages from all clients (including themselves)
  for (const auto& handler : clientHandlers)
  {
    EXPECT_GE(handler->reliableReceived, NUM_CLIENTS)
      << "Each client should receive all broadcast messages";
  }

  running = false;
  networkThread.join();
}

TEST_F(IntegrationTest, ClientDisconnect)
{
  const uint16_t SERVER_PORT = 15006;

  auto factory = SocketFactoryRegistry::getFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto serverSocket = factory->createUDPSocket(cfg);
  ASSERT_NE(serverSocket, nullptr);

  ASSERT_EQ(serverSocket->bind(SocketAddress::fromIPv4(0), SERVER_PORT), SocketError::None);

  EchoServerHandler serverHandler;
  auto serverManager = std::make_unique<ConnectionManager>(serverSocket.get());
  serverHandler.manager = serverManager.get();
  serverManager->setHandler(&serverHandler);

  auto clientSocket = factory->createUDPSocket(cfg);
  ClientHandler clientHandler;
  auto clientConn = std::make_unique<ReliableConnection>(clientSocket.get());
  clientConn->setHandler(&clientHandler);

  clientConn->connect(SocketAddress::fromIPv4(0x7F000001), SERVER_PORT);

  std::atomic<bool> running{true};
  std::thread networkThread([&]()
  {
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
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !clientHandler.connected; i++)
  {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(clientHandler.connected);

  // Disconnect
  clientConn->disconnect();

  // Wait for disconnection
  std::this_thread::sleep_for(500ms);

  EXPECT_TRUE(clientHandler.disconnected) << "Client should be disconnected";
  EXPECT_FALSE(clientConn->isConnected());

  running = false;
  networkThread.join();
}