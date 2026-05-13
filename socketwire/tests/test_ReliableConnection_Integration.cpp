#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <thread>

#include "i_socket.hpp"
#include "reliable_connection.hpp"
#include "socket_init.hpp"

using namespace std::chrono_literals;

using socketwire::ConnectionManager;
using socketwire::IReliableConnectionHandler;
using socketwire::ISocket;
using socketwire::ReliableConnection;
using socketwire::ReliableConnectionConfig;
using socketwire::SocketAddress;
using socketwire::SocketConfig;
using socketwire::SocketError;
using socketwire::SocketFactoryRegistry;

class IntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    const bool result = socketwire::InitializeSockets();
    ASSERT_TRUE(result) << "Socket initialization should succeed";

    auto factory = SocketFactoryRegistry::GetFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be available";
  }

  void TearDown() override { socketwire::ShutdownSockets(); }
};

// Simple echo server handler
class EchoServerHandler : public IReliableConnectionHandler {
 public:
  ConnectionManager* manager = nullptr;
  std::atomic<int> messagesReceived{0};

  void OnReliableReceived(uint8_t channel, const void* data,
                          size_t size) override {
    messagesReceived++;

    // Echo back to all clients
    if (manager != nullptr) {
      manager->BroadcastReliable(channel, data, size);
    }
  }

  void OnUnreliableReceived(uint8_t channel, const void* data,
                            size_t size) override {
    messagesReceived++;

    // Echo back unreliable
    if (manager != nullptr) {
      manager->BroadcastUnreliable(channel, data, size);
    }
  }
};

// Client handler
class ClientHandler : public IReliableConnectionHandler {
 public:
  std::atomic<bool> connected{false};
  std::atomic<bool> disconnected{false};
  std::atomic<int> reliableReceived{0};
  std::atomic<int> unreliableReceived{0};
  std::vector<std::vector<uint8_t>> receivedMessages;
  std::mutex messagesMutex;

  void OnConnected() override { connected = true; }

  void OnDisconnected() override { disconnected = true; }

  void OnReliableReceived(uint8_t channel, const void* data,
                          size_t size) override {
    (void)channel;
    reliableReceived++;

    const std::scoped_lock lock(messagesMutex);
    const std::vector<uint8_t> msg(static_cast<const uint8_t*>(data),
                             static_cast<const uint8_t*>(data) + size);
    receivedMessages.push_back(msg);
  }

  void OnUnreliableReceived(uint8_t channel, const void* data,
                            size_t size) override {
    (void)channel;
    unreliableReceived++;

    const std::scoped_lock lock(messagesMutex);
    const std::vector<uint8_t> msg(static_cast<const uint8_t*>(data),
                             static_cast<const uint8_t*>(data) + size);
    receivedMessages.push_back(msg);
  }

  std::vector<std::vector<uint8_t>> GetMessages() {
    const std::scoped_lock lock(messagesMutex);
    return receivedMessages;
  }

  void ClearMessages() {
    const std::scoped_lock lock(messagesMutex);
    receivedMessages.clear();
  }
};

TEST_F(IntegrationTest, ClientServerConnect) {
  const uint16_t server_port = 15001;

  auto factory = SocketFactoryRegistry::GetFactory();

  // Server setup
  SocketConfig server_cfg;
  server_cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(server_cfg);
  ASSERT_NE(server_socket, nullptr);

  SocketAddress server_addr = SocketAddress::FromIPv4(0);  // INADDR_ANY
  ASSERT_EQ(server_socket->Bind(server_addr, server_port), SocketError::kNone);

  ReliableConnectionConfig conn_cfg;
  conn_cfg.pingIntervalMs = 200;
  conn_cfg.disconnectTimeoutMs = 1000;

  EchoServerHandler server_handler;
  auto server_manager =
      std::make_unique<ConnectionManager>(server_socket.get(), conn_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  // Client setup
  auto client_socket = factory->CreateUdpSocket(server_cfg);
  ASSERT_NE(client_socket, nullptr);

  ClientHandler client_handler;
  auto client_conn =
      std::make_unique<ReliableConnection>(client_socket.get(), conn_cfg);
  client_conn->SetHandler(&client_handler);

  // Connect
  SocketAddress connect_addr =
      SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  client_conn->Connect(connect_addr, server_port);

  EXPECT_FALSE(client_handler.connected);

  // Run network loop
  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    char buffer[2048];

    while (running) {
      // Server receive
      while (true) {
        SocketAddress from;
        uint16_t from_port = 0;
        auto result =
            server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;

        if (result.bytes > 0) {
          server_manager->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      // Client receive
      while (true) {
        SocketAddress from;
        uint16_t from_port = 0;
        auto result =
            client_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;

        if (result.bytes > 0) {
          client_conn->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      server_manager->Update();
      client_conn->Update();

      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_TRUE(client_handler.connected) << "Client should connect to server";

  auto connections = server_manager->GetConnections();
  EXPECT_EQ(connections.size(), 1) << "Server should have one client";

  running = false;
  network_thread.join();
}

TEST_F(IntegrationTest, ClientServerReliableMessage) {
  const uint16_t server_port = 15002;

  auto factory = SocketFactoryRegistry::GetFactory();

  // Server
  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);

  SocketAddress server_addr = SocketAddress::FromIPv4(0);
  ASSERT_EQ(server_socket->Bind(server_addr, server_port), SocketError::kNone);

  ReliableConnectionConfig conn_cfg;
  conn_cfg.retryTimeoutMs = 100;

  EchoServerHandler server_handler;
  auto server_manager =
      std::make_unique<ConnectionManager>(server_socket.get(), conn_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  // Client
  auto client_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(client_socket, nullptr);

  ClientHandler client_handler;
  auto client_conn =
      std::make_unique<ReliableConnection>(client_socket.get(), conn_cfg);
  client_conn->SetHandler(&client_handler);

  SocketAddress connect_addr = SocketAddress::FromIPv4(0x7F000001);
  client_conn->Connect(connect_addr, server_port);

  // Network loop
  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    char buffer[2048];

    while (running) {
      while (true) {
        SocketAddress from;
        uint16_t from_port = 0;
        auto result =
            server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      while (true) {
        SocketAddress from;
        uint16_t from_port = 0;
        auto result =
            client_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          client_conn->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      server_manager->Update();
      client_conn->Update();
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }

  ASSERT_TRUE(client_handler.connected);

  // Send message
  const char* test_message = "Hello, Server!";
  client_conn->SendReliable(0, test_message, strlen(test_message));

  // Wait for echo
  for (int i = 0; i < 50 && client_handler.reliableReceived == 0; i++) {
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_GT(client_handler.reliableReceived, 0)
      << "Should receive echoed message";
  EXPECT_GT(server_handler.messagesReceived, 0)
      << "Server should receive message";

  auto messages = client_handler.GetMessages();
  ASSERT_FALSE(messages.empty());

  const std::string received(messages.at(0).begin(), messages.at(0).end());
  EXPECT_EQ(received, std::string(test_message));

  running = false;
  network_thread.join();
}

TEST_F(IntegrationTest, ClientServerMultipleMessages) {
  const uint16_t server_port = 15003;

  auto factory = SocketFactoryRegistry::GetFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);

  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), server_port),
            SocketError::kNone);

  ReliableConnectionConfig conn_cfg;
  EchoServerHandler server_handler;
  auto server_manager =
      std::make_unique<ConnectionManager>(server_socket.get(), conn_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  auto client_socket = factory->CreateUdpSocket(cfg);
  ClientHandler client_handler;
  auto client_conn =
      std::make_unique<ReliableConnection>(client_socket.get(), conn_cfg);
  client_conn->SetHandler(&client_handler);

  client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    char buffer[2048];
    while (running) {
      SocketAddress from;
      uint16_t from_port = 0;

      while (true) {
        auto result =
            server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      while (true) {
        auto result =
            client_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          client_conn->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      server_manager->Update();
      client_conn->Update();
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(client_handler.connected);

  // Send multiple messages
  const int message_count = 10;
  for (int i = 0; i < message_count; i++) {
    const std::string msg = "Message #" + std::to_string(i);
    client_conn->SendReliable(0, msg.c_str(), msg.length());
    std::this_thread::sleep_for(20ms);
  }

  // Wait for all echoes
  for (int i = 0; i < 100 && client_handler.reliableReceived < message_count;
       i++) {
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_GE(client_handler.reliableReceived, message_count)
      << "Should receive all echoed messages";

  running = false;
  network_thread.join();
}

TEST_F(IntegrationTest, ClientServerUnreliableMessages) {
  const uint16_t server_port = 15004;

  auto factory = SocketFactoryRegistry::GetFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);

  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), server_port),
            SocketError::kNone);

  EchoServerHandler server_handler;
  auto server_manager =
      std::make_unique<ConnectionManager>(server_socket.get());
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  auto client_socket = factory->CreateUdpSocket(cfg);
  ClientHandler client_handler;
  auto client_conn = std::make_unique<ReliableConnection>(client_socket.get());
  client_conn->SetHandler(&client_handler);

  client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    char buffer[2048];
    while (running) {
      SocketAddress from;
      uint16_t from_port = 0;

      while (true) {
        auto result =
            server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      while (true) {
        auto result =
            client_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          client_conn->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      server_manager->Update();
      client_conn->Update();
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(client_handler.connected);

  // Send unreliable messages
  const char* msg = "Unreliable snapshot";
  for (int i = 0; i < 5; i++) {
    client_conn->SendUnreliable(1, msg, strlen(msg));
    std::this_thread::sleep_for(30ms);
  }

  // Give time for processing
  std::this_thread::sleep_for(300ms);

  EXPECT_GT(client_handler.unreliableReceived, 0)
      << "Should receive some unreliable messages";

  running = false;
  network_thread.join();
}

TEST_F(IntegrationTest, MultipleClients) {
  const uint16_t server_port = 15005;
  const int num_clients = 3;

  auto factory = SocketFactoryRegistry::GetFactory();

  // Server
  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);

  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), server_port),
            SocketError::kNone);

  EchoServerHandler server_handler;
  auto server_manager =
      std::make_unique<ConnectionManager>(server_socket.get());
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  // Multiple clients
  std::vector<std::unique_ptr<ISocket>> client_sockets;
  std::vector<std::unique_ptr<ReliableConnection>> client_conns;
  std::vector<std::unique_ptr<ClientHandler>> client_handlers;

  for (int i = 0; i < num_clients; i++) {
    auto socket = factory->CreateUdpSocket(cfg);
    ASSERT_NE(socket, nullptr);

    auto handler = std::make_unique<ClientHandler>();
    auto conn = std::make_unique<ReliableConnection>(socket.get());
    conn->SetHandler(handler.get());
    conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

    client_sockets.push_back(std::move(socket));
    client_conns.push_back(std::move(conn));
    client_handlers.push_back(std::move(handler));
  }

  // Network loop
  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    char buffer[2048];
    while (running) {
      SocketAddress from;
      uint16_t from_port = 0;

      while (true) {
        auto result =
            server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      for (size_t i = 0; i < client_sockets.size(); i++) {
        while (true) {
          auto result = client_sockets.at(i)->Receive(buffer, sizeof(buffer), from, from_port);
          if (!result.Succeeded()) break;
          if (result.bytes > 0) {
            client_conns.at(i)->ProcessPacket(
                buffer, static_cast<std::size_t>(result.bytes), from,
                from_port);
          }
        }
        client_conns.at(i)->Update();
      }
      server_manager->Update();
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for all clients to connect
  bool all_connected = false;
  for (int attempt = 0; attempt < 100 && !all_connected; attempt++) {
    all_connected = true;
    for (const auto& handler : client_handlers) {
      if (!handler->connected) {
        all_connected = false;
        break;
      }
    }
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_TRUE(all_connected) << "All clients should connect";

  auto connections = server_manager->GetConnections();
  EXPECT_EQ(connections.size(), num_clients)
      << "Server should have " << num_clients << " clients";

  // Each client sends a message
  for (size_t i = 0; i < client_conns.size(); i++) {
    const std::string msg = "Client " + std::to_string(i);
    client_conns.at(i)->SendReliable(0, msg.c_str(), msg.length());
  }

  // Wait for broadcasts
  std::this_thread::sleep_for(1s);

  // Each client should receive messages from all clients (including themselves)
  for (const auto& handler : client_handlers) {
    EXPECT_GE(handler->reliableReceived, num_clients)
        << "Each client should receive all broadcast messages";
  }

  running = false;
  network_thread.join();
}

TEST_F(IntegrationTest, ClientDisconnect) {
  const uint16_t server_port = 15006;

  auto factory = SocketFactoryRegistry::GetFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);

  ASSERT_EQ(server_socket->Bind(SocketAddress::FromIPv4(0), server_port),
            SocketError::kNone);

  EchoServerHandler server_handler;
  auto server_manager =
      std::make_unique<ConnectionManager>(server_socket.get());
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  auto client_socket = factory->CreateUdpSocket(cfg);
  ClientHandler client_handler;
  auto client_conn = std::make_unique<ReliableConnection>(client_socket.get());
  client_conn->SetHandler(&client_handler);

  client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

  std::atomic<bool> running{true};
  std::thread network_thread([&]() {
    char buffer[2048];
    while (running) {
      SocketAddress from;
      uint16_t from_port = 0;

      while (true) {
        auto result =
            server_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          server_manager->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      while (true) {
        auto result =
            client_socket->Receive(buffer, sizeof(buffer), from, from_port);
        if (!result.Succeeded()) break;
        if (result.bytes > 0) {
          client_conn->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
        }
      }

      server_manager->Update();
      client_conn->Update();
      std::this_thread::sleep_for(10ms);
    }
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(client_handler.connected);

  // Disconnect
  client_conn->Disconnect();

  // Wait for disconnection
  std::this_thread::sleep_for(500ms);

  EXPECT_TRUE(client_handler.disconnected) << "Client should be disconnected";
  EXPECT_FALSE(client_conn->IsConnected());

  running = false;
  network_thread.join();
}