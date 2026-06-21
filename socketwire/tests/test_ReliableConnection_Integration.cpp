#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "connection_manager.hpp"
#include "i_socket.hpp"
#include "reliable_connection.hpp"
#include "sharded_connection_manager.hpp"
#include "socket_constants.hpp"
#include "socket_init.hpp"
#include "task_queue.hpp"

using namespace std::chrono_literals;
using namespace socketwire;  // NOLINT
using socketwire::ReliableConnectionConfig;
using socketwire::SocketAddress;

class IntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    socketwire::InitializeSockets();

    auto factory = SocketFactoryRegistry::GetFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be available";
  }
};

// Simple echo server handler
class EchoServerHandler : public IReliableConnectionHandler {
public:
  ConnectionManager* manager = nullptr;
  std::atomic<int> messagesReceived{0};

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    messagesReceived++;

    // Echo back to all clients
    if (manager != nullptr) {
      BroadcastReliable(*manager, channel, data, size);
    }
  }

  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            std::size_t size) override {
    messagesReceived++;

    // Echo back unreliable
    if (manager != nullptr) {
      BroadcastUnreliable(*manager, channel, data, size);
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
  std::vector<std::vector<std::uint8_t>> receivedMessages;
  std::mutex messagesMutex;

  void OnConnected() override { connected = true; }

  void OnDisconnected() override { disconnected = true; }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    (void)channel;
    reliableReceived++;

    const std::scoped_lock lock(messagesMutex);
    const std::vector<std::uint8_t> msg(
      static_cast<const std::uint8_t*>(data),
      static_cast<const std::uint8_t*>(data) + size);
    receivedMessages.push_back(msg);
  }

  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            std::size_t size) override {
    (void)channel;
    unreliableReceived++;

    const std::scoped_lock lock(messagesMutex);
    const std::vector<std::uint8_t> msg(
      static_cast<const std::uint8_t*>(data),
      static_cast<const std::uint8_t*>(data) + size);
    receivedMessages.push_back(msg);
  }

  std::vector<std::vector<std::uint8_t>> GetMessages() {
    const std::scoped_lock lock(messagesMutex);
    return receivedMessages;
  }

  void ClearMessages() {
    const std::scoped_lock lock(messagesMutex);
    receivedMessages.clear();
  }
};

void PumpPair(ISocket& server_socket, ConnectionManager& server_manager,
              ISocket& client_socket, ReliableConnection& client_conn) {
  char buffer[2048];

  while (true) {
    SocketAddress from;
    std::uint16_t from_port = 0;
    auto result = server_socket.Receive(buffer, sizeof(buffer), from, from_port);
    if (!result.Succeeded()) break;
    if (result.bytes > 0) {
      server_manager.ProcessPacket(buffer,
                                   static_cast<std::size_t>(result.bytes),
                                   from, from_port);
    }
  }

  while (true) {
    SocketAddress from;
    std::uint16_t from_port = 0;
    auto result = client_socket.Receive(buffer, sizeof(buffer), from, from_port);
    if (!result.Succeeded()) break;
    if (result.bytes > 0) {
      client_conn.ProcessPacket(buffer, static_cast<std::size_t>(result.bytes),
                                from, from_port);
    }
  }

  server_manager.Update();
  client_conn.Update();
}

template <typename Done>
bool PumpUntil(ISocket& server_socket, ConnectionManager& server_manager,
               ISocket& client_socket, ReliableConnection& client_conn,
               Done done, std::chrono::milliseconds timeout = 2s) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (std::chrono::steady_clock::now() < deadline) {
    PumpPair(server_socket, server_manager, client_socket, client_conn);
    if (done()) return true;
    std::this_thread::sleep_for(5ms);
  }
  PumpPair(server_socket, server_manager, client_socket, client_conn);
  return done();
}

TEST_F(IntegrationTest, ClientServerReliableMessageIPv6Loopback) {
  auto factory = SocketFactoryRegistry::GetFactory();

  SocketConfig cfg;
  cfg.nonBlocking = true;
  cfg.enableIPv6 = true;

  auto server_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(server_socket, nullptr);
  const SocketError server_bind =
    server_socket->Bind(socket_constants::AnyIPv6(), 0);
  if (server_bind != SocketError::kNone) {
    GTEST_SKIP() << "IPv6 loopback is unavailable";
  }
  const std::uint16_t server_port = server_socket->LocalPort();

  auto client_socket = factory->CreateUdpSocket(cfg);
  ASSERT_NE(client_socket, nullptr);
  const SocketError client_bind =
    client_socket->Bind(socket_constants::LoopbackIPv6(), 0);
  if (client_bind != SocketError::kNone) {
    GTEST_SKIP() << "IPv6 loopback client bind is unavailable";
  }

  ReliableConnectionConfig conn_cfg;
  conn_cfg.retryTimeoutMs = 50;
  ConnectionManagerConfig manager_cfg;
  manager_cfg.connection = conn_cfg;

  EchoServerHandler server_handler;
  ConnectionManager server_manager(server_socket.get(), manager_cfg);
  server_handler.manager = &server_manager;
  server_manager.SetHandler(&server_handler);

  ClientHandler client_handler;
  ReliableConnection client_conn(client_socket.get(), conn_cfg);
  client_conn.SetHandler(&client_handler);
  ASSERT_TRUE(client_conn.Connect(socket_constants::LoopbackIPv6(),
                                  server_port));

  ASSERT_TRUE(PumpUntil(*server_socket, server_manager, *client_socket,
                        client_conn,
                        [&] { return client_handler.connected.load(); }))
    << "IPv6 client should connect to server";

  const std::array<std::uint8_t, 3> payload{'v', '6', '!'};
  ASSERT_TRUE(client_conn.SendReliable(0, payload.data(), payload.size()));
  ASSERT_TRUE(PumpUntil(*server_socket, server_manager, *client_socket,
                        client_conn,
                        [&] { return client_handler.reliableReceived > 0; }))
    << "IPv6 reliable echo should arrive";
}

TEST_F(IntegrationTest, DualStackServerAcceptsIPv4Client) {
  auto factory = SocketFactoryRegistry::GetFactory();

  SocketConfig server_cfg;
  server_cfg.nonBlocking = true;
  server_cfg.enableIPv6 = true;
  auto server_socket = factory->CreateUdpSocket(server_cfg);
  ASSERT_NE(server_socket, nullptr);
  const SocketError server_bind =
    server_socket->Bind(socket_constants::AnyIPv6(), 0);
  if (server_bind != SocketError::kNone) {
    GTEST_SKIP() << "dual-stack bind is unavailable";
  }
  const std::uint16_t server_port = server_socket->LocalPort();

  SocketConfig client_cfg;
  client_cfg.nonBlocking = true;
  auto client_socket = factory->CreateUdpSocket(client_cfg);
  ASSERT_NE(client_socket, nullptr);
  ASSERT_EQ(client_socket->Bind(socket_constants::Any(), 0),
            SocketError::kNone);

  ReliableConnectionConfig conn_cfg;
  conn_cfg.retryTimeoutMs = 50;
  ConnectionManagerConfig manager_cfg;
  manager_cfg.connection = conn_cfg;

  EchoServerHandler server_handler;
  ConnectionManager server_manager(server_socket.get(), manager_cfg);
  server_handler.manager = &server_manager;
  server_manager.SetHandler(&server_handler);

  ClientHandler client_handler;
  ReliableConnection client_conn(client_socket.get(), conn_cfg);
  client_conn.SetHandler(&client_handler);
  ASSERT_TRUE(
    client_conn.Connect(socket_constants::Loopback(), server_port));

  ASSERT_TRUE(PumpUntil(*server_socket, server_manager, *client_socket,
                        client_conn,
                        [&] { return client_handler.connected.load(); }))
    << "IPv4 client should connect to dual-stack server";

  const auto clients = server_manager.GetConnections();
  ASSERT_EQ(clients.size(), 1U);
  EXPECT_FALSE(clients.front()->address.isIPv6);
  EXPECT_EQ(clients.front()->address.ipv4.hostOrderAddress,
            socket_constants::kIpV4Loopback);
}

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
  ConnectionManagerConfig manager_cfg;
  manager_cfg.connection = conn_cfg;

  EchoServerHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get(), manager_cfg);
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
  TaskQueue network_queue;
  std::thread network_thread([&]() {
    char buffer[2048];

    while (running) {
      network_queue.Drain();

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
      network_queue.Drain();

      std::this_thread::sleep_for(10ms);
    }
    network_queue.Drain();
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }

  EXPECT_TRUE(client_handler.connected) << "Client should connect to server";

  running = false;
  network_thread.join();

  auto connections = server_manager->GetConnections();
  EXPECT_EQ(connections.size(), 1) << "Server should have one client";
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
  ConnectionManagerConfig manager_cfg;
  manager_cfg.connection = conn_cfg;

  EchoServerHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get(), manager_cfg);
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
  TaskQueue network_queue;
  std::thread network_thread([&]() {
    char buffer[2048];

    while (running) {
      network_queue.Drain();

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
      network_queue.Drain();
      std::this_thread::sleep_for(10ms);
    }
    network_queue.Drain();
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }

  ASSERT_TRUE(client_handler.connected);

  // Send message
  const char* test_message = "Hello, Server!";
  std::atomic<bool> send_done{false};
  std::atomic<bool> send_ok{false};
  ASSERT_TRUE(network_queue.Post([&] {
    send_ok = client_conn->SendReliable(0, test_message, strlen(test_message));
    send_done = true;
  }));
  for (int i = 0; i < 50 && !send_done; i++) {
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_TRUE(send_done);
  ASSERT_TRUE(send_ok);

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
  ConnectionManagerConfig manager_cfg;
  manager_cfg.connection = conn_cfg;
  EchoServerHandler server_handler;
  auto server_manager =
    std::make_unique<ConnectionManager>(server_socket.get(), manager_cfg);
  server_handler.manager = server_manager.get();
  server_manager->SetHandler(&server_handler);

  auto client_socket = factory->CreateUdpSocket(cfg);
  ClientHandler client_handler;
  auto client_conn =
    std::make_unique<ReliableConnection>(client_socket.get(), conn_cfg);
  client_conn->SetHandler(&client_handler);

  client_conn->Connect(SocketAddress::FromIPv4(0x7F000001), server_port);

  std::atomic<bool> running{true};
  TaskQueue network_queue;
  std::thread network_thread([&]() {
    char buffer[2048];
    while (running) {
      network_queue.Drain();

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
      network_queue.Drain();
      std::this_thread::sleep_for(10ms);
    }
    network_queue.Drain();
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(client_handler.connected);

  // Send multiple messages
  const int message_count = 10;
  std::atomic<int> sent{0};
  std::atomic<int> send_errors{0};
  for (int i = 0; i < message_count; i++) {
    const auto msg =
      std::make_shared<const std::string>("Message #" + std::to_string(i));
    ASSERT_TRUE(network_queue.Post([&, msg] {
      try {
        if (client_conn->SendReliable(0, msg->c_str(), msg->length())) ++sent;
      } catch (...) {
        ++send_errors;
      }
    }));
    std::this_thread::sleep_for(20ms);
  }
  for (int i = 0; i < 100 && sent < message_count; i++) {
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_EQ(send_errors, 0);
  ASSERT_EQ(sent, message_count);

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
  TaskQueue network_queue;
  std::thread network_thread([&]() {
    char buffer[2048];
    while (running) {
      network_queue.Drain();

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
      network_queue.Drain();
      std::this_thread::sleep_for(10ms);
    }
    network_queue.Drain();
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(client_handler.connected);

  // Send unreliable messages
  const char* msg = "Unreliable snapshot";
  std::atomic<int> sent{0};
  for (int i = 0; i < 5; i++) {
    ASSERT_TRUE(network_queue.Post([&] {
      if (client_conn->SendUnreliable(1, msg, strlen(msg))) ++sent;
    }));
    std::this_thread::sleep_for(30ms);
  }
  for (int i = 0; i < 50 && sent < 5; i++) {
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_EQ(sent, 5);

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
  TaskQueue network_queue;
  std::thread network_thread([&]() {
    char buffer[2048];
    while (running) {
      network_queue.Drain();

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
          auto result = client_sockets.at(i)->Receive(buffer, sizeof(buffer),
                                                      from, from_port);
          if (!result.Succeeded()) break;
          if (result.bytes > 0) {
            client_conns.at(i)->ProcessPacket(
              buffer, static_cast<std::size_t>(result.bytes), from, from_port);
          }
        }
        client_conns.at(i)->Update();
      }
      server_manager->Update();
      network_queue.Drain();
      std::this_thread::sleep_for(10ms);
    }
    network_queue.Drain();
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

  std::atomic<int> connection_count{-1};
  ASSERT_TRUE(network_queue.Post([&] {
    connection_count =
      static_cast<int>(server_manager->GetConnections().size());
  }));
  for (int i = 0; i < 50 && connection_count < 0; i++) {
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_EQ(connection_count, num_clients)
    << "Server should have " << num_clients << " clients";

  // Each client sends a message
  std::atomic<int> sent{0};
  std::atomic<int> send_errors{0};
  for (size_t i = 0; i < client_conns.size(); i++) {
    const auto msg =
      std::make_shared<const std::string>("Client " + std::to_string(i));
    ASSERT_TRUE(network_queue.Post([&, i, msg] {
      try {
        if (client_conns.at(i)->SendReliable(0, msg->c_str(), msg->length())) {
          ++sent;
        }
      } catch (...) {
        ++send_errors;
      }
    }));
  }
  for (int i = 0; i < 100 && sent < num_clients; i++) {
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_EQ(send_errors, 0);
  ASSERT_EQ(sent, num_clients);

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
  TaskQueue network_queue;
  std::thread network_thread([&]() {
    char buffer[2048];
    while (running) {
      network_queue.Drain();

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
      network_queue.Drain();
      std::this_thread::sleep_for(10ms);
    }
    network_queue.Drain();
  });

  // Wait for connection
  for (int i = 0; i < 50 && !client_handler.connected; i++) {
    std::this_thread::sleep_for(50ms);
  }
  ASSERT_TRUE(client_handler.connected);

  // Disconnect
  std::atomic<bool> disconnect_done{false};
  ASSERT_TRUE(network_queue.Post([&] {
    client_conn->Disconnect();
    disconnect_done = true;
  }));
  for (int i = 0; i < 50 && !disconnect_done; i++) {
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_TRUE(disconnect_done);

  // Wait for disconnection
  std::this_thread::sleep_for(500ms);

  running = false;
  network_thread.join();

  EXPECT_TRUE(client_handler.disconnected) << "Client should be disconnected";
  EXPECT_FALSE(client_conn->IsConnected());
}

TEST_F(IntegrationTest, ShardedConnectionManagerEchoesManyClients) {
  constexpr int k_client_count = 100;

  auto factory = SocketFactoryRegistry::GetFactory();
  ASSERT_NE(factory, nullptr);

  ReliableConnectionConfig conn_cfg;
  conn_cfg.retryTimeoutMs = 50;
  conn_cfg.disconnectTimeoutMs = 2000;
  conn_cfg.numChannels = 2;

  ShardedConnectionManagerConfig server_cfg;
  server_cfg.port = 0;
  server_cfg.workerCount = 2;
  server_cfg.connection.connection = conn_cfg;
  server_cfg.connection.maxClients = 256;
  server_cfg.connection.maxHandshakesPerSecond = 1000;

  ShardedConnectionManager server(server_cfg);
  server.SetPacketCallback([](ShardedClientHandle,
                              ConnectionManager::RemoteClient& client,
                              std::uint8_t channel, const void* data,
                              std::size_t size, bool reliable) {
    if (client.connection == nullptr || !client.connection->IsConnected()) {
      return;
    }
    if (reliable) {
      (void)client.connection->SendReliable(channel, data, size);
    } else {
      (void)client.connection->SendUnreliable(channel, data, size);
    }
  });

  if (!server.Start()) {
    GTEST_SKIP() << "SO_REUSEPORT is not available on this platform";
  }

  struct Client {
    std::unique_ptr<ISocket> socket;
    std::unique_ptr<ReliableConnection> connection;
    std::unique_ptr<ClientHandler> handler;
  };

  SocketConfig socket_cfg;
  socket_cfg.nonBlocking = true;

  std::vector<Client> clients;
  clients.reserve(k_client_count);
  for (int i = 0; i < k_client_count; ++i) {
    Client client;
    client.socket = factory->CreateUdpSocket(socket_cfg);
    ASSERT_NE(client.socket, nullptr);
    client.handler = std::make_unique<ClientHandler>();
    client.connection =
      std::make_unique<ReliableConnection>(client.socket.get(), conn_cfg);
    client.connection->SetHandler(client.handler.get());
    ASSERT_TRUE(client.connection->Connect(SocketAddress::FromIPv4(0x7F000001),
                                           server.LocalPort()));
    clients.push_back(std::move(client));
  }

  const auto pump_clients = [&] {
    std::array<std::uint8_t, 2048> buffer{};
    for (auto& client : clients) {
      while (true) {
        SocketAddress from;
        std::uint16_t port = 0;
        const auto result =
          client.socket->Receive(buffer.data(), buffer.size(), from, port);
        if (result.Failed() || result.bytes <= 0) break;
        client.connection->ProcessPacket(
          buffer.data(), static_cast<std::size_t>(result.bytes), from, port);
      }
      client.connection->Update();
    }
  };

  const auto connected_count = [&] {
    int connected = 0;
    for (const auto& client : clients) {
      if (client.handler->connected) connected += 1;
    }
    return connected;
  };

  for (int i = 0; i < 500 && connected_count() < k_client_count; ++i) {
    pump_clients();
    std::this_thread::sleep_for(10ms);
  }
  ASSERT_EQ(connected_count(), k_client_count);

  const char payload[] = "sharded echo";
  for (auto& client : clients) {
    ASSERT_TRUE(client.connection->SendReliable(0, payload, sizeof(payload)));
  }

  const auto echoed_count = [&] {
    int echoed = 0;
    for (const auto& client : clients) {
      echoed += client.handler->reliableReceived.load();
    }
    return echoed;
  };

  for (int i = 0; i < 500 && echoed_count() < k_client_count; ++i) {
    pump_clients();
    std::this_thread::sleep_for(10ms);
  }

  EXPECT_GE(echoed_count(), k_client_count);

  std::vector<ShardedClientHandle> handles;
  for (const auto& event : server.DrainEvents()) {
    if (event.type == ShardedEventType::kConnected) {
      handles.push_back(event.client);
    }
  }
  ASSERT_FALSE(handles.empty());

  const int before_push = echoed_count();
  const char server_push[] = "server push";
  ASSERT_TRUE(
    server.SendReliable(handles.front(), 0, server_push, sizeof(server_push)));
  for (int i = 0; i < 500 && echoed_count() == before_push; ++i) {
    pump_clients();
    std::this_thread::sleep_for(10ms);
  }
  EXPECT_GT(echoed_count(), before_push);

  std::this_thread::sleep_for(150ms);
  const auto stats = server.SnapshotStats();
  EXPECT_EQ(stats.workerCount, 2U);
  EXPECT_EQ(stats.connectedClients, static_cast<std::uint32_t>(k_client_count));
  EXPECT_GE(stats.workerConnectedMax, 1U);
}
