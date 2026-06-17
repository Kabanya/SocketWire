#include "connection_manager.hpp"
#include "i_socket.hpp"
#include "reliable_connection.hpp"
#include "socket_init.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

class TestFailure final : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

[[noreturn]] void ThrowParityFailure(const char* file, int line,
                                     const char* condition) {
  throw TestFailure(std::string(file) + ":" + std::to_string(line) +
                    ": check failed: " + condition);
}

#define SOCKETWIRE_PARITY_CHECK(condition)                                    \
  ((condition) ? static_cast<void>(0)                                         \
               : ThrowParityFailure(__FILE__, __LINE__, #condition))

struct ReceivedPacket {
  std::uint8_t channel = 0;
  std::string payload;
};

class CountingHandler final : public socketwire::IReliableConnectionHandler {
 public:
  void OnConnected() override { connected = true; }
  void OnDisconnected() override { disconnected = true; }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    Record(reliable, channel, data, size);
  }

  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            std::size_t size) override {
    Record(unreliable, channel, data, size);
  }

  [[nodiscard]] bool HasReliable(const std::string& payload) const {
    const std::scoped_lock lock(mutex_);
    return std::any_of(reliable.begin(), reliable.end(), [&](const auto& item) {
      return item.payload == payload;
    });
  }

  [[nodiscard]] bool HasUnreliable(const std::string& payload) const {
    const std::scoped_lock lock(mutex_);
    return std::any_of(unreliable.begin(), unreliable.end(),
                       [&](const auto& item) { return item.payload == payload; });
  }

  [[nodiscard]] std::vector<ReceivedPacket> Reliable() const {
    const std::scoped_lock lock(mutex_);
    return reliable;
  }

  bool connected = false;
  bool disconnected = false;

 private:
  void Record(std::vector<ReceivedPacket>& target, std::uint8_t channel,
              const void* data, std::size_t size) {
    const auto* bytes = static_cast<const char*>(data);
    const std::scoped_lock lock(mutex_);
    target.push_back({channel, std::string(bytes, bytes + size)});
  }

  mutable std::mutex mutex_;
  std::vector<ReceivedPacket> reliable;
  std::vector<ReceivedPacket> unreliable;
};

struct Client {
  std::unique_ptr<socketwire::ISocket> socket;
  std::unique_ptr<socketwire::ReliableConnection> connection;
  CountingHandler handler;
};

class ParityHarness final {
 public:
  ParityHarness() {
    socketwire::InitializeSockets();
    auto* factory = socketwire::SocketFactoryRegistry::GetFactory();
    SOCKETWIRE_PARITY_CHECK(factory != nullptr);

    socketwire::SocketConfig socket_config;
    socket_config.nonBlocking = true;

    server_socket_ = factory->CreateUdpSocket(socket_config);
    SOCKETWIRE_PARITY_CHECK(server_socket_ != nullptr);
    SOCKETWIRE_PARITY_CHECK(
      server_socket_->Bind(socketwire::SocketAddress::FromIPv4(0), 0) ==
      socketwire::SocketError::kNone);
    // NOLINTNEXTLINE(cppcoreguidelines-prefer-member-initializer)
    server_port_ = server_socket_->LocalPort();
    SOCKETWIRE_PARITY_CHECK(server_port_ != 0);

    connection_config_.retryTimeoutMs = 50;
    connection_config_.pingIntervalMs = 100;
    connection_config_.disconnectTimeoutMs = 2000;
    connection_config_.maxPacketSize = 600;
    connection_config_.numChannels = 2;

    socketwire::ConnectionManagerConfig manager_config;
    manager_config.connection = connection_config_;
    manager_ = std::make_unique<socketwire::ConnectionManager>(
      server_socket_.get(), manager_config);
    manager_->SetHandler(&server_handler_);
  }

  Client& AddClient() {
    auto* factory = socketwire::SocketFactoryRegistry::GetFactory();
    socketwire::SocketConfig socket_config;
    socket_config.nonBlocking = true;

    auto client = std::make_unique<Client>();
    client->socket = factory->CreateUdpSocket(socket_config);
    SOCKETWIRE_PARITY_CHECK(client->socket != nullptr);
    SOCKETWIRE_PARITY_CHECK(
      client->socket->Bind(socketwire::SocketAddress::FromIPv4(0), 0) ==
      socketwire::SocketError::kNone);
    client->connection = std::make_unique<socketwire::ReliableConnection>(
      client->socket.get(), connection_config_);
    client->connection->SetHandler(&client->handler);
    SOCKETWIRE_PARITY_CHECK(client->connection->Connect(
      socketwire::SocketAddress::FromIPv4(0x7F000001), server_port_));

    clients_.push_back(std::move(client));
    return *clients_.back();
  }

  void WaitForConnections(std::size_t count) {
    SOCKETWIRE_PARITY_CHECK(WaitFor(3s, [&] {
      return manager_->GetConnections().size() == count &&
             std::all_of(clients_.begin(), clients_.end(), [](const auto& c) {
               return c->handler.connected;
             });
    }));
  }

  bool WaitFor(std::chrono::milliseconds timeout,
               const std::function<bool()>& done) {
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
      PumpOnce();
      if (done()) return true;
      std::this_thread::sleep_for(1ms);
    }
    PumpOnce();
    return done();
  }

  void DropNextServerDatagrams(int count) { drop_server_datagrams_ = count; }

  CountingHandler& ServerHandler() { return server_handler_; }
  socketwire::ConnectionManager& Manager() { return *manager_; }

 private:
  void PumpOnce() {
    std::vector<std::uint8_t> buffer(8192);
    socketwire::SocketAddress from;
    std::uint16_t from_port = 0;

    while (true) {
      const auto result =
        server_socket_->Receive(buffer.data(), buffer.size(), from, from_port);
      if (result.Failed() || result.bytes <= 0) break;
      if (drop_server_datagrams_ > 0) {
        --drop_server_datagrams_;
        continue;
      }
      manager_->ProcessPacket(buffer.data(), static_cast<std::size_t>(result.bytes),
                              from, from_port);
    }

    for (auto& client : clients_) {
      while (true) {
        const auto result =
          client->socket->Receive(buffer.data(), buffer.size(), from, from_port);
        if (result.Failed() || result.bytes <= 0) break;
        client->connection->ProcessPacket(
          buffer.data(), static_cast<std::size_t>(result.bytes), from,
          from_port);
      }
    }

    manager_->Update();
    for (auto& client : clients_) client->connection->Update();
  }

  socketwire::ReliableConnectionConfig connection_config_;
  std::unique_ptr<socketwire::ISocket> server_socket_;
  std::unique_ptr<socketwire::ConnectionManager> manager_;
  CountingHandler server_handler_;
  std::vector<std::unique_ptr<Client>> clients_;
  std::uint16_t server_port_ = 0;
  int drop_server_datagrams_ = 0;
};

void DuplicateConnectDisconnect() {
  ParityHarness harness;
  Client& client = harness.AddClient();
  harness.WaitForConnections(1);

  client.connection->Disconnect();
  SOCKETWIRE_PARITY_CHECK(client.handler.disconnected);
  SOCKETWIRE_PARITY_CHECK(!client.connection->IsConnected());
}

void DuplicateReliableDelivery() {
  ParityHarness harness;
  Client& client = harness.AddClient();
  harness.WaitForConnections(1);

  const std::string payload = "reliable-message";
  SOCKETWIRE_PARITY_CHECK(
    client.connection->SendReliable(0, payload.data(), payload.size()));
  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(
    3s, [&] { return harness.ServerHandler().HasReliable(payload); }));
}

void DuplicateUnreliableDelivery() {
  ParityHarness harness;
  Client& client = harness.AddClient();
  harness.WaitForConnections(1);

  const std::string payload = "unreliable-message";
  SOCKETWIRE_PARITY_CHECK(
    client.connection->SendUnreliable(1, payload.data(), payload.size()));
  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(
    3s, [&] { return harness.ServerHandler().HasUnreliable(payload); }));
}

void DuplicateChannelSeparation() {
  ParityHarness harness;
  Client& client = harness.AddClient();
  harness.WaitForConnections(1);

  SOCKETWIRE_PARITY_CHECK(client.connection->SendReliable(0, "channel-0", 9));
  SOCKETWIRE_PARITY_CHECK(client.connection->SendReliable(1, "channel-1", 9));
  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(3s, [&] {
    return harness.ServerHandler().HasReliable("channel-0") &&
           harness.ServerHandler().HasReliable("channel-1");
  }));

  const auto received = harness.ServerHandler().Reliable();
  SOCKETWIRE_PARITY_CHECK(received.size() >= 2);
  SOCKETWIRE_PARITY_CHECK(received.at(received.size() - 2).channel == 0);
  SOCKETWIRE_PARITY_CHECK(received.at(received.size() - 1).channel == 1);
}

void DuplicateFragmentedReliablePacket() {
  ParityHarness harness;
  Client& client = harness.AddClient();
  harness.WaitForConnections(1);

  std::string payload(4096, '\0');
  for (std::size_t i = 0; i < payload.size(); ++i) {
    payload.at(i) = static_cast<char>('A' + (i % 26));
  }

  SOCKETWIRE_PARITY_CHECK(
    client.connection->SendReliable(0, payload.data(), payload.size()));
  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(
    5s, [&] { return harness.ServerHandler().HasReliable(payload); }));
}

void DuplicateMultipleClients() {
  ParityHarness harness;
  Client& first = harness.AddClient();
  Client& second = harness.AddClient();
  harness.WaitForConnections(2);

  SOCKETWIRE_PARITY_CHECK(first.connection->SendReliable(0, "client-a", 8));
  SOCKETWIRE_PARITY_CHECK(second.connection->SendReliable(0, "client-b", 8));
  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(3s, [&] {
    return harness.ServerHandler().HasReliable("client-a") &&
           harness.ServerHandler().HasReliable("client-b");
  }));
}

void DuplicateBroadcastReliable() {
  ParityHarness harness;
  Client& first = harness.AddClient();
  Client& second = harness.AddClient();
  harness.WaitForConnections(2);

  const std::string payload = "broadcast-message";
  socketwire::BroadcastReliable(harness.Manager(), 0, payload.data(),
                                payload.size());
  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(3s, [&] {
    return first.handler.HasReliable(payload) &&
           second.handler.HasReliable(payload);
  }));
}

void DuplicateTransportStats() {
  ParityHarness harness;
  Client& client = harness.AddClient();
  harness.WaitForConnections(1);

  const std::string payload = "stats-message";
  SOCKETWIRE_PARITY_CHECK(
    client.connection->SendReliable(0, payload.data(), payload.size()));
  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(
    3s, [&] { return harness.ServerHandler().HasReliable(payload); }));

  const auto connections = harness.Manager().GetConnections();
  SOCKETWIRE_PARITY_CHECK(connections.size() == 1);
  SOCKETWIRE_PARITY_CHECK(client.connection->GetSentPackets() > 0);
  SOCKETWIRE_PARITY_CHECK(
    connections.front()->connection->GetReceivedPackets() > 0);
}

void AdverseReliableDeliveryAfterDroppedDatagrams() {
  ParityHarness harness;
  Client& client = harness.AddClient();
  harness.WaitForConnections(1);

  harness.DropNextServerDatagrams(2);
  const std::string payload = "reliable-after-drop";
  SOCKETWIRE_PARITY_CHECK(
    client.connection->SendReliable(0, payload.data(), payload.size()));
  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(
    5s, [&] { return harness.ServerHandler().HasReliable(payload); }));
}

void PerformanceReliableBurstCompletesWithinBudget() {
  ParityHarness harness;
  Client& client = harness.AddClient();
  harness.WaitForConnections(1);

  constexpr int k_burst_size = 64;
  const auto start = Clock::now();
  for (int i = 0; i < k_burst_size; ++i) {
    const std::string payload = "burst-" + std::to_string(i);
    SOCKETWIRE_PARITY_CHECK(
      client.connection->SendReliable(0, payload.data(), payload.size()));
  }

  SOCKETWIRE_PARITY_CHECK(harness.WaitFor(2s, [&] {
    return harness.ServerHandler().Reliable().size() ==
           static_cast<std::size_t>(k_burst_size);
  }));
  SOCKETWIRE_PARITY_CHECK(Clock::now() - start <= 2s);

  const auto received = harness.ServerHandler().Reliable();
  for (int i = 0; i < k_burst_size; ++i) {
    SOCKETWIRE_PARITY_CHECK(received.at(static_cast<std::size_t>(i)).payload ==
                            "burst-" + std::to_string(i));
  }
}

using TestFn = void (*)();

const std::map<std::string, TestFn>& Tests() {
  static const std::map<std::string, TestFn> kTests{
    {"Duplicate.ConnectDisconnect", &DuplicateConnectDisconnect},
    {"Duplicate.ReliableDelivery", &DuplicateReliableDelivery},
    {"Duplicate.UnreliableDelivery", &DuplicateUnreliableDelivery},
    {"Duplicate.ChannelSeparation", &DuplicateChannelSeparation},
    {"Duplicate.FragmentedReliablePacket", &DuplicateFragmentedReliablePacket},
    {"Duplicate.MultipleClients", &DuplicateMultipleClients},
    {"Duplicate.BroadcastReliable", &DuplicateBroadcastReliable},
    {"Duplicate.TransportStats", &DuplicateTransportStats},
    {"Adverse.ReliableDeliveryAfterDroppedDatagrams",
     &AdverseReliableDeliveryAfterDroppedDatagrams},
    {"Performance.ReliableBurstCompletesWithinBudget",
     &PerformanceReliableBurstCompletesWithinBudget},
  };
  return kTests;
}

void PrintUsage(const char* executable) {
  std::cerr << "usage: " << executable << " --case <name>\n\n";
  std::cerr << "available cases:\n";
  for (const auto& [name, _] : Tests()) std::cerr << "  " << name << '\n';
}

}  // namespace

int main(int argc, char** argv) {
  const char* selected_case = "<none>";
  try {
    if (argc == 3 && std::string(argv[1]) == "--case") {
      selected_case = argv[2];
    } else if (argc == 2 && std::string(argv[1]) == "--list") {
      for (const auto& [name, _] : Tests()) std::cout << name << '\n';
      return 0;
    } else {
      PrintUsage(argv[0]);
      return 2;
    }

    const auto iter = Tests().find(selected_case);
    if (iter == Tests().end()) {
      PrintUsage(argv[0]);
      return 2;
    }

    iter->second();
    std::cout << "[  PASSED  ] " << selected_case << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "[  FAILED  ] " << selected_case << ": " << error.what()
              << '\n';
    return 1;
  } catch (...) {
    std::cerr << "[  FAILED  ] unknown exception\n";
    return 1;
  }
}
