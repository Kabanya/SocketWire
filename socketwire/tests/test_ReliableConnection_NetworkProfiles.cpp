#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "i_socket.hpp"
#include "reliable_connection.hpp"

using socketwire::IncomingDatagram;
using socketwire::IReliableConnectionHandler;
using socketwire::ISocket;
using socketwire::ISocketEventHandler;
using socketwire::ReliableConnection;
using socketwire::ReliableConnectionConfig;
using socketwire::SocketAddress;
using socketwire::SocketError;
using socketwire::SocketResult;

namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

constexpr std::array<std::uint8_t, 4> kPayloadMagic{'S', 'W', 'N', 'P'};
constexpr std::uint16_t kClientPort = 32001;
constexpr std::uint16_t kServerPort = 32002;

enum class EndpointRole : std::uint8_t {
  kClient,
  kServer,
};

struct NetworkProfile {
  std::string name;
  std::uint32_t base_delay_ms = 0;
  std::uint32_t jitter_ms = 0;
  double loss_rate = 0.0;
  double duplicate_rate = 0.0;
  double reorder_rate = 0.0;
  std::uint32_t reorder_extra_ms = 0;
  std::uint32_t bandwidth_bytes_per_second = 0;
  std::int32_t blackout_start_ms = -1;
  std::uint32_t blackout_duration_ms = 0;
  std::uint32_t max_packet_size = 600;
  std::uint32_t scenario_timeout_ms = 1200;
};

struct NetworkTrafficStats {
  std::uint32_t packets_sent = 0;
  std::uint32_t packets_received = 0;
  std::uint32_t packets_dropped_by_network = 0;
  std::uint32_t packets_duplicated_by_network = 0;
  std::uint32_t packets_reordered_by_network = 0;
  std::size_t max_queue_bytes = 0;
};

struct NetworkMetrics {
  std::string scenario_name;
  std::string network_profile;
  std::uint32_t seed = 0;
  std::uint32_t reliable_messages_sent = 0;
  std::uint32_t reliable_messages_delivered = 0;
  std::uint32_t unreliable_messages_sent = 0;
  std::uint32_t unreliable_messages_delivered = 0;
  std::uint32_t duplicate_deliveries = 0;
  std::uint32_t corrupted_deliveries = 0;
  std::uint32_t ordered_violations = 0;
  std::uint32_t wrong_channel_deliveries = 0;
  std::uint32_t partial_message_deliveries = 0;
  std::uint32_t malformed_packets_accepted = 0;
  std::uint32_t timeout_count = 0;
  std::uint32_t disconnect_count = 0;
  std::vector<double> message_latencies_ms;
};

struct ScheduledDatagram {
  Clock::time_point due_time;
  SocketAddress from_addr;
  std::uint16_t from_port = 0;
  SocketAddress to_addr;
  std::uint16_t to_port = 0;
  std::vector<std::uint8_t> payload;
};

bool SameAddress(const SocketAddress& lhs, const SocketAddress& rhs) {
  return lhs == rhs;
}

bool InBlackout(const NetworkProfile& profile, Clock::time_point start,
                Clock::time_point now) {
  if (profile.blackout_start_ms < 0 || profile.blackout_duration_ms == 0) {
    return false;
  }

  const auto elapsed_ms =
    std::chrono::duration_cast<std::chrono::milliseconds>(now - start).count();
  const auto blackout_start =
    static_cast<std::int64_t>(profile.blackout_start_ms);
  const auto blackout_end =
    blackout_start + static_cast<std::int64_t>(profile.blackout_duration_ms);
  return elapsed_ms >= blackout_start && elapsed_ms < blackout_end;
}

class SimulatedNetwork {
 public:
  SimulatedNetwork(NetworkProfile client_to_server,
                   NetworkProfile server_to_client, std::uint32_t seed)
      : client_to_server_(std::move(client_to_server)),
        server_to_client_(std::move(server_to_client)),
        rng_(seed),
        start_time_(Clock::now()),
        next_client_to_server_send_(start_time_),
        next_server_to_client_send_(start_time_) {}

  SocketError BindEndpoint(const SocketAddress& address, std::uint16_t port) {
    for (const auto& endpoint : endpoints_) {
      if (endpoint.port == port) return SocketError::kSystem;
    }
    endpoints_.push_back({address, port});
    return SocketError::kNone;
  }

  SocketResult Send(EndpointRole role, const SocketAddress& from_addr,
                    std::uint16_t from_port, const void* data,
                    std::size_t length, const SocketAddress& to_addr,
                    std::uint16_t to_port) {
    if (data == nullptr || length == 0) {
      return {.bytes = -1, .error = SocketError::kInvalidParam};
    }

    const auto now = Clock::now();
    auto& profile =
      role == EndpointRole::kClient ? client_to_server_ : server_to_client_;
    ++stats_.packets_sent;

    if (InBlackout(profile, start_time_, now) || Roll(profile.loss_rate)) {
      ++stats_.packets_dropped_by_network;
      return {.bytes = static_cast<std::ptrdiff_t>(length),
              .error = SocketError::kNone};
    }

    const std::vector<std::uint8_t> payload(
      static_cast<const std::uint8_t*>(data),
      static_cast<const std::uint8_t*>(data) + length);

    Schedule(profile, role, now, from_addr, from_port, to_addr, to_port,
             payload, false);

    if (Roll(profile.duplicate_rate)) {
      ++stats_.packets_duplicated_by_network;
      Schedule(profile, role, now + 2ms, from_addr, from_port, to_addr, to_port,
               payload, true);
    }

    UpdateMaxQueueBytes();
    return {.bytes = static_cast<std::ptrdiff_t>(length),
            .error = SocketError::kNone};
  }

  SocketResult Receive(const SocketAddress& address, std::uint16_t port,
                       void* buffer, std::size_t capacity,
                       SocketAddress& from_addr, std::uint16_t& from_port) {
    if (buffer == nullptr || capacity == 0) {
      return {.bytes = -1, .error = SocketError::kInvalidParam};
    }

    const auto now = Clock::now();
    for (auto it = scheduled_.begin(); it != scheduled_.end(); ++it) {
      if (it->due_time > now || it->to_port != port ||
          !SameAddress(it->to_addr, address)) {
        continue;
      }

      const std::size_t copy_size = std::min(capacity, it->payload.size());
      std::memcpy(buffer, it->payload.data(), copy_size);
      from_addr = it->from_addr;
      from_port = it->from_port;
      scheduled_.erase(it);
      ++stats_.packets_received;
      return {.bytes = static_cast<std::ptrdiff_t>(copy_size),
              .error = SocketError::kNone};
    }

    return {.bytes = -1, .error = SocketError::kWouldBlock};
  }

  [[nodiscard]] const NetworkTrafficStats& Stats() const { return stats_; }

 private:
  struct Endpoint {
    SocketAddress address;
    std::uint16_t port = 0;
  };

  bool Roll(double probability) {
    if (probability <= 0.0) return false;
    if (probability >= 1.0) return true;
    return probability_dist_(rng_) < probability;
  }

  std::uint32_t JitteredDelayMs(const NetworkProfile& profile) {
    const auto base = static_cast<int>(profile.base_delay_ms);
    if (profile.jitter_ms == 0) return profile.base_delay_ms;

    std::uniform_int_distribution<int> jitter_dist(
      -static_cast<int>(profile.jitter_ms),
      static_cast<int>(profile.jitter_ms));
    return static_cast<std::uint32_t>(std::max(0, base + jitter_dist(rng_)));
  }

  Clock::time_point ApplyBandwidthDelay(const NetworkProfile& profile,
                                        EndpointRole role,
                                        Clock::time_point due_time,
                                        std::size_t bytes) {
    if (profile.bandwidth_bytes_per_second == 0) return due_time;

    auto& next_send = role == EndpointRole::kClient
                        ? next_client_to_server_send_
                        : next_server_to_client_send_;
    const auto start = std::max(due_time, next_send);
    const auto transmit_ms =
      std::max<std::uint64_t>(1, (static_cast<std::uint64_t>(bytes) * 1000U +
                                  profile.bandwidth_bytes_per_second - 1U) /
                                   profile.bandwidth_bytes_per_second);
    next_send = start + std::chrono::milliseconds(transmit_ms);
    return next_send;
  }

  void Schedule(const NetworkProfile& profile, EndpointRole role,
                Clock::time_point now, const SocketAddress& from_addr,
                std::uint16_t from_port, const SocketAddress& to_addr,
                std::uint16_t to_port, const std::vector<std::uint8_t>& payload,
                bool duplicate) {
    auto due_time = now + std::chrono::milliseconds(JitteredDelayMs(profile));
    if (!duplicate && Roll(profile.reorder_rate)) {
      ++stats_.packets_reordered_by_network;
      due_time += std::chrono::milliseconds(profile.reorder_extra_ms);
    }
    due_time = ApplyBandwidthDelay(profile, role, due_time, payload.size());

    scheduled_.push_back(ScheduledDatagram{due_time, from_addr, from_port,
                                           to_addr, to_port, payload});
    std::stable_sort(
      scheduled_.begin(), scheduled_.end(),
      [](const ScheduledDatagram& lhs, const ScheduledDatagram& rhs) {
        return lhs.due_time < rhs.due_time;
      });
  }

  void UpdateMaxQueueBytes() {
    std::size_t queued_bytes = 0;
    for (const auto& datagram : scheduled_) {
      queued_bytes += datagram.payload.size();
    }
    stats_.max_queue_bytes = std::max(stats_.max_queue_bytes, queued_bytes);
  }

  NetworkProfile client_to_server_;
  NetworkProfile server_to_client_;
  std::mt19937 rng_;
  std::uniform_real_distribution<double> probability_dist_{0.0, 1.0};
  Clock::time_point start_time_;
  Clock::time_point next_client_to_server_send_;
  Clock::time_point next_server_to_client_send_;
  std::vector<Endpoint> endpoints_;
  std::deque<ScheduledDatagram> scheduled_;
  NetworkTrafficStats stats_;
};

class SimulatedSocket : public ISocket {
 public:
  SimulatedSocket(SimulatedNetwork* network, EndpointRole role)
      : network_(network), role_(role) {}

  SocketError Bind(const SocketAddress& address, std::uint16_t port) override {
    if (network_ == nullptr || closed_) return SocketError::kClosed;
    const SocketError result = network_->BindEndpoint(address, port);
    if (result != SocketError::kNone) return result;
    address_ = address;
    port_ = port;
    bound_ = true;
    return SocketError::kNone;
  }

  SocketResult SendTo(const void* data, std::size_t length,
                      const SocketAddress& to_addr,
                      std::uint16_t to_port) override {
    if (network_ == nullptr || closed_) {
      return {.bytes = -1, .error = SocketError::kClosed};
    }
    if (!bound_) return {.bytes = -1, .error = SocketError::kNotBound};
    return network_->Send(role_, address_, port_, data, length, to_addr,
                          to_port);
  }

  SocketResult Receive(void* buffer, std::size_t capacity,
                       SocketAddress& from_addr,
                       std::uint16_t& from_port) override {
    if (network_ == nullptr || closed_) {
      return {.bytes = -1, .error = SocketError::kClosed};
    }
    if (!bound_) return {.bytes = -1, .error = SocketError::kNotBound};
    return network_->Receive(address_, port_, buffer, capacity, from_addr,
                             from_port);
  }

  std::size_t ReceiveMany(std::span<IncomingDatagram> datagrams) override {
    std::size_t received_count = 0;
    for (auto& datagram : datagrams) {
      datagram.result = Receive(datagram.data, datagram.capacity,
                                datagram.fromAddr, datagram.fromPort);
      if (datagram.result.Failed() || datagram.result.bytes <= 0) break;
      ++received_count;
    }
    return received_count;
  }

  void Poll(ISocketEventHandler* handler) override { (void)handler; }

  SocketError SetBlocking(bool enable) override {
    blocking_ = enable;
    return SocketError::kNone;
  }

  [[nodiscard]] bool IsBlocking() const override { return blocking_; }
  [[nodiscard]] std::uint16_t LocalPort() const override { return port_; }
  [[nodiscard]] int NativeHandle() const override { return -1; }
  void Close() override { closed_ = true; }

 private:
  SimulatedNetwork* network_ = nullptr;
  EndpointRole role_ = EndpointRole::kClient;
  SocketAddress address_ = SocketAddress::FromIPv4(0x7F000001);
  std::uint16_t port_ = 0;
  bool bound_ = false;
  bool blocking_ = false;
  bool closed_ = false;
};

struct SentMessage {
  std::uint32_t id = 0;
  std::uint8_t channel = 0;
  bool reliable = true;
  std::uint32_t order = 0;
  std::vector<std::uint8_t> payload;
  Clock::time_point sent_at;
  std::uint32_t deliveries = 0;
};

struct ParsedMessage {
  std::uint32_t id = 0;
  std::uint8_t channel = 0;
  bool reliable = true;
  std::uint32_t order = 0;
};

void WriteU32(std::vector<std::uint8_t>& data, std::uint32_t value) {
  const auto* src = reinterpret_cast<const std::uint8_t*>(&value);
  data.insert(data.end(), src, src + sizeof(value));
}

std::uint32_t ReadU32(const std::uint8_t* data) {
  std::uint32_t value = 0;
  std::memcpy(&value, data, sizeof(value));
  return value;
}

std::vector<std::uint8_t> MakePayload(std::uint32_t id, std::uint8_t channel,
                                      bool reliable, std::uint32_t order,
                                      std::size_t body_size) {
  std::vector<std::uint8_t> payload;
  payload.reserve(14 + body_size);
  payload.insert(payload.end(), kPayloadMagic.begin(), kPayloadMagic.end());
  payload.push_back(reliable ? 'R' : 'U');
  payload.push_back(channel);
  WriteU32(payload, id);
  WriteU32(payload, order);

  for (std::size_t i = 0; i < body_size; ++i) {
    payload.push_back(
      static_cast<std::uint8_t>((id * 31U + channel * 17U + i) & 0xFFU));
  }
  return payload;
}

std::optional<ParsedMessage> ParsePayload(const void* data, std::size_t size) {
  if (data == nullptr || size < 14) return std::nullopt;

  const auto* bytes = static_cast<const std::uint8_t*>(data);
  if (!std::equal(kPayloadMagic.begin(), kPayloadMagic.end(), bytes)) {
    return std::nullopt;
  }

  const bool reliable = bytes[4] == 'R';
  if (!reliable && bytes[4] != 'U') return std::nullopt;

  return ParsedMessage{ReadU32(bytes + 6), bytes[5], reliable,
                       ReadU32(bytes + 10)};
}

double Percentile(std::vector<double> values, double percentile) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  const auto index = static_cast<std::size_t>(
    std::clamp(percentile, 0.0, 1.0) * static_cast<double>(values.size() - 1));
  return values.at(index);
}

class RecordingHandler : public IReliableConnectionHandler {
 public:
  RecordingHandler(NetworkMetrics* metrics,
                   std::unordered_map<std::uint32_t, SentMessage>* sent)
      : metrics_(metrics), sent_(sent) {}

  void OnDisconnected() override {
    if (metrics_ != nullptr) ++metrics_->disconnect_count;
  }

  void OnTimeout() override {
    if (metrics_ != nullptr) ++metrics_->timeout_count;
  }

  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override {
    HandleMessage(true, channel, data, size);
  }

  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            std::size_t size) override {
    HandleMessage(false, channel, data, size);
  }

 private:
  void HandleMessage(bool reliable_callback, std::uint8_t callback_channel,
                     const void* data, std::size_t size) {
    if (metrics_ == nullptr || sent_ == nullptr) return;

    const auto parsed = ParsePayload(data, size);
    if (!parsed.has_value()) {
      ++metrics_->corrupted_deliveries;
      ++metrics_->malformed_packets_accepted;
      return;
    }

    const auto record_it = sent_->find(parsed->id);
    if (record_it == sent_->end()) {
      ++metrics_->corrupted_deliveries;
      return;
    }

    SentMessage& record = record_it->second;
    if (record.channel != callback_channel ||
        parsed->channel != record.channel) {
      ++metrics_->wrong_channel_deliveries;
    }
    if (record.reliable != reliable_callback ||
        record.reliable != parsed->reliable) {
      ++metrics_->corrupted_deliveries;
    }
    if (size < record.payload.size()) {
      ++metrics_->partial_message_deliveries;
    }

    const auto* bytes = static_cast<const std::uint8_t*>(data);
    const bool payload_matches =
      size == record.payload.size() &&
      std::equal(record.payload.begin(), record.payload.end(), bytes);
    if (!payload_matches) ++metrics_->corrupted_deliveries;

    if (record.reliable) {
      if (record.deliveries > 0) {
        ++metrics_->duplicate_deliveries;
      } else {
        ++metrics_->reliable_messages_delivered;
        const auto latency_ms = std::chrono::duration<double, std::milli>(
                                  Clock::now() - record.sent_at)
                                  .count();
        metrics_->message_latencies_ms.push_back(latency_ms);

        auto& last_order = last_reliable_order_by_channel_[record.channel];
        if (last_order.has_value() && parsed->order <= *last_order) {
          ++metrics_->ordered_violations;
        }
        last_order = parsed->order;
      }
    } else if (record.deliveries == 0) {
      ++metrics_->unreliable_messages_delivered;
    }

    ++record.deliveries;
  }

  NetworkMetrics* metrics_ = nullptr;
  std::unordered_map<std::uint32_t, SentMessage>* sent_ = nullptr;
  std::unordered_map<std::uint8_t, std::optional<std::uint32_t>>
    last_reliable_order_by_channel_;
};

class ScenarioRunner {
 public:
  ScenarioRunner(std::string scenario_name, NetworkProfile client_to_server,
                 NetworkProfile server_to_client, std::uint32_t seed)
      : profile_(client_to_server),
        network_(std::move(client_to_server), std::move(server_to_client),
                 seed),
        client_socket_(&network_, EndpointRole::kClient),
        server_socket_(&network_, EndpointRole::kServer),
        client_handler_(&metrics_, &sent_messages_),
        server_handler_(&metrics_, &sent_messages_) {
    metrics_.scenario_name = std::move(scenario_name);
    metrics_.network_profile = profile_.name;
    metrics_.seed = seed;

    const SocketAddress loopback = SocketAddress::FromIPv4(0x7F000001);
    EXPECT_EQ(client_socket_.Bind(loopback, kClientPort), SocketError::kNone);
    EXPECT_EQ(server_socket_.Bind(loopback, kServerPort), SocketError::kNone);

    ReliableConnectionConfig config;
    config.retryTimeoutMs = 15;
    config.maxRetries = 120;
    config.pingIntervalMs = 10000;
    config.disconnectTimeoutMs = 2500;
    config.fragmentTimeoutMs = 1800;
    config.maxPacketSize = profile_.max_packet_size;
    config.numChannels = 2;
    config.enablePacketBatching = true;

    client_connection_ =
      std::make_unique<ReliableConnection>(&client_socket_, config);
    server_connection_ =
      std::make_unique<ReliableConnection>(&server_socket_, config);

    client_connection_->SetHandler(&client_handler_);
    server_connection_->SetHandler(&server_handler_);
    client_connection_->SetRemoteAddress(loopback, kServerPort);
    server_connection_->SetRemoteAddress(loopback, kClientPort);
    client_connection_->SetConnectedForTest();
    server_connection_->SetConnectedForTest();
  }

  bool SendReliableFromClient(std::uint8_t channel, std::size_t body_size) {
    return Send(*client_connection_, channel, true, body_size);
  }

  bool SendReliableFromServer(std::uint8_t channel, std::size_t body_size) {
    return Send(*server_connection_, channel, true, body_size);
  }

  bool SendUnreliableFromClient(std::uint8_t channel, std::size_t body_size) {
    return Send(*client_connection_, channel, false, body_size);
  }

  void RunUntilReliableDelivered(std::uint32_t expected_delivered,
                                 std::uint32_t timeout_ms) {
    RunForOrUntil(timeout_ms, [&]() {
      return metrics_.reliable_messages_delivered >= expected_delivered;
    });
  }

  void RunFor(std::uint32_t duration_ms) {
    RunForOrUntil(duration_ms, []() { return false; });
  }

  [[nodiscard]] const NetworkMetrics& Metrics() const { return metrics_; }
  [[nodiscard]] const NetworkTrafficStats& TrafficStats() const {
    return network_.Stats();
  }

  void PrintDashboard() const {
    const auto& traffic = network_.Stats();
    std::cout
      << "[network-profile] scenario=" << metrics_.scenario_name
      << " profile=" << metrics_.network_profile << " seed=" << metrics_.seed
      << " reliable_sent=" << metrics_.reliable_messages_sent
      << " reliable_delivered=" << metrics_.reliable_messages_delivered
      << " unreliable_sent=" << metrics_.unreliable_messages_sent
      << " unreliable_delivered=" << metrics_.unreliable_messages_delivered
      << " packets_sent=" << traffic.packets_sent
      << " packets_received=" << traffic.packets_received
      << " packets_dropped=" << traffic.packets_dropped_by_network
      << " packets_duplicated=" << traffic.packets_duplicated_by_network
      << " packets_reordered=" << traffic.packets_reordered_by_network
      << " max_queue_bytes=" << traffic.max_queue_bytes
      << " latency_p95_ms=" << Percentile(metrics_.message_latencies_ms, 0.95)
      << " latency_p99_ms=" << Percentile(metrics_.message_latencies_ms, 0.99)
      << " latency_max_ms=" << Percentile(metrics_.message_latencies_ms, 1.0)
      << " duplicate_deliveries=" << metrics_.duplicate_deliveries
      << " corrupted_deliveries=" << metrics_.corrupted_deliveries
      << " ordered_violations=" << metrics_.ordered_violations
      << " wrong_channel_deliveries=" << metrics_.wrong_channel_deliveries
      << " partial_message_deliveries=" << metrics_.partial_message_deliveries
      << " timeout_count=" << metrics_.timeout_count
      << " disconnect_count=" << metrics_.disconnect_count << "\n";
  }

 private:
  bool Send(ReliableConnection& connection, std::uint8_t channel, bool reliable,
            std::size_t body_size) {
    const std::uint32_t id = next_message_id_++;
    const std::uint32_t order = next_order_by_channel_.at(channel)++;
    auto payload = MakePayload(id, channel, reliable, order, body_size);
    const auto sent_at = Clock::now();

    bool sent = false;
    if (reliable) {
      sent = connection.SendReliable(channel, payload.data(), payload.size());
    } else {
      sent = connection.SendUnreliable(channel, payload.data(), payload.size());
    }

    if (!sent) return false;

    sent_messages_.emplace(
      id, SentMessage{id, channel, reliable, order, payload, sent_at, 0});
    if (reliable) {
      ++metrics_.reliable_messages_sent;
    } else {
      ++metrics_.unreliable_messages_sent;
    }
    return true;
  }

  template <typename Predicate>
  void RunForOrUntil(std::uint32_t timeout_ms, Predicate done) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Clock::now() < deadline) {
      client_connection_->Tick();
      server_connection_->Tick();
      if (done()) break;
      std::this_thread::sleep_for(1ms);
    }

    const auto drain_deadline = Clock::now() + 60ms;
    while (Clock::now() < drain_deadline) {
      client_connection_->Tick();
      server_connection_->Tick();
      std::this_thread::sleep_for(1ms);
    }
  }

  NetworkProfile profile_;
  SimulatedNetwork network_;
  SimulatedSocket client_socket_;
  SimulatedSocket server_socket_;
  NetworkMetrics metrics_;
  std::unordered_map<std::uint32_t, SentMessage> sent_messages_;
  RecordingHandler client_handler_;
  RecordingHandler server_handler_;
  std::unique_ptr<ReliableConnection> client_connection_;
  std::unique_ptr<ReliableConnection> server_connection_;
  std::uint32_t next_message_id_ = 1;
  std::array<std::uint32_t, 256> next_order_by_channel_{};
};

std::vector<NetworkProfile> PrProfiles() {
  return {
    {.name = "perfect_lan",
     .base_delay_ms = 0,
     .jitter_ms = 0,
     .max_packet_size = 600,
     .scenario_timeout_ms = 600},
    {.name = "normal_online",
     .base_delay_ms = 5,
     .jitter_ms = 2,
     .loss_rate = 0.005,
     .max_packet_size = 600,
     .scenario_timeout_ms = 900},
    {.name = "bad_wifi",
     .base_delay_ms = 12,
     .jitter_ms = 8,
     .loss_rate = 0.03,
     .duplicate_rate = 0.01,
     .reorder_rate = 0.03,
     .reorder_extra_ms = 18,
     .bandwidth_bytes_per_second = 125000,
     .max_packet_size = 600,
     .scenario_timeout_ms = 1300},
    {.name = "high_ping",
     .base_delay_ms = 35,
     .jitter_ms = 10,
     .loss_rate = 0.02,
     .duplicate_rate = 0.01,
     .reorder_rate = 0.03,
     .reorder_extra_ms = 35,
     .bandwidth_bytes_per_second = 125000,
     .max_packet_size = 600,
     .scenario_timeout_ms = 1600},
    {.name = "loss_10",
     .base_delay_ms = 12,
     .jitter_ms = 5,
     .loss_rate = 0.10,
     .duplicate_rate = 0.01,
     .reorder_rate = 0.03,
     .reorder_extra_ms = 20,
     .bandwidth_bytes_per_second = 125000,
     .max_packet_size = 600,
     .scenario_timeout_ms = 1800},
    {.name = "small_mtu",
     .base_delay_ms = 8,
     .jitter_ms = 3,
     .loss_rate = 0.02,
     .duplicate_rate = 0.01,
     .reorder_rate = 0.03,
     .reorder_extra_ms = 20,
     .bandwidth_bytes_per_second = 125000,
     .max_packet_size = 160,
     .scenario_timeout_ms = 1600},
    {.name = "low_bandwidth",
     .base_delay_ms = 10,
     .jitter_ms = 5,
     .loss_rate = 0.01,
     .reorder_rate = 0.01,
     .reorder_extra_ms = 20,
     .bandwidth_bytes_per_second = 12000,
     .max_packet_size = 600,
     .scenario_timeout_ms = 1800},
  };
}

void ExpectHardInvariants(const ScenarioRunner& runner,
                          bool allow_timeout = false) {
  const auto& metrics = runner.Metrics();
  EXPECT_EQ(metrics.duplicate_deliveries, 0u);
  EXPECT_EQ(metrics.corrupted_deliveries, 0u);
  EXPECT_EQ(metrics.ordered_violations, 0u);
  EXPECT_EQ(metrics.wrong_channel_deliveries, 0u);
  EXPECT_EQ(metrics.partial_message_deliveries, 0u);
  EXPECT_EQ(metrics.malformed_packets_accepted, 0u);
  if (!allow_timeout) {
    EXPECT_EQ(metrics.timeout_count, 0u);
    EXPECT_EQ(metrics.disconnect_count, 0u);
  }
}

struct ProfileDemoResult {
  std::string profile;
  NetworkMetrics metrics;
  NetworkTrafficStats traffic;
  double elapsed_ms = 0.0;
};

ProfileDemoResult RunProfileDemo(const NetworkProfile& profile, std::uint32_t seed) {
  const auto started_at = Clock::now();
  ScenarioRunner runner("visible_degradation_demo", profile, profile, seed);

  for (std::uint32_t i = 0; i < 16; ++i) {
    EXPECT_TRUE(runner.SendReliableFromClient(i % 2, 256));
  }

  for (std::uint32_t i = 0; i < 48; ++i) {
    EXPECT_TRUE(runner.SendUnreliableFromClient(1, 128));
  }

  runner.RunUntilReliableDelivered(runner.Metrics().reliable_messages_sent,
                                   profile.scenario_timeout_ms);
  runner.RunFor(250);

  return ProfileDemoResult{
    profile.name,
    runner.Metrics(),
    runner.TrafficStats(),
    std::chrono::duration<double, std::milli>(Clock::now() - started_at)
      .count(),
  };
}

void PrintProfileDemoResult(const ProfileDemoResult& result) {
  const auto& metrics = result.metrics;
  const auto& traffic = result.traffic;
  const double delivered_unreliable_pct =
    metrics.unreliable_messages_sent == 0
      ? 0.0
      : 100.0 * static_cast<double>(metrics.unreliable_messages_delivered) /
          static_cast<double>(metrics.unreliable_messages_sent);

  std::cout << std::fixed << std::setprecision(2)
            << "[visible-network-demo] profile=" << result.profile
            << " elapsed_ms=" << result.elapsed_ms
            << " reliable=" << metrics.reliable_messages_delivered << "/"
            << metrics.reliable_messages_sent
            << " unreliable=" << metrics.unreliable_messages_delivered << "/"
            << metrics.unreliable_messages_sent << " ("
            << delivered_unreliable_pct << "%)"
            << " packets_sent=" << traffic.packets_sent
            << " packets_received=" << traffic.packets_received
            << " packets_dropped=" << traffic.packets_dropped_by_network
            << " packets_duplicated="
            << traffic.packets_duplicated_by_network
            << " packets_reordered=" << traffic.packets_reordered_by_network
            << " latency_p95_ms="
            << Percentile(metrics.message_latencies_ms, 0.95)
            << " latency_max_ms="
            << Percentile(metrics.message_latencies_ms, 1.0) << "\n";
}

}  // namespace

TEST(ReliableConnectionNetworkProfiles,
     ReliableMessagesPreserveInvariantsAcrossPrProfiles) {
  constexpr std::array<std::uint32_t, 3> seeds{11, 23, 47};

  for (const auto& profile : PrProfiles()) {
    for (const std::uint32_t seed : seeds) {
      SCOPED_TRACE(profile.name + " seed=" + std::to_string(seed));
      ScenarioRunner runner("pr_matrix", profile, profile, seed);

      for (std::uint32_t i = 0; i < 4; ++i) {
        ASSERT_TRUE(runner.SendReliableFromClient(i % 2, 32));
        ASSERT_TRUE(runner.SendReliableFromServer((i + 1) % 2, 32));
      }

      runner.RunUntilReliableDelivered(runner.Metrics().reliable_messages_sent,
                                       profile.scenario_timeout_ms);
      runner.PrintDashboard();

      EXPECT_EQ(runner.Metrics().reliable_messages_delivered,
                runner.Metrics().reliable_messages_sent);
      ExpectHardInvariants(runner);
    }
  }
}

TEST(ReliableConnectionNetworkProfiles, ReliableDeliveryWithTwentyFivePctLoss) {
  const NetworkProfile profile{.name = "loss_25",
                         .base_delay_ms = 4,
                         .jitter_ms = 2,
                         .loss_rate = 0.25,
                         .max_packet_size = 600,
                         .scenario_timeout_ms = 3000};
  ScenarioRunner runner("reliable_loss_25", profile, profile, 2025);

  for (std::uint32_t i = 0; i < 24; ++i) {
    ASSERT_TRUE(runner.SendReliableFromClient(0, 24));
  }

  runner.RunUntilReliableDelivered(runner.Metrics().reliable_messages_sent,
                                   profile.scenario_timeout_ms);
  runner.PrintDashboard();

  EXPECT_EQ(runner.Metrics().reliable_messages_delivered,
            runner.Metrics().reliable_messages_sent);
  EXPECT_GT(runner.TrafficStats().packets_dropped_by_network, 0u);
  ExpectHardInvariants(runner);
}

TEST(ReliableConnectionNetworkProfiles, DuplicateAndReorderAreSuppressed) {
  const NetworkProfile profile{.name = "duplicate_reorder",
                         .base_delay_ms = 1,
                         .jitter_ms = 1,
                         .duplicate_rate = 0.80,
                         .reorder_rate = 0.80,
                         .reorder_extra_ms = 25,
                         .max_packet_size = 600,
                         .scenario_timeout_ms = 1000};
  ScenarioRunner runner("duplicate_reorder", profile, profile, 1234);

  for (std::uint32_t i = 0; i < 10; ++i) {
    ASSERT_TRUE(runner.SendReliableFromClient(0, 16));
  }

  runner.RunUntilReliableDelivered(runner.Metrics().reliable_messages_sent,
                                   profile.scenario_timeout_ms);
  runner.PrintDashboard();

  EXPECT_EQ(runner.Metrics().reliable_messages_delivered,
            runner.Metrics().reliable_messages_sent);
  EXPECT_GT(runner.TrafficStats().packets_duplicated_by_network, 0u);
  EXPECT_GT(runner.TrafficStats().packets_reordered_by_network, 0u);
  ExpectHardInvariants(runner);
}

TEST(ReliableConnectionNetworkProfiles, BurstBlackoutRecovers) {
  const NetworkProfile profile{.name = "burst_blackout",
                         .base_delay_ms = 3,
                         .jitter_ms = 1,
                         .loss_rate = 0.01,
                         .blackout_start_ms = 30,
                         .blackout_duration_ms = 1000,
                         .max_packet_size = 600,
                         .scenario_timeout_ms = 3200};
  ScenarioRunner runner("burst_blackout", profile, profile, 3456);

  ASSERT_TRUE(runner.SendReliableFromClient(0, 32));
  runner.RunFor(60);
  for (std::uint32_t i = 0; i < 5; ++i) {
    ASSERT_TRUE(runner.SendReliableFromClient(0, 32));
  }

  runner.RunUntilReliableDelivered(runner.Metrics().reliable_messages_sent,
                                   profile.scenario_timeout_ms);
  runner.PrintDashboard();

  EXPECT_EQ(runner.Metrics().reliable_messages_delivered,
            runner.Metrics().reliable_messages_sent);
  EXPECT_GT(runner.TrafficStats().packets_dropped_by_network, 0u);
  ExpectHardInvariants(runner);
}

TEST(ReliableConnectionNetworkProfiles, SmallMtuFragmentationReassemblesOnce) {
  const NetworkProfile profile{.name = "small_mtu_fragmentation",
                         .base_delay_ms = 2,
                         .jitter_ms = 1,
                         .loss_rate = 0.04,
                         .duplicate_rate = 0.05,
                         .reorder_rate = 0.05,
                         .reorder_extra_ms = 15,
                         .max_packet_size = 96,
                         .scenario_timeout_ms = 2200};
  ScenarioRunner runner("small_mtu_fragmentation", profile, profile, 4567);

  ASSERT_TRUE(runner.SendReliableFromClient(0, 2048));

  runner.RunUntilReliableDelivered(runner.Metrics().reliable_messages_sent,
                                   profile.scenario_timeout_ms);
  runner.PrintDashboard();

  EXPECT_EQ(runner.Metrics().reliable_messages_delivered, 1u);
  ExpectHardInvariants(runner);
}

TEST(ReliableConnectionNetworkProfiles, UnreliableDropsButDoesNotCorrupt) {
  const NetworkProfile profile{.name = "unreliable_loss",
                         .base_delay_ms = 3,
                         .jitter_ms = 2,
                         .loss_rate = 0.30,
                         .duplicate_rate = 0.10,
                         .reorder_rate = 0.10,
                         .reorder_extra_ms = 10,
                         .max_packet_size = 600,
                         .scenario_timeout_ms = 700};
  ScenarioRunner runner("unreliable_loss", profile, profile, 5678);

  for (std::uint32_t i = 0; i < 30; ++i) {
    ASSERT_TRUE(runner.SendUnreliableFromClient(1, 20));
  }

  runner.RunFor(profile.scenario_timeout_ms);
  runner.PrintDashboard();

  EXPECT_GT(runner.Metrics().unreliable_messages_delivered, 0u);
  EXPECT_LE(runner.Metrics().unreliable_messages_delivered,
            runner.Metrics().unreliable_messages_sent);
  ExpectHardInvariants(runner);
}

TEST(ReliableConnectionNetworkProfiles, MixedChannelsDoNotDeliverWrongChannel) {
  const NetworkProfile profile{.name = "mixed_channels",
                         .base_delay_ms = 4,
                         .jitter_ms = 2,
                         .loss_rate = 0.03,
                         .duplicate_rate = 0.02,
                         .reorder_rate = 0.05,
                         .reorder_extra_ms = 20,
                         .bandwidth_bytes_per_second = 16000,
                         .max_packet_size = 140,
                         .scenario_timeout_ms = 2400};
  ScenarioRunner runner("mixed_channels", profile, profile, 6789);

  ASSERT_TRUE(runner.SendReliableFromClient(0, 1024));
  for (std::uint32_t i = 0; i < 8; ++i) {
    ASSERT_TRUE(runner.SendReliableFromClient(1, 16));
  }

  runner.RunUntilReliableDelivered(runner.Metrics().reliable_messages_sent,
                                   profile.scenario_timeout_ms);
  runner.PrintDashboard();

  EXPECT_EQ(runner.Metrics().reliable_messages_delivered,
            runner.Metrics().reliable_messages_sent);
  ExpectHardInvariants(runner);
}

TEST(ReliableConnectionNetworkProfiles,
     MalformedPacketsAreRejectedWithoutDelivery) {
  const NetworkProfile profile{
    .name = "malformed", .max_packet_size = 600, .scenario_timeout_ms = 100};
  const ScenarioRunner runner("malformed", profile, profile, 7890);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  ReliableConnectionConfig config;
  config.maxPacketSize = 600;
  SimulatedNetwork network(profile, profile, 7891);
  SimulatedSocket socket(&network, EndpointRole::kServer);
  ASSERT_EQ(socket.Bind(addr, 33002), SocketError::kNone);

  NetworkMetrics metrics;
  std::unordered_map<std::uint32_t, SentMessage> sent_messages;
  RecordingHandler handler(&metrics, &sent_messages);
  ReliableConnection connection(&socket, config);
  connection.SetHandler(&handler);
  connection.SetRemoteAddress(addr, 33001);
  connection.SetConnectedForTest();

  const std::array<std::uint8_t, 2> too_short{1, 0};
  const std::array<std::uint8_t, 6> invalid_type{100, 0, 0, 0, 0, 0};
  const std::array<std::uint8_t, 9> malformed_batch{10, 0, 0, 0, 0,
                                                    0,  1, 0, 99};

  connection.ProcessPacket(too_short.data(), too_short.size(), addr, 33001);
  connection.ProcessPacket(invalid_type.data(), invalid_type.size(), addr,
                           33001);
  connection.ProcessPacket(malformed_batch.data(), malformed_batch.size(), addr,
                           33001);
  connection.Tick();

  EXPECT_EQ(metrics.reliable_messages_delivered, 0u);
  EXPECT_EQ(metrics.unreliable_messages_delivered, 0u);
  EXPECT_EQ(metrics.malformed_packets_accepted, 0u);
  EXPECT_EQ(metrics.corrupted_deliveries, 0u);
}

TEST(ReliableConnectionNetworkProfiles, VeryBadIsVisibleComparedToPerfectLan) {
  const NetworkProfile perfect_lan{.name = "perfect_lan",
                                   .base_delay_ms = 0,
                                   .jitter_ms = 0,
                                   .max_packet_size = 600,
                                   .scenario_timeout_ms = 1000};
  const NetworkProfile very_bad{.name = "very_bad",
                                .base_delay_ms = 100,
                                .jitter_ms = 30,
                                .loss_rate = 0.25,
                                .duplicate_rate = 0.05,
                                .reorder_rate = 0.10,
                                .reorder_extra_ms = 75,
                                .bandwidth_bytes_per_second = 64000,
                                .max_packet_size = 600,
                                .scenario_timeout_ms = 5000};

  const auto perfect = RunProfileDemo(perfect_lan, 9001);
  const auto degraded = RunProfileDemo(very_bad, 9001);

  PrintProfileDemoResult(perfect);
  PrintProfileDemoResult(degraded);

  EXPECT_EQ(perfect.metrics.reliable_messages_delivered,
            perfect.metrics.reliable_messages_sent);
  EXPECT_EQ(degraded.metrics.reliable_messages_delivered,
            degraded.metrics.reliable_messages_sent);
  EXPECT_EQ(perfect.traffic.packets_dropped_by_network, 0u);
  EXPECT_GT(degraded.traffic.packets_dropped_by_network, 0u);
  EXPECT_LT(degraded.metrics.unreliable_messages_delivered,
            degraded.metrics.unreliable_messages_sent);
  EXPECT_GT(Percentile(degraded.metrics.message_latencies_ms, 0.95),
            Percentile(perfect.metrics.message_latencies_ms, 0.95));
}
