#include <array>
#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <memory>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <algorithm>
#include <exception>
#include <string_view>
#ifndef _WIN32
#include <sys/resource.h>
#endif

#include "i_socket.hpp"
#include "reliable_connection.hpp"
#include "sharded_connection_manager.hpp"
#include "socket_constants.hpp"
#include "socket_init.hpp"
#include "socket_resolver.hpp"

using namespace std::chrono_literals;  // NOLINT
using Clock = std::chrono::steady_clock;

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables)
std::atomic<bool> g_stop{false};

void StopHandler(int) { g_stop.store(true); }

constexpr std::array<std::uint8_t, 4> kMagic{'S', 'W', 'L', 'T'};
constexpr std::size_t kHeaderSize = 25;
constexpr std::uint8_t kKindState = 1;
constexpr std::uint8_t kKindAction = 2;

struct Options {
  std::string mode;
  std::string host = "127.0.0.1";
  std::uint16_t port = 16000;
  std::uint32_t workers = 0;
  std::uint32_t max_clients = 10000;
  std::uint32_t start = 100;
  std::uint32_t step = 100;
  std::uint32_t max = 2000;
  std::uint32_t step_seconds = 30;
  std::uint32_t connect_timeout_seconds = 20;
  double state_hz = 20.0;
  double action_hz = 1.0;
  std::size_t state_payload = 64;
  std::size_t action_payload = 128;
  double min_connect_rate = 0.99;
  double min_state_delivery = 0.90;
  double min_reliable_delivery = 0.99;
  double max_p95_ms = 150.0;
  double max_send_fail_rate = 0.001;
  bool stop_on_fail = true;
  std::string csv_path;
};

[[nodiscard]] std::uint64_t NowNs() {
  return static_cast<std::uint64_t>(
    std::chrono::duration_cast<std::chrono::nanoseconds>(
      Clock::now().time_since_epoch())
      .count());
}

struct ProcessSample {
  Clock::time_point wall = Clock::now();
  double cpu_seconds = 0.0;
  double rss_mb = 0.0;
};

[[nodiscard]] ProcessSample SampleProcess() {
  ProcessSample sample;
#ifndef _WIN32
  auto timeval_seconds = [](const timeval& value) {
    return static_cast<double>(value.tv_sec) +
           static_cast<double>(value.tv_usec) / 1000000.0;
  };
  rusage usage{};
  if (getrusage(RUSAGE_SELF, &usage) == 0) {
    sample.cpu_seconds =
      timeval_seconds(usage.ru_utime) + timeval_seconds(usage.ru_stime);
#ifdef __APPLE__
    sample.rss_mb = static_cast<double>(usage.ru_maxrss) / (1024.0 * 1024.0);
#else
    sample.rss_mb = static_cast<double>(usage.ru_maxrss) / 1024.0;
#endif
  }
#endif
  return sample;
}

[[nodiscard]] double CpuPercent(const ProcessSample& before,
                                const ProcessSample& after) {
  const double wall_seconds =
    std::chrono::duration<double>(after.wall - before.wall).count();
  if (wall_seconds <= 0.0) return 0.0;
  return ((after.cpu_seconds - before.cpu_seconds) / wall_seconds) * 100.0;
}

void WriteU32(std::vector<std::uint8_t>& data, std::size_t offset,
              std::uint32_t value) {
  data.at(offset) = static_cast<std::uint8_t>((value >> 24) & 0xFFu);
  data.at(offset + 1) = static_cast<std::uint8_t>((value >> 16) & 0xFFu);
  data.at(offset + 2) = static_cast<std::uint8_t>((value >> 8) & 0xFFu);
  data.at(offset + 3) = static_cast<std::uint8_t>(value & 0xFFu);
}

void WriteU64(std::vector<std::uint8_t>& data, std::size_t offset,
              std::uint64_t value) {
  for (std::size_t i = 0; i < 8; ++i) {
    data.at(offset + i) =
      static_cast<std::uint8_t>((value >> ((7 - i) * 8)) & 0xFFu);
  }
}

[[nodiscard]] std::uint32_t ReadU32(const std::uint8_t* data,
                                    std::size_t offset) {
  return (static_cast<std::uint32_t>(data[offset]) << 24) |
         (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
         (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
         static_cast<std::uint32_t>(data[offset + 3]);
}

[[nodiscard]] std::uint64_t ReadU64(const std::uint8_t* data,
                                    std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value = (value << 8) | static_cast<std::uint64_t>(data[offset + i]);
  }
  return value;
}

struct Payload {
  std::uint8_t kind = 0;
  std::uint32_t step = 0;
  std::uint64_t sent_ns = 0;
};

[[nodiscard]] bool ParsePayload(const void* data, std::size_t size,
                                Payload& out) {
  if (data == nullptr || size < kHeaderSize) return false;
  const auto* bytes = static_cast<const std::uint8_t*>(data);
  if (!std::equal(kMagic.begin(), kMagic.end(), bytes)) return false;
  out.kind = bytes[4];
  out.step = ReadU32(bytes, 5);
  out.sent_ns = ReadU64(bytes, 17);
  return out.kind == kKindState || out.kind == kKindAction;
}

[[nodiscard]] std::vector<std::uint8_t> MakePayload(
  std::uint8_t kind, std::uint32_t step, std::uint32_t client_id,
  std::uint32_t seq, std::size_t requested_size) {
  std::vector<std::uint8_t> payload(std::max(requested_size, kHeaderSize));
  std::copy(kMagic.begin(), kMagic.end(), payload.begin());
  payload.at(4) = kind;
  WriteU32(payload, 5, step);
  WriteU32(payload, 9, client_id);
  WriteU32(payload, 13, seq);
  WriteU64(payload, 17, NowNs());
  for (std::size_t i = kHeaderSize; i < payload.size(); ++i) {
    payload.at(i) =
      static_cast<std::uint8_t>((static_cast<std::size_t>(client_id) * 31u +
                                 static_cast<std::size_t>(seq) * 17u + i) &
                                0xFFu);
  }
  return payload;
}

[[nodiscard]] bool ParseBool(std::string_view value) {
  return value == "1" || value == "true" || value == "yes" || value == "on";
}

[[nodiscard]] std::string ArgValue(const std::vector<std::string>& args,
                                   std::string_view name,
                                   std::string_view fallback) {
  for (std::size_t i = 0; i + 1 < args.size(); ++i) {
    if (args.at(i) == name) return args.at(i + 1);
  }
  return std::string(fallback);
}

[[nodiscard]] bool HasArg(const std::vector<std::string>& args,
                          std::string_view name) {
  return std::find(args.begin(), args.end(), name) != args.end();
}

[[nodiscard]] std::uint32_t ParseU32(const std::vector<std::string>& args,
                                     std::string_view name,
                                     std::uint32_t fallback) {
  const std::string value = ArgValue(args, name, "");
  if (value.empty()) return fallback;
  return static_cast<std::uint32_t>(std::stoul(value));
}

[[nodiscard]] std::uint16_t ParseU16(const std::vector<std::string>& args,
                                     std::string_view name,
                                     std::uint16_t fallback) {
  return static_cast<std::uint16_t>(ParseU32(args, name, fallback));
}

[[nodiscard]] double ParseDouble(const std::vector<std::string>& args,
                                 std::string_view name, double fallback) {
  const std::string value = ArgValue(args, name, "");
  if (value.empty()) return fallback;
  return std::stod(value);
}

[[nodiscard]] std::size_t ParseSize(const std::vector<std::string>& args,
                                    std::string_view name,
                                    std::size_t fallback) {
  const std::string value = ArgValue(args, name, "");
  if (value.empty()) return fallback;
  return static_cast<std::size_t>(std::stoull(value));
}

[[nodiscard]] Options ParseOptions(int argc, char** argv) {
  std::vector<std::string> args;
  for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);

  Options opts;
  if (!args.empty()) opts.mode = args.front();
  opts.host = ArgValue(args, "--host", opts.host);
  opts.port = ParseU16(args, "--port", opts.port);
  opts.workers = ParseU32(args, "--workers", opts.workers);
  opts.max_clients = ParseU32(args, "--max-clients", opts.max_clients);
  opts.start = ParseU32(args, "--start", opts.start);
  opts.step = ParseU32(args, "--step", opts.step);
  opts.max = ParseU32(args, "--max", opts.max);
  opts.step_seconds = ParseU32(args, "--step-seconds", opts.step_seconds);
  opts.connect_timeout_seconds =
    ParseU32(args, "--connect-timeout", opts.connect_timeout_seconds);
  opts.state_hz = ParseDouble(args, "--state-hz", opts.state_hz);
  opts.action_hz = ParseDouble(args, "--action-hz", opts.action_hz);
  opts.state_payload = ParseSize(args, "--state-payload", opts.state_payload);
  opts.action_payload =
    ParseSize(args, "--action-payload", opts.action_payload);
  opts.min_connect_rate =
    ParseDouble(args, "--min-connect-rate", opts.min_connect_rate);
  opts.min_state_delivery =
    ParseDouble(args, "--min-state-delivery", opts.min_state_delivery);
  opts.min_reliable_delivery =
    ParseDouble(args, "--min-reliable-delivery", opts.min_reliable_delivery);
  opts.max_p95_ms = ParseDouble(args, "--max-p95-ms", opts.max_p95_ms);
  opts.max_send_fail_rate =
    ParseDouble(args, "--max-send-fail-rate", opts.max_send_fail_rate);
  opts.stop_on_fail = ParseBool(
    ArgValue(args, "--stop-on-fail", opts.stop_on_fail ? "true" : "false"));
  opts.csv_path = ArgValue(args, "--csv", "");
  if (opts.step == 0) opts.step = 1;
  if (opts.start == 0) opts.start = 1;
  return opts;
}

void PrintUsage(const char* argv0) {
  std::cout << "Usage:\n"
            << "  " << argv0
            << " server --port 16000 --workers 8 --max-clients 10000"
               " --csv server.csv\n"
            << "  " << argv0
            << " client --host 127.0.0.1 --port 16000 --start 100 --step 100"
               " --max 2000 --step-seconds 30 --csv results.csv\n\n"
            << "Client defaults: 20 Hz sequenced state, 1 Hz reliable action,"
               " fail at p95 > 150 ms, state delivery < 90%,"
               " or reliable delivery < 99%.\n";
}

[[nodiscard]] socketwire::ReliableConnectionConfig ConnectionConfig() {
  socketwire::ReliableConnectionConfig cfg;
  cfg.retryTimeoutMs = 50;
  cfg.pingIntervalMs = 1000;
  cfg.disconnectTimeoutMs = 5000;
  cfg.maxPendingReliablePackets = 4096;
  cfg.numChannels = 2;
  return cfg;
}

[[nodiscard]] std::uint32_t DefaultWorkers() {
  const auto hardware = std::thread::hardware_concurrency();
  return std::max<std::uint32_t>(1, hardware == 0 ? 1 : hardware);
}

void WriteServerCsvHeader(const Options& opts) {
  if (opts.csv_path.empty()) return;

  std::ofstream out(opts.csv_path, std::ios::trunc);
  out << "t_sec,connected,total,workers,worker_min,worker_max,update_avg_ms,"
         "update_max_ms,rtt_ms,lost,inflight,rx_rel,rx_unrel,echo_failed,"
         "cpu_percent,rss_mb,rx_bytes_per_sec,tx_bytes_per_sec\n";
}

void AppendServerCsvRow(const Options& opts, double elapsed,
                        const socketwire::ShardedConnectionStats& stats,
                        std::uint64_t rx_reliable, std::uint64_t rx_unreliable,
                        std::uint64_t echo_failed, double cpu_percent,
                        double rss_mb, double rx_bytes_per_sec,
                        double tx_bytes_per_sec) {
  if (opts.csv_path.empty()) return;

  std::ofstream out(opts.csv_path, std::ios::app);
  out << std::fixed << std::setprecision(3) << elapsed << ','
      << stats.connectedClients << ',' << stats.totalClients << ','
      << stats.workerCount << ',' << stats.workerConnectedMin << ','
      << stats.workerConnectedMax << ',' << stats.workerUpdateMsAvg << ','
      << stats.workerUpdateMsMax << ',' << stats.rttMs << ','
      << stats.lostPackets << ',' << stats.inflightPackets << ',' << rx_reliable
      << ',' << rx_unreliable << ',' << echo_failed << ',' << cpu_percent << ','
      << rss_mb << ',' << rx_bytes_per_sec << ',' << tx_bytes_per_sec << '\n';
}

int RunServer(const Options& opts) {
  socketwire::InitializeSockets();

  socketwire::SocketConfig socket_cfg;
  socket_cfg.nonBlocking = true;
  socket_cfg.reuseAddress = true;
  socket_cfg.reusePort = true;
  socket_cfg.recvBufferSize = 8 * 1024 * 1024;
  socket_cfg.sendBufferSize = 8 * 1024 * 1024;

  socketwire::ShardedConnectionManagerConfig cfg;
  cfg.port = opts.port;
  cfg.workerCount = opts.workers == 0 ? DefaultWorkers() : opts.workers;
  cfg.socket = socket_cfg;
  cfg.connection.connection = ConnectionConfig();
  cfg.connection.maxClients = opts.max_clients;
  cfg.connection.maxHandshakesPerSecond = 0;

  std::atomic<std::uint64_t> rx_reliable{0};
  std::atomic<std::uint64_t> rx_unreliable{0};
  std::atomic<std::uint64_t> rx_bytes{0};
  std::atomic<std::uint64_t> tx_bytes{0};
  std::atomic<std::uint64_t> echo_failed{0};

  socketwire::ShardedConnectionManager server(cfg);
  server.SetPacketCallback([&](socketwire::ShardedClientHandle,
                               socketwire::ConnectionManager::RemoteClient& c,
                               std::uint8_t channel, const void* data,
                               std::size_t size, bool reliable) {
    if (c.connection == nullptr || !c.connection->IsConnected()) return;
    bool sent = false;
    rx_bytes.fetch_add(size);
    if (reliable) {
      rx_reliable.fetch_add(1);
      sent = c.connection->SendReliable(channel, data, size);
    } else {
      rx_unreliable.fetch_add(1);
      sent = c.connection->SendUnreliable(channel, data, size);
    }
    if (sent) tx_bytes.fetch_add(size);
    if (!sent) echo_failed.fetch_add(1);
  });

  if (!server.Start()) {
    std::cerr << "failed to start SocketWireLoad server\n";
    return 1;
  }

  std::cout << "server_started port=" << server.LocalPort()
            << " workers=" << cfg.workerCount
            << " reuse_port=" << (server.ReusePortEnabled() ? 1 : 0)
            << " max_clients=" << cfg.connection.maxClients << "\n";
  WriteServerCsvHeader(opts);

  const auto started = Clock::now();
  auto next_print = started + 1s;
  auto last_sample_time = started;
  auto last_process = SampleProcess();
  std::uint64_t last_rx_bytes = 0;
  std::uint64_t last_tx_bytes = 0;
  while (!g_stop.load()) {
    const auto now = Clock::now();
    if (now >= next_print) {
      const auto stats = server.SnapshotStats();
      const double elapsed =
        std::chrono::duration<double>(now - started).count();
      const double sample_seconds =
        std::chrono::duration<double>(now - last_sample_time).count();
      const auto process = SampleProcess();
      const auto current_rx_bytes = rx_bytes.load();
      const auto current_tx_bytes = tx_bytes.load();
      const double rx_bytes_per_sec =
        sample_seconds <= 0.0
          ? 0.0
          : static_cast<double>(current_rx_bytes - last_rx_bytes) /
              sample_seconds;
      const double tx_bytes_per_sec =
        sample_seconds <= 0.0
          ? 0.0
          : static_cast<double>(current_tx_bytes - last_tx_bytes) /
              sample_seconds;
      const double cpu_percent = CpuPercent(last_process, process);
      std::cout << std::fixed << std::setprecision(2) << "server t=" << elapsed
                << " connected=" << stats.connectedClients
                << " total=" << stats.totalClients
                << " workers=" << stats.workerCount
                << " worker_min=" << stats.workerConnectedMin
                << " worker_max=" << stats.workerConnectedMax
                << " update_avg_ms=" << stats.workerUpdateMsAvg
                << " update_max_ms=" << stats.workerUpdateMsMax
                << " rtt_ms=" << stats.rttMs << " lost=" << stats.lostPackets
                << " inflight=" << stats.inflightPackets
                << " rx_rel=" << rx_reliable.load()
                << " rx_unrel=" << rx_unreliable.load()
                << " echo_failed=" << echo_failed.load()
                << " cpu_percent=" << cpu_percent
                << " rss_mb=" << process.rss_mb
                << " rx_Bps=" << rx_bytes_per_sec
                << " tx_Bps=" << tx_bytes_per_sec << "\n";
      AppendServerCsvRow(opts, elapsed, stats, rx_reliable.load(),
                         rx_unreliable.load(), echo_failed.load(), cpu_percent,
                         process.rss_mb, rx_bytes_per_sec, tx_bytes_per_sec);
      last_sample_time = now;
      last_process = process;
      last_rx_bytes = current_rx_bytes;
      last_tx_bytes = current_tx_bytes;
      next_print = now + 1s;
    }
    std::this_thread::sleep_for(50ms);
  }

  server.Stop();
  return 0;
}

struct ClientMetrics {
  std::uint32_t step = 0;
  std::uint64_t sent_state = 0;
  std::uint64_t sent_reliable = 0;
  std::uint64_t recv_state = 0;
  std::uint64_t recv_reliable = 0;
  std::uint64_t sent_state_bytes = 0;
  std::uint64_t sent_reliable_bytes = 0;
  std::uint64_t recv_state_bytes = 0;
  std::uint64_t recv_reliable_bytes = 0;
  std::uint64_t send_failed = 0;
  std::uint64_t parse_failed = 0;
  std::vector<double> latency_ms;

  void Reset(std::uint32_t next_step) {
    step = next_step;
    sent_state = 0;
    sent_reliable = 0;
    recv_state = 0;
    recv_reliable = 0;
    sent_state_bytes = 0;
    sent_reliable_bytes = 0;
    recv_state_bytes = 0;
    recv_reliable_bytes = 0;
    send_failed = 0;
    parse_failed = 0;
    latency_ms.clear();
  }
};

struct StepResult {
  std::uint32_t users = 0;
  bool passed = false;
  std::size_t connected = 0;
  double connect_rate = 0.0;
  double state_delivery = 0.0;
  double reliable_delivery = 0.0;
  double p50_ms = 0.0;
  double p95_ms = 0.0;
  double p99_ms = 0.0;
  std::uint64_t sent_state = 0;
  std::uint64_t sent_reliable = 0;
  std::uint64_t recv_state = 0;
  std::uint64_t recv_reliable = 0;
  std::uint64_t sent_bytes = 0;
  std::uint64_t recv_bytes = 0;
  double cpu_percent = 0.0;
  double rss_mb = 0.0;
  double tx_bytes_per_sec = 0.0;
  double rx_bytes_per_sec = 0.0;
  std::uint64_t send_failed = 0;
  std::uint64_t parse_failed = 0;
  std::string fail_reason;
};

void WriteCsvHeader(const Options& opts) {
  if (opts.csv_path.empty()) return;

  std::ofstream out(opts.csv_path, std::ios::trunc);
  out << "state_hz,action_hz,users,passed,connected,connect_rate,"
         "state_delivery,reliable_delivery,p50_ms,p95_ms,p99_ms,"
         "sent_state,sent_reliable,recv_state,recv_reliable,sent_bytes,"
         "recv_bytes,cpu_percent,rss_mb,tx_bytes_per_sec,rx_bytes_per_sec,"
         "send_failed,parse_failed,fail_reason\n";
}

void AppendCsvRow(const Options& opts, const StepResult& row) {
  if (opts.csv_path.empty()) return;

  std::ofstream out(opts.csv_path, std::ios::app);
  out << std::fixed << std::setprecision(3) << opts.state_hz << ','
      << opts.action_hz << ',' << row.users << ',' << (row.passed ? 1 : 0)
      << ',' << row.connected << ',' << row.connect_rate << ','
      << row.state_delivery << ',' << row.reliable_delivery << ',' << row.p50_ms
      << ',' << row.p95_ms << ',' << row.p99_ms << ',' << row.sent_state << ','
      << row.sent_reliable << ',' << row.recv_state << ',' << row.recv_reliable
      << ',' << row.sent_bytes << ',' << row.recv_bytes << ','
      << row.cpu_percent << ',' << row.rss_mb << ',' << row.tx_bytes_per_sec
      << ',' << row.rx_bytes_per_sec << ',' << row.send_failed << ','
      << row.parse_failed << ',' << row.fail_reason << '\n';
}

struct LoadClient;

class LoadClientHandler final : public socketwire::IReliableConnectionHandler {
public:
  LoadClientHandler(LoadClient& client, ClientMetrics& metrics)
      : client_(&client), metrics_(&metrics) {}

  void OnConnected() override;
  void OnDisconnected() override;
  void OnReliableReceived(std::uint8_t channel, const void* data,
                          std::size_t size) override;
  void OnUnreliableReceived(std::uint8_t channel, const void* data,
                            std::size_t size) override;

private:
  void Record(const void* data, std::size_t size);

  LoadClient* client_;
  ClientMetrics* metrics_;
};

struct LoadClient {
  std::uint32_t id = 0;
  bool connected = false;
  bool disconnected = false;
  std::uint32_t state_seq = 0;
  std::uint32_t action_seq = 0;
  Clock::time_point next_state{};
  Clock::time_point next_action{};
  std::unique_ptr<socketwire::ISocket> socket;
  std::unique_ptr<socketwire::ReliableConnection> connection;
  std::unique_ptr<LoadClientHandler> handler;
};

void LoadClientHandler::OnConnected() {
  client_->connected = true;
  client_->disconnected = false;
}

void LoadClientHandler::OnDisconnected() { client_->disconnected = true; }

void LoadClientHandler::OnReliableReceived(std::uint8_t channel,
                                           const void* data, std::size_t size) {
  (void)channel;
  Record(data, size);
}

void LoadClientHandler::OnUnreliableReceived(std::uint8_t channel,
                                             const void* data,
                                             std::size_t size) {
  (void)channel;
  Record(data, size);
}

void LoadClientHandler::Record(const void* data, std::size_t size) {
  Payload payload;
  if (!ParsePayload(data, size, payload)) {
    metrics_->parse_failed += 1;
    return;
  }
  if (payload.step != metrics_->step) return;

  const std::uint64_t now_ns = NowNs();
  const double latency_ms =
    static_cast<double>(now_ns - payload.sent_ns) / 1000000.0;
  metrics_->latency_ms.push_back(latency_ms);
  if (payload.kind == kKindAction) {
    metrics_->recv_reliable += 1;
    metrics_->recv_reliable_bytes += size;
  } else {
    metrics_->recv_state += 1;
    metrics_->recv_state_bytes += size;
  }
}

[[nodiscard]] std::size_t ConnectedCount(
  const std::vector<std::unique_ptr<LoadClient>>& clients) {
  return static_cast<std::size_t>(
    std::count_if(clients.begin(), clients.end(), [](const auto& client) {
      return client->connection != nullptr && client->connection->IsConnected();
    }));
}

void PumpClients(std::vector<std::unique_ptr<LoadClient>>& clients) {
  std::array<std::uint8_t, 2048> buffer{};
  for (auto& client : clients) {
    while (true) {
      socketwire::SocketAddress from;
      std::uint16_t port = 0;
      const auto result =
        client->socket->Receive(buffer.data(), buffer.size(), from, port);
      if (result.Failed() || result.bytes <= 0) break;
      client->connection->ProcessPacket(
        buffer.data(), static_cast<std::size_t>(result.bytes), from, port);
    }
    client->connection->Update();
  }
}

void SendDueTraffic(std::vector<std::unique_ptr<LoadClient>>& clients,
                    const Options& opts, ClientMetrics& metrics) {
  const auto now = Clock::now();
  const auto state_interval =
    opts.state_hz <= 0.0
      ? Clock::duration::max()
      : std::chrono::duration_cast<Clock::duration>(
          std::chrono::duration<double>(1.0 / opts.state_hz));
  const auto action_interval =
    opts.action_hz <= 0.0
      ? Clock::duration::max()
      : std::chrono::duration_cast<Clock::duration>(
          std::chrono::duration<double>(1.0 / opts.action_hz));

  for (auto& client : clients) {
    if (client->connection == nullptr || !client->connection->IsConnected()) {
      continue;
    }

    if (opts.state_hz > 0.0 && now >= client->next_state) {
      auto payload = MakePayload(kKindState, metrics.step, client->id,
                                 client->state_seq++, opts.state_payload);
      if (client->connection->SendSequenced(0, payload.data(),
                                            payload.size())) {
        metrics.sent_state += 1;
        metrics.sent_state_bytes += payload.size();
      } else {
        metrics.send_failed += 1;
      }
      client->next_state = now + state_interval;
    }

    if (opts.action_hz > 0.0 && now >= client->next_action) {
      auto payload = MakePayload(kKindAction, metrics.step, client->id,
                                 client->action_seq++, opts.action_payload);
      if (client->connection->SendReliable(1, payload.data(), payload.size())) {
        metrics.sent_reliable += 1;
        metrics.sent_reliable_bytes += payload.size();
      } else {
        metrics.send_failed += 1;
      }
      client->next_action = now + action_interval;
    }
  }
}

void DisconnectClients(std::vector<std::unique_ptr<LoadClient>>& clients) {
  for (auto& client : clients) {
    if (client->connection != nullptr && client->connection->IsConnected()) {
      client->connection->Disconnect();
    }
  }

  const auto deadline = Clock::now() + 250ms;
  while (Clock::now() < deadline) {
    PumpClients(clients);
    std::this_thread::sleep_for(1ms);
  }
}

[[nodiscard]] double Percentile(std::vector<double> values, double percentile) {
  if (values.empty()) return 0.0;
  std::sort(values.begin(), values.end());
  const double rank =
    (percentile / 100.0) * static_cast<double>(values.size() - 1);
  return values.at(static_cast<std::size_t>(rank));
}

[[nodiscard]] std::string FailReason(const Options& opts, std::uint32_t target,
                                     std::size_t connected,
                                     const ClientMetrics& metrics,
                                     double p95_ms) {
  const double connect_rate =
    static_cast<double>(connected) / static_cast<double>(target);
  const double reliable_delivery =
    metrics.sent_reliable == 0 ? 1.0
                               : static_cast<double>(metrics.recv_reliable) /
                                   static_cast<double>(metrics.sent_reliable);
  const double state_delivery = metrics.sent_state == 0
                                  ? 1.0
                                  : static_cast<double>(metrics.recv_state) /
                                      static_cast<double>(metrics.sent_state);
  const std::uint64_t sent_total = metrics.sent_state + metrics.sent_reliable;
  const double send_fail_rate =
    sent_total == 0 ? 0.0
                    : static_cast<double>(metrics.send_failed) /
                        static_cast<double>(sent_total + metrics.send_failed);

  if (connect_rate < opts.min_connect_rate) return "connect_rate";
  if (state_delivery < opts.min_state_delivery) return "state_delivery";
  if (reliable_delivery < opts.min_reliable_delivery) {
    return "reliable_delivery";
  }
  if (p95_ms > opts.max_p95_ms) return "p95_latency";
  if (send_fail_rate > opts.max_send_fail_rate) return "send_fail_rate";
  return "";
}

[[nodiscard]] socketwire::SocketAddress ResolveServerAddress(
  const Options& opts) {
  const auto direct =
    socketwire::socket_constants::TryFromString(opts.host.c_str());
  if (direct.has_value()) return *direct;

  const auto resolved = socketwire::ResolveHost(
    opts.host, opts.port, socketwire::AddressFamily::kIPv4);
  if (resolved.Succeeded() && !resolved.addresses.empty()) {
    return resolved.addresses.front();
  }
  throw std::runtime_error("failed to resolve host: " + opts.host);
}

void AddClients(std::vector<std::unique_ptr<LoadClient>>& clients,
                std::uint32_t target, const Options& opts,
                const socketwire::SocketAddress& server_addr,
                ClientMetrics& metrics) {
  socketwire::ISocketFactory* factory =
    socketwire::SocketFactoryRegistry::GetFactory();
  if (factory == nullptr) throw std::runtime_error("socket factory missing");

  socketwire::SocketConfig socket_cfg;
  socket_cfg.nonBlocking = true;
  socket_cfg.recvBufferSize = 1024 * 1024;
  socket_cfg.sendBufferSize = 1024 * 1024;

  auto conn_cfg = ConnectionConfig();
  const auto now = Clock::now();
  clients.reserve(target);
  while (clients.size() < target) {
    auto client = std::make_unique<LoadClient>();
    client->id = static_cast<std::uint32_t>(clients.size() + 1);
    client->socket = factory->CreateUdpSocket(socket_cfg);
    if (client->socket == nullptr) {
      throw std::runtime_error("failed to create client socket");
    }
    client->connection = std::make_unique<socketwire::ReliableConnection>(
      client->socket.get(), conn_cfg);
    client->handler = std::make_unique<LoadClientHandler>(*client, metrics);
    client->connection->SetHandler(client->handler.get());

    const auto state_phase =
      std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(
        opts.state_hz <= 0.0
          ? 0.0
          : static_cast<double>(client->id % 1000) / (1000.0 * opts.state_hz)));
    const auto action_phase =
      std::chrono::duration_cast<Clock::duration>(std::chrono::duration<double>(
        opts.action_hz <= 0.0 ? 0.0
                              : static_cast<double>((client->id * 37U) % 1000) /
                                  (1000.0 * opts.action_hz)));
    client->next_state = now + state_phase;
    client->next_action = now + action_phase;

    if (!client->connection->Connect(server_addr, opts.port)) {
      throw std::runtime_error("client connect send failed");
    }
    clients.push_back(std::move(client));
  }
}

int RunClient(const Options& opts) {
  socketwire::InitializeSockets();
  const auto server_addr = ResolveServerAddress(opts);

  std::vector<std::unique_ptr<LoadClient>> clients;
  ClientMetrics metrics;
  std::uint32_t last_passed = 0;
  WriteCsvHeader(opts);

  std::cout << "client_started host=" << opts.host << " port=" << opts.port
            << " start=" << opts.start << " step=" << opts.step
            << " max=" << opts.max << " step_seconds=" << opts.step_seconds
            << " state_hz=" << opts.state_hz << " action_hz=" << opts.action_hz
            << "\n";

  for (std::uint32_t target = opts.start; target <= opts.max;
       target += opts.step) {
    AddClients(clients, target, opts, server_addr, metrics);

    const auto connect_deadline =
      Clock::now() + std::chrono::seconds(opts.connect_timeout_seconds);
    while (!g_stop.load() && Clock::now() < connect_deadline &&
           ConnectedCount(clients) <
             static_cast<std::size_t>(static_cast<double>(target) *
                                      opts.min_connect_rate)) {
      PumpClients(clients);
      std::this_thread::sleep_for(1ms);
    }

    metrics.Reset(metrics.step + 1);
    const auto step_started = Clock::now();
    const auto process_started = SampleProcess();
    const auto step_end =
      step_started + std::chrono::seconds(opts.step_seconds);
    auto next_print = Clock::now() + 1s;
    while (!g_stop.load() && Clock::now() < step_end) {
      PumpClients(clients);
      SendDueTraffic(clients, opts, metrics);

      const auto now = Clock::now();
      if (now >= next_print) {
        std::cout << "progress users=" << target
                  << " connected=" << ConnectedCount(clients)
                  << " sent_state=" << metrics.sent_state
                  << " sent_rel=" << metrics.sent_reliable
                  << " recv_state=" << metrics.recv_state
                  << " recv_rel=" << metrics.recv_reliable
                  << " send_failed=" << metrics.send_failed << "\n";
        next_print = now + 1s;
      }
      std::this_thread::sleep_for(1ms);
    }
    PumpClients(clients);
    const auto process_finished = SampleProcess();
    const double step_seconds =
      std::chrono::duration<double>(process_finished.wall - step_started)
        .count();

    const auto connected = ConnectedCount(clients);
    const double p50_ms = Percentile(metrics.latency_ms, 50.0);
    const double p95_ms = Percentile(metrics.latency_ms, 95.0);
    const double p99_ms = Percentile(metrics.latency_ms, 99.0);
    const double reliable_delivery =
      metrics.sent_reliable == 0 ? 1.0
                                 : static_cast<double>(metrics.recv_reliable) /
                                     static_cast<double>(metrics.sent_reliable);
    const double state_delivery = metrics.sent_state == 0
                                    ? 1.0
                                    : static_cast<double>(metrics.recv_state) /
                                        static_cast<double>(metrics.sent_state);
    const std::string reason =
      FailReason(opts, target, connected, metrics, p95_ms);
    const bool passed = reason.empty();
    const double connect_rate =
      static_cast<double>(connected) / static_cast<double>(target);
    StepResult row;
    row.users = target;
    row.passed = passed;
    row.connected = connected;
    row.connect_rate = connect_rate;
    row.state_delivery = state_delivery;
    row.reliable_delivery = reliable_delivery;
    row.p50_ms = p50_ms;
    row.p95_ms = p95_ms;
    row.p99_ms = p99_ms;
    row.sent_state = metrics.sent_state;
    row.sent_reliable = metrics.sent_reliable;
    row.recv_state = metrics.recv_state;
    row.recv_reliable = metrics.recv_reliable;
    row.sent_bytes = metrics.sent_state_bytes + metrics.sent_reliable_bytes;
    row.recv_bytes = metrics.recv_state_bytes + metrics.recv_reliable_bytes;
    row.cpu_percent = CpuPercent(process_started, process_finished);
    row.rss_mb = process_finished.rss_mb;
    row.tx_bytes_per_sec =
      step_seconds <= 0.0 ? 0.0
                          : static_cast<double>(row.sent_bytes) / step_seconds;
    row.rx_bytes_per_sec =
      step_seconds <= 0.0 ? 0.0
                          : static_cast<double>(row.recv_bytes) / step_seconds;
    row.send_failed = metrics.send_failed;
    row.parse_failed = metrics.parse_failed;
    row.fail_reason = reason;
    AppendCsvRow(opts, row);

    std::cout << std::fixed << std::setprecision(3) << "step users=" << target
              << " pass=" << (passed ? 1 : 0) << " connected=" << connected
              << " connect_rate=" << connect_rate
              << " state_delivery=" << state_delivery
              << " reliable_delivery=" << reliable_delivery
              << " p50_ms=" << p50_ms << " p95_ms=" << p95_ms
              << " p99_ms=" << p99_ms << " sent_state=" << metrics.sent_state
              << " sent_rel=" << metrics.sent_reliable
              << " recv_state=" << metrics.recv_state
              << " recv_rel=" << metrics.recv_reliable
              << " cpu_percent=" << row.cpu_percent << " rss_mb=" << row.rss_mb
              << " tx_Bps=" << row.tx_bytes_per_sec
              << " rx_Bps=" << row.rx_bytes_per_sec
              << " send_failed=" << metrics.send_failed
              << " parse_failed=" << metrics.parse_failed << "\n";

    if (passed) {
      last_passed = target;
      continue;
    }

    std::cout << "FAIL_CAPACITY failed_users=" << target
              << " last_passed=" << last_passed << " reason=" << reason << "\n";
    if (opts.stop_on_fail) {
      DisconnectClients(clients);
      return 2;
    }
  }

  std::cout << "PASS_CAPACITY last_passed=" << last_passed << "\n";
  DisconnectClients(clients);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGINT, StopHandler);
  std::signal(SIGTERM, StopHandler);
  std::cout << std::unitbuf;
  std::cerr << std::unitbuf;

  if (argc < 2 || HasArg({argv + 1, argv + argc}, "--help")) {
    PrintUsage(argv[0]);
    return argc < 2 ? 1 : 0;
  }

  try {
    const Options opts = ParseOptions(argc, argv);
    if (opts.mode == "server") return RunServer(opts);
    if (opts.mode == "client") return RunClient(opts);
    PrintUsage(argv[0]);
    return 1;
  } catch (const std::exception& e) {
    std::cerr << "error: " << e.what() << "\n";
    return 1;
  }
}
