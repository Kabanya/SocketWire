# Thread Pool

SocketWire keeps sockets, protocol state, and connection state owned by one
network thread. `IReliableConnectionHandler` callbacks run inline on that
thread. Use `ThreadPool` manually for application work that would otherwise
block the network loop.

## Manual Payload Work

```cpp
socketwire::ThreadPool workers(4);
workers.Start();
```

Copy payload bytes before submitting work because receive buffers may be reused
by the network layer:

```cpp
class Handler : public socketwire::IReliableConnectionHandler {
 public:
  Handler(socketwire::ConnectionManager& manager,
          socketwire::ThreadPool& workers)
      : manager_(manager), workers_(workers) {}

  void OnReliableReceived(std::uint8_t channel,
                          const void* data,
                          std::size_t size) override {
    std::vector<std::uint8_t> payload(
      static_cast<const std::uint8_t*>(data),
      static_cast<const std::uint8_t*>(data) + size);

    workers_.Submit([this, channel, payload = std::move(payload)] {
      auto response = BuildResponse(payload);

      manager_.Post([this, channel, response = std::move(response)] {
        manager_.BroadcastReliable(channel, response.data(), response.size());
      });
    });
  }

 private:
  socketwire::ConnectionManager& manager_;
  socketwire::ThreadPool& workers_;
};
```

For a client-side `ReliableConnection`, post back through the connection:

```cpp
connection.Post([&connection, response = std::move(response)] {
  connection.SendReliable(0, response.data(), response.size());
});
```

Call `workers.Stop()` during shutdown.

## Lifetime Rules

- `ThreadPool` has explicit `Start()` / `Stop()` lifecycle.
- Worker callbacks must not call socket or protocol methods directly.
- `Tick()` and `Update()` drain posted network-thread tasks automatically.
- The handler and captured data must outlive pending worker tasks.

## Benchmark

The performance benchmark compares inline handler work with manual
`ThreadPool` dispatch:

```sh
cmake -S . -B build-perf -DCMAKE_BUILD_TYPE=Release
cmake --build build-perf --parallel
./build-perf/socketwire/tests/SocketWireTests \
  --gtest_filter='ReliableConnectionPerformanceTest.ApplicationWorkloadInlineVsThreadPool'
```
