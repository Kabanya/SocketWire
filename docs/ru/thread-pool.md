# Пул Потоков

SocketWire оставляет сокеты, состояние протокола и состояние соединений во
владении одного network thread. `IReliableConnectionHandler` callbacks
выполняются inline на этом потоке. Для тяжелой прикладной работы используйте
`ThreadPool` вручную.

## Ручная Обработка Payload

```cpp
socketwire::ThreadPool workers(4);
workers.Start();
socketwire::TaskQueue network_queue;
```

Payload bytes нужно скопировать перед отправкой задачи, потому что receive
buffers могут переиспользоваться сетевым слоем:

```cpp
class Handler : public socketwire::IReliableConnectionHandler {
 public:
  Handler(socketwire::ConnectionManager& manager,
          socketwire::ThreadPool& workers,
          socketwire::TaskQueue& network_queue)
      : manager_(manager), workers_(workers), network_queue_(network_queue) {}

  void OnReliableReceived(std::uint8_t channel,
                          const void* data,
                          std::size_t size) override {
    std::vector<std::uint8_t> payload(
      static_cast<const std::uint8_t*>(data),
      static_cast<const std::uint8_t*>(data) + size);

    workers_.Submit([this, channel, payload = std::move(payload)] {
      auto response = BuildResponse(payload);

      network_queue_.Post([this, channel, response = std::move(response)] {
        manager_.BroadcastReliable(channel, response.data(), response.size());
      });
    });
  }

 private:
  socketwire::ConnectionManager& manager_;
  socketwire::ThreadPool& workers_;
  socketwire::TaskQueue& network_queue_;
};
```

Для client-side `ReliableConnection` возвращайте работу через ту же явную
network queue:

```cpp
network_queue.Post([&connection, response = std::move(response)] {
  connection.SendReliable(0, response.data(), response.size());
});
```

Drain этой queue делается на network owner thread:

```cpp
while (running) {
  network_queue.Drain();
  manager.Tick();
  connection.Tick();
  network_queue.Drain();
}
```

На shutdown вызовите `workers.Stop()`.

## Lifetime Правила

- У `ThreadPool` явный lifecycle: `Start()` / `Stop()`.
- Worker callbacks не должны напрямую вызывать socket или protocol методы.
- Caller сам владеет и drain-ит любую cross-thread `TaskQueue`.
- Handler и захваченные данные должны жить дольше pending worker tasks.

## Benchmark

Performance benchmark сравнивает inline handler work с ручным `ThreadPool`
dispatch:

```sh
cmake -S . -B build-perf -DCMAKE_BUILD_TYPE=Release
cmake --build build-perf --parallel
./build-perf/socketwire/tests/SocketWireTests \
  --gtest_filter='ReliableConnectionPerformanceTest.ApplicationWorkloadInlineVsThreadPool'
```
