# SocketWire

Cross-platform framework for multiplayer games. Uses C++23, libsodium for cryptography, and has no runtime dependencies. GoogleTest is used only for testing.

## Requirements

- CMake 3.28 or higher
- A C++ compiler that supports C++23 standard

## Examples

Check out examples of usage at [SocketWire-Examples](https://github.com/Kabanya/SocketWire-Examples), including integration with raylib.

## Performance notes

Secure mode (`config.crypto.enabled = true`) disables protocol-level packet batching. This means ACKs and small protocol packets are not packed into fewer UDP datagrams while encryption is enabled.

Socket-level receive batching (`ReceiveMany`) can still be used by socket implementations. The tradeoff is intentional: secure mode favors a simpler encrypted packet model over the datagram-count optimization provided by protocol batching.

## Thread pool usage

`socketwire::ThreadPool` is intended for application-side work that should not
run inside the network loop. `ReliableConnection`, `ConnectionManager`, and
`ISocket` still belong to one network thread; worker tasks should not call
`Send*`, `Broadcast*`, `Tick`, `Update`, or socket I/O directly.

Use `socketwire::TaskQueue` to marshal results back to the network thread:

```cpp
socketwire::ThreadPool workers;
socketwire::TaskQueue network_queue;

void OnReliableReceived(std::uint8_t channel, const void* data,
                        std::size_t size) {
  std::vector<std::uint8_t> payload(
    static_cast<const std::uint8_t*>(data),
    static_cast<const std::uint8_t*>(data) + size);

  workers.Post([payload = std::move(payload), channel, &network_queue,
                manager]() mutable {
    auto response = BuildResponse(payload);

    network_queue.Post([manager, channel, response = std::move(response)] {
      manager->BroadcastReliable(channel, response.data(), response.size());
    });
  });
}
```

The network loop should drain queued network work before or after ticking:

```cpp
while (running) {
  network_queue.Drain();
  manager.Tick();
  network_queue.Drain();
}
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
