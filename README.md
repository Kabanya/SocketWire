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

By default, all `IReliableConnectionHandler` callbacks run inline on the
network thread, matching the original behavior.

For heavier application payload handlers, enable async payload dispatch:

```cpp
socketwire::ReliableConnectionConfig config;
config.handlerDispatchMode = socketwire::HandlerDispatchMode::kAsyncPayload;

socketwire::ConnectionManager manager(socket, config);
manager.SetHandler(&handler);
```

In this mode, `OnReliableReceived` and `OnUnreliableReceived` copy their
payload and run on a worker pool owned by SocketWire. Control callbacks
(`OnConnected`, `OnDisconnected`, `OnTimeout`) still run on the network thread.

Network operations still belong to the network thread. Use `Post()` when an
async payload callback needs to send a response:

```cpp
void OnReliableReceived(std::uint8_t channel, const void* data,
                        std::size_t size) {
  std::vector<std::uint8_t> payload(
    static_cast<const std::uint8_t*>(data),
    static_cast<const std::uint8_t*>(data) + size);

  auto response = BuildResponse(payload);

  manager.Post([this, channel, response = std::move(response)] {
    manager.BroadcastReliable(channel, response.data(), response.size());
  });
}
```

`ConnectionManager::Tick()` / `Update()` and `ReliableConnection::Tick()` /
`Update()` drain posted network tasks automatically. Low-level
`socketwire::ThreadPool` and `socketwire::TaskQueue` remain available when an
application needs full manual control.

If the async worker queue is full, SocketWire falls back to inline delivery for
that payload callback so the message callback is not dropped.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
