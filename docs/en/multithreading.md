# Multithreading

SocketWire uses a single-owner protocol model. Networking classes do not add
locks around every method; protocol state stays on one network thread.

## Network-thread Ownership

These operations must run on the owner network thread:

- `ReliableConnection::Tick()` and `Update()`;
- `ReliableConnection::ProcessPacket()`;
- `ReliableConnection::SendReliable()` and related `Send*` methods;
- `ConnectionManager::Tick()` and `Update()`;
- `ConnectionManager::BroadcastReliable()` and related `Broadcast*` methods;
- `ISocket` receive/send operations.

Calling these methods concurrently from different threads is outside the
threading contract.

## Handler Callbacks

All `IReliableConnectionHandler` callbacks run inline on the network thread.
Keep them short enough not to block the network loop.

For CPU-heavy payload work, copy the payload and submit the expensive part to a
user-owned `ThreadPool`. Worker callbacks must use `Post()` to return network
operations to the owner thread:

```cpp
workers.Submit([&manager, channel, payload = std::move(payload)] {
  auto response = BuildResponse(payload);

  manager.Post([&manager, channel, response = std::move(response)] {
    manager.BroadcastReliable(channel, response.data(), response.size());
  });
});
```

`Tick()` and `Update()` drain posted tasks automatically before and after
protocol work.

## Recommended Model

Use one network owner thread per `ConnectionManager` or standalone
`ReliableConnection`. Use `ThreadPool` only for application work that would
otherwise block that owner thread.
