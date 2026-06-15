# Pipeline

This document shows the usual flow from user code into SocketWire internals.

## Server Flow

1. Initialize the socket subsystem.

```cpp
socketwire::InitializeSockets();
```

2. Create a non-blocking UDP socket.

```cpp
auto* factory = socketwire::SocketFactoryRegistry::GetFactory();

socketwire::SocketConfig socket_config;
socket_config.nonBlocking = true;

auto socket = factory->CreateUdpSocket(socket_config);
socket->Bind(socketwire::SocketAddress::FromIPv4(0), 7777);
```

3. Create a handler and a `ConnectionManager`.

```cpp
class Handler : public socketwire::IReliableConnectionHandler {
 public:
  void OnConnected() override {}

  void OnReliableReceived(std::uint8_t channel,
                          const void* data,
                          std::size_t size) override {}
};

socketwire::ReliableConnectionConfig config;
socketwire::ConnectionManager manager(socket.get(), config);

Handler handler;
manager.SetHandler(&handler);
```

4. Run the network loop.

```cpp
while (running) {
  manager.Tick();
}
```

## Client Flow

```cpp
socketwire::InitializeSockets();

auto* factory = socketwire::SocketFactoryRegistry::GetFactory();

socketwire::SocketConfig socket_config;
socket_config.nonBlocking = true;

auto socket = factory->CreateUdpSocket(socket_config);

socketwire::ReliableConnectionConfig config;
socketwire::ReliableConnection connection(socket.get(), config);

Handler handler;
connection.SetHandler(&handler);

connection.Connect(socketwire::SocketAddress::FromIPv4(0x7F000001), 7777);

while (running) {
  connection.Tick();
}
```

## Internal Flow

```text
User calls Tick()
        |
        v
SocketWire reads socket datagrams
        |
        v
ConnectionManager routes by endpoint
        |
        v
ReliableConnection decodes protocol packets
        |
        v
handler receives connection or payload callbacks
        |
        v
Update performs retry, ACK flush, ping, timeout, and cleanup
```

## Manual Worker Variant

For heavy application work:

```cpp
workers.Submit([&manager, channel, payload = std::move(payload)] {
  auto response = BuildResponse(payload);

  manager.Post([&manager, channel, response = std::move(response)] {
    manager.BroadcastReliable(channel, response.data(), response.size());
  });
});
```

The network loop stays the same. `Tick()` and `Update()` drain posted tasks.
