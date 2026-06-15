# Pipeline

Этот документ показывает обычный путь от пользовательского кода внутрь
SocketWire.

## Server Flow

1. Инициализировать socket subsystem.

```cpp
socketwire::InitializeSockets();
```

2. Создать non-blocking UDP socket.

```cpp
auto* factory = socketwire::SocketFactoryRegistry::GetFactory();

socketwire::SocketConfig socket_config;
socket_config.nonBlocking = true;

auto socket = factory->CreateUdpSocket(socket_config);
socket->Bind(socketwire::SocketAddress::FromIPv4(0), 7777);
```

3. Создать handler и `ConnectionManager`.

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

4. Запустить network loop.

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
Пользователь вызывает Tick()
        |
        v
SocketWire читает socket datagrams
        |
        v
ConnectionManager маршрутизирует по endpoint
        |
        v
ReliableConnection декодирует protocol packets
        |
        v
handler получает connection или payload callbacks
        |
        v
Update делает retry, ACK flush, ping, timeout и cleanup
```

## Manual Worker Variant

Для тяжелой прикладной работы:

```cpp
workers.Submit([&manager, channel, payload = std::move(payload)] {
  auto response = BuildResponse(payload);

  manager.Post([&manager, channel, response = std::move(response)] {
    manager.BroadcastReliable(channel, response.data(), response.size());
  });
});
```

Network loop остается таким же. `Tick()` и `Update()` drain-ят posted tasks.
