# Многопоточность

SocketWire использует модель single-owner protocol state. Сетевые классы не
добавляют mutex вокруг каждого метода; состояние протокола остается на одном
network thread.

## Владение Network Thread

Эти операции должны выполняться на owner network thread:

- `ReliableConnection::Tick()` и `Update()`;
- `ReliableConnection::ProcessPacket()`;
- `ReliableConnection::SendReliable()` и связанные `Send*` методы;
- `ConnectionManager::Tick()` и `Update()`;
- `ConnectionManager::BroadcastReliable()` и связанные `Broadcast*` методы;
- receive/send операции `ISocket`.

Вызов этих методов одновременно из разных потоков находится вне threading
contract.

## Handler Callbacks

Все `IReliableConnectionHandler` callbacks выполняются inline на network
thread. Они должны быть достаточно короткими, чтобы не блокировать network loop.

Для CPU-heavy payload work скопируйте payload и отправьте тяжелую часть в
user-owned `ThreadPool`. Worker callbacks должны использовать `Post()`, чтобы
вернуть сетевые операции на owner thread:

```cpp
workers.Submit([&manager, channel, payload = std::move(payload)] {
  auto response = BuildResponse(payload);

  manager.Post([&manager, channel, response = std::move(response)] {
    manager.BroadcastReliable(channel, response.data(), response.size());
  });
});
```

`Tick()` и `Update()` автоматически drain-ят posted tasks до и после
протокольной работы.

## Рекомендуемая Модель

Используйте один network owner thread на `ConnectionManager` или standalone
`ReliableConnection`. `ThreadPool` используйте только для прикладной работы,
которая иначе блокировала бы owner thread.
