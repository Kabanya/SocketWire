# Архитектура

SocketWire — C++23 сетевая библиотека прикладного уровня для multiplayer games.
Она строит reliable и unreliable доставку сообщений поверх UDP-style датаграмм,
оставляя состояние протокола явным и принадлежащим network loop.

## Transport Layer

Публичная граница сокетов — `ISocket`. Платформенные реализации скрывают детали
ОС:

- Linux может использовать `epoll` и batch UDP syscalls, где они доступны.
- macOS и BSD используют `kqueue`-style polling, где он доступен.
- Windows использует Winsock.
- Browser builds могут передавать датаграммы через WebSocket transport.

Протокольный слой не создает отдельный socket на клиента. Сервер обычно владеет
одним UDP socket и маршрутизирует датаграммы по remote endpoint.

## Server Demultiplexing

`ConnectionManager` владеет server-side таблицей клиентов:

```text
endpoint -> RemoteClient -> ReliableConnection
```

Для каждой входящей датаграммы он:

1. Читает адрес и порт отправителя.
2. Ищет соответствующего клиента.
3. Создает нового клиента только для валидного connect packet.
4. Передает датаграммы известных клиентов в их `ReliableConnection`.

Поток на каждого клиента не создается. Каждый server-side client представлен
объектом состояния.

## ReliableConnection

`ReliableConnection` владеет per-peer состоянием протокола:

- connection state;
- sequence numbers;
- ACK tracking;
- retry scheduling;
- congestion window;
- fragmentation and reassembly;
- optional crypto state;
- ping, timeout и statistics.

Reliable messages хранятся до подтверждения ACK. Потерянные пакеты
переотправляются после configured timeout. Optional send-window ограничивает
число reliable packets in flight.

## Serialization

`BitStream` — низкоуровневый helper сериализации. Он записывает явный network
format вместо зависимости от C++ structure layout, padding или host byte order.

Протокол также использует payload buffers с inline storage для маленьких
сообщений, чтобы common hot paths обходились без heap allocation.

## Batching И Crypto

Protocol batching может упаковать несколько маленьких commands в одну
датаграмму. Secure mode использует libsodium-based authenticated encryption.
Когда crypto включена, protocol batching намеренно отключается, чтобы encrypted
framing оставался проще.

Socket-level batching все еще может использоваться socket implementations, если
платформа это поддерживает.

## Threading Boundary

`ReliableConnection`, `ConnectionManager` и `ISocket` остаются во владении
network thread. Async payload dispatch может перенести прикладную работу handler
в worker pool, но все protocol methods и socket I/O по-прежнему выполняются на
network owner thread.
