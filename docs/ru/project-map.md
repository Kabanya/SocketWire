# Карта Проекта

Короткая карта структуры репозитория и основных модулей SocketWire.

## Структура Репозитория

```text
socketwire/
  source/      Исходники библиотеки и публичные headers
  tests/       GoogleTest test suite
cmake/         CMake helper files
docs/          Документация проекта
```

## Основные Модули

- `i_socket.hpp` / platform socket implementations: transport abstraction.
- `socket_init.hpp`: инициализация platform socket subsystem.
- `connection_manager.hpp`: server-side таблица клиентов и datagram routing.
- `reliable_connection.hpp`: per-peer состояние reliable/unreliable протокола.
- `reliable_protocol.hpp`: packet codec и protocol-level helpers.
- `bit_stream.hpp`: helper для явной binary serialization.
- `crypto.hpp`: optional encrypted transport support.
- `thread_pool.hpp`: executor для прикладной работы.
- `task_queue.hpp`: очередь для возврата работы на network thread.

## Runtime Ownership

`ConnectionManager` владеет server-side экземплярами `ReliableConnection`.
Клиент обычно владеет одним standalone `ReliableConnection`. В обеих моделях
protocol state остается на network owner thread.

Async payload dispatch может добавить worker threads для application callbacks,
но не переносит protocol state или socket I/O с network thread.

## Tests

Тесты покрывают:

- packet encoding and decoding;
- reliable delivery and retransmission;
- fragmentation and reassembly;
- connection manager integration;
- deadline-aware sends;
- crypto behavior;
- thread pool and task queue behavior;
- performance scenarios.
