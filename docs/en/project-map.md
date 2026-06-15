# Project Map

This is a short map of the repository layout and the main SocketWire modules.

## Repository Layout

```text
socketwire/
  source/      Library sources and public headers
  tests/       GoogleTest test suite
cmake/         CMake helper files
docs/          Project documentation
```

## Core Modules

- `i_socket.hpp` / platform socket implementations: transport abstraction.
- `socket_init.hpp`: platform socket subsystem initialization.
- `connection_manager.hpp`: server-side client table and datagram routing.
- `reliable_connection.hpp`: per-peer reliable/unreliable protocol state.
- `reliable_protocol.hpp`: packet codec and protocol-level helpers.
- `bit_stream.hpp`: explicit binary serialization helper.
- `crypto.hpp`: optional encrypted transport support.
- `thread_pool.hpp`: application work executor.
- `task_queue.hpp`: queue for returning work to the network thread.

## Runtime Ownership

`ConnectionManager` owns server-side `ReliableConnection` instances. A client
usually owns one standalone `ReliableConnection`. Both models keep protocol
state on the network owner thread.

Async payload dispatch can add worker threads for application callbacks, but it
does not move protocol state or socket I/O off the network thread.

## Tests

The tests cover:

- packet encoding and decoding;
- reliable delivery and retransmission;
- fragmentation and reassembly;
- connection manager integration;
- deadline-aware sends;
- crypto behavior;
- thread pool and task queue behavior;
- performance scenarios.
