# Architecture

SocketWire is a C++23 application-layer networking library for multiplayer
games. It builds reliable and unreliable message delivery on top of UDP-style
datagrams while keeping protocol state explicit and owned by the network loop.

## Transport Layer

The public socket boundary is `ISocket`. Platform-specific implementations hide
the OS details:

- Linux can use `epoll` and batched UDP syscalls where available.
- macOS and BSD use `kqueue`-style polling where available.
- Windows uses Winsock.
- Browser builds can route datagrams through a WebSocket transport.

The protocol layer does not create one socket per client. A server normally owns
one UDP socket and routes datagrams by remote endpoint.

## Server Demultiplexing

`ConnectionManager` owns the server-side client table:

```text
endpoint -> RemoteClient -> ReliableConnection
```

For every incoming datagram it:

1. Reads the sender address and port.
2. Looks up the matching client.
3. Creates a new client only for valid connect packets.
4. Passes known-client datagrams to that client's `ReliableConnection`.

There is no thread per client. Each server-side client is represented by a
state object.

## ReliableConnection

`ReliableConnection` owns the per-peer protocol state:

- connection state;
- sequence numbers;
- ACK tracking;
- retry scheduling;
- congestion window;
- fragmentation and reassembly;
- optional crypto state;
- ping, timeout, and statistics.

Reliable messages are stored until acknowledged. Lost packets are retried after
the configured timeout. Optional send-window control limits the number of
in-flight reliable packets.

## Serialization

`BitStream` is the low-level serialization helper. It writes explicit network
formats instead of relying on C++ structure layout, padding, or host byte order.

The protocol also uses payload buffers with inline storage for small messages so
common hot paths avoid heap allocation.

## Batching And Crypto

Protocol batching can pack several small commands into one datagram. Secure mode
uses libsodium-based authenticated encryption. When crypto is enabled, protocol
batching is intentionally disabled to keep encrypted framing simpler.

Socket-level batching can still be used by socket implementations where the
platform supports it.

## Threading Boundary

`ReliableConnection`, `ConnectionManager`, and `ISocket` remain network-thread
owned. Async payload dispatch can move application handler work to a worker pool,
but all protocol methods and socket I/O still run on the network owner thread.
