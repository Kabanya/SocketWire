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

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
