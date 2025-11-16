#pragma once

#include "i_socket.hpp"
#include <chrono>
#include <vector>
#include <X11/extensions/randr.h>
#include <cstdint>


namespace socketwire
{

// Packet types for internal protocol
enum class PacketType
{
  Unreliable = 0,
  Reliable = 1,
  Unsequenced = 2,
  Ping = 4,
  Pong = 5,
  Connect = 6,
  Disconnect = 7,
  Ack = 8,
};

// Connection states
enum class Connection : std::uint8_t
{
  Disconnected = 0,
  Connecting = 1,
  Connected = 2,
  Disconnecting = 3,
};

// Configuration for reliable connection
struct ReliableConnectionConfig
{
  std::uint32_t maxRetries = 10;
  std::uint32_t retryTimeoutMs = 100;
  std::uint32_t maxPacketSize = 1400;
  std::uint32_t pintIntervalMs = 1000;
  std::uint32_t disconnectTimeoutMs = 5000;
  std::uint8_t numChannels = 2;
};

// Pending packet waiting for acknowledgment
struct PendingPacket
{
  std::uint32_t sequance;
  std::vector<std::uint8_t> data;
  std::chrono::steady_clock::time_point sendTime;
  std::uint32_t retries = 0;
  std::uint8_t channel = 0;
};

struct ReceivedPacket
{
  std::uint32_t sequence;
  std::vector<std::uint8_t> data;
  std::uint8_t channel = 0;
}








} // namespace socketwire