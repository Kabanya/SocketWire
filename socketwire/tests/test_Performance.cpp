// Performance-oriented tests for BitStream, sockets, and SocketPoller.

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <iostream>

#include "bit_stream.hpp"
#include "i_socket.hpp"
#include "socket_init.hpp"
#include "socket_poller.hpp"

using namespace socketwire;  // NOLINT

class PerformanceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    std::cout << "\n\n________Running_test:_"
              << ::testing::UnitTest::GetInstance()->current_test_info()->name()
              << "________\n\n\n";

    InitializeSockets();
    factory = SocketFactoryRegistry::GetFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be registered";
  }

  void TearDown() override { std::cout << "\n"; }

  ISocketFactory* factory = nullptr;

  template <typename Func>
  double MeasureTime(const std::string& operation_name, int iterations,
                     Func func) {
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
      func();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration =
      duration_cast<std::chrono::microseconds>(end - start).count();
    const auto duration_value = static_cast<double>(duration);
    const double ms = duration_value / 1000.0;
    const double ops_per_sec =
      (static_cast<double>(iterations) * 1000000.0) / duration_value;

    std::cout << "  " << operation_name << ":\n"
              << "    Iterations: " << iterations << "\n"
              << "    Total time: " << ms << " ms\n"
              << "    Avg time: "
              << (duration_value / static_cast<double>(iterations))
              << " μs/op\n"
              << "    Throughput: " << static_cast<int>(ops_per_sec)
              << " ops/sec\n";

    return ms;
  }

  static constexpr int kMultiplier = 1;
};

TEST_F(PerformanceTest, BitStreamWriteReadBit) {
  const int iterations = 1000000 * kMultiplier;

  std::cout << "BitStream Bit Operations Performance:\n";

  // Write performance
  MeasureTime("Write 1M bits", iterations, []() {
    socketwire::BitStream bs;
    bs.WriteBit(true);
  });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    bs_read.WriteBit(i % 2 == 0);
  }

  MeasureTime("Read 1M bits", iterations, [&bs_read]() {
    bs_read.ResetRead();
    for (int i = 0; i < 100; ++i) {
      bs_read.ReadBit();
    }
  });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamWriteReadBytes) {
  const int iterations = 100000 * kMultiplier;

  std::cout << "BitStream Byte Operations Performance:\n";

  const char* data = "Hello World! This is a test message.";
  const std::size_t data_len = strlen(data);

  // Write performance
  MeasureTime("Write " + std::to_string(iterations) + " byte arrays",
              iterations, [data, data_len]() {
                socketwire::BitStream bs;
                bs.WriteBytes(data, data_len);
              });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    bs_read.WriteBytes(data, data_len);
  }

  char buffer[64];
  MeasureTime("Read " + std::to_string(iterations) + " byte arrays", iterations,
              [&bs_read, &buffer, data_len]() {
                bs_read.ResetRead();
                for (int i = 0; i < 10; ++i) {
                  bs_read.ReadBytes(buffer, data_len);
                }
              });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamWriteReadIntegers) {
  const int iterations = 500000 * kMultiplier;

  std::cout << "BitStream Integer Operations Performance:\n";

  // Write performance
  MeasureTime("Write " + std::to_string(iterations) + " integers", iterations,
              []() {
                socketwire::BitStream bs;
                bs.Write(42);
                bs.Write(-123);
                bs.Write(0);
              });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    bs_read.Write(i);
  }

  int value = 0;
  MeasureTime("Read " + std::to_string(iterations) + " integers", iterations,
              [&bs_read, &value]() {
                bs_read.ResetRead();
                for (int i = 0; i < 10; ++i) {
                  bs_read.Read(value);
                }
              });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamQuantizedFloat) {
  const int iterations = 200000 * kMultiplier;

  std::cout << "BitStream Quantized Float Performance:\n";

  // Write performance
  MeasureTime("Write " + std::to_string(iterations) + " quantized floats",
              iterations, []() {
                socketwire::BitStream bs;
                bs.WriteQuantizedFloat(3.14f, 0.0f, 10.0f, 16);
                bs.WriteQuantizedFloat(7.5f, 0.0f, 10.0f, 16);
              });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    const float val = static_cast<float>(i % 100) / 10.0f;
    bs_read.WriteQuantizedFloat(val, 0.0f, 10.0f, 16);
  }

  MeasureTime("Read " + std::to_string(iterations) + " quantized floats",
              iterations, [&bs_read]() {
                bs_read.ResetRead();
                for (int i = 0; i < 10; ++i) {
                  bs_read.ReadQuantizedFloat(0.0f, 10.0f, 16);
                }
              });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamStringOperations) {
  const int iterations = 100000 * kMultiplier;

  std::cout << "BitStream String Operations Performance:\n";

  std::string test_string = "This is a test string for performance measurement";

  // Write performance
  MeasureTime("Write " + std::to_string(iterations) + " strings", iterations,
              [&test_string]() {
                socketwire::BitStream bs;
                bs.Write(test_string);
              });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    bs_read.Write(test_string);
  }

  std::string result;
  MeasureTime("Read " + std::to_string(iterations) + " strings", iterations,
              [&bs_read, &result]() {
                bs_read.ResetRead();
                for (int i = 0; i < 10; ++i) {
                  bs_read.Read(result);
                }
              });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamMixedOperations) {
  const int iterations = 50000 * kMultiplier;

  std::cout << "BitStream Mixed Operations Performance:\n";

  // Complex write scenario
  const double write_time = MeasureTime(
    "Write " + std::to_string(iterations) + " mixed data packets", iterations,
    []() {
      socketwire::BitStream bs;

      // Simulate a game packet
      bs.WriteBit(true);                                // connected flag
      bs.Write(42);                                     // player ID
      bs.WriteQuantizedFloat(10.5f, 0.0f, 100.0f, 16);  // position X
      bs.WriteQuantizedFloat(20.3f, 0.0f, 100.0f, 16);  // position Y
      bs.WriteQuantizedFloat(5.1f, 0.0f, 100.0f, 16);   // position Z
      bs.Write(std::string("Player"));                  // name
      bs.WriteBits(0xFF, 8);                            // flags
    });

  // Complex read scenario
  socketwire::BitStream bs_read;
  for (int i = 0; i < 1000; ++i) {
    bs_read.WriteBit(true);
    bs_read.Write(i);
    bs_read.WriteQuantizedFloat(10.5f, 0.0f, 100.0f, 16);
    bs_read.WriteQuantizedFloat(20.3f, 0.0f, 100.0f, 16);
    bs_read.WriteQuantizedFloat(5.1f, 0.0f, 100.0f, 16);
    bs_read.Write(std::string("Player"));
    bs_read.WriteBits(0xFF, 8);
  }

  const double read_time =
    MeasureTime("Read 50K mixed data packets", iterations, [&bs_read]() {
      bs_read.ResetRead();

      const bool flag = bs_read.ReadBit();
      int id = 0;
      bs_read.Read(id);
      const float x = bs_read.ReadQuantizedFloat(0.0f, 100.0f, 16);
      const float y = bs_read.ReadQuantizedFloat(0.0f, 100.0f, 16);
      const float z = bs_read.ReadQuantizedFloat(0.0f, 100.0f, 16);
      std::string name;
      bs_read.Read(name);
      const uint32_t flags = bs_read.ReadBits(8);

      (void)flag;
      (void)id;
      (void)x;
      (void)y;
      (void)z;
      (void)name;
      (void)flags;
    });

  std::cout << "  Write/Read ratio: " << (write_time / read_time) << "x\n";

  SUCCEED();
}

TEST_F(PerformanceTest, NetSocketCreation) {
  const int iterations = 10000 * kMultiplier;

  std::cout << "NetSocket Creation Performance:\n";

  MeasureTime("Create and bind " + std::to_string(iterations) + " sockets",
              iterations, [this]() {
                const SocketConfig config;
                auto sock = factory->CreateUdpSocket(config);
                const SocketAddress addr =
                  SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
                sock->Bind(addr, 0);
              });

  SUCCEED();
}

TEST_F(PerformanceTest, NetSocketSendReceive) {
  const int iterations = 10000 * kMultiplier;

  std::cout << "NetSocket Send/Receive Performance:\n";

  // Create sender and receiver
  const SocketConfig config;
  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  ASSERT_EQ(sender->Bind(addr, 0), SocketError::kNone);
  ASSERT_EQ(receiver->Bind(addr, 0), SocketError::kNone);

  std::uint16_t receiver_port = receiver->LocalPort();
  ASSERT_GT(receiver_port, 0);

  const char* message = "Performance test message";
  const std::size_t message_len = strlen(message);

  MeasureTime("Send 10K UDP packets", iterations,
              [&sender, message, message_len, &addr, receiver_port]() {
                sender->SendTo(message, message_len, addr, receiver_port);
              });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamLargeDataTransfer) {
  const int iterations = 1000 * kMultiplier;
  const int data_size = 1024 * 10;  // 10 KB

  std::cout << "BitStream Large Data Transfer Performance:\n";

  std::vector<char> large_data(data_size, 'X');

  const double write_time =
    MeasureTime("Write " + std::to_string(iterations) + " x " +
                  std::to_string(data_size / 1024) + " blocks",
                iterations, [&large_data]() {
                  socketwire::BitStream bs;
                  bs.WriteBytes(large_data.data(), large_data.size());
                });

  socketwire::BitStream bs_read;
  for (int i = 0; i < 100; ++i) {
    bs_read.WriteBytes(large_data.data(), data_size);
  }

  std::vector<char> read_buffer(data_size);
  const double read_time =
    MeasureTime("Read " + std::to_string(iterations) + " x " +
                  std::to_string(data_size / 1024) + " blocks",
                iterations, [&bs_read, &read_buffer]() {
                  bs_read.ResetRead();
                  bs_read.ReadBytes(read_buffer.data(), read_buffer.size());
                });

  const double mb_written = (iterations * data_size) / (1024.0 * 1024.0);
  const double write_throughput = mb_written / (write_time / 1000.0);
  const double read_throughput = mb_written / (read_time / 1000.0);

  std::cout << "  Total data: " << mb_written << " MB\n"
            << "  Write throughput: " << write_throughput << " MB/s\n"
            << "  Read throughput: " << read_throughput << " MB/s\n";

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamAlignment) {
  const int iterations = 500000 * kMultiplier;

  std::cout << "BitStream Alignment Performance:\n";

  MeasureTime("Write + Align " + std::to_string(iterations) + " times",
              iterations, []() {
                socketwire::BitStream bs;
                bs.WriteBits(0b111, 3);
                bs.AlignWrite();
                bs.WriteBytes("A", 1);
              });

  socketwire::BitStream bs_read;
  for (int i = 0; i < 1000; ++i) {
    bs_read.WriteBits(0b111, 3);
    bs_read.AlignWrite();
    bs_read.WriteBytes("A", 1);
  }

  MeasureTime("Read + Align " + std::to_string(iterations) + " times",
              iterations, [&bs_read]() {
                bs_read.ResetRead();
                bs_read.ReadBits(3);
                bs_read.AlignRead();
                char c = 0;
                bs_read.ReadBytes(&c, 1);
              });

  SUCCEED();
}

TEST_F(PerformanceTest, SocketPollerAddRemoveSockets) {
  const int iterations = 1000 * kMultiplier;

  std::cout << "SocketPoller Add/Remove Sockets Performance:\n";

  MeasureTime("Add/Remove " + std::to_string(iterations) + " sockets",
              iterations, [this]() {
                SocketPoller poller;
                const SocketConfig config;
                auto socket = factory->CreateUdpSocket(config);
                const SocketAddress addr =
                  SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
                socket->Bind(addr, 0);
                poller.AddSocket(socket.get(), false);
                poller.RemoveSocket(socket.get());
              });

  SUCCEED();
}

TEST_F(PerformanceTest, SocketPollerPollEmpty) {
  const int iterations = 10000 * kMultiplier;

  std::cout << "SocketPoller Poll Empty Performance:\n";

  SocketPoller poller;

  MeasureTime("Poll empty poller " + std::to_string(iterations) + " times",
              iterations, [&poller]() {
                auto events = poller.Poll(0);  // Non-blocking
                (void)events;
              });

  SUCCEED();
}

TEST_F(PerformanceTest, SocketPollerPollWithSockets) {
  const int num_sockets = 100;
  const int iterations = 1000 * kMultiplier;

  std::cout << "SocketPoller Poll With Sockets Performance:\n";

  std::vector<std::unique_ptr<ISocket>> sockets;
  SocketPoller poller;
  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1

  // Create and add sockets
  for (int i = 0; i < num_sockets; ++i) {
    const SocketConfig config;
    auto socket = factory->CreateUdpSocket(config);
    socket->Bind(addr, 0);
    sockets.push_back(std::move(socket));
    poller.AddSocket(sockets.back().get(), false);
  }

  MeasureTime("Poll 100 sockets 1K times", iterations, [&poller]() {
    auto events = poller.Poll(0);  // Non-blocking
    (void)events;
  });

  SUCCEED();
}

TEST_F(PerformanceTest, SocketPollerDispatchEvents) {
  const int iterations = 100000 * kMultiplier;

  std::cout << "SocketPoller Dispatch Events Performance:\n";

  // Simple event handler that does nothing
  class DummyHandler : public ISocketEventHandler {
   public:
    void OnDataReceived(const SocketAddress&, std::uint16_t, const void*,
                        std::size_t) override {}
    void OnSocketError(SocketError) override {}
    void OnSocketClosed() override {}
  };

  DummyHandler handler;
  SocketPoller poller;

  // Create a socket and add to poller
  const SocketConfig config;
  auto socket = factory->CreateUdpSocket(config);
  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);
  socket->Bind(addr, 0);
  poller.AddSocket(socket.get(), false);

  // Create dummy events
  std::vector<SocketEvent> events;
  SocketEvent ev;
  ev.socket = socket.get();
  ev.readable = true;
  events.push_back(ev);

  MeasureTime(
    "Dispatch " + std::to_string(iterations) + " events", iterations,
    [&poller, &events, &handler]() { poller.DispatchAll(events, &handler); });

  SUCCEED();
}

TEST_F(PerformanceTest, SocketPollerIntegrationSendReceive) {
  const int iterations = 10000 * kMultiplier;

  std::cout << "SocketPoller Integration Send/Receive Performance:\n";

  // Create sender and receiver
  const SocketConfig config;
  auto sender = factory->CreateUdpSocket(config);
  auto receiver = factory->CreateUdpSocket(config);

  const SocketAddress addr = SocketAddress::FromIPv4(0x7F000001);  // 127.0.0.1
  sender->Bind(addr, 0);
  receiver->Bind(addr, 0);
  uint16_t receiver_port = receiver->LocalPort();

  SocketPoller poller;
  poller.AddSocket(receiver.get(), false);

  const char* message = "Perf test message";
  const size_t message_len = strlen(message);

  // Handler to count received messages
  class CountingHandler : public ISocketEventHandler {
   public:
    int count = 0;
    void OnDataReceived(const SocketAddress&, std::uint16_t, const void*,
                        std::size_t) override {
      ++count;
    }
    void OnSocketError(SocketError) override {}
    void OnSocketClosed() override {}
  };

  CountingHandler handler;

  MeasureTime(
    "Send/Receive " + std::to_string(iterations) + " messages via poller",
    iterations, [&]() {
      // Send message
      sender->SendTo(message, message_len, addr, receiver_port);

      // Poll and dispatch
      auto events = poller.Poll(10);  // Short timeout
      const SocketEvent& ev = events.at(0);
      if (!events.empty()) {
        poller.DispatchReadable(ev, &handler);
      }
    });

  std::cout << "  Total messages received: " << handler.count << "\n";

  SUCCEED();
}
