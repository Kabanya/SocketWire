/*
Performance test suite for SocketWire library
Migrated from legacy net_socket tests to use the new ISocket architecture
with factory pattern and POSIX UDP socket implementation.
*/

#include <gtest/gtest.h>
#include <chrono>
#include <iostream>
#include <cstring>
#include "bit_stream.hpp"
#include "i_socket.hpp"

// Forward declaration
namespace socketwire {
  void register_posix_socket_factory();
}

using namespace socketwire; //NOLINT

class PerformanceTest : public ::testing::Test
{
protected:
  void SetUp() override {
    std::cout << "\n\n________Running_test:_" << ::testing::UnitTest::GetInstance()->current_test_info()->name() << "________\n\n\n";

    // Register POSIX socket factory
    register_posix_socket_factory();
    factory = SocketFactoryRegistry::getFactory();
    ASSERT_NE(factory, nullptr) << "Socket factory should be registered";
  }

  void TearDown() override {
    std::cout << "\n";
  }

  ISocketFactory* factory = nullptr;

  template<typename Func>
  double measureTime(const std::string& operation_name, int iterations, Func func) {
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; ++i) {
      func();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = duration_cast<std::chrono::microseconds>(end - start).count();
    double ms = duration / 1000.0;
    double ops_per_sec = (iterations * 1000000.0) / duration;

    std::cout << "  " << operation_name << ":\n"
              << "    Iterations: " << iterations << "\n"
              << "    Total time: " << ms << " ms\n"
              << "    Avg time: " << (duration / static_cast<double>(iterations)) << " μs/op\n"
              << "    Throughput: " << static_cast<int>(ops_per_sec) << " ops/sec\n";

    return ms;
  }

  static constexpr double multiplier = 1;
};

TEST_F(PerformanceTest, BitStreamWriteReadBit) {
  const int iterations = 1000000 * multiplier;

  std::cout << "BitStream Bit Operations Performance:\n";

  // Write performance
  measureTime("Write 1M bits", iterations, []() {
    socketwire::BitStream bs;
    bs.writeBit(true);
  });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    bs_read.writeBit(i % 2 == 0);
  }

  measureTime("Read 1M bits", iterations, [&bs_read]() {
    bs_read.resetRead();
    for (int i = 0; i < 100; ++i) {
      bs_read.readBit();
    }
  });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamWriteReadBytes) {
  const int iterations = 100000 * multiplier;

  std::cout << "BitStream Byte Operations Performance:\n";

  const char* data = "Hello World! This is a test message.";
  size_t data_len = strlen(data);

  // Write performance
  measureTime("Write 100K byte arrays", iterations, [data, data_len]() {
    socketwire::BitStream bs;
    bs.writeBytes(data, data_len);
  });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    bs_read.writeBytes(data, data_len);
  }

  char buffer[64];
  measureTime("Read 100K byte arrays", iterations, [&bs_read, &buffer, data_len]() {
    bs_read.resetRead();
    for (int i = 0; i < 10; ++i) {
      bs_read.readBytes(buffer, data_len);
    }
  });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamWriteReadIntegers) {
  const int iterations = 500000 * multiplier;

  std::cout << "BitStream Integer Operations Performance:\n";

  // Write performance
  measureTime("Write 500K integers", iterations, []() {
    socketwire::BitStream bs;
    bs.write(42);
    bs.write(-123);
    bs.write(0);
  });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    bs_read.write(i);
  }

  int value;
  measureTime("Read 500K integers", iterations, [&bs_read, &value]() {
    bs_read.resetRead();
    for (int i = 0; i < 10; ++i) {
      bs_read.read(value);
    }
  });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamQuantizedFloat) {
  const int iterations = 200000 * multiplier;

  std::cout << "BitStream Quantized Float Performance:\n";

  // Write performance
  measureTime("Write 200K quantized floats", iterations, []() {
    socketwire::BitStream bs;
    bs.writeQuantizedFloat(3.14f, 0.0f, 10.0f, 16);
    bs.writeQuantizedFloat(7.5f, 0.0f, 10.0f, 16);
  });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    float val = (i % 100) / 10.0f;
    bs_read.writeQuantizedFloat(val, 0.0f, 10.0f, 16);
  }

  measureTime("Read 200K quantized floats", iterations, [&bs_read]() {
    bs_read.resetRead();
    for (int i = 0; i < 10; ++i) {
      bs_read.readQuantizedFloat(0.0f, 10.0f, 16);
    }
  });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamStringOperations) {
  const int iterations = 100000 * multiplier;

  std::cout << "BitStream String Operations Performance:\n";

  std::string test_string = "This is a test string for performance measurement";

  // Write performance
  measureTime("Write 100K strings", iterations, [&test_string]() {
    socketwire::BitStream bs;
    bs.write(test_string);
  });

  // Read performance
  socketwire::BitStream bs_read;
  for (int i = 0; i < iterations; ++i) {
    bs_read.write(test_string);
  }

  std::string result;
  measureTime("Read 100K strings", iterations, [&bs_read, &result]() {
    bs_read.resetRead();
    for (int i = 0; i < 10; ++i) {
      bs_read.read(result);
    }
  });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamMixedOperations) {
  const int iterations = 50000 * multiplier;

  std::cout << "BitStream Mixed Operations Performance:\n";

  // Complex write scenario
  double write_time = measureTime("Write 50K mixed data packets", iterations, []() {
    socketwire::BitStream bs;

    // Simulate a game packet
    bs.writeBit(true);                                              // connected flag
    bs.write(42);                                                   // player ID
    bs.writeQuantizedFloat(10.5f, 0.0f, 100.0f, 16); // position X
    bs.writeQuantizedFloat(20.3f, 0.0f, 100.0f, 16); // position Y
    bs.writeQuantizedFloat(5.1f, 0.0f, 100.0f, 16);  // position Z
    bs.write(std::string("Player"));                             // name
    bs.writeBits(0xFF, 8);                               // flags
  });

  // Complex read scenario
  socketwire::BitStream bs_read;
  for (int i = 0; i < 1000; ++i) {
    bs_read.writeBit(true);
    bs_read.write(i);
    bs_read.writeQuantizedFloat(10.5f, 0.0f, 100.0f, 16);
    bs_read.writeQuantizedFloat(20.3f, 0.0f, 100.0f, 16);
    bs_read.writeQuantizedFloat(5.1f, 0.0f, 100.0f, 16);
    bs_read.write(std::string("Player"));
    bs_read.writeBits(0xFF, 8);
  }

  double read_time = measureTime("Read 50K mixed data packets", iterations, [&bs_read]() {
    bs_read.resetRead();

    bool flag = bs_read.readBit();
    int id;
    bs_read.read(id);
    float x = bs_read.readQuantizedFloat(0.0f, 100.0f, 16);
    float y = bs_read.readQuantizedFloat(0.0f, 100.0f, 16);
    float z = bs_read.readQuantizedFloat(0.0f, 100.0f, 16);
    std::string name;
    bs_read.read(name);
    uint32_t flags = bs_read.readBits(8);

    (void)flag; (void)id; (void)x; (void)y; (void)z; (void)name; (void)flags;
  });

  std::cout << "  Write/Read ratio: " << (write_time / read_time) << "x\n";

  SUCCEED();
}

TEST_F(PerformanceTest, NetSocketCreation) {
  const int iterations = 10000 * multiplier;

  std::cout << "NetSocket Creation Performance:\n";

  measureTime("Create and bind 10K sockets", iterations, [this]() {
    SocketConfig config;
    auto sock = factory->createUDPSocket(config);
    SocketAddress addr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
    sock->bind(addr, 0);
  });

  SUCCEED();
}

TEST_F(PerformanceTest, NetSocketSendReceive) {
  const int iterations = 10000 * multiplier;

  std::cout << "NetSocket Send/Receive Performance:\n";

  // Create sender and receiver
  SocketConfig config;
  auto sender = factory->createUDPSocket(config);
  auto receiver = factory->createUDPSocket(config);

  ASSERT_NE(sender, nullptr);
  ASSERT_NE(receiver, nullptr);

  SocketAddress addr = SocketAddress::fromIPv4(0x7F000001); // 127.0.0.1
  ASSERT_EQ(sender->bind(addr, 0), SocketError::None);
  ASSERT_EQ(receiver->bind(addr, 0), SocketError::None);

  std::uint16_t receiverPort = receiver->localPort();
  ASSERT_GT(receiverPort, 0);

  const char* message = "Performance test message";
  size_t message_len = strlen(message);

  measureTime("Send 10K UDP packets", iterations, [&sender, message, message_len, &addr, receiverPort]() {
    sender->sendTo(message, message_len, addr, receiverPort);
  });

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamLargeDataTransfer) {
  const int iterations = 1000 * multiplier;
  const int data_size = 1024 * 10; // 10 KB

  std::cout << "BitStream Large Data Transfer Performance:\n";

  std::vector<char> large_data(data_size, 'X');

  double write_time = measureTime("Write 1K x 10KB blocks", iterations, [&large_data]() {
    socketwire::BitStream bs;
    bs.writeBytes(large_data.data(), large_data.size());
  });

  socketwire::BitStream bs_read;
  for (int i = 0; i < 100; ++i) {
    bs_read.writeBytes(large_data.data(), data_size);
  }

  std::vector<char> read_buffer(data_size);
  double read_time = measureTime("Read 1K x 10KB blocks", iterations, [&bs_read, &read_buffer]() {
    bs_read.resetRead();
    bs_read.readBytes(read_buffer.data(), read_buffer.size());
  });

  double mb_written = (iterations * data_size) / (1024.0 * 1024.0);
  double write_throughput = mb_written / (write_time / 1000.0);
  double read_throughput = mb_written / (read_time / 1000.0);

  std::cout << "  Total data: " << mb_written << " MB\n"
            << "  Write throughput: " << write_throughput << " MB/s\n"
            << "  Read throughput: " << read_throughput << " MB/s\n";

  SUCCEED();
}

TEST_F(PerformanceTest, BitStreamAlignment) {
  const int iterations = 500000 * multiplier;

  std::cout << "BitStream Alignment Performance:\n";

  measureTime("Write + Align 500K times", iterations, []() {
    socketwire::BitStream bs;
    bs.writeBits(0b111, 3);
    bs.alignWrite();
    bs.writeBytes("A", 1);
  });

  socketwire::BitStream bs_read;
  for (int i = 0; i < 1000; ++i) {
    bs_read.writeBits(0b111, 3);
    bs_read.alignWrite();
    bs_read.writeBytes("A", 1);
  }

  measureTime("Read + Align 500K times", iterations, [&bs_read]() {
    bs_read.resetRead();
    bs_read.readBits(3);
    bs_read.alignRead();
    char c;
    bs_read.readBytes(&c, 1);
  });

  SUCCEED();
}
