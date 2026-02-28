#pragma once

#include <vector>
#include <cstdint>
#include <type_traits>
#include <string>

namespace socketwire
{

// Configurable safety limits for deserialization
constexpr std::uint32_t kMaxBitStreamStringLength = 65536;
constexpr std::uint32_t kMaxBitStreamBoolArraySize = 65536;

class BitStream
{
private:
  std::vector<std::uint8_t> buffer;
  size_t m_WritePose = 0;
  size_t m_ReadPose = 0;

public:
  BitStream();
  BitStream(const std::uint8_t* data, size_t size);

  // -----------------Bit operations-----------------

  // Writes a single bit to the stream
  void writeBit(bool value);
  // Reads a single bit from the stream
  bool readBit();

  // Writes the specified number of bits to the stream
  void writeBits(uint32_t value, uint8_t bit_count);
  // Reads the specified number of bits from the stream
  uint32_t readBits(uint8_t bit_count);

  // -----------------Byte operations-----------------

  // Writes an array of bytes to the stream
  void writeBytes(const void* data, size_t size);
  // Reads an array of bytes from the stream
  void readBytes(void* data, size_t size);

  // Alignment operations.
  // Aligns the write pointer to the byte boundary
  void alignWrite();
  // Aligns the read pointer to the byte boundary
  void alignRead();

  // -----------------Template operations-----------------

  // Writes a value to the stream (type must be trivially copyable)
  template<typename T>
  void write(const T& value)
  {
    static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
    writeBytes(&value, sizeof(T));
  }

  // Reads a value from the stream (type must be trivially copyable)
  template<typename T>
  void read(T& value)
  {
    static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
    readBytes(&value, sizeof(T));
  }

  // Template specialization for writing a string.
  // Writes a string to the stream
  void write(const std::string& value);
  // Template specialization for reading a string.
  // Reads a string from the stream
  void read(std::string& value);

  // Boolean array operations.
  // Writes an array of boolean values to the stream
  void writeBoolArray(const std::vector<bool>& bools);
  // Reads an array of boolean values from the stream
  std::vector<bool> readBoolArray();

  // -----------------Utility methods-----------------

  // Returns a pointer to the data in the stream
  const std::uint8_t* getData() const;
  // Returns the size of the data in the stream in bytes
  size_t getSizeBytes() const;
  // Returns the size of the data in the stream in bits
  size_t getSizeBits() const;
  // Returns the number of bytes remaining to be read
  size_t getRemainingBytes() const;
  // Resets the write pointer to the beginning of the stream
  void resetWrite();
  // Resets the read pointer to the beginning of the stream
  void resetRead();
  // Clears the stream
  void clear();

  // -----------------Quantized float operations-----------------

  // Writes a quantized float to the stream
  void writeQuantizedFloat(float value, float min, float max, uint8_t bits);
  // Reads a quantized float from the stream
  float readQuantizedFloat(float min, float max, uint8_t bits);
};

} // namespace socketwire
