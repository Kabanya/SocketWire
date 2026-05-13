#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <type_traits>
#include <vector>

namespace socketwire {

// Configurable safety limits for deserialization
constexpr std::uint32_t kMaxBitStreamStringLength = 65536;
constexpr std::uint32_t kMaxBitStreamBoolArraySize = 65536;

/** Error codes for non-throwing BitStream read operations. */
enum class BitStreamError : std::uint8_t {
  kEndOfStream,  ///< Not enough data remaining in the stream
  kInvalidData,  ///< Data violates format/bounds constraints
};

// Convert BitStreamError to human-readable string
[[nodiscard]] const char* ToString(BitStreamError error) noexcept;

class BitStream {
 private:
  std::vector<std::uint8_t> buffer;
  size_t m_WritePos = 0;
  size_t m_ReadPos = 0;

 public:
  BitStream();
  BitStream(const std::uint8_t* data, size_t size);

  // -----------------Bit operations-----------------

  // Writes a single bit to the stream
  void WriteBit(bool value);
  // Reads a single bit from the stream
  bool ReadBit();

  // Writes the specified number of bits to the stream
  void WriteBits(uint32_t value, uint8_t bit_count);
  // Reads the specified number of bits from the stream
  uint32_t ReadBits(uint8_t bit_count);

  // -----------------Byte operations-----------------

  // Writes an array of bytes to the stream
  void WriteBytes(const void* data, size_t size);
  // Reads an array of bytes from the stream
  void ReadBytes(void* data, size_t size);

  // Alignment operations.
  // Aligns the write pointer to the byte boundary
  void AlignWrite();
  // Aligns the read pointer to the byte boundary
  void AlignRead();

  // -----------------Template operations-----------------

  // Writes a value to the stream (type must be trivially copyable)
  template <typename T>
  void Write(const T& value) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Type must be trivially copyable");
    WriteBytes(&value, sizeof(T));
  }

  // Reads a value from the stream (type must be trivially copyable)
  template <typename T>
  void Read(T& value) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Type must be trivially copyable");
    ReadBytes(&value, sizeof(T));
  }

  // Template specialization for writing a string.
  // Writes a string to the stream
  void Write(const std::string& value);
  // Template specialization for reading a string.
  // Reads a string from the stream
  void Read(std::string& value);

  // Boolean array operations.
  // Writes an array of boolean values to the stream
  void WriteBoolArray(const std::vector<bool>& bools);
  // Reads an array of boolean values from the stream
  std::vector<bool> ReadBoolArray();

  // -----------------Non-throwing (C++23 std::expected) read
  // variants-----------

  // Returns the read bit, or BitStreamError::EndOfStream if exhausted.
  [[nodiscard]] std::expected<bool, BitStreamError> TryReadBit() noexcept;

  // Returns the read bits, or BitStreamError::EndOfStream if exhausted.
  [[nodiscard]] std::expected<std::uint32_t, BitStreamError> TryReadBits(
      std::uint8_t bit_count) noexcept;

  // Returns the read string, or an error if the stream is exhausted / data
  // invalid.
  [[nodiscard]] std::expected<std::string, BitStreamError>
  TryReadString() noexcept;

  // Returns the read bool array, or an error if the stream is exhausted / data
  // invalid.
  [[nodiscard]] std::expected<std::vector<bool>, BitStreamError>
  TryReadBoolArray() noexcept;

  // Non-throwing read for any trivially-copyable type.
  template <typename T>
  [[nodiscard]] std::expected<T, BitStreamError> TryRead() noexcept {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Type must be trivially copyable");
    try {
      T value{};
      Read(value);
      return value;
    } catch (...) {
      return std::unexpected(BitStreamError::kEndOfStream);
    }
  }

  // -----------------Utility methods-----------------

  // Returns a pointer to the data in the stream
  [[nodiscard]] const std::uint8_t* GetData() const;
  // Returns the size of the data in the stream in bytes
  [[nodiscard]] size_t GetSizeBytes() const;
  // Returns the size of the data in the stream in bits
  [[nodiscard]] size_t GetSizeBits() const;
  // Returns the number of bytes remaining to be read
  [[nodiscard]] size_t GetRemainingBytes() const;
  // Resets the write pointer to the beginning of the stream
  void ResetWrite();
  // Resets the read pointer to the beginning of the stream
  void ResetRead();
  // Clears the stream
  void Clear();

  // -----------------Quantized float operations-----------------

  // Writes a quantized float to the stream
  void WriteQuantizedFloat(float value, float min, float max, uint8_t bits);
  // Reads a quantized float from the stream
  float ReadQuantizedFloat(float min, float max, uint8_t bits);
};

}  // namespace socketwire
