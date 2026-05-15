#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <type_traits>
#include <vector>

namespace socketwire {

/// Safety limits for deserialization.
constexpr std::uint32_t kMaxBitStreamStringLength = 65536;
constexpr std::uint32_t kMaxBitStreamBoolArraySize = 65536;

/// Error codes for non-throwing BitStream read operations.
enum class BitStreamError : std::uint8_t {
  kEndOfStream,  ///< Not enough data remains in the stream.
  kInvalidData,  ///< Data violates format or bounds constraints.
};

/// Converts BitStreamError to a human-readable string.
[[nodiscard]] const char* ToString(BitStreamError error) noexcept;

class BitStream {
 private:
  std::vector<std::uint8_t> buffer_;
  std::size_t write_pos_ = 0;
  std::size_t read_pos_ = 0;

 public:
  BitStream();
  BitStream(const std::uint8_t* data, std::size_t size);

  /// Writes a single bit to the stream.
  void WriteBit(bool value);
  /// Reads a single bit from the stream.
  bool ReadBit();

  /// Writes the specified number of low-order bits to the stream.
  void WriteBits(std::uint32_t value, std::uint8_t bit_count);
  /// Reads the specified number of bits from the stream.
  std::uint32_t ReadBits(std::uint8_t bit_count);

  /// Writes a byte array to the stream.
  void WriteBytes(const void* data, std::size_t size);
  /// Reads a byte array from the stream.
  void ReadBytes(void* data, std::size_t size);

  /// Aligns the write pointer to a byte boundary.
  void AlignWrite();
  /// Aligns the read pointer to a byte boundary.
  void AlignRead();

  /// Writes a trivially copyable value to the stream.
  template <typename T>
  void Write(const T& value) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Type must be trivially copyable");
    WriteBytes(&value, sizeof(T));
  }

  /// Reads a trivially copyable value from the stream.
  template <typename T>
  void Read(T& value) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Type must be trivially copyable");
    ReadBytes(&value, sizeof(T));
  }

  /// Writes a string to the stream.
  void Write(const std::string& value);
  /// Reads a string from the stream.
  void Read(std::string& value);

  /// Writes an array of boolean values to the stream.
  void WriteBoolArray(const std::vector<bool>& bools);
  /// Reads an array of boolean values from the stream.
  std::vector<bool> ReadBoolArray();

  /// Returns the read bit, or kEndOfStream if exhausted.
  [[nodiscard]] std::expected<bool, BitStreamError> TryReadBit() noexcept;

  /// Returns the read bits, or kEndOfStream if exhausted.
  [[nodiscard]] std::expected<std::uint32_t, BitStreamError> TryReadBits(
      std::uint8_t bit_count) noexcept;

  /// Returns the read string, or an error if data is exhausted or invalid.
  [[nodiscard]] std::expected<std::string, BitStreamError>
  TryReadString() noexcept;

  /// Returns the read bool array, or an error if data is exhausted or invalid.
  [[nodiscard]] std::expected<std::vector<bool>, BitStreamError>
  TryReadBoolArray() noexcept;

  /// Non-throwing read for any trivially copyable type.
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

  /// Returns a pointer to the stream data.
  [[nodiscard]] const std::uint8_t* GetData() const;
  /// Returns the stream size in bytes.
  [[nodiscard]] std::size_t GetSizeBytes() const;
  /// Returns the stream size in bits.
  [[nodiscard]] std::size_t GetSizeBits() const;
  /// Returns the number of bytes remaining to read.
  [[nodiscard]] std::size_t GetRemainingBytes() const;
  /// Resets the write pointer to the beginning of the stream.
  void ResetWrite();
  /// Resets the read pointer to the beginning of the stream.
  void ResetRead();
  /// Clears the stream.
  void Clear();

  /// Writes a quantized float to the stream.
  void WriteQuantizedFloat(float value, float min, float max,
                           std::uint8_t bits);
  /// Reads a quantized float from the stream.
  float ReadQuantizedFloat(float min, float max, std::uint8_t bits);
};

}  // namespace socketwire
