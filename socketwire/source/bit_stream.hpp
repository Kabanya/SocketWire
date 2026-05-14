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
[[nodiscard]] inline const char* to_string(BitStreamError error) noexcept {
  return ToString(error);
}

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
  void writeBit(bool value) { WriteBit(value); }
  /// Reads a single bit from the stream.
  bool ReadBit();
  bool readBit() { return ReadBit(); }

  /// Writes the specified number of low-order bits to the stream.
  void WriteBits(std::uint32_t value, std::uint8_t bit_count);
  void writeBits(std::uint32_t value, std::uint8_t bit_count) {
    WriteBits(value, bit_count);
  }
  /// Reads the specified number of bits from the stream.
  std::uint32_t ReadBits(std::uint8_t bit_count);
  std::uint32_t readBits(std::uint8_t bit_count) {
    return ReadBits(bit_count);
  }

  /// Writes a byte array to the stream.
  void WriteBytes(const void* data, std::size_t size);
  void writeBytes(const void* data, std::size_t size) { WriteBytes(data, size); }
  /// Reads a byte array from the stream.
  void ReadBytes(void* data, std::size_t size);
  void readBytes(void* data, std::size_t size) { ReadBytes(data, size); }

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
  template <typename T>
  void write(const T& value) {
    Write<T>(value);
  }

  /// Reads a trivially copyable value from the stream.
  template <typename T>
  void Read(T& value) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "Type must be trivially copyable");
    ReadBytes(&value, sizeof(T));
  }
  template <typename T>
  void read(T& value) {
    Read<T>(value);
  }

  /// Writes a string to the stream.
  void Write(const std::string& value);
  void write(const std::string& value) { Write(value); }
  /// Reads a string from the stream.
  void Read(std::string& value);
  void read(std::string& value) { Read(value); }

  /// Writes an array of boolean values to the stream.
  void WriteBoolArray(const std::vector<bool>& bools);
  void writeBoolArray(const std::vector<bool>& bools) {
    WriteBoolArray(bools);
  }
  /// Reads an array of boolean values from the stream.
  std::vector<bool> ReadBoolArray();
  std::vector<bool> readBoolArray() { return ReadBoolArray(); }

  /// Returns the read bit, or kEndOfStream if exhausted.
  [[nodiscard]] std::expected<bool, BitStreamError> TryReadBit() noexcept;
  [[nodiscard]] std::expected<bool, BitStreamError> try_readBit() noexcept {
    return TryReadBit();
  }

  /// Returns the read bits, or kEndOfStream if exhausted.
  [[nodiscard]] std::expected<std::uint32_t, BitStreamError> TryReadBits(
      std::uint8_t bit_count) noexcept;
  [[nodiscard]] std::expected<std::uint32_t, BitStreamError> try_readBits(
      std::uint8_t bit_count) noexcept {
    return TryReadBits(bit_count);
  }

  /// Returns the read string, or an error if data is exhausted or invalid.
  [[nodiscard]] std::expected<std::string, BitStreamError>
  TryReadString() noexcept;
  [[nodiscard]] std::expected<std::string, BitStreamError>
  try_readString() noexcept {
    return TryReadString();
  }

  /// Returns the read bool array, or an error if data is exhausted or invalid.
  [[nodiscard]] std::expected<std::vector<bool>, BitStreamError>
  TryReadBoolArray() noexcept;
  [[nodiscard]] std::expected<std::vector<bool>, BitStreamError>
  try_readBoolArray() noexcept {
    return TryReadBoolArray();
  }

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
  template <typename T>
  [[nodiscard]] std::expected<T, BitStreamError> try_read() noexcept {
    return TryRead<T>();
  }

  /// Returns a pointer to the stream data.
  [[nodiscard]] const std::uint8_t* GetData() const;
  [[nodiscard]] const std::uint8_t* getData() const { return GetData(); }
  /// Returns the stream size in bytes.
  [[nodiscard]] std::size_t GetSizeBytes() const;
  [[nodiscard]] std::size_t getSizeBytes() const { return GetSizeBytes(); }
  /// Returns the stream size in bits.
  [[nodiscard]] std::size_t GetSizeBits() const;
  [[nodiscard]] std::size_t getSizeBits() const { return GetSizeBits(); }
  /// Returns the number of bytes remaining to read.
  [[nodiscard]] std::size_t GetRemainingBytes() const;
  [[nodiscard]] std::size_t getRemainingBytes() const {
    return GetRemainingBytes();
  }
  /// Resets the write pointer to the beginning of the stream.
  void ResetWrite();
  void resetWrite() { ResetWrite(); }
  /// Resets the read pointer to the beginning of the stream.
  void ResetRead();
  void resetRead() { ResetRead(); }
  /// Clears the stream.
  void Clear();
  void clear() { Clear(); }

  /// Writes a quantized float to the stream.
  void WriteQuantizedFloat(float value, float min, float max, std::uint8_t bits);
  void writeQuantizedFloat(float value, float min, float max,
                           std::uint8_t bits) {
    WriteQuantizedFloat(value, min, max, bits);
  }
  /// Reads a quantized float from the stream.
  float ReadQuantizedFloat(float min, float max, std::uint8_t bits);
  float readQuantizedFloat(float min, float max, std::uint8_t bits) {
    return ReadQuantizedFloat(min, max, bits);
  }
};

}  // namespace socketwire
