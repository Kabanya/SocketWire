#pragma once
/// Compact bit-level serialization for packet payloads.
///
/// Bit operations pack values least-significant bit first, while byte and typed
/// reads align to byte boundaries and expose non-throwing variants for
/// defensive packet parsing.

#include <climits>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <type_traits>
#include <vector>

namespace socketwire {

/// Safety limits for deserialization.
constexpr std::uint32_t kMaxBitStreamStringLength  = 65536;
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

  template <typename T>
  static constexpr bool kSupportedTypedValue =
    std::is_integral_v<T> || std::is_enum_v<T> || std::is_same_v<T, float> ||
    std::is_same_v<T, double>;

  template <typename U>
  void WriteUnsignedBigEndian(U value) {
    static_assert(CHAR_BIT == 8,
                  "BitStream portable serialization requires 8-bit bytes");
    static_assert(std::is_unsigned_v<U> && !std::is_same_v<U, bool>,
                  "U must be a non-bool unsigned integer");
    static_assert(std::numeric_limits<U>::digits == sizeof(U) * CHAR_BIT,
                  "BitStream integer serialization requires no padding bits");

    std::uint8_t bytes[sizeof(U)] = {};
    for (std::size_t i = 0; i < sizeof(U); ++i) {
      const std::size_t shift = (sizeof(U) - 1 - i) * CHAR_BIT;
      bytes[i] = static_cast<std::uint8_t>((value >> shift) & U{0xFF});
    }
    WriteBytes(bytes, sizeof(bytes));
  }

  template <typename U>
  U ReadUnsignedBigEndian() {
    static_assert(CHAR_BIT == 8,
                  "BitStream portable serialization requires 8-bit bytes");
    static_assert(std::is_unsigned_v<U> && !std::is_same_v<U, bool>,
                  "U must be a non-bool unsigned integer");
    static_assert(std::numeric_limits<U>::digits == sizeof(U) * CHAR_BIT,
                  "BitStream integer serialization requires no padding bits");

    std::uint8_t bytes[sizeof(U)] = {};
    ReadBytes(bytes, sizeof(bytes));

    U value = 0;
    for (const std::uint8_t byte : bytes) {
      value = static_cast<U>((value << CHAR_BIT) | static_cast<U>(byte));
    }
    return value;
  }

  template <typename T, typename U>
  static T DecodeSignedTwosComplement(U bits) {
    static_assert(std::is_signed_v<T>);
    static_assert(std::is_unsigned_v<U>);
    static_assert(sizeof(T) == sizeof(U));
    static_assert(std::numeric_limits<T>::digits == sizeof(T) * CHAR_BIT - 1,
                  "BitStream signed integer serialization requires no padding "
                  "bits");

    constexpr U sign_bit = U{1} << (sizeof(U) * CHAR_BIT - 1);
    if ((bits & sign_bit) == 0) return static_cast<T>(bits);

    const U magnitude = U{0} - bits;
    if (magnitude == sign_bit) return std::numeric_limits<T>::min();
    return static_cast<T>(-static_cast<T>(magnitude));
  }

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

  /// Writes a portable scalar value to the stream.
  template <typename T>
  void Write(const T& value) {
    using Value = std::remove_cv_t<T>;
    static_assert(kSupportedTypedValue<Value>,
                  "BitStream::Write<T> supports only bool, integral, enum, "
                  "float, and double; serialize structs field-by-field or use "
                  "WriteBytes for raw data");

    if constexpr (std::is_same_v<Value, bool>) {
      const std::uint8_t byte = value ? 1 : 0;
      WriteBytes(&byte, sizeof(byte));
    } else if constexpr (std::is_enum_v<Value>) {
      using Underlying = std::underlying_type_t<Value>;
      Write<Underlying>(static_cast<Underlying>(value));
    } else if constexpr (std::is_integral_v<Value>) {
      using Unsigned = std::make_unsigned_t<Value>;
      WriteUnsignedBigEndian(static_cast<Unsigned>(value));
    } else if constexpr (std::is_same_v<Value, float>) {
      static_assert(std::numeric_limits<float>::is_iec559 &&
                      sizeof(float) == sizeof(std::uint32_t),
                    "BitStream float serialization requires IEEE-754 float");
      WriteUnsignedBigEndian(std::__bit_cast<std::uint32_t>(value));
    } else if constexpr (std::is_same_v<Value, double>) {
      static_assert(std::numeric_limits<double>::is_iec559 &&
                      sizeof(double) == sizeof(std::uint64_t),
                    "BitStream double serialization requires IEEE-754 double");
      WriteUnsignedBigEndian(std::__bit_cast<std::uint64_t>(value));
    }
  }

  /// Reads a portable scalar value from the stream.
  template <typename T>
  void Read(T& value) {
    using Value = std::remove_cv_t<T>;
    static_assert(kSupportedTypedValue<Value>,
                  "BitStream::Read<T> supports only bool, integral, enum, "
                  "float, and double; serialize structs field-by-field or use "
                  "ReadBytes for raw data");

    if constexpr (std::is_same_v<Value, bool>) {
      std::uint8_t byte = 0;
      ReadBytes(&byte, sizeof(byte));
      value = byte != 0;
    } else if constexpr (std::is_enum_v<Value>) {
      using Underlying = std::underlying_type_t<Value>;
      Underlying underlying = {};
      Read(underlying);
      value = static_cast<Value>(underlying);
    } else if constexpr (std::is_integral_v<Value>) {
      using Unsigned = std::make_unsigned_t<Value>;
      const Unsigned bits = ReadUnsignedBigEndian<Unsigned>();
      if constexpr (std::is_signed_v<Value>) {
        value = DecodeSignedTwosComplement<Value>(bits);
      } else {
        value = static_cast<Value>(bits);
      }
    } else if constexpr (std::is_same_v<Value, float>) {
      static_assert(std::numeric_limits<float>::is_iec559 &&
                      sizeof(float) == sizeof(std::uint32_t),
                    "BitStream float serialization requires IEEE-754 float");
      value = std::__bit_cast<float>(ReadUnsignedBigEndian<std::uint32_t>());
    } else if constexpr (std::is_same_v<Value, double>) {
      static_assert(std::numeric_limits<double>::is_iec559 &&
                      sizeof(double) == sizeof(std::uint64_t),
                    "BitStream double serialization requires IEEE-754 double");
      value = std::__bit_cast<double>(ReadUnsignedBigEndian<std::uint64_t>());
    }
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

  /// Non-throwing read for any portable scalar type.
  template <typename T>
  [[nodiscard]] std::expected<T, BitStreamError> TryRead() noexcept {
    static_assert(kSupportedTypedValue<std::remove_cv_t<T>>,
                  "BitStream::TryRead<T> supports only bool, integral, enum, "
                  "float, and double");
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
