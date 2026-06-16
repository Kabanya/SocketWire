#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <stdexcept>

#include "bit_stream.hpp"

namespace socketwire {
namespace detail {

inline std::uint32_t QuantizedFloatRange(std::uint8_t bits) {
  if (bits == 0 || bits > 32) {
    throw std::out_of_range("bits must be in range [1, 32]");
  }

  return bits == 32 ? std::numeric_limits<std::uint32_t>::max()
                    : ((std::uint32_t{1} << bits) - 1);
}

}  // namespace detail

/// Writes a float compressed into a fixed number of bits.
inline void WriteQuantizedFloat(BitStream& stream, float value, float min,
                                float max, std::uint8_t bits) {
  value = std::clamp(value, min, max);
  const std::uint32_t range = detail::QuantizedFloatRange(bits);
  const auto quantized = static_cast<std::uint32_t>(
    static_cast<float>(range) * ((value - min) / (max - min)));
  stream.WriteBits(quantized, bits);
}

/// Reads a float compressed with WriteQuantizedFloat.
inline float ReadQuantizedFloat(BitStream& stream, float min, float max,
                                std::uint8_t bits) {
  const std::uint32_t range     = detail::QuantizedFloatRange(bits);
  const std::uint32_t quantized = stream.ReadBits(bits);
  return min + (static_cast<float>(quantized) / static_cast<float>(range)) *
                 (max - min);
}

}  // namespace socketwire
