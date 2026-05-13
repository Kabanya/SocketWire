#include "bit_stream.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace socketwire {

const char* ToString(BitStreamError error) noexcept {
  switch (error) {
    case BitStreamError::kEndOfStream:
      return "EndOfStream";
    case BitStreamError::kInvalidData:
      return "InvalidData";
    default:
      return "Unknown";
  }
}

std::expected<bool, BitStreamError> BitStream::TryReadBit() noexcept {
  try {
    return ReadBit();
  } catch (...) {
    return std::unexpected(BitStreamError::kEndOfStream);
  }
}

std::expected<std::uint32_t, BitStreamError> BitStream::TryReadBits(
    std::uint8_t bit_count) noexcept {
  try {
    return ReadBits(bit_count);
  } catch (...) {
    return std::unexpected(BitStreamError::kEndOfStream);
  }
}

std::expected<std::string, BitStreamError> BitStream::TryReadString() noexcept {
  try {
    std::string value;
    Read(value);
    return value;
  } catch (const std::out_of_range&) {
    return std::unexpected(BitStreamError::kInvalidData);
  } catch (...) {
    return std::unexpected(BitStreamError::kEndOfStream);
  }
}

std::expected<std::vector<bool>, BitStreamError>
BitStream::TryReadBoolArray() noexcept {
  try {
    return ReadBoolArray();
  } catch (const std::out_of_range&) {
    return std::unexpected(BitStreamError::kInvalidData);
  } catch (...) {
    return std::unexpected(BitStreamError::kEndOfStream);
  }
}

BitStream::BitStream() = default;

BitStream::BitStream(const std::uint8_t* data, size_t size)
    : m_WritePos(size * 8) {
  buffer.assign(data, data + size);
}

void BitStream::WriteBit(bool value) {
  const size_t byte_index = m_WritePos / 8;
  const size_t bit_index = m_WritePos % 8;

  if (byte_index >= buffer.size()) {
    buffer.push_back(0);
  }

  if (value) {
    buffer.at(byte_index) |=
        static_cast<std::uint8_t>(std::uint32_t{1} << bit_index);
  }

  m_WritePos++;
}

bool BitStream::ReadBit() {
  const size_t byte_index = m_ReadPos / 8;
  const size_t bit_index = m_ReadPos % 8;

  if (byte_index >= buffer.size()) {
    throw std::out_of_range("Attempting to read beyond buffer");
  }

  const bool value = (buffer.at(byte_index) &
                static_cast<std::uint8_t>(std::uint32_t{1} << bit_index)) != 0;
  m_ReadPos++;

  return value;
}

void BitStream::WriteBits(uint32_t value, uint8_t bit_count) {
  if (bit_count > 32) throw std::out_of_range("bit_count must be <= 32");

  for (uint8_t i = 0; i < bit_count; ++i) {
    WriteBit((value & (std::uint32_t{1} << i)) != 0);
  }
}

uint32_t BitStream::ReadBits(uint8_t bit_count) {
  if (bit_count > 32) throw std::out_of_range("bit_count must be <= 32");

  uint32_t value = 0;
  for (uint8_t i = 0; i < bit_count; ++i) {
    if (ReadBit()) value |= (std::uint32_t{1} << i);
  }
  return value;
}

void BitStream::WriteBytes(const void* data, size_t size) {
  AlignWrite();
  const size_t byte_index = m_WritePos / 8;

  if (byte_index + size > buffer.size()) {
    buffer.resize(byte_index + size);
  }
  std::memcpy(buffer.data() + byte_index, data, size);
  m_WritePos += size * 8;
}

void BitStream::ReadBytes(void* data, size_t size) {
  AlignRead();
  const size_t byte_index = m_ReadPos / 8;

  if (byte_index + size > buffer.size()) {
    throw std::out_of_range("Attempting to read beyond buffer");
  }

  std::memcpy(data, buffer.data() + byte_index, size);
  m_ReadPos += size * 8;
}

void BitStream::AlignWrite() {
  if (m_WritePos % 8 != 0) {
    m_WritePos = ((m_WritePos + 7) / 8) * 8;  // Round up to next byte
  }
}

void BitStream::AlignRead() {
  if (m_ReadPos % 8 != 0) {
    m_ReadPos = ((m_ReadPos + 7) / 8) * 8;  // Round up to next byte
  }
}

void BitStream::Write(const std::string& value) {
  auto length = static_cast<uint32_t>(value.length());
  Write<uint32_t>(length);
  if (length > 0) {
    WriteBytes(value.data(), length);
  }
}

void BitStream::Read(std::string& value) {
  uint32_t length = 0;
  Read<uint32_t>(length);

  if (length > kMaxBitStreamStringLength) {
    throw std::out_of_range("String length " + std::to_string(length) +
                            " exceeds maximum allowed (" +
                            std::to_string(kMaxBitStreamStringLength) + ")");
  }

  const size_t remaining = GetRemainingBytes();
  if (length > remaining) {
    throw std::out_of_range("String length " + std::to_string(length) +
                            " exceeds remaining buffer (" +
                            std::to_string(remaining) + " bytes)");
  }

  if (length > 0) {
    value.resize(length);
    ReadBytes(&value.at(0), length);
  } else {
    value.clear();
  }
}

void BitStream::WriteBoolArray(const std::vector<bool>& bools) {
  Write<uint32_t>(static_cast<uint32_t>(bools.size()));
  for (const bool b : bools) {
    WriteBit(b);
  }
}

std::vector<bool> BitStream::ReadBoolArray() {
  uint32_t size = 0;
  Read<uint32_t>(size);

  if (size > kMaxBitStreamBoolArraySize) {
    throw std::out_of_range("Bool array size " + std::to_string(size) +
                            " exceeds maximum allowed (" +
                            std::to_string(kMaxBitStreamBoolArraySize) + ")");
  }

  // Each bool needs 1 bit; check remaining bits in the buffer
  const size_t remaining_bits = (buffer.size() * 8) - m_ReadPos;
  if (size > remaining_bits) {
    throw std::out_of_range("Bool array size " + std::to_string(size) +
                            " exceeds remaining bits (" +
                            std::to_string(remaining_bits) + ")");
  }

  std::vector<bool> bools(size);
  for (uint32_t i = 0; i < size; ++i) {
    bools.at(i) = ReadBit();
  }

  return bools;
}

const std::uint8_t* BitStream::GetData() const { return buffer.data(); }

size_t BitStream::GetSizeBytes() const {
  return (m_WritePos + 7) / 8;  // Round up to nearest byte
}

size_t BitStream::GetSizeBits() const { return m_WritePos; }

size_t BitStream::GetRemainingBytes() const {
  const size_t read_byte = (m_ReadPos + 7) / 8;  // current read position, rounded up to byte
  return (read_byte < buffer.size()) ? (buffer.size() - read_byte) : 0;
}

void BitStream::ResetWrite() { m_WritePos = 0; }

void BitStream::ResetRead() { m_ReadPos = 0; }

void BitStream::Clear() {
  buffer.clear();
  m_WritePos = 0;
  m_ReadPos = 0;
}

void BitStream::WriteQuantizedFloat(float value, float min, float max,
                                    uint8_t bits) {
  if (bits == 0 || bits > 32) {
    throw std::out_of_range("bits must be in range [1, 32]");
  }

  value = std::clamp(value, min, max);

  const uint32_t range = (bits == 32) ? std::numeric_limits<std::uint32_t>::max() : ((std::uint32_t{1} << bits) - 1);
  const auto quantized = static_cast<uint32_t>(static_cast<float>(range) * ((value - min) / (max - min)));

  WriteBits(quantized, bits);
}

float BitStream::ReadQuantizedFloat(float min, float max, uint8_t bits) {
  if (bits == 0 || bits > 32) {
    throw std::out_of_range("bits must be in range [1, 32]");
  }

  const uint32_t range = (bits == 32) ? std::numeric_limits<std::uint32_t>::max() : ((std::uint32_t{1} << bits) - 1);
  const uint32_t quantized = ReadBits(bits);
  return min + (static_cast<float>(quantized) / static_cast<float>(range)) * (max - min);
}

}  // namespace socketwire
