#include "bit_stream.hpp"
#include <cstring>
#include <algorithm>
#include <stdexcept>

namespace socketwire
{

BitStream::BitStream() = default;

BitStream::BitStream(const std::uint8_t* data, size_t size)
{
  buffer.assign(data, data + size);
}

void BitStream::writeBit(bool value)
{
  size_t byteIndex = m_WritePose / 8;
  size_t bitIndex = m_WritePose % 8;

  if (byteIndex >= buffer.size())
  {
    buffer.push_back(0);
  }

  if (value)
  {
    buffer[byteIndex] |= (1 << bitIndex);
  }

  m_WritePose++;
}

bool BitStream::readBit()
{
  size_t byteIndex = m_ReadPose / 8;
  size_t bitIndex = m_ReadPose % 8;

  if (byteIndex >= buffer.size())
  {
    throw std::out_of_range("Attempting to read beyond buffer");
  }

  bool value = (buffer[byteIndex] & (1 << bitIndex)) != 0;
  m_ReadPose++;

  return value;
}

void BitStream::writeBits(uint32_t value, uint8_t bit_count)
{
  for (uint8_t i = 0; i < bit_count; ++i)
  {
    writeBit((value & (1 << i)) != 0);
  }
}

uint32_t BitStream::readBits(uint8_t bit_count)
{
  uint32_t value = 0;
  for (uint8_t i = 0; i < bit_count; ++i)
  {
    if (readBit())
      value |= (1 << i);
  }
  return value;
}

void BitStream::writeBytes(const void* data, size_t size)
{
  alignWrite();
  size_t byteIndex = m_WritePose / 8;

  if (byteIndex + size > buffer.size())
  {
    buffer.resize(byteIndex + size);
  }
  std::memcpy(buffer.data() + byteIndex, data, size);
  m_WritePose += size * 8;
}

void BitStream::readBytes(void* data, size_t size)
{
  alignRead();
  size_t byteIndex = m_ReadPose / 8;

  if (byteIndex + size > buffer.size())
  {
    throw std::out_of_range("Attempting to read beyond buffer");
  }

  std::memcpy(data, buffer.data() + byteIndex, size);
  m_ReadPose += size * 8;
}

void BitStream::alignWrite()
{
  if (m_WritePose % 8 != 0)
  {
    m_WritePose = (m_WritePose + 7) & ~7; // Round up to next byte
  }
}

void BitStream::alignRead()
{
  if (m_ReadPose % 8 != 0)
  {
    m_ReadPose = (m_ReadPose + 7) & ~7; // Round up to next byte
  }
}

void BitStream::write(const std::string& value)
{
  uint32_t length = static_cast<uint32_t>(value.length());
  write<uint32_t>(length);
  if (length > 0)
  {
    writeBytes(value.data(), length);
  }
}

void BitStream::read(std::string& value)
{
  uint32_t length;
  read<uint32_t>(length);
  if (length > 0)
  {
    value.resize(length);
    readBytes(&value[0], length);
  }
  else
  {
    value.clear();
  }
}

void BitStream::writeBoolArray(const std::vector<bool>& bools)
{
  write<uint32_t>(static_cast<uint32_t>(bools.size()));
  for (bool b : bools)
  {
    writeBit(b);
  }
}

std::vector<bool> BitStream::readBoolArray()
{
  uint32_t size;
  read<uint32_t>(size);
  std::vector<bool> bools(size);
  for (uint32_t i = 0; i < size; ++i)
  {
    bools[i] = readBit();
  }

  return bools;
}

const std::uint8_t* BitStream::getData() const
{
  return buffer.data();
}

size_t BitStream::getSizeBytes() const
{
  return (m_WritePose + 7) / 8; // Round up to nearest byte
}

size_t BitStream::getSizeBits() const
{
  return m_WritePose;
}

void BitStream::resetWrite()
{
  m_WritePose = 0;
}

void BitStream::resetRead()
{
  m_ReadPose = 0;
}

void BitStream::clear()
{
  buffer.clear();
  m_WritePose = 0;
  m_ReadPose = 0;
}


void BitStream::writeQuantizedFloat(float value, float min, float max, uint8_t bits)
{
  value = std::clamp(value, min, max);

  uint32_t range = (1 << bits) - 1;
  uint32_t quantized = static_cast<uint32_t>(range * ((value - min) / (max - min)));

  writeBits(quantized, bits);
}

float BitStream::readQuantizedFloat(float min, float max, uint8_t bits)
{
  uint32_t range = (1 << bits) - 1;
  uint32_t quantized = readBits(bits);
  return min + (float(quantized) / float(range)) * (max - min);
}

} // namespace socketwire
