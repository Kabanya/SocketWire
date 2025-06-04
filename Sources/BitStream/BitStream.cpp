#include "BitStream.h"
#include <cstring>
#include <cmath>
#include <algorithm>

BitStream::BitStream() = default;

BitStream::BitStream(const std::uint8_t* data, size_t size)
{
  buffer.assign(data, data + size);
}

void BitStream::WriteBit(bool value)
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

bool BitStream::ReadBit()
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

void BitStream::WriteBits(uint32_t value, uint8_t bitCount)
{
  for (uint8_t i = 0; i < bitCount; ++i)
  {
    WriteBit((value & (1 << i)) != 0);
  }
}

uint32_t BitStream::ReadBits(uint8_t bitCount)
{
  uint32_t value = 0;
  for (uint8_t i = 0; i < bitCount; ++i)
  {
    if (ReadBit())
      value |= (1 << i);
  }
  return value;
}

void BitStream::WriteBytes(const void* data, size_t size)
{
  AlignWrite();   
  size_t byteIndex = m_WritePose / 8;
  
  if (byteIndex + size > buffer.size())
  {
    buffer.resize(byteIndex + size);
  }
  std::memcpy(buffer.data() + byteIndex, data, size);
  m_WritePose += size * 8;
}

void BitStream::ReadBytes(void* data, size_t size)
{
  AlignRead();
  size_t byteIndex = m_ReadPose / 8;

  if (byteIndex + size > buffer.size())
  {
    throw std::out_of_range("Attempting to read beyond buffer");
  }

  std::memcpy(data, buffer.data() + byteIndex, size);    
  m_ReadPose += size * 8;
}

void BitStream::AlignWrite()
{
  if (m_WritePose % 8 != 0)
  {
    m_WritePose = (m_WritePose + 7) & ~7; // Round up to next byte
  }
}

void BitStream::AlignRead()
{
  if (m_ReadPose % 8 != 0)
  {
    m_ReadPose = (m_ReadPose + 7) & ~7; // Round up to next byte
  }
}

void BitStream::Write(const std::string& value)
{
  uint32_t length = static_cast<uint32_t>(value.length());
  Write<uint32_t>(length);
  if (length > 0)
  {
    WriteBytes(value.data(), length);
  }
}

void BitStream::Read(std::string& value)
{
  uint32_t length;
  Read<uint32_t>(length);
  if (length > 0)
  {
    value.resize(length);
    ReadBytes(&value[0], length);
  }
  else
  {
    value.clear();
  }
}

void BitStream::WriteBoolArray(const std::vector<bool>& bools)
{
  Write<uint32_t>(static_cast<uint32_t>(bools.size()));   
  for (bool b : bools)
  {
    WriteBit(b);
  }
}

std::vector<bool> BitStream::ReadBoolArray()
{
  uint32_t size;
  Read<uint32_t>(size);
  std::vector<bool> bools(size);
  for (uint32_t i = 0; i < size; ++i)
  {
    bools[i] = ReadBit();
  }
  
  return bools;
}

const std::uint8_t* BitStream::GetData() const
{
  return buffer.data();
}

size_t BitStream::GetSizeBytes() const
{
  return (m_WritePose + 7) / 8; // Round up to nearest byte
}

size_t BitStream::GetSizeBits() const
{
  return m_WritePose;
}

void BitStream::ResetWrite()
{
  m_WritePose = 0;
}

void BitStream::ResetRead()
{
    m_ReadPose = 0;
}

void BitStream::Clear()
{
  buffer.clear();
  m_WritePose = 0;
  m_ReadPose = 0;
}


void BitStream::WriteQuantizedFloat(float value, float min, float max, uint8_t bits) 
{
  value = std::clamp(value, min, max);
  
  uint32_t range = (1 << bits) - 1;
  uint32_t quantized = static_cast<uint32_t>(range * ((value - min) / (max - min)));
  
  WriteBits(quantized, bits);
}

float BitStream::ReadQuantizedFloat(float min, float max, uint8_t bits) 
{
  uint32_t range = (1 << bits) - 1;
  uint32_t quantized = ReadBits(bits);
  return min + (float(quantized) / float(range)) * (max - min);
}