#include "BitStream.h"
#include <iostream>
#include <vector>

int main() 
{
  BitStream stream;
  
  std::cout << "Test 1: Integer Types: \n" << std::endl;
  int8_t val1 = -128;
  uint16_t val2 = 65535;
  int32_t val3 = -2147483648;
  uint64_t val4 = 18446744073709551615ULL;
  
  stream.Write<int8_t>(val1);
  stream.Write<uint16_t>(val2);
  stream.Write<int32_t>(val3);
  stream.Write<uint64_t>(val4);
  
  std::cout << "Written: " << (int)val1 << ", " << val2 << ", " << val3 << ", " << val4 << std::endl;
  std::cout << "Size after integers: " << stream.GetSizeBytes() << " bytes" << std::endl;
  
  std::cout << "\n\nTest 2: Strings: \n" << std::endl;
  std::string short_str = "Hi";
  std::string long_str = "This is a much longer string to test serialization";
  std::string empty_str = "";
  
  stream.Write(short_str);
  stream.Write(long_str);
  stream.Write(empty_str);
  
  std::cout << "Written strings: '" << short_str << "', '" << long_str << "', '" << empty_str << "'" << std::endl;
  std::cout << "Size after strings: " << stream.GetSizeBytes() << " bytes" << std::endl;
  
  std::cout << "\n\nTest 3: Bits: \n" << std::endl;
  bool bits[] = {true, false, true, true, false};
  for (int i = 0; i < 5; i++) {
    stream.WriteBit(bits[i]);
    std::cout << "Written bit " << i << ": " << bits[i] << std::endl;
  }
  
  stream.WriteBits(170, 8); // 10101010 в двоичном
  stream.WriteBits(15, 4);  // 1111 в двоичном
  std::cout << "Written 8 bits: 170 (10101010), 4 bits: 15 (1111)" << std::endl;
  std::cout << "Size after bits: " << stream.GetSizeBytes() << " bytes" << std::endl;
  
  std::cout << "\n\nTest 4: Quantized Floats: \n" << std::endl;
  float floats[] = {0.0f, 2.5f, 5.0f, 7.75f, 10.0f};
  for (int i = 0; i < 5; i++) {
    stream.WriteQuantizedFloat(floats[i], 0.0f, 10.0f, 8);
    std::cout << "Written quantized float: " << floats[i] << std::endl;
  }
  std::cout << "Final size: " << stream.GetSizeBytes() << " bytes" << std::endl;
  
  std::cout << "\n\nReading Back: " << std::endl;
  stream.ResetRead();
  
  int8_t r_val1; stream.Read<int8_t>(r_val1);
  uint16_t r_val2; stream.Read<uint16_t>(r_val2);
  int32_t r_val3; stream.Read<int32_t>(r_val3);
  uint64_t r_val4; stream.Read<uint64_t>(r_val4);
  
  std::cout << "Read integers: " << (int)r_val1 << ", " << r_val2 << ", " << r_val3 << ", " << r_val4 << std::endl;
  
  std::string r_short, r_long, r_empty;
  stream.Read(r_short);
  stream.Read(r_long);
  stream.Read(r_empty);
  
  std::cout << "Read strings: '" << r_short << "', '" << r_long << "', '" << r_empty << "'" << std::endl;
  
  std::cout << "Read bits: ";
  for (int i = 0; i < 5; i++) {
    std::cout << stream.ReadBit() << " ";
  }
  std::cout << std::endl;
  
  uint32_t r_bits8 = stream.ReadBits(8);
  uint32_t r_bits4 = stream.ReadBits(4);
  std::cout << "Read 8 bits: " << r_bits8 << ", 4 bits: " << r_bits4 << std::endl;
  
  std::cout << "Read quantized floats: ";
  for (int i = 0; i < 5; i++) {
    float qf = stream.ReadQuantizedFloat(0.0f, 10.0f, 8);
    std::cout << qf << " ";
  }
  std::cout << std::endl;
  
  return 0;
}