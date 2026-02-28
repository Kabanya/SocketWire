#include <gtest/gtest.h>
#include "bit_stream.hpp"

class BitStreamTest : public ::testing::Test
{
protected:
  socketwire::BitStream bs;
};

TEST_F(BitStreamTest, WriteAndReadBit)
{
  // Write individual bits
  bs.writeBit(true);
  bs.writeBit(false);
  bs.writeBit(true);
  bs.writeBit(false);
  bs.writeBit(false);

  // Verify stream has data
  EXPECT_GT(bs.getSizeBits(), 0) << "BitStream should contain data after writing bits";
  EXPECT_EQ(bs.getSizeBits(), 5) << "BitStream should contain exactly 5 bits";

  // Read back and verify each bit
  bs.resetRead();
  EXPECT_TRUE(bs.readBit()) << "First bit should be true";
  EXPECT_FALSE(bs.readBit()) << "Second bit should be false";
  EXPECT_TRUE(bs.readBit()) << "Third bit should be true";
  EXPECT_FALSE(bs.readBit()) << "Fourth bit should be false";
  EXPECT_FALSE(bs.readBit()) << "Fifth bit should be false";
}

TEST_F(BitStreamTest, WriteAndReadBits)
{
  // Test writing and reading 8-bit patterns
  bs.writeBits(0b10101010, 8);
  EXPECT_EQ(bs.getSizeBits(), 8) << "Should have written exactly 8 bits";

  bs.resetRead();
  uint32_t result = bs.readBits(8);
  EXPECT_EQ(result, 0b10101010) << "Read value should match written value";

  // Test with different bit counts
  socketwire::BitStream bs2;
  bs2.writeBits(0b111, 3);
  bs2.writeBits(0b0000, 4);
  bs2.writeBits(0b11111, 5);
  EXPECT_EQ(bs2.getSizeBits(), 12) << "Should have written 3+4+5=12 bits total";

  bs2.resetRead();
  EXPECT_EQ(bs2.readBits(3), 0b111) << "First 3 bits should be 111";
  EXPECT_EQ(bs2.readBits(4), 0b0000) << "Next 4 bits should be 0000";
  EXPECT_EQ(bs2.readBits(5), 0b11111) << "Last 5 bits should be 11111";

  // Test full 32-bit value
  socketwire::BitStream bs3;
  uint32_t test_value = 0xDEADBEEF;
  bs3.writeBits(test_value, 32);
  bs3.resetRead();
  EXPECT_EQ(bs3.readBits(32), test_value) << "Should correctly handle 32-bit values";
}

TEST_F(BitStreamTest, WriteAndReadBytes)
{
  // Test basic byte array writing/reading
  const char* data = "Hello";
  size_t data_len = strlen(data);
  bs.writeBytes(data, data_len);

  EXPECT_EQ(bs.getSizeBytes(), data_len) << "BitStream should contain " << data_len << " bytes";

  bs.resetRead();
  char buffer[6] = {0}; // +1 for null terminator
  bs.readBytes(buffer, data_len);
  EXPECT_STREQ(buffer, "Hello") << "Read data should match written data";

  // Test with binary data
  socketwire::BitStream bs2;
  unsigned char binary_data[] = {0x00, 0xFF, 0xAA, 0x55, 0xDE, 0xAD};
  bs2.writeBytes(reinterpret_cast<const char*>(binary_data), 6);

  bs2.resetRead();
  unsigned char read_buffer[6];
  bs2.readBytes(reinterpret_cast<char*>(read_buffer), 6);

  for (int i = 0; i < 6; ++i) {
    EXPECT_EQ(read_buffer[i], binary_data[i])
      << "Binary data mismatch at index " << i;
  }

  // Test empty data
  socketwire::BitStream bs3;
  bs3.writeBytes("", 0);
  EXPECT_EQ(bs3.getSizeBytes(), 0) << "Empty write should result in 0 bytes";
}

TEST_F(BitStreamTest, WriteAndReadString)
{
  // Test regular string
  std::string original = "Test String";
  bs.write(original);
  EXPECT_GT(bs.getSizeBytes(), original.length())
    << "BitStream should contain string data plus length encoding";

  bs.resetRead();
  std::string result;
  bs.read(result);
  EXPECT_EQ(original, result) << "Read string should match written string";

  // Test empty string
  socketwire::BitStream bs2;
  std::string empty = "";
  bs2.write(empty);
  bs2.resetRead();
  std::string empty_result;
  bs2.read(empty_result);
  EXPECT_EQ(empty_result, "") << "Empty string should be read correctly";
  EXPECT_TRUE(empty_result.empty()) << "Result should be empty";

  // Test string with special characters
  socketwire::BitStream bs3;
  std::string special = "Hello\nWorld\t!\0Extra";
  bs3.write(special);
  bs3.resetRead();
  std::string special_result;
  bs3.read(special_result);
  EXPECT_EQ(special_result, special) << "Special characters should be preserved";

  // Test long string
  socketwire::BitStream bs4;
  std::string long_str(1000, 'X');
  bs4.write(long_str);
  bs4.resetRead();
  std::string long_result;
  bs4.read(long_result);
  EXPECT_EQ(long_result.length(), 1000) << "Long string length should be preserved";
  EXPECT_EQ(long_result, long_str) << "Long string content should match";
}

TEST_F(BitStreamTest, WriteAndReadBoolArray)
{
  // Test basic bool array
  std::vector<bool> original = {true, false, true, false};
  bs.writeBoolArray(original);
  EXPECT_GT(bs.getSizeBits(), 0) << "BitStream should contain data";

  bs.resetRead();
  auto result = bs.readBoolArray();
  ASSERT_EQ(original.size(), result.size())
    << "Array sizes should match. Expected: " << original.size()
    << ", Got: " << result.size();

  for (size_t i = 0; i < original.size(); ++i) {
    EXPECT_EQ(original[i], result[i])
      << "Bool array mismatch at index " << i;
  }

  // Test empty array
  socketwire::BitStream bs2;
  std::vector<bool> empty;
  bs2.writeBoolArray(empty);
  bs2.resetRead();
  auto empty_result = bs2.readBoolArray();
  EXPECT_TRUE(empty_result.empty()) << "Empty array should remain empty";
  EXPECT_EQ(empty_result.size(), 0) << "Empty array size should be 0";

  // Test large array
  socketwire::BitStream bs3;
  std::vector<bool> large(100);
  for (size_t i = 0; i < 100; ++i) {
    large[i] = (i % 3 == 0); // Pattern: true, false, false, true, false, false...
  }
  bs3.writeBoolArray(large);
  bs3.resetRead();
  auto large_result = bs3.readBoolArray();
  ASSERT_EQ(large.size(), large_result.size()) << "Large array size should match";
  for (size_t i = 0; i < large.size(); ++i) {
    EXPECT_EQ(large[i], large_result[i])
      << "Large array mismatch at index " << i;
  }
}

TEST_F(BitStreamTest, WriteAndReadInt)
{
  // Test positive integer
  int original = 42;
  bs.write(original);
  EXPECT_GT(bs.getSizeBytes(), 0) << "BitStream should contain data";

  bs.resetRead();
  int result;
  bs.read(result);
  EXPECT_EQ(original, result) << "Positive integer should be read correctly";

  // Test negative integer
  socketwire::BitStream bs2;
  int negative = -12345;
  bs2.write(negative);
  bs2.resetRead();
  int negative_result;
  bs2.read(negative_result);
  EXPECT_EQ(negative, negative_result) << "Negative integer should be preserved";

  // Test zero
  socketwire::BitStream bs3;
  int zero = 0;
  bs3.write(zero);
  bs3.resetRead();
  int zero_result;
  bs3.read(zero_result);
  EXPECT_EQ(zero, zero_result) << "Zero should be read correctly";

  // Test maximum values
  socketwire::BitStream bs4;
  int max_val = std::numeric_limits<int>::max();
  bs4.write(max_val);
  bs4.resetRead();
  int max_result;
  bs4.read(max_result);
  EXPECT_EQ(max_val, max_result) << "Maximum int value should be preserved";

  // Test minimum values
  socketwire::BitStream bs5;
  int min_val = std::numeric_limits<int>::min();
  bs5.write(min_val);
  bs5.resetRead();
  int min_result;
  bs5.read(min_result);
  EXPECT_EQ(min_val, min_result) << "Minimum int value should be preserved";

  // Test multiple integers in sequence
  socketwire::BitStream bs6;
  std::vector<int> values = {1, 2, 3, -1, -2, -3, 0, 100, -100};
  for (int val : values) {
    bs6.write(val);
  }
  bs6.resetRead();
  for (size_t i = 0; i < values.size(); ++i) {
    int read_val;
    bs6.read(read_val);
    EXPECT_EQ(values[i], read_val)
      << "Integer mismatch at index " << i
      << ". Expected: " << values[i] << ", Got: " << read_val;
  }
}

TEST_F(BitStreamTest, QuantizedFloat)
{
  // Test basic quantization
  float original = 3.14f;
  bs.writeQuantizedFloat(original, 0.0f, 10.0f, 16);

  bs.resetRead();
  float result = bs.readQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(original, result, 0.01f)
    << "Quantized float should be close to original. Expected: " << original
    << ", Got: " << result;

  // Test boundary values
  socketwire::BitStream bs2;
  float min_val = 0.0f;
  bs2.writeQuantizedFloat(min_val, 0.0f, 10.0f, 16);
  bs2.resetRead();
  float min_result = bs2.readQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(min_val, min_result, 0.01f)
    << "Minimum boundary value should be preserved";

  socketwire::BitStream bs3;
  float max_val = 10.0f;
  bs3.writeQuantizedFloat(max_val, 0.0f, 10.0f, 16);
  bs3.resetRead();
  float max_result = bs3.readQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(max_val, max_result, 0.01f)
    << "Maximum boundary value should be preserved";

  // Test different precision levels
  socketwire::BitStream bs4;
  float test_val = 5.5f;
  bs4.writeQuantizedFloat(test_val, 0.0f, 10.0f, 8);  // Lower precision
  bs4.resetRead();
  float low_prec_result = bs4.readQuantizedFloat(0.0f, 10.0f, 8);
  EXPECT_NEAR(test_val, low_prec_result, 0.1f)
    << "8-bit quantization should have lower precision";

  socketwire::BitStream bs5;
  bs5.writeQuantizedFloat(test_val, 0.0f, 10.0f, 16);  // Medium precision
  bs5.resetRead();
  float med_prec_result = bs5.readQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(test_val, med_prec_result, 0.01f)
    << "16-bit quantization should have medium precision";

  // Test negative range
  socketwire::BitStream bs6;
  float neg_val = -5.0f;
  bs6.writeQuantizedFloat(neg_val, -10.0f, 10.0f, 16);
  bs6.resetRead();
  float neg_result = bs6.readQuantizedFloat(-10.0f, 10.0f, 16);
  EXPECT_NEAR(neg_val, neg_result, 0.01f)
    << "Negative values should be quantized correctly";

  // Test multiple sequential quantized floats
  socketwire::BitStream bs7;
  std::vector<float> values = {0.0f, 2.5f, 5.0f, 7.5f, 10.0f};
  for (float val : values) {
    bs7.writeQuantizedFloat(val, 0.0f, 10.0f, 16);
  }
  bs7.resetRead();
  for (size_t i = 0; i < values.size(); ++i) {
    float read_val = bs7.readQuantizedFloat(0.0f, 10.0f, 16);
    EXPECT_NEAR(values[i], read_val, 0.01f)
      << "Sequential quantized float mismatch at index " << i;
  }
}

TEST_F(BitStreamTest, Alignment)
{
  // Write a single bit, then align
  bs.writeBit(true);
  EXPECT_EQ(bs.getSizeBits(), 1) << "Should have 1 bit before alignment";

  bs.alignWrite();
  EXPECT_EQ(bs.getSizeBits(), 8) << "Should be aligned to 8 bits (1 byte) after alignWrite";

  // Write a byte after alignment
  bs.writeBytes("A", 1);
  EXPECT_EQ(bs.getSizeBytes(), 2) << "Should have 2 bytes total";

  // Read back with alignment
  bs.resetRead();
  EXPECT_TRUE(bs.readBit()) << "First bit should be true";

  bs.alignRead();
  char c;
  bs.readBytes(&c, 1);
  EXPECT_EQ(c, 'A') << "Byte after alignment should be 'A'";

  // Test alignment with multiple bits
  socketwire::BitStream bs2;
  bs2.writeBits(0b111, 3);  // 3 bits
  EXPECT_EQ(bs2.getSizeBits(), 3);
  bs2.alignWrite();
  EXPECT_EQ(bs2.getSizeBits(), 8) << "3 bits should align to 8 bits";

  // Test already aligned stream
  socketwire::BitStream bs3;
  bs3.writeBytes("ABC", 3);  // Already byte-aligned
  EXPECT_EQ(bs3.getSizeBits(), 24);
  bs3.alignWrite();  // Should not change anything
  EXPECT_EQ(bs3.getSizeBits(), 24) << "Already aligned stream should remain unchanged";

  // Test alignment preserves data
  socketwire::BitStream bs4;
  bs4.writeBits(0b101, 3);
  bs4.alignWrite();
  bs4.writeBytes("X", 1);

  bs4.resetRead();
  uint32_t bits = bs4.readBits(3);
  EXPECT_EQ(bits, 0b101) << "Bits before alignment should be preserved";
  bs4.alignRead();
  char x;
  bs4.readBytes(&x, 1);
  EXPECT_EQ(x, 'X') << "Data after alignment should be correct";
}

TEST_F(BitStreamTest, Size)
{
  // Test initial size
  EXPECT_EQ(bs.getSizeBytes(), 0) << "New BitStream should have 0 bytes";
  EXPECT_EQ(bs.getSizeBits(), 0) << "New BitStream should have 0 bits";

  // Write exactly 1 byte
  bs.writeBits(0xFF, 8);
  EXPECT_EQ(bs.getSizeBytes(), 1) << "After writing 8 bits, should have 1 byte";
  EXPECT_EQ(bs.getSizeBits(), 8) << "After writing 8 bits, should have 8 bits";

  // Write partial byte
  socketwire::BitStream bs2;
  bs2.writeBits(0b111, 3);  // 3 bits
  EXPECT_EQ(bs2.getSizeBytes(), 1) << "3 bits should occupy 1 byte";
  EXPECT_EQ(bs2.getSizeBits(), 3) << "Bit count should be exactly 3";

  // Write multiple bytes
  socketwire::BitStream bs3;
  bs3.writeBytes("Hello", 5);  // 5 bytes
  EXPECT_EQ(bs3.getSizeBytes(), 5) << "Should have 5 bytes";
  EXPECT_EQ(bs3.getSizeBits(), 40) << "5 bytes = 40 bits";

  // Test size accumulation
  socketwire::BitStream bs4;
  bs4.writeBit(true);           // 1 bit
  EXPECT_EQ(bs4.getSizeBits(), 1);

  bs4.writeBits(0xFF, 8);       // +8 bits = 9 total
  EXPECT_EQ(bs4.getSizeBits(), 9);
  EXPECT_EQ(bs4.getSizeBytes(), 2) << "9 bits should occupy 2 bytes";

  bs4.alignWrite();              // Align to byte boundary (add 7 padding bits to reach 16)
  size_t aligned_bits = bs4.getSizeBits();
  EXPECT_EQ(aligned_bits % 8, 0) << "After alignment, bit count should be multiple of 8";

  bs4.writeBytes("A", 1);       // +8 bits
  EXPECT_EQ(bs4.getSizeBits(), aligned_bits + 8)
    << "Writing 1 byte should add 8 bits";

  // Verify that reading doesn't change size
  socketwire::BitStream bs5;
  bs5.writeBits(0xABCD, 16);
  size_t orig_size_bits = bs5.getSizeBits();
  size_t orig_size_bytes = bs5.getSizeBytes();

  bs5.resetRead();
  bs5.readBits(8);  // Read half

  EXPECT_EQ(bs5.getSizeBits(), orig_size_bits)
    << "Reading should not change bit size";
  EXPECT_EQ(bs5.getSizeBytes(), orig_size_bytes)
    << "Reading should not change byte size";
}

// ========================= Safety & correctness tests =========================

TEST_F(BitStreamTest, DataConstructorSetsSizeCorrectly)
{
  // Write some data, then construct a new stream from the raw buffer
  socketwire::BitStream source;
  source.write<uint32_t>(42);
  source.write<uint16_t>(7);
  source.write(std::string("hello"));

  const uint8_t* data = source.getData();
  size_t bytes = source.getSizeBytes();

  // Construct from raw data — m_WritePose should be set
  socketwire::BitStream fromData(data, bytes);
  EXPECT_EQ(fromData.getSizeBytes(), bytes)
    << "BitStream constructed from data should report correct size in bytes";
  EXPECT_EQ(fromData.getSizeBits(), bytes * 8)
    << "BitStream constructed from data should report correct size in bits";

  // Verify we can read back correctly
  uint32_t v1;
  fromData.read<uint32_t>(v1);
  EXPECT_EQ(v1, 42);
  uint16_t v2;
  fromData.read<uint16_t>(v2);
  EXPECT_EQ(v2, 7);
  std::string s;
  fromData.read(s);
  EXPECT_EQ(s, "hello");
}

TEST_F(BitStreamTest, ReadStringRejectsExcessiveLength)
{
  // Manually craft a BitStream with a huge length prefix
  socketwire::BitStream craft;
  craft.write<uint32_t>(0xFFFFFFFF); // 4 GB length — DoS vector

  craft.resetRead();
  std::string out;
  EXPECT_THROW(craft.read(out), std::out_of_range)
    << "Reading a string with length > kMaxBitStreamStringLength should throw";
}

TEST_F(BitStreamTest, ReadStringRejectsLengthExceedingBuffer)
{
  // Length is within the max limit, but exceeds actual buffer contents
  socketwire::BitStream craft;
  craft.write<uint32_t>(1000); // claim 1000 bytes, but buffer only has 4 bytes after the length
  craft.writeBytes("AB", 2);   // only 2 bytes of actual payload

  craft.resetRead();
  std::string out;
  EXPECT_THROW(craft.read(out), std::out_of_range)
    << "Reading a string whose length exceeds remaining buffer should throw";
}

TEST_F(BitStreamTest, ReadStringLegitimateStringsStillWork)
{
  socketwire::BitStream stream;
  stream.write(std::string(""));
  stream.write(std::string("a"));
  stream.write(std::string("hello world"));
  stream.write(std::string(1000, 'x')); // 1000 chars — well within limit

  stream.resetRead();

  std::string s1, s2, s3, s4;
  EXPECT_NO_THROW(stream.read(s1));
  EXPECT_NO_THROW(stream.read(s2));
  EXPECT_NO_THROW(stream.read(s3));
  EXPECT_NO_THROW(stream.read(s4));

  EXPECT_EQ(s1, "");
  EXPECT_EQ(s2, "a");
  EXPECT_EQ(s3, "hello world");
  EXPECT_EQ(s4, std::string(1000, 'x'));
}

TEST_F(BitStreamTest, ReadBoolArrayRejectsExcessiveSize)
{
  socketwire::BitStream craft;
  craft.write<uint32_t>(0xFFFFFFFF); // massive bool array size

  craft.resetRead();
  EXPECT_THROW(craft.readBoolArray(), std::out_of_range)
    << "Reading a bool array with size > kMaxBitStreamBoolArraySize should throw";
}

TEST_F(BitStreamTest, ReadBoolArrayRejectsSizeExceedingBuffer)
{
  // Claim 500 bools but only have a few bits
  socketwire::BitStream craft;
  craft.write<uint32_t>(500);
  craft.writeBit(true);
  craft.writeBit(false);

  craft.resetRead();
  EXPECT_THROW(craft.readBoolArray(), std::out_of_range)
    << "Reading a bool array whose size exceeds remaining bits should throw";
}

TEST_F(BitStreamTest, ReadBoolArrayLegitimateArraysStillWork)
{
  std::vector<bool> original = {true, false, true, true, false, false, true};

  socketwire::BitStream stream;
  stream.writeBoolArray(original);

  stream.resetRead();
  std::vector<bool> result;
  EXPECT_NO_THROW(result = stream.readBoolArray());
  EXPECT_EQ(result, original);
}

TEST_F(BitStreamTest, GetRemainingBytes)
{
  socketwire::BitStream stream;
  stream.write<uint32_t>(42);   // 4 bytes
  stream.write<uint16_t>(7);    // 2 bytes = 6 total

  stream.resetRead();
  EXPECT_EQ(stream.getRemainingBytes(), 6);

  uint32_t v;
  stream.read<uint32_t>(v);
  EXPECT_EQ(stream.getRemainingBytes(), 2);

  uint16_t v2;
  stream.read<uint16_t>(v2);
  EXPECT_EQ(stream.getRemainingBytes(), 0);
}