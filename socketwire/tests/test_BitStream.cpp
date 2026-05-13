#include <gtest/gtest.h>

#include "bit_stream.hpp"

class BitStreamTest : public ::testing::Test {
 protected:
  socketwire::BitStream bs;
};

TEST_F(BitStreamTest, WriteAndReadBit) {
  // Write individual bits
  bs.WriteBit(true);
  bs.WriteBit(false);
  bs.WriteBit(true);
  bs.WriteBit(false);
  bs.WriteBit(false);

  // Verify stream has data
  EXPECT_GT(bs.GetSizeBits(), 0)
      << "BitStream should contain data after writing bits";
  EXPECT_EQ(bs.GetSizeBits(), 5) << "BitStream should contain exactly 5 bits";

  // Read back and verify each bit
  bs.ResetRead();
  EXPECT_TRUE(bs.ReadBit()) << "First bit should be true";
  EXPECT_FALSE(bs.ReadBit()) << "Second bit should be false";
  EXPECT_TRUE(bs.ReadBit()) << "Third bit should be true";
  EXPECT_FALSE(bs.ReadBit()) << "Fourth bit should be false";
  EXPECT_FALSE(bs.ReadBit()) << "Fifth bit should be false";
}

TEST_F(BitStreamTest, WriteAndReadBits) {
  // Test writing and reading 8-bit patterns
  bs.WriteBits(0b10101010, 8);
  EXPECT_EQ(bs.GetSizeBits(), 8) << "Should have written exactly 8 bits";

  bs.ResetRead();
  uint32_t const result = bs.ReadBits(8);
  EXPECT_EQ(result, 0b10101010) << "Read value should match written value";

  // Test with different bit counts
  socketwire::BitStream bs2;
  bs2.WriteBits(0b111, 3);
  bs2.WriteBits(0b0000, 4);
  bs2.WriteBits(0b11111, 5);
  EXPECT_EQ(bs2.GetSizeBits(), 12) << "Should have written 3+4+5=12 bits total";

  bs2.ResetRead();
  EXPECT_EQ(bs2.ReadBits(3), 0b111) << "First 3 bits should be 111";
  EXPECT_EQ(bs2.ReadBits(4), 0b0000) << "Next 4 bits should be 0000";
  EXPECT_EQ(bs2.ReadBits(5), 0b11111) << "Last 5 bits should be 11111";

  // Test full 32-bit value
  socketwire::BitStream bs3;
  uint32_t const test_value = 0xDEADBEEF;
  bs3.WriteBits(test_value, 32);
  bs3.ResetRead();
  EXPECT_EQ(bs3.ReadBits(32), test_value)
      << "Should correctly handle 32-bit values";
}

TEST_F(BitStreamTest, WriteAndReadBytes) {
  // Test basic byte array writing/reading
  const char* data = "Hello";
  const std::size_t data_len = strlen(data);
  bs.WriteBytes(data, data_len);

  EXPECT_EQ(bs.GetSizeBytes(), data_len)
      << "BitStream should contain " << data_len << " bytes";

  bs.ResetRead();
  char buffer[6] = {0};  // +1 for null terminator
  bs.ReadBytes(buffer, data_len);
  EXPECT_STREQ(buffer, "Hello") << "Read data should match written data";

  // Test with binary data
  socketwire::BitStream bs2;
  unsigned char binary_data[] = {0x00, 0xFF, 0xAA, 0x55, 0xDE, 0xAD};
  bs2.WriteBytes(reinterpret_cast<const char*>(binary_data), 6);

  bs2.ResetRead();
  unsigned char read_buffer[6] = {};
  bs2.ReadBytes(reinterpret_cast<char*>(read_buffer), 6);

  for (int i = 0; i < 6; ++i) {
    EXPECT_EQ(read_buffer[i], binary_data[i])
        << "Binary data mismatch at index " << i;
  }

  // Test empty data
  socketwire::BitStream bs3;
  bs3.WriteBytes("", 0);
  EXPECT_EQ(bs3.GetSizeBytes(), 0) << "Empty write should result in 0 bytes";
}

TEST_F(BitStreamTest, WriteAndReadString) {
  // Test regular string
  std::string const original = "Test String";
  bs.Write(original);
  EXPECT_GT(bs.GetSizeBytes(), original.length())
      << "BitStream should contain string data plus length encoding";

  bs.ResetRead();
  std::string result;
  bs.Read(result);
  EXPECT_EQ(original, result) << "Read string should match written string";

  // Test empty string
  socketwire::BitStream bs2;
  const std::string empty = "";
  bs2.Write(empty);
  bs2.ResetRead();
  std::string empty_result;
  bs2.Read(empty_result);
  EXPECT_EQ(empty_result, "") << "Empty string should be read correctly";
  EXPECT_TRUE(empty_result.empty()) << "Result should be empty";

  // Test string with special characters
  socketwire::BitStream bs3;
  const std::string special("Hello\nWorld\t!\0Extra", 19);
  bs3.Write(special);
  bs3.ResetRead();
  std::string special_result;
  bs3.Read(special_result);
  EXPECT_EQ(special_result, special)
      << "Special characters should be preserved";

  // Test long string
  socketwire::BitStream bs4;
  const std::string long_str(1000, 'X');
  bs4.Write(long_str);
  bs4.ResetRead();
  std::string long_result;
  bs4.Read(long_result);
  EXPECT_EQ(long_result.length(), 1000)
      << "Long string length should be preserved";
  EXPECT_EQ(long_result, long_str) << "Long string content should match";
}

TEST_F(BitStreamTest, WriteAndReadBoolArray) {
  // Test basic bool array
  const std::vector<bool> original = {true, false, true, false};
  bs.WriteBoolArray(original);
  EXPECT_GT(bs.GetSizeBits(), 0) << "BitStream should contain data";

  bs.ResetRead();
  auto result = bs.ReadBoolArray();
  ASSERT_EQ(original.size(), result.size())
      << "Array sizes should match. Expected: " << original.size()
      << ", Got: " << result.size();

  for (std::size_t i = 0; i < original.size(); ++i) {
    EXPECT_EQ(original.at(i), result.at(i))
        << "Bool array mismatch at index " << i;
  }

  // Test empty array
  socketwire::BitStream bs2;
  const std::vector<bool> empty;
  bs2.WriteBoolArray(empty);
  bs2.ResetRead();
  auto empty_result = bs2.ReadBoolArray();
  EXPECT_TRUE(empty_result.empty()) << "Empty array should remain empty";
  EXPECT_EQ(empty_result.size(), 0) << "Empty array size should be 0";

  // Test large array
  socketwire::BitStream bs3;
  std::vector<bool> large(100);
  for (std::size_t i = 0; i < 100; ++i) {
    large.at(i) =
        (i % 3 == 0);  // Pattern: true, false, false, true, false, false...
  }
  bs3.WriteBoolArray(large);
  bs3.ResetRead();
  auto large_result = bs3.ReadBoolArray();
  ASSERT_EQ(large.size(), large_result.size())
      << "Large array size should match";
  for (std::size_t i = 0; i < large.size(); ++i) {
    EXPECT_EQ(large.at(i), large_result.at(i))
        << "Large array mismatch at index " << i;
  }
}

TEST_F(BitStreamTest, WriteAndReadInt) {
  // Test positive integer
  const int original = 42;
  bs.Write(original);
  EXPECT_GT(bs.GetSizeBytes(), 0) << "BitStream should contain data";

  bs.ResetRead();
  int result = 0;
  bs.Read(result);
  EXPECT_EQ(original, result) << "Positive integer should be read correctly";

  // Test negative integer
  socketwire::BitStream bs2;
  const int negative = -12345;
  bs2.Write(negative);
  bs2.ResetRead();
  int negative_result = 0;
  bs2.Read(negative_result);
  EXPECT_EQ(negative, negative_result)
      << "Negative integer should be preserved";

  // Test zero
  socketwire::BitStream bs3;
  const int zero = 0;
  bs3.Write(zero);
  bs3.ResetRead();
  int zero_result = 0;
  bs3.Read(zero_result);
  EXPECT_EQ(zero, zero_result) << "Zero should be read correctly";

  // Test maximum values
  socketwire::BitStream bs4;
  const int max_val = std::numeric_limits<int>::max();
  bs4.Write(max_val);
  bs4.ResetRead();
  int max_result = 0;
  bs4.Read(max_result);
  EXPECT_EQ(max_val, max_result) << "Maximum int value should be preserved";

  // Test minimum values
  socketwire::BitStream bs5;
  const int min_val = std::numeric_limits<int>::min();
  bs5.Write(min_val);
  bs5.ResetRead();
  int min_result = 0;
  bs5.Read(min_result);
  EXPECT_EQ(min_val, min_result) << "Minimum int value should be preserved";

  // Test multiple integers in sequence
  socketwire::BitStream bs6;
  std::vector<int> values = {1, 2, 3, -1, -2, -3, 0, 100, -100};
  for (const int val : values) {
    bs6.Write(val);
  }
  bs6.ResetRead();
  for (std::size_t i = 0; i < values.size(); ++i) {
    int read_val = 0;
    bs6.Read(read_val);
    EXPECT_EQ(values.at(i), read_val)
        << "Integer mismatch at index " << i << ". Expected: " << values.at(i)
        << ", Got: " << read_val;
  }
}

TEST_F(BitStreamTest, QuantizedFloat) {
  // Test basic quantization
  float const original = 3.14f;
  bs.WriteQuantizedFloat(original, 0.0f, 10.0f, 16);

  bs.ResetRead();
  float const result = bs.ReadQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(original, result, 0.01f)
      << "Quantized float should be close to original. Expected: " << original
      << ", Got: " << result;

  // Test boundary values
  socketwire::BitStream bs2;
  float const min_val = 0.0f;
  bs2.WriteQuantizedFloat(min_val, 0.0f, 10.0f, 16);
  bs2.ResetRead();
  float const min_result = bs2.ReadQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(min_val, min_result, 0.01f)
      << "Minimum boundary value should be preserved";

  socketwire::BitStream bs3;
  float const max_val = 10.0f;
  bs3.WriteQuantizedFloat(max_val, 0.0f, 10.0f, 16);
  bs3.ResetRead();
  float const max_result = bs3.ReadQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(max_val, max_result, 0.01f)
      << "Maximum boundary value should be preserved";

  // Test different precision levels
  socketwire::BitStream bs4;
  const float test_val = 5.5f;
  bs4.WriteQuantizedFloat(test_val, 0.0f, 10.0f, 8);  // Lower precision
  bs4.ResetRead();
  const float low_prec_result = bs4.ReadQuantizedFloat(0.0f, 10.0f, 8);
  EXPECT_NEAR(test_val, low_prec_result, 0.1f)
      << "8-bit quantization should have lower precision";

  socketwire::BitStream bs5;
  bs5.WriteQuantizedFloat(test_val, 0.0f, 10.0f, 16);  // Medium precision
  bs5.ResetRead();
  const float med_prec_result = bs5.ReadQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(test_val, med_prec_result, 0.01f)
      << "16-bit quantization should have medium precision";

  // Test negative range
  socketwire::BitStream bs6;
  const float neg_val = -5.0f;
  bs6.WriteQuantizedFloat(neg_val, -10.0f, 10.0f, 16);
  bs6.ResetRead();
  const float neg_result = bs6.ReadQuantizedFloat(-10.0f, 10.0f, 16);
  EXPECT_NEAR(neg_val, neg_result, 0.01f)
      << "Negative values should be quantized correctly";

  // Test multiple sequential quantized floats
  socketwire::BitStream bs7;
  std::vector<float> values = {0.0f, 2.5f, 5.0f, 7.5f, 10.0f};
  for (const float val : values) {
    bs7.WriteQuantizedFloat(val, 0.0f, 10.0f, 16);
  }
  bs7.ResetRead();
  for (std::size_t i = 0; i < values.size(); ++i) {
    const float read_val = bs7.ReadQuantizedFloat(0.0f, 10.0f, 16);
    EXPECT_NEAR(values.at(i), read_val, 0.01f)
        << "Sequential quantized float mismatch at index " << i;
  }
}

TEST_F(BitStreamTest, Alignment) {
  // Write a single bit, then align
  bs.WriteBit(true);
  EXPECT_EQ(bs.GetSizeBits(), 1) << "Should have 1 bit before alignment";

  bs.AlignWrite();
  EXPECT_EQ(bs.GetSizeBits(), 8)
      << "Should be aligned to 8 bits (1 byte) after alignWrite";

  // Write a byte after alignment
  bs.WriteBytes("A", 1);
  EXPECT_EQ(bs.GetSizeBytes(), 2) << "Should have 2 bytes total";

  // Read back with alignment
  bs.ResetRead();
  EXPECT_TRUE(bs.ReadBit()) << "First bit should be true";

  bs.AlignRead();
  char c = 0;
  bs.ReadBytes(&c, 1);
  EXPECT_EQ(c, 'A') << "Byte after alignment should be 'A'";

  // Test alignment with multiple bits
  socketwire::BitStream bs2;
  bs2.WriteBits(0b111, 3);  // 3 bits
  EXPECT_EQ(bs2.GetSizeBits(), 3);
  bs2.AlignWrite();
  EXPECT_EQ(bs2.GetSizeBits(), 8) << "3 bits should align to 8 bits";

  // Test already aligned stream
  socketwire::BitStream bs3;
  bs3.WriteBytes("ABC", 3);  // Already byte-aligned
  EXPECT_EQ(bs3.GetSizeBits(), 24);
  bs3.AlignWrite();  // Should not change anything
  EXPECT_EQ(bs3.GetSizeBits(), 24)
      << "Already aligned stream should remain unchanged";

  // Test alignment preserves data
  socketwire::BitStream bs4;
  bs4.WriteBits(0b101, 3);
  bs4.AlignWrite();
  bs4.WriteBytes("X", 1);

  bs4.ResetRead();
  const std::uint32_t bits = bs4.ReadBits(3);
  EXPECT_EQ(bits, 0b101) << "Bits before alignment should be preserved";
  bs4.AlignRead();
  char x = 0;
  bs4.ReadBytes(&x, 1);
  EXPECT_EQ(x, 'X') << "Data after alignment should be correct";
}

TEST_F(BitStreamTest, Size) {
  // Test initial size
  EXPECT_EQ(bs.GetSizeBytes(), 0) << "New BitStream should have 0 bytes";
  EXPECT_EQ(bs.GetSizeBits(), 0) << "New BitStream should have 0 bits";

  // Write exactly 1 byte
  bs.WriteBits(0xFF, 8);
  EXPECT_EQ(bs.GetSizeBytes(), 1) << "After writing 8 bits, should have 1 byte";
  EXPECT_EQ(bs.GetSizeBits(), 8) << "After writing 8 bits, should have 8 bits";

  // Write partial byte
  socketwire::BitStream bs2;
  bs2.WriteBits(0b111, 3);  // 3 bits
  EXPECT_EQ(bs2.GetSizeBytes(), 1) << "3 bits should occupy 1 byte";
  EXPECT_EQ(bs2.GetSizeBits(), 3) << "Bit count should be exactly 3";

  // Write multiple bytes
  socketwire::BitStream bs3;
  bs3.WriteBytes("Hello", 5);  // 5 bytes
  EXPECT_EQ(bs3.GetSizeBytes(), 5) << "Should have 5 bytes";
  EXPECT_EQ(bs3.GetSizeBits(), 40) << "5 bytes = 40 bits";

  // Test size accumulation
  socketwire::BitStream bs4;
  bs4.WriteBit(true);  // 1 bit
  EXPECT_EQ(bs4.GetSizeBits(), 1);

  bs4.WriteBits(0xFF, 8);  // +8 bits = 9 total
  EXPECT_EQ(bs4.GetSizeBits(), 9);
  EXPECT_EQ(bs4.GetSizeBytes(), 2) << "9 bits should occupy 2 bytes";

  bs4.AlignWrite();  // Align to byte boundary (add 7 padding bits to reach 16)
  const std::size_t aligned_bits = bs4.GetSizeBits();
  EXPECT_EQ(aligned_bits % 8, 0)
      << "After alignment, bit count should be multiple of 8";

  bs4.WriteBytes("A", 1);  // +8 bits
  EXPECT_EQ(bs4.GetSizeBits(), aligned_bits + 8)
      << "Writing 1 byte should add 8 bits";

  // Verify that reading doesn't change size
  socketwire::BitStream bs5;
  bs5.WriteBits(0xABCD, 16);
  std::size_t const orig_size_bits = bs5.GetSizeBits();
  std::size_t const orig_size_bytes = bs5.GetSizeBytes();

  bs5.ResetRead();
  bs5.ReadBits(8);  // Read half

  EXPECT_EQ(bs5.GetSizeBits(), orig_size_bits)
      << "Reading should not change bit size";
  EXPECT_EQ(bs5.GetSizeBytes(), orig_size_bytes)
      << "Reading should not change byte size";
}

// Safety and correctness tests.

TEST_F(BitStreamTest, DataConstructorSetsSizeCorrectly) {
  // Write some data, then construct a new stream from the raw buffer
  socketwire::BitStream source;
  source.Write<uint32_t>(42);
  source.Write<uint16_t>(7);
  source.Write(std::string("hello"));

  const uint8_t* data = source.GetData();
  const std::size_t bytes = source.GetSizeBytes();

  // Construct from raw data; write position should be set.
  socketwire::BitStream from_data(data, bytes);
  EXPECT_EQ(from_data.GetSizeBytes(), bytes)
      << "BitStream constructed from data should report correct size in bytes";
  EXPECT_EQ(from_data.GetSizeBits(), bytes * 8)
      << "BitStream constructed from data should report correct size in bits";

  // Verify we can read back correctly
  uint32_t v1 = 0;
  from_data.Read<uint32_t>(v1);
  EXPECT_EQ(v1, 42);
  uint16_t v2 = 0;
  from_data.Read<uint16_t>(v2);
  EXPECT_EQ(v2, 7);
  std::string s;
  from_data.Read(s);
  EXPECT_EQ(s, "hello");
}

TEST_F(BitStreamTest, ReadStringRejectsExcessiveLength) {
  // Manually craft a BitStream with a huge length prefix
  socketwire::BitStream craft;
  craft.Write<uint32_t>(0xFFFFFFFF);  // 4 GB length; DoS vector.

  craft.ResetRead();
  std::string out;
  EXPECT_THROW(craft.Read(out), std::out_of_range)
      << "Reading a string with length > kMaxBitStreamStringLength should "
         "throw";
}

TEST_F(BitStreamTest, ReadStringRejectsLengthExceedingBuffer) {
  // Length is within the max limit, but exceeds actual buffer contents
  socketwire::BitStream craft;
  craft.Write<uint32_t>(
      1000);  // claim 1000 bytes, but buffer only has 4 bytes after the length
  craft.WriteBytes("AB", 2);  // only 2 bytes of actual payload

  craft.ResetRead();
  std::string out;
  EXPECT_THROW(craft.Read(out), std::out_of_range)
      << "Reading a string whose length exceeds remaining buffer should throw";
}

TEST_F(BitStreamTest, ReadStringLegitimateStringsStillWork) {
  socketwire::BitStream stream;
  stream.Write(std::string(""));
  stream.Write(std::string("a"));
  stream.Write(std::string("hello world"));
  stream.Write(std::string(1000, 'x'));  // 1000 chars; within limit.

  stream.ResetRead();

  std::string s1, s2, s3, s4;
  EXPECT_NO_THROW(stream.Read(s1));
  EXPECT_NO_THROW(stream.Read(s2));
  EXPECT_NO_THROW(stream.Read(s3));
  EXPECT_NO_THROW(stream.Read(s4));

  EXPECT_EQ(s1, "");
  EXPECT_EQ(s2, "a");
  EXPECT_EQ(s3, "hello world");
  EXPECT_EQ(s4, std::string(1000, 'x'));
}

TEST_F(BitStreamTest, ReadBoolArrayRejectsExcessiveSize) {
  socketwire::BitStream craft;
  craft.Write<uint32_t>(0xFFFFFFFF);  // massive bool array size

  craft.ResetRead();
  EXPECT_THROW(craft.ReadBoolArray(), std::out_of_range)
      << "Reading a bool array with size > kMaxBitStreamBoolArraySize should "
         "throw";
}

TEST_F(BitStreamTest, ReadBoolArrayRejectsSizeExceedingBuffer) {
  // Claim 500 bools but only have a few bits
  socketwire::BitStream craft;
  craft.Write<uint32_t>(500);
  craft.WriteBit(true);
  craft.WriteBit(false);

  craft.ResetRead();
  EXPECT_THROW(craft.ReadBoolArray(), std::out_of_range)
      << "Reading a bool array whose size exceeds remaining bits should throw";
}

TEST_F(BitStreamTest, ReadBoolArrayLegitimateArraysStillWork) {
  const std::vector<bool> original = {true,  false, true, true,
                                      false, false, true};

  socketwire::BitStream stream;
  stream.WriteBoolArray(original);

  stream.ResetRead();
  std::vector<bool> result;
  EXPECT_NO_THROW(result = stream.ReadBoolArray());
  EXPECT_EQ(result, original);
}

TEST_F(BitStreamTest, GetRemainingBytes) {
  socketwire::BitStream stream;
  stream.Write<uint32_t>(42);  // 4 bytes
  stream.Write<uint16_t>(7);   // 2 bytes = 6 total

  stream.ResetRead();
  EXPECT_EQ(stream.GetRemainingBytes(), 6);

  uint32_t v = 0;
  stream.Read<uint32_t>(v);
  EXPECT_EQ(stream.GetRemainingBytes(), 2);

  uint16_t v2 = 0;
  stream.Read<uint16_t>(v2);
  EXPECT_EQ(stream.GetRemainingBytes(), 0);
}
