#include <gtest/gtest.h>
#include "bit_stream.hpp"

class BitStreamTest : public ::testing::Test
{
protected:
  BitStream bs;
};

TEST_F(BitStreamTest, WriteAndReadBit)
{
  bs.writeBit(true);
  bs.writeBit(false);
  bs.writeBit(true);

  bs.resetRead();
  EXPECT_TRUE(bs.readBit());
  EXPECT_FALSE(bs.readBit());
  EXPECT_TRUE(bs.readBit());
}

TEST_F(BitStreamTest, WriteAndReadBits)
{
  bs.writeBits(0b10101010, 8);
  bs.resetRead();
  EXPECT_EQ(bs.readBits(8), 0b10101010);
}

TEST_F(BitStreamTest, WriteAndReadBytes)
{
  const char* data = "Hello";
  bs.writeBytes(data, 5);
  bs.resetRead();
  char buffer[5];
  bs.readBytes(buffer, 5);
  EXPECT_STREQ(buffer, "Hello");
}

TEST_F(BitStreamTest, WriteAndReadString)
{
  std::string original = "Test String";
  bs.write(original);
  bs.resetRead();
  std::string result;
  bs.read(result);
  EXPECT_EQ(original, result);
}

TEST_F(BitStreamTest, WriteAndReadBoolArray)
{
  std::vector<bool> original = {true, false, true, false};
  bs.writeBoolArray(original);
  bs.resetRead();
  auto result = bs.readBoolArray();
  EXPECT_EQ(original, result);
}

TEST_F(BitStreamTest, WriteAndReadInt)
{
  int original = 42;
  bs.write(original);
  bs.resetRead();
  int result;
  bs.read(result);
  EXPECT_EQ(original, result);
}

TEST_F(BitStreamTest, QuantizedFloat)
{
  float original = 3.14f;
  bs.writeQuantizedFloat(original, 0.0f, 10.0f, 16);
  bs.resetRead();
  float result = bs.readQuantizedFloat(0.0f, 10.0f, 16);
  EXPECT_NEAR(original, result, 0.01f);
}

TEST_F(BitStreamTest, Alignment)
{
  bs.writeBit(true);
  bs.alignWrite();
  bs.writeBytes("A", 1);
  bs.resetRead();
  bs.readBit();
  bs.alignRead();
  char c;
  bs.readBytes(&c, 1);
  EXPECT_EQ(c, 'A');
}

TEST_F(BitStreamTest, Size)
{
  bs.writeBits(0xFF, 8);
  EXPECT_EQ(bs.getSizeBytes(), 1);
  EXPECT_EQ(bs.getSizeBits(), 8);
}