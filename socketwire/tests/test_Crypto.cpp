#include <gtest/gtest.h>
#include "crypto.hpp"
#include <vector>
#include <cstring>

class CryptoTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
    // Initialize libsodium before each test
#if SOCKETWIRE_HAVE_LIBSODIUM
    auto result = socketwire::crypto::initialize();
    ASSERT_TRUE(result.ok) << "Failed to initialize crypto library";
    ASSERT_EQ(result.error, socketwire::crypto::CryptoError::None);
#else
    (void)socketwire::crypto::initialize();
#endif
  }
};


// Initialization Tests
TEST_F(CryptoTest, InitializeSucceeds)
{
  auto result = socketwire::crypto::initialize();
#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(result.ok) << "Initialization should succeed when libsodium is available";
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::None);
#else
  EXPECT_FALSE(result.ok) << "Initialization should fail without libsodium";
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::NotInitialized);
#endif
}

TEST_F(CryptoTest, MultipleInitializationCalls)
{
  // Should be safe to call multiple times
  auto result1 = socketwire::crypto::initialize();
  auto result2 = socketwire::crypto::initialize();
  auto result3 = socketwire::crypto::initialize();

#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(result1.ok);
  EXPECT_TRUE(result2.ok);
  EXPECT_TRUE(result3.ok);
#else
  EXPECT_FALSE(result1.ok);
  EXPECT_FALSE(result2.ok);
  EXPECT_FALSE(result3.ok);
#endif
}


// Result Tests
TEST_F(CryptoTest, ResultSuccess)
{
  auto result = socketwire::crypto::Result::success();
  EXPECT_TRUE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::None);
}

TEST_F(CryptoTest, ResultFailure)
{
  auto result = socketwire::crypto::Result::failure(socketwire::crypto::CryptoError::InvalidState);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::InvalidState);
}

TEST_F(CryptoTest, ResultAllErrorCodes)
{
  std::vector<socketwire::crypto::CryptoError> errors = {
    socketwire::crypto::CryptoError::None,
    socketwire::crypto::CryptoError::NotInitialized,
    socketwire::crypto::CryptoError::UnsupportedSuite,
    socketwire::crypto::CryptoError::InvalidState,
    socketwire::crypto::CryptoError::DecodeError,
    socketwire::crypto::CryptoError::KeyExchangeFailed,
    socketwire::crypto::CryptoError::SodiumFailure,
    socketwire::crypto::CryptoError::BufferTooSmall,
    socketwire::crypto::CryptoError::SequenceExpired,
    socketwire::crypto::CryptoError::DecryptFailed,
    socketwire::crypto::CryptoError::NotReady
  };

  for (auto err : errors) {
    auto result = socketwire::crypto::Result::failure(err);
    EXPECT_FALSE(result.ok) << "Result with error should not be ok";
    EXPECT_EQ(result.error, err) << "Error code should match";
  }
}


// CipherSuite Tests
TEST_F(CryptoTest, CipherSuiteSupported)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(socketwire::crypto::cipherSuiteSupported(socketwire::crypto::CipherSuite::XChaCha20Poly1305))
    << "XChaCha20Poly1305 should be supported with libsodium";
#endif

  EXPECT_FALSE(socketwire::crypto::cipherSuiteSupported(socketwire::crypto::CipherSuite::None))
    << "None cipher suite should never be supported";
}


// KeyPair Tests
TEST_F(CryptoTest, KeyPairGeneration)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto kp1 = socketwire::crypto::KeyPair::generate();
  EXPECT_TRUE(kp1.valid()) << "Generated keypair should be valid";

  auto kp2 = socketwire::crypto::KeyPair::generate();
  EXPECT_TRUE(kp2.valid()) << "Second generated keypair should be valid";

  // Keys should be different (extremely high probability)
  EXPECT_NE(kp1.publicKey, kp2.publicKey) << "Different keypairs should have different public keys";
  EXPECT_NE(kp1.secretKey, kp2.secretKey) << "Different keypairs should have different secret keys";
#else
  auto kp = socketwire::crypto::KeyPair::generate();
  EXPECT_FALSE(kp.valid()) << "KeyPair should be invalid without libsodium";
#endif
}

TEST_F(CryptoTest, KeyPairValid)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto kp = socketwire::crypto::KeyPair::generate();
  EXPECT_TRUE(kp.valid()) << "Generated keypair should be valid";

  // Zero out keys - should become invalid
  socketwire::crypto::KeyPair zero_kp;
  zero_kp.publicKey.fill(0);
  zero_kp.secretKey.fill(0);
  EXPECT_FALSE(zero_kp.valid()) << "All-zero keypair should be invalid";

  // Partially non-zero should be valid
  socketwire::crypto::KeyPair partial_kp;
  partial_kp.publicKey.fill(0);
  partial_kp.publicKey[0] = 1;
  partial_kp.secretKey.fill(0);
  EXPECT_TRUE(partial_kp.valid()) << "Keypair with non-zero public key should be valid";
#endif
}

TEST_F(CryptoTest, MultipleKeyPairGenerations)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  std::vector<socketwire::crypto::KeyPair> keypairs;
  const int count = 10;

  for (int i = 0; i < count; ++i) {
    auto kp = socketwire::crypto::KeyPair::generate();
    ASSERT_TRUE(kp.valid()) << "Keypair " << i << " should be valid";
    keypairs.push_back(kp);
  }

  // All should be unique
  for (int i = 0; i < count; ++i) {
    for (int j = i + 1; j < count; ++j) {
      EXPECT_NE(keypairs[i].publicKey, keypairs[j].publicKey)
        << "Keypairs " << i << " and " << j << " should have different public keys";
    }
  }
#endif
}


// SessionKeys Tests


TEST_F(CryptoTest, SessionKeysValid)
{
  socketwire::crypto::SessionKeys keys;

  // Default constructed should be invalid (all zeros)
  EXPECT_FALSE(keys.valid()) << "Default SessionKeys should be invalid";

#if SOCKETWIRE_HAVE_LIBSODIUM
  // Set some non-zero values
  keys.rx[0] = 1;
  EXPECT_TRUE(keys.valid()) << "SessionKeys with non-zero rx should be valid";

  socketwire::crypto::SessionKeys keys2;
  keys2.tx[0] = 1;
  EXPECT_TRUE(keys2.valid()) << "SessionKeys with non-zero tx should be valid";

  socketwire::crypto::SessionKeys keys3;
  keys3.rx[5] = 42;
  keys3.tx[10] = 99;
  EXPECT_TRUE(keys3.valid()) << "SessionKeys with both non-zero should be valid";
#endif
}


// NonceGenerator Tests


TEST_F(CryptoTest, NonceGeneratorInitRandom)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  socketwire::crypto::NonceGenerator ng1;
  socketwire::crypto::NonceGenerator ng2;

  ng1.initRandom();
  ng2.initRandom();

  // Counter should be zero after init
  EXPECT_EQ(ng1.counter, 0) << "Counter should be zero after initRandom";
  EXPECT_EQ(ng2.counter, 0) << "Counter should be zero after initRandom";

  // Base should be different (high probability)
  EXPECT_NE(ng1.base, ng2.base) << "Random bases should be different";
#endif
}

TEST_F(CryptoTest, NonceGeneratorFillNonce)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  socketwire::crypto::NonceGenerator ng;
  ng.initRandom();

  unsigned char nonce1[24];
  unsigned char nonce2[24];

  ng.fillNonce(nonce1);
  ng.fillNonce(nonce2); // Same counter

  // Should be identical since counter didn't change
  EXPECT_EQ(std::memcmp(nonce1, nonce2, 24), 0)
    << "fillNonce with same counter should produce same nonce";

  // Counter should still be zero
  EXPECT_EQ(ng.counter, 0) << "fillNonce should not increment counter";
#endif
}

TEST_F(CryptoTest, NonceGeneratorNextNonce)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  socketwire::crypto::NonceGenerator ng;
  ng.initRandom();

  unsigned char nonce1[24];
  unsigned char nonce2[24];
  unsigned char nonce3[24];

  ng.nextNonce(nonce1);
  EXPECT_EQ(ng.counter, 1) << "Counter should increment to 1";

  ng.nextNonce(nonce2);
  EXPECT_EQ(ng.counter, 2) << "Counter should increment to 2";

  ng.nextNonce(nonce3);
  EXPECT_EQ(ng.counter, 3) << "Counter should increment to 3";

  // All nonces should be different
  EXPECT_NE(std::memcmp(nonce1, nonce2, 24), 0) << "Sequential nonces should differ";
  EXPECT_NE(std::memcmp(nonce2, nonce3, 24), 0) << "Sequential nonces should differ";
  EXPECT_NE(std::memcmp(nonce1, nonce3, 24), 0) << "Sequential nonces should differ";

  // First 16 bytes (base) should be the same
  EXPECT_EQ(std::memcmp(nonce1, nonce2, 16), 0) << "Base portion should be same";
  EXPECT_EQ(std::memcmp(nonce2, nonce3, 16), 0) << "Base portion should be same";
#endif
}

TEST_F(CryptoTest, NonceGeneratorCounterOverflow)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  socketwire::crypto::NonceGenerator ng;
  ng.initRandom();
  ng.counter = 0xFFFFFFFFFFFFFFFEULL; // Near max

  unsigned char nonce1[24];
  unsigned char nonce2[24];
  unsigned char nonce3[24];

  ng.nextNonce(nonce1);
  EXPECT_EQ(ng.counter, 0xFFFFFFFFFFFFFFFFULL) << "Counter should be at max";

  ng.nextNonce(nonce2);
  EXPECT_EQ(ng.counter, 0ULL) << "Counter should wrap to 0";

  ng.nextNonce(nonce3);
  EXPECT_EQ(ng.counter, 1ULL) << "Counter should continue from 0";

  // All nonces should be different
  EXPECT_NE(std::memcmp(nonce1, nonce2, 24), 0);
  EXPECT_NE(std::memcmp(nonce2, nonce3, 24), 0);
#endif
}


// ClientHello Serialization Tests


TEST_F(CryptoTest, ClientHelloWriteRead)
{
  socketwire::crypto::ClientHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = socketwire::crypto::CipherSuite::None;

  // Fill nonce with test pattern
  for (size_t i = 0; i < original.nonce.size(); ++i) {
    original.nonce[i] = static_cast<unsigned char>(i);
  }

  // Test public key
  original.clientPub = {1, 2, 3, 4, 5, 6, 7, 8};

  // Write to BitStream
  socketwire::BitStream bs;
  socketwire::crypto::writeClientHello(bs, original);
  EXPECT_GT(bs.getSizeBytes(), 0) << "ClientHello should write data";

  // Read back
  socketwire::crypto::ClientHelloData read;
  bool success = socketwire::crypto::readClientHello(bs.getData(), bs.getSizeBytes(), read);
  EXPECT_TRUE(success) << "Should successfully read ClientHello";

  EXPECT_EQ(read.versionMajor, original.versionMajor);
  EXPECT_EQ(read.versionMinor, original.versionMinor);
  EXPECT_EQ(read.suite, original.suite);
  EXPECT_EQ(read.nonce, original.nonce);
  EXPECT_EQ(read.clientPub, original.clientPub);
}

TEST_F(CryptoTest, ClientHelloEmptyPublicKey)
{
  socketwire::crypto::ClientHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = socketwire::crypto::CipherSuite::None;
  original.clientPub.clear(); // Empty

  socketwire::BitStream bs;
  socketwire::crypto::writeClientHello(bs, original);

  socketwire::crypto::ClientHelloData read;
  bool success = socketwire::crypto::readClientHello(bs.getData(), bs.getSizeBytes(), read);
  EXPECT_TRUE(success);
  EXPECT_TRUE(read.clientPub.empty()) << "Empty public key should be preserved";
}

TEST_F(CryptoTest, ClientHelloInvalidData)
{
  // Test with empty buffer
  socketwire::crypto::ClientHelloData read;
  bool success = socketwire::crypto::readClientHello(nullptr, 0, read);
  EXPECT_FALSE(success) << "Should fail on empty data";

  // Test with wrong opcode
  socketwire::BitStream bs;
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(socketwire::crypto::HandshakeOpcode::ServerHello));
  success = socketwire::crypto::readClientHello(bs.getData(), bs.getSizeBytes(), read);
  EXPECT_FALSE(success) << "Should fail on wrong opcode";

  // Test with truncated data
  socketwire::crypto::ClientHelloData original;
  socketwire::BitStream bs2;
  socketwire::crypto::writeClientHello(bs2, original);
  success = socketwire::crypto::readClientHello(bs2.getData(), 5, read); // Too short
  EXPECT_FALSE(success) << "Should fail on truncated data";
}


// ServerHello Serialization Tests


TEST_F(CryptoTest, ServerHelloWriteRead)
{
  socketwire::crypto::ServerHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = socketwire::crypto::CipherSuite::None;

  for (size_t i = 0; i < original.nonce.size(); ++i) {
    original.nonce[i] = static_cast<unsigned char>(255 - i);
  }

  original.serverPub = {10, 20, 30, 40, 50};

  socketwire::BitStream bs;
  socketwire::crypto::writeServerHello(bs, original);
  EXPECT_GT(bs.getSizeBytes(), 0);

  socketwire::crypto::ServerHelloData read;
  bool success = socketwire::crypto::readServerHello(bs.getData(), bs.getSizeBytes(), read);
  EXPECT_TRUE(success);

  EXPECT_EQ(read.versionMajor, original.versionMajor);
  EXPECT_EQ(read.versionMinor, original.versionMinor);
  EXPECT_EQ(read.suite, original.suite);
  EXPECT_EQ(read.nonce, original.nonce);
  EXPECT_EQ(read.serverPub, original.serverPub);
}


// HandshakeState Tests - Basic Handshake Flow


TEST_F(CryptoTest, FullHandshakeClientServer)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto clientKeys = socketwire::crypto::KeyPair::generate();
  auto serverKeys = socketwire::crypto::KeyPair::generate();

  // 1. Client starts and sends hello
  socketwire::crypto::HandshakeState client;
  client.startClient(clientKeys);

  socketwire::BitStream clientHello;
  auto result = client.writeClientHello(clientHello);
  ASSERT_TRUE(result.ok);

  // 2. Server processes client hello
  socketwire::crypto::HandshakeState server;
  server.startServer(serverKeys);
  bool success = server.processClientHello(clientHello.getData(), clientHello.getSizeBytes());
  ASSERT_TRUE(success);
  ASSERT_TRUE(server.completed());

  // 3. Server sends hello
  socketwire::BitStream serverHello;
  result = server.writeServerHello(serverHello);
  ASSERT_TRUE(result.ok);

  // 4. Client processes server hello
  success = client.processServerHello(serverHello.getData(), serverHello.getSizeBytes());
  ASSERT_TRUE(success);
  ASSERT_TRUE(client.completed());

  // Both should have valid session keys
  EXPECT_TRUE(client.getSessionKeys().valid());
  EXPECT_TRUE(server.getSessionKeys().valid());
#endif
}


// CryptoContext Tests - Encryption/Decryption


TEST_F(CryptoTest, EncryptDecryptBasic)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  // Complete handshake
  auto clientKeys = socketwire::crypto::KeyPair::generate();
  auto serverKeys = socketwire::crypto::KeyPair::generate();

  socketwire::crypto::HandshakeState client;
  client.startClient(clientKeys);
  socketwire::BitStream clientHello;
  client.writeClientHello(clientHello);

  socketwire::crypto::HandshakeState server;
  server.startServer(serverKeys);
  server.processClientHello(clientHello.getData(), clientHello.getSizeBytes());

  socketwire::BitStream serverHello;
  server.writeServerHello(serverHello);
  client.processServerHello(serverHello.getData(), serverHello.getSizeBytes());

  auto clientCtx = client.createClientCryptoContext();
  auto serverCtx = server.createServerCryptoContext();

  // Test message
  const char* message = "Hello, World!";
  std::uint64_t seq = 1;

  // Client encrypts
  socketwire::BitStream encrypted;
  bool success = clientCtx.encrypt(seq,
    reinterpret_cast<const unsigned char*>(message),
    std::strlen(message),
    encrypted);
  ASSERT_TRUE(success) << "Encryption should succeed";
  EXPECT_GT(encrypted.getSizeBytes(), std::strlen(message)) << "Encrypted should be larger due to MAC";

  // Server decrypts
  socketwire::BitStream decrypted;
  success = serverCtx.decrypt(seq, encrypted.getData(), encrypted.getSizeBytes(), decrypted);
  ASSERT_TRUE(success) << "Decryption should succeed";
  EXPECT_EQ(decrypted.getSizeBytes(), std::strlen(message)) << "Decrypted size should match original";

  // Verify content
  std::vector<char> buffer(decrypted.getSizeBytes());
  decrypted.resetRead();
  decrypted.readBytes(buffer.data(), buffer.size());
  EXPECT_EQ(std::memcmp(buffer.data(), message, std::strlen(message)), 0)
    << "Decrypted content should match original";
#endif
}

TEST_F(CryptoTest, DecryptWithWrongSequence)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto clientKeys = socketwire::crypto::KeyPair::generate();
  auto serverKeys = socketwire::crypto::KeyPair::generate();

  socketwire::crypto::HandshakeState client;
  client.startClient(clientKeys);
  socketwire::BitStream clientHello;
  client.writeClientHello(clientHello);

  socketwire::crypto::HandshakeState server;
  server.startServer(serverKeys);
  server.processClientHello(clientHello.getData(), clientHello.getSizeBytes());

  socketwire::BitStream serverHello;
  server.writeServerHello(serverHello);
  client.processServerHello(serverHello.getData(), serverHello.getSizeBytes());

  auto clientCtx = client.createClientCryptoContext();
  auto serverCtx = server.createServerCryptoContext();

  const char* message = "Test message";
  std::uint64_t encryptSeq = 100;
  std::uint64_t decryptSeq = 200; // Wrong sequence

  socketwire::BitStream encrypted;
  clientCtx.encrypt(encryptSeq,
    reinterpret_cast<const unsigned char*>(message),
    std::strlen(message),
    encrypted);

  socketwire::BitStream decrypted;
  bool success = serverCtx.decrypt(decryptSeq, encrypted.getData(), encrypted.getSizeBytes(), decrypted);

  EXPECT_FALSE(success) << "Decryption with wrong sequence should fail";
#endif
}

TEST_F(CryptoTest, BidirectionalCommunication)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto clientKeys = socketwire::crypto::KeyPair::generate();
  auto serverKeys = socketwire::crypto::KeyPair::generate();

  // Complete handshake
  socketwire::crypto::HandshakeState client;
  client.startClient(clientKeys);
  socketwire::BitStream clientHello;
  client.writeClientHello(clientHello);

  socketwire::crypto::HandshakeState server;
  server.startServer(serverKeys);
  server.processClientHello(clientHello.getData(), clientHello.getSizeBytes());

  socketwire::BitStream serverHello;
  server.writeServerHello(serverHello);
  client.processServerHello(serverHello.getData(), serverHello.getSizeBytes());

  auto clientCtx = client.createClientCryptoContext();
  auto serverCtx = server.createServerCryptoContext();

  // Client -> Server
  const char* clientMsg = "Client to Server";
  socketwire::BitStream c2sEncrypted;
  clientCtx.encrypt(1,
    reinterpret_cast<const unsigned char*>(clientMsg),
    std::strlen(clientMsg),
    c2sEncrypted);

  socketwire::BitStream c2sDecrypted;
  bool success = serverCtx.decrypt(1, c2sEncrypted.getData(), c2sEncrypted.getSizeBytes(), c2sDecrypted);
  ASSERT_TRUE(success);

  std::vector<char> c2sBuffer(c2sDecrypted.getSizeBytes());
  c2sDecrypted.resetRead();
  c2sDecrypted.readBytes(c2sBuffer.data(), c2sBuffer.size());
  EXPECT_EQ(std::memcmp(c2sBuffer.data(), clientMsg, std::strlen(clientMsg)), 0);

  // Server -> Client
  const char* serverMsg = "Server to Client";
  socketwire::BitStream s2cEncrypted;
  serverCtx.encrypt(2,
    reinterpret_cast<const unsigned char*>(serverMsg),
    std::strlen(serverMsg),
    s2cEncrypted);

  socketwire::BitStream s2cDecrypted;
  success = clientCtx.decrypt(2, s2cEncrypted.getData(), s2cEncrypted.getSizeBytes(), s2cDecrypted);
  ASSERT_TRUE(success);

  std::vector<char> s2cBuffer(s2cDecrypted.getSizeBytes());
  s2cDecrypted.resetRead();
  s2cDecrypted.readBytes(s2cBuffer.data(), s2cBuffer.size());
  EXPECT_EQ(std::memcmp(s2cBuffer.data(), serverMsg, std::strlen(serverMsg)), 0);
#endif
}