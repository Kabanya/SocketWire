#include <gtest/gtest.h>

#include "crypto.hpp"

#include <array>
#include <cstring>
#include <vector>

namespace {

class CryptoTest : public ::testing::Test
{
protected:
  void SetUp() override
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    auto result = socketwire::crypto::initialize();
    ASSERT_TRUE(result.ok) << "Failed to initialize crypto library";
#else
    (void)socketwire::crypto::initialize();
#endif
  }
};

#if SOCKETWIRE_HAVE_LIBSODIUM
struct HandshakeFixture
{
  socketwire::crypto::HandshakeState client;
  socketwire::crypto::HandshakeState server;
  socketwire::crypto::CryptoContext clientContext;
  socketwire::crypto::CryptoContext serverContext;
};

HandshakeFixture completeHandshake()
{
  auto client_keys = socketwire::crypto::KeyPair::generate();
  auto server_keys = socketwire::crypto::KeyPair::generate();

  HandshakeFixture fixture;
  EXPECT_TRUE(fixture.client.start_client(client_keys, server_keys.publicKey).ok);
  EXPECT_TRUE(fixture.server.start_server(server_keys).ok);

  socketwire::BitStream client_hello;
  EXPECT_TRUE(fixture.client.write_client_hello(client_hello).ok);
  EXPECT_TRUE(fixture.server.process_client_hello(client_hello.getData(), client_hello.getSizeBytes()).ok);

  socketwire::BitStream server_hello;
  EXPECT_TRUE(fixture.server.write_server_hello(server_hello).ok);
  EXPECT_TRUE(fixture.client.process_server_hello(server_hello.getData(), server_hello.getSizeBytes()).ok);

  fixture.clientContext = fixture.client.create_client_crypto_context();
  fixture.serverContext = fixture.server.create_server_crypto_context();
  return fixture;
}
#endif

} // namespace

TEST_F(CryptoTest, InitializeSucceeds)
{
  auto result = socketwire::crypto::initialize();
#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::None);
#else
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::NotInitialized);
#endif
}

TEST_F(CryptoTest, MultipleInitializationCalls)
{
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

TEST_F(CryptoTest, ResultHelpers)
{
  auto success = socketwire::crypto::Result::success();
  EXPECT_TRUE(success.ok);
  EXPECT_EQ(success.error, socketwire::crypto::CryptoError::None);

  auto failure = socketwire::crypto::Result::failure(socketwire::crypto::CryptoError::InvalidState);
  EXPECT_FALSE(failure.ok);
  EXPECT_EQ(failure.error, socketwire::crypto::CryptoError::InvalidState);
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
    socketwire::crypto::CryptoError::NotReady,
    socketwire::crypto::CryptoError::InvalidPeerKey,
    socketwire::crypto::CryptoError::ReplayDetected
  };

  for (auto err : errors)
  {
    auto result = socketwire::crypto::Result::failure(err);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error, err);
    EXPECT_STRNE(socketwire::crypto::to_string(err), "Unknown");
  }
}

TEST_F(CryptoTest, CipherSuiteSupported)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(socketwire::crypto::cipher_suite_supported(socketwire::crypto::CipherSuite::XChaCha20Poly1305));
#else
  EXPECT_FALSE(socketwire::crypto::cipher_suite_supported(socketwire::crypto::CipherSuite::XChaCha20Poly1305));
#endif
  EXPECT_FALSE(socketwire::crypto::cipher_suite_supported(socketwire::crypto::CipherSuite::None));
}

TEST_F(CryptoTest, KeyPairGeneration)
{
  socketwire::crypto::KeyPair kp1;
  auto result = socketwire::crypto::KeyPair::generate(kp1);

#if SOCKETWIRE_HAVE_LIBSODIUM
  ASSERT_TRUE(result.ok);
  EXPECT_TRUE(kp1.valid());

  auto kp2 = socketwire::crypto::KeyPair::generate();
  EXPECT_TRUE(kp2.valid());
  EXPECT_NE(kp1.publicKey, kp2.publicKey);
  EXPECT_NE(kp1.secretKey, kp2.secretKey);
#else
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::NotInitialized);
  EXPECT_FALSE(kp1.valid());
#endif
}

TEST_F(CryptoTest, KeyPairValidRequiresPublicAndSecretKey)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto kp = socketwire::crypto::KeyPair::generate();
  EXPECT_TRUE(kp.valid());
#endif

  socketwire::crypto::KeyPair zero_kp;
  EXPECT_FALSE(zero_kp.valid());

  socketwire::crypto::KeyPair partial_kp;
  partial_kp.publicKey[0] = 1;
  EXPECT_FALSE(partial_kp.valid());
}

TEST_F(CryptoTest, SessionKeysValidRequiresBothDirections)
{
  socketwire::crypto::SessionKeys keys;
  EXPECT_FALSE(keys.valid());

  keys.rx[0] = 1;
  EXPECT_FALSE(keys.valid());

  keys.tx[0] = 1;
  EXPECT_TRUE(keys.valid());
}

TEST_F(CryptoTest, NonceGeneratorInitRandom)
{
  socketwire::crypto::NonceGenerator ng;
  auto result = ng.init_random();

#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(result.ok);
  EXPECT_TRUE(ng.initialized);
  EXPECT_EQ(ng.counter, 0u);
#else
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::NotInitialized);
  EXPECT_FALSE(ng.initialized);
#endif
}

TEST_F(CryptoTest, NonceGeneratorNextNonce)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  socketwire::crypto::NonceGenerator ng;
  ASSERT_TRUE(ng.init_random().ok);

  socketwire::crypto::Nonce nonce1;
  socketwire::crypto::Nonce nonce2;
  ASSERT_TRUE(ng.next_nonce(nonce1).ok);
  ASSERT_TRUE(ng.next_nonce(nonce2).ok);

  EXPECT_EQ(ng.counter, 2u);
  EXPECT_NE(nonce1, nonce2);
  EXPECT_EQ(std::memcmp(nonce1.data(), nonce2.data(), 16), 0);
#endif
}

TEST_F(CryptoTest, NonceGeneratorCounterOverflowFails)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  socketwire::crypto::NonceGenerator ng;
  ASSERT_TRUE(ng.init_random().ok);
  ng.counter = 0xFFFFFFFFFFFFFFFEULL;

  socketwire::crypto::Nonce nonce;
  EXPECT_TRUE(ng.next_nonce(nonce).ok);
  EXPECT_EQ(ng.counter, 0xFFFFFFFFFFFFFFFFULL);

  auto result = ng.next_nonce(nonce);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::SequenceExpired);
  EXPECT_EQ(ng.counter, 0xFFFFFFFFFFFFFFFFULL);
#endif
}

TEST_F(CryptoTest, ClientHelloWriteReadStrict)
{
  socketwire::crypto::ClientHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = socketwire::crypto::CipherSuite::XChaCha20Poly1305;

  for (std::size_t i = 0; i < original.nonce.size(); ++i)
    original.nonce[i] = static_cast<unsigned char>(i);
  for (std::size_t i = 0; i < original.clientPub.size(); ++i)
    original.clientPub[i] = static_cast<unsigned char>(i + 1);

  socketwire::BitStream bs;
  ASSERT_TRUE(socketwire::crypto::write_client_hello(bs, original).ok);
  EXPECT_EQ(bs.getSizeBytes(), socketwire::crypto::k_client_hello_size);

  socketwire::crypto::ClientHelloData read;
  auto result = socketwire::crypto::read_client_hello(bs.getData(), bs.getSizeBytes(), read);
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(read.versionMajor, original.versionMajor);
  EXPECT_EQ(read.versionMinor, original.versionMinor);
  EXPECT_EQ(read.suite, original.suite);
  EXPECT_EQ(read.nonce, original.nonce);
  EXPECT_EQ(read.clientPub, original.clientPub);
}

TEST_F(CryptoTest, ClientHelloInvalidData)
{
  socketwire::crypto::ClientHelloData read;
  auto result = socketwire::crypto::read_client_hello(nullptr, 0, read);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::DecodeError);

  socketwire::BitStream wrong_opcode;
  wrong_opcode.write<std::uint8_t>(static_cast<std::uint8_t>(socketwire::crypto::HandshakeOpcode::ServerHello));
  wrong_opcode.write<std::uint8_t>(1);
  wrong_opcode.write<std::uint8_t>(0);
  wrong_opcode.write<std::uint8_t>(static_cast<std::uint8_t>(socketwire::crypto::CipherSuite::XChaCha20Poly1305));
  std::array<unsigned char, socketwire::crypto::k_handshake_nonce_size> nonce{};
  std::array<unsigned char, socketwire::crypto::k_public_key_size> pub{};
  wrong_opcode.writeBytes(nonce.data(), nonce.size());
  wrong_opcode.writeBytes(pub.data(), pub.size());
  result = socketwire::crypto::read_client_hello(wrong_opcode.getData(), wrong_opcode.getSizeBytes(), read);
  EXPECT_FALSE(result.ok);

  socketwire::crypto::ClientHelloData original;
  socketwire::BitStream bs;
  ASSERT_TRUE(socketwire::crypto::write_client_hello(bs, original).ok);
  result = socketwire::crypto::read_client_hello(bs.getData(), bs.getSizeBytes() - 1, read);
  EXPECT_FALSE(result.ok);
  result = socketwire::crypto::read_client_hello(bs.getData(), bs.getSizeBytes() + 1, read);
  EXPECT_FALSE(result.ok);
}

TEST_F(CryptoTest, ServerHelloWriteReadStrict)
{
  socketwire::crypto::ServerHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = socketwire::crypto::CipherSuite::XChaCha20Poly1305;

  for (std::size_t i = 0; i < original.nonce.size(); ++i)
    original.nonce[i] = static_cast<unsigned char>(255 - i);
  for (std::size_t i = 0; i < original.serverPub.size(); ++i)
    original.serverPub[i] = static_cast<unsigned char>(i + 10);

  socketwire::BitStream bs;
  ASSERT_TRUE(socketwire::crypto::write_server_hello(bs, original).ok);
  EXPECT_EQ(bs.getSizeBytes(), socketwire::crypto::k_server_hello_size);

  socketwire::crypto::ServerHelloData read;
  auto result = socketwire::crypto::read_server_hello(bs.getData(), bs.getSizeBytes(), read);
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(read.versionMajor, original.versionMajor);
  EXPECT_EQ(read.versionMinor, original.versionMinor);
  EXPECT_EQ(read.suite, original.suite);
  EXPECT_EQ(read.nonce, original.nonce);
  EXPECT_EQ(read.serverPub, original.serverPub);
}

TEST_F(CryptoTest, FullHandshakeClientServer)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = completeHandshake();
  EXPECT_TRUE(fixture.client.completed());
  EXPECT_TRUE(fixture.server.completed());
  EXPECT_TRUE(fixture.client.get_session_keys().valid());
  EXPECT_TRUE(fixture.server.get_session_keys().valid());
  EXPECT_TRUE(fixture.clientContext.is_ready());
  EXPECT_TRUE(fixture.serverContext.is_ready());
#endif
}

TEST_F(CryptoTest, PinnedServerKeyMismatchFails)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto client_keys = socketwire::crypto::KeyPair::generate();
  auto server_keys = socketwire::crypto::KeyPair::generate();
  auto wrong_server_keys = socketwire::crypto::KeyPair::generate();

  socketwire::crypto::HandshakeState client;
  socketwire::crypto::HandshakeState server;
  ASSERT_TRUE(client.start_client(client_keys, wrong_server_keys.publicKey).ok);
  ASSERT_TRUE(server.start_server(server_keys).ok);

  socketwire::BitStream client_hello;
  ASSERT_TRUE(client.write_client_hello(client_hello).ok);
  ASSERT_TRUE(server.process_client_hello(client_hello.getData(), client_hello.getSizeBytes()).ok);

  socketwire::BitStream server_hello;
  ASSERT_TRUE(server.write_server_hello(server_hello).ok);
  auto result = client.process_server_hello(server_hello.getData(), server_hello.getSizeBytes());
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::InvalidPeerKey);
  EXPECT_FALSE(client.completed());
#endif
}

TEST_F(CryptoTest, EncryptDecryptBasic)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = completeHandshake();
  const char* message = "Hello, World!";
  std::uint64_t seq = 1;

  socketwire::BitStream encrypted;
  auto result = fixture.clientContext.encrypt(seq,
    reinterpret_cast<const unsigned char*>(message),
    std::strlen(message),
    encrypted);
  ASSERT_TRUE(result.ok);
  EXPECT_GT(encrypted.getSizeBytes(), std::strlen(message));

  socketwire::BitStream decrypted;
  result = fixture.serverContext.decrypt(seq, encrypted.getData(), encrypted.getSizeBytes(), decrypted);
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(decrypted.getSizeBytes(), std::strlen(message));

  std::vector<char> buffer(decrypted.getSizeBytes());
  decrypted.resetRead();
  decrypted.readBytes(buffer.data(), buffer.size());
  EXPECT_EQ(std::memcmp(buffer.data(), message, std::strlen(message)), 0);
#endif
}

TEST_F(CryptoTest, DecryptWithWrongSequenceFails)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = completeHandshake();
  const char* message = "Test message";

  socketwire::BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext.encrypt(100,
    reinterpret_cast<const unsigned char*>(message),
    std::strlen(message),
    encrypted).ok);

  socketwire::BitStream decrypted;
  auto result = fixture.serverContext.decrypt(200, encrypted.getData(), encrypted.getSizeBytes(), decrypted);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::DecryptFailed);
#endif
}

TEST_F(CryptoTest, CorruptedCiphertextFails)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = completeHandshake();
  const char* message = "Corrupt me";

  socketwire::BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext.encrypt(7,
    reinterpret_cast<const unsigned char*>(message),
    std::strlen(message),
    encrypted).ok);

  std::vector<std::uint8_t> corrupted(encrypted.getData(),
                                      encrypted.getData() + encrypted.getSizeBytes());
  corrupted.back() ^= 0x80;

  socketwire::BitStream decrypted;
  auto result = fixture.serverContext.decrypt(7, corrupted.data(), corrupted.size(), decrypted);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::DecryptFailed);
#endif
}

TEST_F(CryptoTest, ReplayedCiphertextFails)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = completeHandshake();
  const char* message = "Replay me";

  socketwire::BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext.encrypt(9,
    reinterpret_cast<const unsigned char*>(message),
    std::strlen(message),
    encrypted).ok);

  socketwire::BitStream decrypted;
  ASSERT_TRUE(fixture.serverContext.decrypt(9, encrypted.getData(), encrypted.getSizeBytes(), decrypted).ok);

  socketwire::BitStream replay;
  auto result = fixture.serverContext.decrypt(9, encrypted.getData(), encrypted.getSizeBytes(), replay);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::ReplayDetected);
#endif
}

TEST_F(CryptoTest, BidirectionalCommunication)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = completeHandshake();

  const char* client_msg = "Client to Server";
  socketwire::BitStream c2s_encrypted;
  ASSERT_TRUE(fixture.clientContext.encrypt(1,
    reinterpret_cast<const unsigned char*>(client_msg),
    std::strlen(client_msg),
    c2s_encrypted).ok);

  socketwire::BitStream c2s_decrypted;
  ASSERT_TRUE(fixture.serverContext.decrypt(1,
    c2s_encrypted.getData(),
    c2s_encrypted.getSizeBytes(),
    c2s_decrypted).ok);

  const char* server_msg = "Server to Client";
  socketwire::BitStream s2c_encrypted;
  ASSERT_TRUE(fixture.serverContext.encrypt(2,
    reinterpret_cast<const unsigned char*>(server_msg),
    std::strlen(server_msg),
    s2c_encrypted).ok);

  socketwire::BitStream s2c_decrypted;
  ASSERT_TRUE(fixture.clientContext.decrypt(2,
    s2c_encrypted.getData(),
    s2c_encrypted.getSizeBytes(),
    s2c_decrypted).ok);
#endif
}
