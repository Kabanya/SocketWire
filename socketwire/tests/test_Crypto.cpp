#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <vector>

#include "crypto.hpp"

namespace {

class CryptoTest : public ::testing::Test {
 protected:
  void SetUp() override {
#if SOCKETWIRE_HAVE_LIBSODIUM
    auto result = socketwire::crypto::Initialize();
    ASSERT_TRUE(result.ok) << "Failed to initialize crypto library";
#else
    (void)socketwire::crypto::initialize();
#endif
  }
};

#if SOCKETWIRE_HAVE_LIBSODIUM
struct HandshakeFixture {
  socketwire::crypto::HandshakeState client;
  socketwire::crypto::HandshakeState server;
  socketwire::crypto::CryptoContext clientContext;
  socketwire::crypto::CryptoContext serverContext;
};

HandshakeFixture CompleteHandshake() {
  auto client_keys = socketwire::crypto::KeyPair::Generate();
  auto server_keys = socketwire::crypto::KeyPair::Generate();

  HandshakeFixture fixture;
  EXPECT_TRUE(
      fixture.client.StartClient(client_keys, server_keys.publicKey).ok);
  EXPECT_TRUE(fixture.server.StartServer(server_keys).ok);

  socketwire::BitStream client_hello;
  EXPECT_TRUE(fixture.client.WriteClientHello(client_hello).ok);
  EXPECT_TRUE(fixture.server
                  .ProcessClientHello(client_hello.GetData(),
                                      client_hello.GetSizeBytes())
                  .ok);

  socketwire::BitStream server_hello;
  EXPECT_TRUE(fixture.server.WriteServerHello(server_hello).ok);
  EXPECT_TRUE(fixture.client
                  .ProcessServerHello(server_hello.GetData(),
                                      server_hello.GetSizeBytes())
                  .ok);

  fixture.clientContext = fixture.client.CreateClientCryptoContext();
  fixture.serverContext = fixture.server.CreateServerCryptoContext();
  return fixture;
}
#endif

}  // namespace

TEST_F(CryptoTest, InitializeSucceeds) {
  auto result = socketwire::crypto::Initialize();
#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::kNone);
#else
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::NotInitialized);
#endif
}

TEST_F(CryptoTest, MultipleInitializationCalls) {
  auto result1 = socketwire::crypto::Initialize();
  auto result2 = socketwire::crypto::Initialize();
  auto result3 = socketwire::crypto::Initialize();

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

TEST_F(CryptoTest, ResultHelpers) {
  auto success = socketwire::crypto::Result::Success();
  EXPECT_TRUE(success.ok);
  EXPECT_EQ(success.error, socketwire::crypto::CryptoError::kNone);

  auto failure = socketwire::crypto::Result::Failure(
      socketwire::crypto::CryptoError::kInvalidState);
  EXPECT_FALSE(failure.ok);
  EXPECT_EQ(failure.error, socketwire::crypto::CryptoError::kInvalidState);
}

TEST_F(CryptoTest, ResultAllErrorCodes) {
  const std::vector<socketwire::crypto::CryptoError> errors = {
      socketwire::crypto::CryptoError::kNone,
      socketwire::crypto::CryptoError::kNotInitialized,
      socketwire::crypto::CryptoError::kUnsupportedSuite,
      socketwire::crypto::CryptoError::kInvalidState,
      socketwire::crypto::CryptoError::kDecodeError,
      socketwire::crypto::CryptoError::kKeyExchangeFailed,
      socketwire::crypto::CryptoError::kSodiumFailure,
      socketwire::crypto::CryptoError::kBufferTooSmall,
      socketwire::crypto::CryptoError::kSequenceExpired,
      socketwire::crypto::CryptoError::kDecryptFailed,
      socketwire::crypto::CryptoError::kNotReady,
      socketwire::crypto::CryptoError::kInvalidPeerKey,
      socketwire::crypto::CryptoError::kReplayDetected};

  for (auto err : errors) {
    auto result = socketwire::crypto::Result::Failure(err);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error, err);
    EXPECT_STRNE(socketwire::crypto::ToString(err), "Unknown");
  }
}

TEST_F(CryptoTest, CipherSuiteSupported) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(socketwire::crypto::CipherSuiteSupported(
      socketwire::crypto::CipherSuite::kXChaCha20Poly1305));
#else
  EXPECT_FALSE(socketwire::crypto::cipher_suite_supported(
      socketwire::crypto::CipherSuite::XChaCha20Poly1305));
#endif
  EXPECT_FALSE(socketwire::crypto::CipherSuiteSupported(
      socketwire::crypto::CipherSuite::kNone));
}

TEST_F(CryptoTest, KeyPairGeneration) {
  socketwire::crypto::KeyPair kp1;
  auto result = socketwire::crypto::KeyPair::Generate(kp1);

#if SOCKETWIRE_HAVE_LIBSODIUM
  ASSERT_TRUE(result.ok);
  EXPECT_TRUE(kp1.Valid());

  auto kp2 = socketwire::crypto::KeyPair::Generate();
  EXPECT_TRUE(kp2.Valid());
  EXPECT_NE(kp1.publicKey, kp2.publicKey);
  EXPECT_NE(kp1.secretKey, kp2.secretKey);
#else
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::NotInitialized);
  EXPECT_FALSE(kp1.valid());
#endif
}

TEST_F(CryptoTest, KeyPairValidRequiresPublicAndSecretKey) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto kp = socketwire::crypto::KeyPair::Generate();
  EXPECT_TRUE(kp.Valid());
#endif

  const socketwire::crypto::KeyPair zero_kp;
  EXPECT_FALSE(zero_kp.Valid());

  socketwire::crypto::KeyPair partial_kp;
  partial_kp.publicKey.at(0) = 1;
  EXPECT_FALSE(partial_kp.Valid());
}

TEST_F(CryptoTest, SessionKeysValidRequiresBothDirections) {
  socketwire::crypto::SessionKeys keys;
  EXPECT_FALSE(keys.Valid());

  keys.rx.at(0) = 1;
  EXPECT_FALSE(keys.Valid());

  keys.tx.at(0) = 1;
  EXPECT_TRUE(keys.Valid());
}

TEST_F(CryptoTest, NonceGeneratorInitRandom) {
  socketwire::crypto::NonceGenerator ng;
  auto result = ng.InitRandom();

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

TEST_F(CryptoTest, NonceGeneratorNextNonce) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  socketwire::crypto::NonceGenerator ng;
  ASSERT_TRUE(ng.InitRandom().ok);

  socketwire::crypto::Nonce nonce1;
  socketwire::crypto::Nonce nonce2;
  ASSERT_TRUE(ng.NextNonce(nonce1).ok);
  ASSERT_TRUE(ng.NextNonce(nonce2).ok);

  EXPECT_EQ(ng.counter, 2u);
  EXPECT_NE(nonce1, nonce2);
  EXPECT_EQ(std::memcmp(nonce1.data(), nonce2.data(), 16), 0);
#endif
}

TEST_F(CryptoTest, NonceGeneratorCounterOverflowFails) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  socketwire::crypto::NonceGenerator ng;
  ASSERT_TRUE(ng.InitRandom().ok);
  ng.counter = 0xFFFFFFFFFFFFFFFEULL;

  socketwire::crypto::Nonce nonce;
  EXPECT_TRUE(ng.NextNonce(nonce).ok);
  EXPECT_EQ(ng.counter, 0xFFFFFFFFFFFFFFFFULL);

  auto result = ng.NextNonce(nonce);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::kSequenceExpired);
  EXPECT_EQ(ng.counter, 0xFFFFFFFFFFFFFFFFULL);
#endif
}

TEST_F(CryptoTest, ClientHelloWriteReadStrict) {
  socketwire::crypto::ClientHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = socketwire::crypto::CipherSuite::kXChaCha20Poly1305;

  for (std::size_t i = 0; i < original.nonce.size(); ++i) {
    original.nonce.at(i) = static_cast<unsigned char>(i);
  }
  for (std::size_t i = 0; i < original.clientPub.size(); ++i) {
    original.clientPub.at(i) = static_cast<unsigned char>(i + 1);
  }

  socketwire::BitStream bs;
  ASSERT_TRUE(socketwire::crypto::WriteClientHello(bs, original).ok);
  EXPECT_EQ(bs.GetSizeBytes(), socketwire::crypto::kClientHelloSize);

  socketwire::crypto::ClientHelloData read;
  auto result = socketwire::crypto::ReadClientHello(bs.GetData(),
                                                    bs.GetSizeBytes(), read);
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(read.versionMajor, original.versionMajor);
  EXPECT_EQ(read.versionMinor, original.versionMinor);
  EXPECT_EQ(read.suite, original.suite);
  EXPECT_EQ(read.nonce, original.nonce);
  EXPECT_EQ(read.clientPub, original.clientPub);
}

TEST_F(CryptoTest, ClientHelloInvalidData) {
  socketwire::crypto::ClientHelloData read;
  auto result = socketwire::crypto::ReadClientHello(nullptr, 0, read);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::kDecodeError);

  socketwire::BitStream wrong_opcode;
  wrong_opcode.Write<std::uint8_t>(static_cast<std::uint8_t>(
      socketwire::crypto::HandshakeOpcode::kServerHello));
  wrong_opcode.Write<std::uint8_t>(1);
  wrong_opcode.Write<std::uint8_t>(0);
  wrong_opcode.Write<std::uint8_t>(static_cast<std::uint8_t>(
      socketwire::crypto::CipherSuite::kXChaCha20Poly1305));
  std::array<unsigned char, socketwire::crypto::kHandshakeNonceSize> nonce{};
  std::array<unsigned char, socketwire::crypto::kPublicKeySize> pub{};
  wrong_opcode.WriteBytes(nonce.data(), nonce.size());
  wrong_opcode.WriteBytes(pub.data(), pub.size());
  result = socketwire::crypto::ReadClientHello(
      wrong_opcode.GetData(), wrong_opcode.GetSizeBytes(), read);
  EXPECT_FALSE(result.ok);

  const socketwire::crypto::ClientHelloData original;
  socketwire::BitStream bs;
  ASSERT_TRUE(socketwire::crypto::WriteClientHello(bs, original).ok);
  result = socketwire::crypto::ReadClientHello(bs.GetData(),
                                               bs.GetSizeBytes() - 1, read);
  EXPECT_FALSE(result.ok);
  result = socketwire::crypto::ReadClientHello(bs.GetData(),
                                               bs.GetSizeBytes() + 1, read);
  EXPECT_FALSE(result.ok);
}

TEST_F(CryptoTest, ServerHelloWriteReadStrict) {
  socketwire::crypto::ServerHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = socketwire::crypto::CipherSuite::kXChaCha20Poly1305;

  for (std::size_t i = 0; i < original.nonce.size(); ++i) {
    original.nonce.at(i) = static_cast<unsigned char>(255 - i);
  }
  for (std::size_t i = 0; i < original.serverPub.size(); ++i) {
    original.serverPub.at(i) = static_cast<unsigned char>(i + 10);
  }

  socketwire::BitStream bs;
  ASSERT_TRUE(socketwire::crypto::WriteServerHello(bs, original).ok);
  EXPECT_EQ(bs.GetSizeBytes(), socketwire::crypto::kServerHelloSize);

  socketwire::crypto::ServerHelloData read;
  auto result = socketwire::crypto::ReadServerHello(bs.GetData(),
                                                    bs.GetSizeBytes(), read);
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(read.versionMajor, original.versionMajor);
  EXPECT_EQ(read.versionMinor, original.versionMinor);
  EXPECT_EQ(read.suite, original.suite);
  EXPECT_EQ(read.nonce, original.nonce);
  EXPECT_EQ(read.serverPub, original.serverPub);
}

TEST_F(CryptoTest, FullHandshakeClientServer) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();
  EXPECT_TRUE(fixture.client.Completed());
  EXPECT_TRUE(fixture.server.Completed());
  EXPECT_TRUE(fixture.client.GetSessionKeys().Valid());
  EXPECT_TRUE(fixture.server.GetSessionKeys().Valid());
  EXPECT_TRUE(fixture.clientContext.IsReady());
  EXPECT_TRUE(fixture.serverContext.IsReady());
#endif
}

TEST_F(CryptoTest, PinnedServerKeyMismatchFails) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto client_keys = socketwire::crypto::KeyPair::Generate();
  auto server_keys = socketwire::crypto::KeyPair::Generate();
  auto wrong_server_keys = socketwire::crypto::KeyPair::Generate();

  socketwire::crypto::HandshakeState client;
  socketwire::crypto::HandshakeState server;
  ASSERT_TRUE(client.StartClient(client_keys, wrong_server_keys.publicKey).ok);
  ASSERT_TRUE(server.StartServer(server_keys).ok);

  socketwire::BitStream client_hello;
  ASSERT_TRUE(client.WriteClientHello(client_hello).ok);
  ASSERT_TRUE(server
                  .ProcessClientHello(client_hello.GetData(),
                                      client_hello.GetSizeBytes())
                  .ok);

  socketwire::BitStream server_hello;
  ASSERT_TRUE(server.WriteServerHello(server_hello).ok);
  auto result = client.ProcessServerHello(server_hello.GetData(),
                                          server_hello.GetSizeBytes());
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::kInvalidPeerKey);
  EXPECT_FALSE(client.Completed());
#endif
}

TEST_F(CryptoTest, EncryptDecryptBasic) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();
  const char* message = "Hello, World!";
  std::uint64_t seq = 1;

  socketwire::BitStream encrypted;
  auto result = fixture.clientContext.Encrypt(
      seq, reinterpret_cast<const unsigned char*>(message),
      std::strlen(message), encrypted);
  ASSERT_TRUE(result.ok);
  EXPECT_GT(encrypted.GetSizeBytes(), std::strlen(message));

  socketwire::BitStream decrypted;
  result = fixture.serverContext.Decrypt(seq, encrypted.GetData(),
                                         encrypted.GetSizeBytes(), decrypted);
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(decrypted.GetSizeBytes(), std::strlen(message));

  std::vector<char> buffer(decrypted.GetSizeBytes());
  decrypted.ResetRead();
  decrypted.ReadBytes(buffer.data(), buffer.size());
  EXPECT_EQ(std::memcmp(buffer.data(), message, std::strlen(message)), 0);
#endif
}

TEST_F(CryptoTest, DecryptWithWrongSequenceFails) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();
  const char* message = "Test message";

  socketwire::BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Encrypt(100, reinterpret_cast<const unsigned char*>(message),
                           std::strlen(message), encrypted)
                  .ok);

  socketwire::BitStream decrypted;
  auto result = fixture.serverContext.Decrypt(
      200, encrypted.GetData(), encrypted.GetSizeBytes(), decrypted);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::kDecryptFailed);
#endif
}

TEST_F(CryptoTest, CorruptedCiphertextFails) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();
  const char* message = "Corrupt me";

  socketwire::BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Encrypt(7, reinterpret_cast<const unsigned char*>(message),
                           std::strlen(message), encrypted)
                  .ok);

  std::vector<std::uint8_t> corrupted(
      encrypted.GetData(), encrypted.GetData() + encrypted.GetSizeBytes());
  corrupted.back() ^= 0x80;

  socketwire::BitStream decrypted;
  auto result = fixture.serverContext.Decrypt(7, corrupted.data(),
                                              corrupted.size(), decrypted);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::kDecryptFailed);
#endif
}

TEST_F(CryptoTest, ReplayedCiphertextFails) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();
  const char* message = "Replay me";

  socketwire::BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Encrypt(9, reinterpret_cast<const unsigned char*>(message),
                           std::strlen(message), encrypted)
                  .ok);

  socketwire::BitStream decrypted;
  ASSERT_TRUE(
      fixture.serverContext
          .Decrypt(9, encrypted.GetData(), encrypted.GetSizeBytes(), decrypted)
          .ok);

  socketwire::BitStream replay;
  auto result = fixture.serverContext.Decrypt(9, encrypted.GetData(),
                                              encrypted.GetSizeBytes(), replay);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, socketwire::crypto::CryptoError::kReplayDetected);
#endif
}

TEST_F(CryptoTest, BidirectionalCommunication) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();

  const char* client_msg = "Client to Server";
  socketwire::BitStream c2s_encrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Encrypt(1,
                           reinterpret_cast<const unsigned char*>(client_msg),
                           std::strlen(client_msg), c2s_encrypted)
                  .ok);

  socketwire::BitStream c2s_decrypted;
  ASSERT_TRUE(fixture.serverContext
                  .Decrypt(1, c2s_encrypted.GetData(),
                           c2s_encrypted.GetSizeBytes(), c2s_decrypted)
                  .ok);

  const char* server_msg = "Server to Client";
  socketwire::BitStream s2c_encrypted;
  ASSERT_TRUE(fixture.serverContext
                  .Encrypt(2,
                           reinterpret_cast<const unsigned char*>(server_msg),
                           std::strlen(server_msg), s2c_encrypted)
                  .ok);

  socketwire::BitStream s2c_decrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Decrypt(2, s2c_encrypted.GetData(),
                           s2c_encrypted.GetSizeBytes(), s2c_decrypted)
                  .ok);
#endif
}
