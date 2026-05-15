#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <vector>

#include "crypto.hpp"

using namespace socketwire;  // NOLINT

namespace {

class CryptoTest : public ::testing::Test {
 protected:
  void SetUp() override {
#if SOCKETWIRE_HAVE_LIBSODIUM
    auto result = crypto::Initialize();
    ASSERT_TRUE(result.ok) << "Failed to initialize crypto library";
#else
    (void)crypto::Initialize();
#endif
  }
};

#if SOCKETWIRE_HAVE_LIBSODIUM
struct HandshakeFixture {
  crypto::HandshakeState client;
  crypto::HandshakeState server;
  crypto::CryptoContext clientContext;
  crypto::CryptoContext serverContext;
};

HandshakeFixture CompleteHandshake() {
  auto client_keys = crypto::KeyPair::Generate();
  auto server_keys = crypto::KeyPair::Generate();

  HandshakeFixture fixture;
  EXPECT_TRUE(
      fixture.client.StartClient(client_keys, server_keys.publicKey).ok);
  EXPECT_TRUE(fixture.server.StartServer(server_keys).ok);

  BitStream client_hello;
  EXPECT_TRUE(fixture.client.WriteClientHello(client_hello).ok);
  EXPECT_TRUE(fixture.server
                  .ProcessClientHello(client_hello.GetData(),
                                      client_hello.GetSizeBytes())
                  .ok);

  BitStream server_hello;
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
  auto result = crypto::Initialize();
#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kNone);
#else
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kNotInitialized);
#endif
}

TEST_F(CryptoTest, MultipleInitializationCalls) {
  auto result1 = crypto::Initialize();
  auto result2 = crypto::Initialize();
  auto result3 = crypto::Initialize();

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
  auto success = crypto::Result::Success();
  EXPECT_TRUE(success.ok);
  EXPECT_EQ(success.error, crypto::CryptoError::kNone);

  auto failure = crypto::Result::Failure(crypto::CryptoError::kInvalidState);
  EXPECT_FALSE(failure.ok);
  EXPECT_EQ(failure.error, crypto::CryptoError::kInvalidState);
}

TEST_F(CryptoTest, ResultAllErrorCodes) {
  const std::vector<crypto::CryptoError> errors = {
      crypto::CryptoError::kNone,
      crypto::CryptoError::kNotInitialized,
      crypto::CryptoError::kUnsupportedSuite,
      crypto::CryptoError::kInvalidState,
      crypto::CryptoError::kDecodeError,
      crypto::CryptoError::kKeyExchangeFailed,
      crypto::CryptoError::kSodiumFailure,
      crypto::CryptoError::kBufferTooSmall,
      crypto::CryptoError::kSequenceExpired,
      crypto::CryptoError::kDecryptFailed,
      crypto::CryptoError::kNotReady,
      crypto::CryptoError::kInvalidPeerKey,
      crypto::CryptoError::kReplayDetected};

  for (auto err : errors) {
    auto result = crypto::Result::Failure(err);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error, err);
    EXPECT_STRNE(crypto::ToString(err), "Unknown");
  }
}

TEST_F(CryptoTest, CipherSuiteSupported) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(
      crypto::CipherSuiteSupported(crypto::CipherSuite::kXChaCha20Poly1305));
#else
  EXPECT_FALSE(
      crypto::CipherSuiteSupported(crypto::CipherSuite::kXChaCha20Poly1305));
#endif
  EXPECT_FALSE(crypto::CipherSuiteSupported(crypto::CipherSuite::kNone));
}

TEST_F(CryptoTest, KeyPairGeneration) {
  crypto::KeyPair kp1;
  auto result = crypto::KeyPair::Generate(kp1);

#if SOCKETWIRE_HAVE_LIBSODIUM
  ASSERT_TRUE(result.ok);
  EXPECT_TRUE(kp1.Valid());

  auto kp2 = crypto::KeyPair::Generate();
  EXPECT_TRUE(kp2.Valid());
  EXPECT_NE(kp1.publicKey, kp2.publicKey);
  EXPECT_NE(kp1.secretKey, kp2.secretKey);
#else
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kNotInitialized);
  EXPECT_FALSE(kp1.Valid());
#endif
}

TEST_F(CryptoTest, KeyPairValidRequiresPublicAndSecretKey) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto kp = crypto::KeyPair::Generate();
  EXPECT_TRUE(kp.Valid());
#endif

  const crypto::KeyPair zero_kp;
  EXPECT_FALSE(zero_kp.Valid());

  crypto::KeyPair partial_kp;
  partial_kp.publicKey.at(0) = 1;
  EXPECT_FALSE(partial_kp.Valid());
}

TEST_F(CryptoTest, SessionKeysValidRequiresBothDirections) {
  crypto::SessionKeys keys;
  EXPECT_FALSE(keys.Valid());

  keys.rx.at(0) = 1;
  EXPECT_FALSE(keys.Valid());

  keys.tx.at(0) = 1;
  EXPECT_TRUE(keys.Valid());
}

TEST_F(CryptoTest, NonceGeneratorInitRandom) {
  crypto::NonceGenerator ng;
  auto result = ng.InitRandom();

#if SOCKETWIRE_HAVE_LIBSODIUM
  EXPECT_TRUE(result.ok);
  EXPECT_TRUE(ng.initialized);
  EXPECT_EQ(ng.counter, 0u);
#else
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kNotInitialized);
  EXPECT_FALSE(ng.initialized);
#endif
}

TEST_F(CryptoTest, NonceGeneratorNextNonce) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  crypto::NonceGenerator ng;
  ASSERT_TRUE(ng.InitRandom().ok);

  crypto::Nonce nonce1;
  crypto::Nonce nonce2;
  ASSERT_TRUE(ng.NextNonce(nonce1).ok);
  ASSERT_TRUE(ng.NextNonce(nonce2).ok);

  EXPECT_EQ(ng.counter, 2u);
  EXPECT_NE(nonce1, nonce2);
  EXPECT_EQ(std::memcmp(nonce1.data(), nonce2.data(), 16), 0);
#endif
}

TEST_F(CryptoTest, NonceGeneratorCounterOverflowFails) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  crypto::NonceGenerator ng;
  ASSERT_TRUE(ng.InitRandom().ok);
  ng.counter = 0xFFFFFFFFFFFFFFFEULL;

  crypto::Nonce nonce;
  EXPECT_TRUE(ng.NextNonce(nonce).ok);
  EXPECT_EQ(ng.counter, 0xFFFFFFFFFFFFFFFFULL);

  auto result = ng.NextNonce(nonce);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kSequenceExpired);
  EXPECT_EQ(ng.counter, 0xFFFFFFFFFFFFFFFFULL);
#endif
}

TEST_F(CryptoTest, ClientHelloWriteReadStrict) {
  crypto::ClientHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = crypto::CipherSuite::kXChaCha20Poly1305;

  for (std::size_t i = 0; i < original.nonce.size(); ++i) {
    original.nonce.at(i) = static_cast<unsigned char>(i);
  }
  for (std::size_t i = 0; i < original.clientPub.size(); ++i) {
    original.clientPub.at(i) = static_cast<unsigned char>(i + 1);
  }

  BitStream bs;
  ASSERT_TRUE(crypto::WriteClientHello(bs, original).ok);
  EXPECT_EQ(bs.GetSizeBytes(), crypto::kClientHelloSize);

  crypto::ClientHelloData read;
  auto result = crypto::ReadClientHello(bs.GetData(), bs.GetSizeBytes(), read);
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(read.versionMajor, original.versionMajor);
  EXPECT_EQ(read.versionMinor, original.versionMinor);
  EXPECT_EQ(read.suite, original.suite);
  EXPECT_EQ(read.nonce, original.nonce);
  EXPECT_EQ(read.clientPub, original.clientPub);
}

TEST_F(CryptoTest, ClientHelloInvalidData) {
  crypto::ClientHelloData read;
  auto result = crypto::ReadClientHello(nullptr, 0, read);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kDecodeError);

  BitStream wrong_opcode;
  wrong_opcode.Write<std::uint8_t>(
      static_cast<std::uint8_t>(crypto::HandshakeOpcode::kServerHello));
  wrong_opcode.Write<std::uint8_t>(1);
  wrong_opcode.Write<std::uint8_t>(0);
  wrong_opcode.Write<std::uint8_t>(
      static_cast<std::uint8_t>(crypto::CipherSuite::kXChaCha20Poly1305));
  std::array<unsigned char, crypto::kHandshakeNonceSize> nonce{};
  std::array<unsigned char, crypto::kPublicKeySize> pub{};
  wrong_opcode.WriteBytes(nonce.data(), nonce.size());
  wrong_opcode.WriteBytes(pub.data(), pub.size());
  result = crypto::ReadClientHello(wrong_opcode.GetData(),
                                   wrong_opcode.GetSizeBytes(), read);
  EXPECT_FALSE(result.ok);

  const crypto::ClientHelloData original;
  BitStream bs;
  ASSERT_TRUE(crypto::WriteClientHello(bs, original).ok);
  result = crypto::ReadClientHello(bs.GetData(), bs.GetSizeBytes() - 1, read);
  EXPECT_FALSE(result.ok);
  result = crypto::ReadClientHello(bs.GetData(), bs.GetSizeBytes() + 1, read);
  EXPECT_FALSE(result.ok);
}

TEST_F(CryptoTest, ServerHelloWriteReadStrict) {
  crypto::ServerHelloData original;
  original.versionMajor = 1;
  original.versionMinor = 0;
  original.suite = crypto::CipherSuite::kXChaCha20Poly1305;

  for (std::size_t i = 0; i < original.nonce.size(); ++i) {
    original.nonce.at(i) = static_cast<unsigned char>(255 - i);
  }
  for (std::size_t i = 0; i < original.serverPub.size(); ++i) {
    original.serverPub.at(i) = static_cast<unsigned char>(i + 10);
  }

  BitStream bs;
  ASSERT_TRUE(crypto::WriteServerHello(bs, original).ok);
  EXPECT_EQ(bs.GetSizeBytes(), crypto::kServerHelloSize);

  crypto::ServerHelloData read;
  auto result = crypto::ReadServerHello(bs.GetData(), bs.GetSizeBytes(), read);
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
  auto client_keys = crypto::KeyPair::Generate();
  auto server_keys = crypto::KeyPair::Generate();
  auto wrong_server_keys = crypto::KeyPair::Generate();

  crypto::HandshakeState client;
  crypto::HandshakeState server;
  ASSERT_TRUE(client.StartClient(client_keys, wrong_server_keys.publicKey).ok);
  ASSERT_TRUE(server.StartServer(server_keys).ok);

  BitStream client_hello;
  ASSERT_TRUE(client.WriteClientHello(client_hello).ok);
  ASSERT_TRUE(server
                  .ProcessClientHello(client_hello.GetData(),
                                      client_hello.GetSizeBytes())
                  .ok);

  BitStream server_hello;
  ASSERT_TRUE(server.WriteServerHello(server_hello).ok);
  auto result = client.ProcessServerHello(server_hello.GetData(),
                                          server_hello.GetSizeBytes());
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kInvalidPeerKey);
  EXPECT_FALSE(client.Completed());
#endif
}

TEST_F(CryptoTest, EncryptDecryptBasic) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();
  const char* message = "Hello, World!";
  std::uint64_t seq = 1;

  BitStream encrypted;
  auto result = fixture.clientContext.Encrypt(
      seq, reinterpret_cast<const unsigned char*>(message),
      std::strlen(message), encrypted);
  ASSERT_TRUE(result.ok);
  EXPECT_GT(encrypted.GetSizeBytes(), std::strlen(message));

  BitStream decrypted;
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

  BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Encrypt(100, reinterpret_cast<const unsigned char*>(message),
                           std::strlen(message), encrypted)
                  .ok);

  BitStream decrypted;
  auto result = fixture.serverContext.Decrypt(
      200, encrypted.GetData(), encrypted.GetSizeBytes(), decrypted);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kDecryptFailed);
#endif
}

TEST_F(CryptoTest, CorruptedCiphertextFails) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();
  const char* message = "Corrupt me";

  BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Encrypt(7, reinterpret_cast<const unsigned char*>(message),
                           std::strlen(message), encrypted)
                  .ok);

  std::vector<std::uint8_t> corrupted(
      encrypted.GetData(), encrypted.GetData() + encrypted.GetSizeBytes());
  corrupted.back() ^= 0x80;

  BitStream decrypted;
  auto result = fixture.serverContext.Decrypt(7, corrupted.data(),
                                              corrupted.size(), decrypted);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kDecryptFailed);
#endif
}

TEST_F(CryptoTest, ReplayedCiphertextFails) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();
  const char* message = "Replay me";

  BitStream encrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Encrypt(9, reinterpret_cast<const unsigned char*>(message),
                           std::strlen(message), encrypted)
                  .ok);

  BitStream decrypted;
  ASSERT_TRUE(
      fixture.serverContext
          .Decrypt(9, encrypted.GetData(), encrypted.GetSizeBytes(), decrypted)
          .ok);

  BitStream replay;
  auto result = fixture.serverContext.Decrypt(9, encrypted.GetData(),
                                              encrypted.GetSizeBytes(), replay);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, crypto::CryptoError::kReplayDetected);
#endif
}

TEST_F(CryptoTest, BidirectionalCommunication) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  auto fixture = CompleteHandshake();

  const char* client_msg = "Client to Server";
  BitStream c2s_encrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Encrypt(1,
                           reinterpret_cast<const unsigned char*>(client_msg),
                           std::strlen(client_msg), c2s_encrypted)
                  .ok);

  BitStream c2s_decrypted;
  ASSERT_TRUE(fixture.serverContext
                  .Decrypt(1, c2s_encrypted.GetData(),
                           c2s_encrypted.GetSizeBytes(), c2s_decrypted)
                  .ok);

  const char* server_msg = "Server to Client";
  BitStream s2c_encrypted;
  ASSERT_TRUE(fixture.serverContext
                  .Encrypt(2,
                           reinterpret_cast<const unsigned char*>(server_msg),
                           std::strlen(server_msg), s2c_encrypted)
                  .ok);

  BitStream s2c_decrypted;
  ASSERT_TRUE(fixture.clientContext
                  .Decrypt(2, s2c_encrypted.GetData(),
                           s2c_encrypted.GetSizeBytes(), s2c_decrypted)
                  .ok);
#endif
}
