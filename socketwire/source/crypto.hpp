#pragma once
/// Lightweight authenticated encryption and client/server handshakes.
///
/// Public types keep fixed sizes even when libsodium support is disabled, so
/// callers can configure crypto without conditional type branches.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <expected>
#include <limits>
#include <optional>
#include <vector>

#include "bit_stream.hpp"

#if !defined(SOCKETWIRE_HAVE_LIBSODIUM)
#if !defined(SOCKETWIRE_CRYPTO_FORCE_NO_SODIUM) && __has_include(<sodium.h>)
#define SOCKETWIRE_HAVE_LIBSODIUM 1
#else
#define SOCKETWIRE_HAVE_LIBSODIUM 0
#endif
#endif

#if SOCKETWIRE_HAVE_LIBSODIUM
#include <sodium.h>
#endif

namespace socketwire::crypto {

constexpr std::uint8_t kProtocolVersionMajor = 1;
constexpr std::uint8_t kProtocolVersionMinor = 0;

constexpr std::size_t kMacSize = 16;
constexpr std::size_t kNonceSize = 24;
constexpr std::size_t kPublicKeySize = 32;
constexpr std::size_t kSecretKeySize = 32;
constexpr std::size_t kSessionKeySize = 32;
constexpr std::size_t kHandshakeNonceSize = 32;
constexpr std::size_t kMaxHandshakeMessageSize = 512;
constexpr std::size_t kReplayWindowSize = 1024;

using PublicKey = std::array<unsigned char, kPublicKeySize>;
using SecretKey = std::array<unsigned char, kSecretKeySize>;
using SessionKey = std::array<unsigned char, kSessionKeySize>;
using Nonce = std::array<unsigned char, kNonceSize>;
using HandshakeNonce = std::array<unsigned char, kHandshakeNonceSize>;

enum class CipherSuite : std::uint8_t { kNone = 0, kXChaCha20Poly1305 = 1 };

enum class HandshakeOpcode : std::uint8_t {
  kClientHello = 1,
  kServerHello = 2
};

enum class CryptoError : std::uint8_t {
  kNone = 0,
  kNotInitialized,
  kUnsupportedSuite,
  kInvalidState,
  kDecodeError,
  kKeyExchangeFailed,
  kSodiumFailure,
  kBufferTooSmall,
  kSequenceExpired,
  kDecryptFailed,
  kNotReady,
  kInvalidPeerKey,
  kReplayDetected
};

[[nodiscard]] const char* ToString(CryptoError error) noexcept;

struct Result {
  bool ok;
  CryptoError error;

  static constexpr Result Success() noexcept {
    return {.ok = true, .error = CryptoError::kNone};
  }
  static constexpr Result Failure(CryptoError e) noexcept {
    return {.ok = false, .error = e};
  }
  [[nodiscard]] constexpr explicit operator bool() const noexcept { return ok; }
};

Result Initialize();
bool CipherSuiteSupported(CipherSuite s);

template <std::size_t n>
[[nodiscard]] inline bool AllZero(
  const std::array<unsigned char, n>& bytes) noexcept {
  return std::all_of(bytes.begin(), bytes.end(),
                     [](unsigned char b) { return b == 0; });
}

[[nodiscard]] inline bool ValidPublicKey(const PublicKey& key) noexcept {
  return !AllZero(key);
}

[[nodiscard]] inline bool ValidSecretKey(const SecretKey& key) noexcept {
  return !AllZero(key);
}

struct KeyPair {
  PublicKey publicKey{};
  SecretKey secretKey{};

  [[nodiscard]] bool Valid() const noexcept {
    return ValidPublicKey(publicKey) && ValidSecretKey(secretKey);
  }

  static Result Generate(KeyPair& out) {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!Initialize().ok) return Result::Failure(CryptoError::kSodiumFailure);
    if (crypto_kx_keypair(out.publicKey.data(), out.secretKey.data()) != 0) {
      out = {};
      return Result::Failure(CryptoError::kSodiumFailure);
    }
    return Result::Success();
#else
    out = {};
    return Result::Failure(CryptoError::kNotInitialized);
#endif
  }

  static std::expected<KeyPair, CryptoError> TryGenerate() {
    KeyPair kp;
    const auto result = Generate(kp);
    if (!result.ok) return std::unexpected(result.error);
    return kp;
  }

  static KeyPair Generate() {
    KeyPair kp;
    (void)Generate(kp);
    return kp;
  }
};

struct SessionKeys {
  SessionKey rx{};
  SessionKey tx{};

  [[nodiscard]] bool Valid() const noexcept {
    return !AllZero(rx) && !AllZero(tx);
  }
};

struct NonceGenerator {
  Nonce base{};
  std::uint64_t counter = 0;
  bool initialized = false;

  Result InitRandom() {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!Initialize().ok) return Result::Failure(CryptoError::kSodiumFailure);
    randombytes_buf(base.data(), base.size());
    counter = 0;
    initialized = true;
    return Result::Success();
#else
    base.fill(0);
    counter = 0;
    initialized = false;
    return Result::Failure(CryptoError::kNotInitialized);
#endif
  }

  [[nodiscard]] Result FillNonce(Nonce& out) const noexcept {
    if (!initialized) return Result::Failure(CryptoError::kNotReady);

    out = base;
    std::uint64_t c = counter;
    for (std::size_t i = 0; i < 8; ++i) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-avoid-unchecked-container-access)
      out[kNonceSize - 8 + i] = static_cast<unsigned char>(c & 0xFFu);
      c >>= 8;
    }
    return Result::Success();
  }

  Result NextNonce(Nonce& out) noexcept {
    if (counter == std::numeric_limits<std::uint64_t>::max()) {
      return Result::Failure(CryptoError::kSequenceExpired);
    }

    const auto result = FillNonce(out);
    if (!result.ok) return result;

    ++counter;
    return Result::Success();
  }
};

enum class HandshakeRole : std::uint8_t { kNone = 0, kClient = 1, kServer = 2 };

enum class HandshakePhase : std::uint8_t {
  kEmpty = 0,
  kClientHelloSent,
  kServerHelloSent,
  kCompleted,
  kRejected
};

struct ClientHelloData {
  std::uint8_t versionMajor = kProtocolVersionMajor;
  std::uint8_t versionMinor = kProtocolVersionMinor;
  CipherSuite suite = CipherSuite::kXChaCha20Poly1305;
  HandshakeNonce nonce{};
  PublicKey clientPub{};
};

struct ServerHelloData {
  std::uint8_t versionMajor = kProtocolVersionMajor;
  std::uint8_t versionMinor = kProtocolVersionMinor;
  CipherSuite suite = CipherSuite::kXChaCha20Poly1305;
  HandshakeNonce nonce{};
  PublicKey serverPub{};
};

constexpr std::size_t kClientHelloSize =
  1 + 1 + 1 + 1 + kHandshakeNonceSize + kPublicKeySize;
constexpr std::size_t kServerHelloSize =
  1 + 1 + 1 + 1 + kHandshakeNonceSize + kPublicKeySize;

inline Result WriteClientHello(BitStream& bs, const ClientHelloData& d) {
  bs.Write<std::uint8_t>(
    static_cast<std::uint8_t>(HandshakeOpcode::kClientHello));
  bs.Write<std::uint8_t>(d.versionMajor);
  bs.Write<std::uint8_t>(d.versionMinor);
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(d.suite));
  bs.WriteBytes(d.nonce.data(), d.nonce.size());
  bs.WriteBytes(d.clientPub.data(), d.clientPub.size());
  return Result::Success();
}

inline Result ReadClientHello(const unsigned char* data, std::size_t len,
                              ClientHelloData& out) {
  if (data == nullptr || len != kClientHelloSize ||
      len > kMaxHandshakeMessageSize) {
    return Result::Failure(CryptoError::kDecodeError);
  }

  try {
    BitStream bs(data, len);
    std::uint8_t opcode = 0;
    bs.Read<std::uint8_t>(opcode);
    if (opcode != static_cast<std::uint8_t>(HandshakeOpcode::kClientHello)) {
      return Result::Failure(CryptoError::kDecodeError);
    }

    bs.Read<std::uint8_t>(out.versionMajor);
    bs.Read<std::uint8_t>(out.versionMinor);

    std::uint8_t suite_byte = 0;
    bs.Read<std::uint8_t>(suite_byte);
    out.suite = static_cast<CipherSuite>(suite_byte);

    bs.ReadBytes(out.nonce.data(), out.nonce.size());
    bs.ReadBytes(out.clientPub.data(), out.clientPub.size());
    return Result::Success();
  } catch (...) {
    return Result::Failure(CryptoError::kDecodeError);
  }
}

inline Result WriteServerHello(BitStream& bs, const ServerHelloData& d) {
  bs.Write<std::uint8_t>(
    static_cast<std::uint8_t>(HandshakeOpcode::kServerHello));
  bs.Write<std::uint8_t>(d.versionMajor);
  bs.Write<std::uint8_t>(d.versionMinor);
  bs.Write<std::uint8_t>(static_cast<std::uint8_t>(d.suite));
  bs.WriteBytes(d.nonce.data(), d.nonce.size());
  bs.WriteBytes(d.serverPub.data(), d.serverPub.size());
  return Result::Success();
}

inline Result ReadServerHello(const unsigned char* data, std::size_t len,
                              ServerHelloData& out) {
  if (data == nullptr || len != kServerHelloSize ||
      len > kMaxHandshakeMessageSize) {
    return Result::Failure(CryptoError::kDecodeError);
  }

  try {
    BitStream bs(data, len);
    std::uint8_t opcode = 0;
    bs.Read<std::uint8_t>(opcode);
    if (opcode != static_cast<std::uint8_t>(HandshakeOpcode::kServerHello)) {
      return Result::Failure(CryptoError::kDecodeError);
    }

    bs.Read<std::uint8_t>(out.versionMajor);
    bs.Read<std::uint8_t>(out.versionMinor);

    std::uint8_t suite_byte = 0;
    bs.Read<std::uint8_t>(suite_byte);
    out.suite = static_cast<CipherSuite>(suite_byte);

    bs.ReadBytes(out.nonce.data(), out.nonce.size());
    bs.ReadBytes(out.serverPub.data(), out.serverPub.size());
    return Result::Success();
  } catch (...) {
    return Result::Failure(CryptoError::kDecodeError);
  }
}

class HandshakeState {
public:
  HandshakeState() = default;

  Result StartClient(const KeyPair& client_keys,
                     const PublicKey& expected_server_public_key = {}) {
    Reset();
    role = HandshakeRole::kClient;
    staticKeys = client_keys;
    if (!staticKeys.Valid()) {
      phase = HandshakePhase::kRejected;
      return Result::Failure(CryptoError::kInvalidState);
    }

    if (!AllZero(expected_server_public_key)) {
      expectedServerPub = expected_server_public_key;
    }

    RandomHandshakeNonce(clientHello.nonce);
    clientHello.clientPub = staticKeys.publicKey;
    return Result::Success();
  }

  Result StartServer(const KeyPair& server_keys) {
    Reset();
    role = HandshakeRole::kServer;
    staticKeys = server_keys;
    if (!staticKeys.Valid()) {
      phase = HandshakePhase::kRejected;
      return Result::Failure(CryptoError::kInvalidState);
    }
    return Result::Success();
  }

  Result WriteClientHello(BitStream& out) {
    if (role != HandshakeRole::kClient || !staticKeys.Valid()) {
      return Result::Failure(CryptoError::kInvalidState);
    }
    if (!CipherSuiteSupported(CipherSuite::kXChaCha20Poly1305)) {
      return Result::Failure(CryptoError::kUnsupportedSuite);
    }

    clientHello.versionMajor = kProtocolVersionMajor;
    clientHello.versionMinor = kProtocolVersionMinor;
    clientHello.suite = CipherSuite::kXChaCha20Poly1305;
    out.Clear();
    const auto result =
      ::socketwire::crypto::WriteClientHello(out, clientHello);
    if (result.ok) phase = HandshakePhase::kClientHelloSent;
    return result;
  }

  Result WriteServerHello(BitStream& out) {
    if (role != HandshakeRole::kServer || !staticKeys.Valid() ||
        !session.Valid()) {
      return Result::Failure(CryptoError::kInvalidState);
    }
    if (!CipherSuiteSupported(CipherSuite::kXChaCha20Poly1305)) {
      return Result::Failure(CryptoError::kUnsupportedSuite);
    }

    serverHello.versionMajor = kProtocolVersionMajor;
    serverHello.versionMinor = kProtocolVersionMinor;
    serverHello.suite = CipherSuite::kXChaCha20Poly1305;
    serverHello.serverPub = staticKeys.publicKey;
    RandomHandshakeNonce(serverHello.nonce);
    out.Clear();
    const auto result =
      ::socketwire::crypto::WriteServerHello(out, serverHello);
    if (result.ok) phase = HandshakePhase::kCompleted;
    return result;
  }

  Result ProcessClientHello(const unsigned char* data, std::size_t len) {
    if (role != HandshakeRole::kServer || !staticKeys.Valid()) {
      return Result::Failure(CryptoError::kInvalidState);
    }

    ClientHelloData tmp;
    auto result = ReadClientHello(data, len, tmp);
    if (!result.ok) return result;
    result = ValidatePeerHello(tmp.versionMajor, tmp.versionMinor, tmp.suite,
                               tmp.clientPub);
    if (!result.ok) return result;

    clientHello = tmp;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (crypto_kx_server_session_keys(
          session.rx.data(), session.tx.data(), staticKeys.publicKey.data(),
          staticKeys.secretKey.data(), clientHello.clientPub.data()) != 0) {
      phase = HandshakePhase::kRejected;
      session = {};
      return Result::Failure(CryptoError::kKeyExchangeFailed);
    }
    phase = HandshakePhase::kCompleted;
    return Result::Success();
#else
    phase = HandshakePhase::kRejected;
    return Result::Failure(CryptoError::kNotInitialized);
#endif
  }

  Result ProcessServerHello(const unsigned char* data, std::size_t len) {
    if (role != HandshakeRole::kClient || !staticKeys.Valid()) {
      return Result::Failure(CryptoError::kInvalidState);
    }

    ServerHelloData tmp;
    auto result = ReadServerHello(data, len, tmp);
    if (!result.ok) return result;
    result = ValidatePeerHello(tmp.versionMajor, tmp.versionMinor, tmp.suite,
                               tmp.serverPub);
    if (!result.ok) return result;

    if (expectedServerPub.has_value() && *expectedServerPub != tmp.serverPub) {
      phase = HandshakePhase::kRejected;
      return Result::Failure(CryptoError::kInvalidPeerKey);
    }

    serverHello = tmp;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (crypto_kx_client_session_keys(
          session.rx.data(), session.tx.data(), staticKeys.publicKey.data(),
          staticKeys.secretKey.data(), serverHello.serverPub.data()) != 0) {
      phase = HandshakePhase::kRejected;
      session = {};
      return Result::Failure(CryptoError::kKeyExchangeFailed);
    }
    phase = HandshakePhase::kCompleted;
    return Result::Success();
#else
    phase = HandshakePhase::kRejected;
    return Result::Failure(CryptoError::kNotInitialized);
#endif
  }

  [[nodiscard]] bool Completed() const noexcept {
    return phase == HandshakePhase::kCompleted && session.Valid();
  }

  [[nodiscard]] HandshakeRole GetRole() const noexcept { return role; }
  [[nodiscard]] HandshakePhase GetPhase() const noexcept { return phase; }
  [[nodiscard]] const SessionKeys& GetSessionKeys() const noexcept {
    return session;
  }
  [[nodiscard]] const PublicKey& RemotePublicKey() const noexcept {
    return role == HandshakeRole::kClient ? serverHello.serverPub
                                          : clientHello.clientPub;
  }

  [[nodiscard]] class CryptoContext CreateClientCryptoContext() const;
  [[nodiscard]] class CryptoContext CreateServerCryptoContext() const;

private:
  HandshakeRole role = HandshakeRole::kNone;
  HandshakePhase phase = HandshakePhase::kEmpty;
  KeyPair staticKeys{};
  SessionKeys session{};
  ClientHelloData clientHello{};
  ServerHelloData serverHello{};
  std::optional<PublicKey> expectedServerPub{};

  void Reset() {
    role = HandshakeRole::kNone;
    phase = HandshakePhase::kEmpty;
    staticKeys = {};
    session = {};
    clientHello = {};
    serverHello = {};
    expectedServerPub.reset();
  }

  static Result ValidatePeerHello(std::uint8_t maj, std::uint8_t min,
                                  CipherSuite suite,
                                  const PublicKey& peer_key) {
    if (maj != kProtocolVersionMajor || min > kProtocolVersionMinor) {
      return Result::Failure(CryptoError::kDecodeError);
    }
    if (suite != CipherSuite::kXChaCha20Poly1305 ||
        !CipherSuiteSupported(suite)) {
      return Result::Failure(CryptoError::kUnsupportedSuite);
    }
    if (!ValidPublicKey(peer_key)) {
      return Result::Failure(CryptoError::kInvalidPeerKey);
    }
    return Result::Success();
  }

  static void RandomHandshakeNonce(HandshakeNonce& out) {
#if SOCKETWIRE_HAVE_LIBSODIUM
    randombytes_buf(out.data(), out.size());
#else
    out.fill(0);
#endif
  }
};

class CryptoContext {
public:
  CryptoContext() = default;

  [[nodiscard]] bool IsReady() const noexcept {
    return suite == CipherSuite::kXChaCha20Poly1305 && haveKeys;
  }

  Result Encrypt(const unsigned char* plain, std::size_t plain_len,
                 const unsigned char* associated_data,
                 std::size_t associated_data_len, BitStream& out) {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!IsReady()) return Result::Failure(CryptoError::kNotReady);
    if ((plain_len > 0 && plain == nullptr) ||
        (associated_data_len > 0 && associated_data == nullptr)) {
      return Result::Failure(CryptoError::kInvalidState);
    }

    Nonce nonce;
    auto result = txNonce.NextNonce(nonce);
    if (!result.ok) return result;

    std::vector<unsigned char> cipher(plain_len + kMacSize);
    unsigned long long outLen = 0;  // NOLINT
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
          cipher.data(), &outLen, plain, plain_len, associated_data,
          associated_data_len, nullptr, nonce.data(), keyTx.data()) != 0) {
      return Result::Failure(CryptoError::kSodiumFailure);
    }

    out.Clear();
    out.WriteBytes(nonce.data(), nonce.size());
    out.WriteBytes(cipher.data(), static_cast<std::size_t>(outLen));
    return Result::Success();
#else
    (void)plain;
    (void)plain_len;
    (void)associated_data;
    (void)associated_data_len;
    (void)out;
    return Result::Failure(CryptoError::kNotInitialized);
#endif
  }

  Result Decrypt(const unsigned char* data, std::size_t len,
                 const unsigned char* associated_data,
                 std::size_t associated_data_len, BitStream& out_plain) {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!IsReady()) return Result::Failure(CryptoError::kNotReady);
    if (data == nullptr || len < kNonceSize + kMacSize ||
        (associated_data_len > 0 && associated_data == nullptr)) {
      return Result::Failure(CryptoError::kDecodeError);
    }

    Nonce nonce;
    std::memcpy(nonce.data(), data, nonce.size());
    if (NonceSeen(nonce)) return Result::Failure(CryptoError::kReplayDetected);

    const unsigned char* cipher = data + kNonceSize;
    const std::size_t cipher_len = len - kNonceSize;
    std::vector<unsigned char> plain(cipher_len);
    unsigned long long plainOut = 0;  // NOLINT
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
          plain.data(), &plainOut, nullptr, cipher, cipher_len, associated_data,
          associated_data_len, nonce.data(), keyRx.data()) != 0) {
      return Result::Failure(CryptoError::kDecryptFailed);
    }

    RememberNonce(nonce);
    out_plain.Clear();
    out_plain.WriteBytes(plain.data(), static_cast<std::size_t>(plainOut));
    return Result::Success();
#else
    (void)data;
    (void)len;
    (void)associated_data;
    (void)associated_data_len;
    (void)out_plain;
    return Result::Failure(CryptoError::kNotInitialized);
#endif
  }

  Result Encrypt(std::uint64_t seq, const unsigned char* plain,
                 std::size_t plain_len, BitStream& out) {
    unsigned char ad[8];
    EncodeLe64(seq, ad);
    return Encrypt(plain, plain_len, ad, sizeof(ad), out);
  }

  Result Decrypt(std::uint64_t seq, const unsigned char* data, std::size_t len,
                 BitStream& out_plain) {
    unsigned char ad[8];
    EncodeLe64(seq, ad);
    return Decrypt(data, len, ad, sizeof(ad), out_plain);
  }

  static CryptoContext FromClient(const SessionKeys& keys) {
    CryptoContext ctx;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (keys.Valid()) {
      ctx.keyRx = keys.rx;
      ctx.keyTx = keys.tx;
      const auto tx_ready = ctx.txNonce.InitRandom();
      if (tx_ready.ok) {
        ctx.haveKeys = true;
        ctx.suite = CipherSuite::kXChaCha20Poly1305;
      }
    }
#else
    (void)keys;
#endif
    return ctx;
  }

  static CryptoContext FromServer(const SessionKeys& keys) {
    CryptoContext ctx;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (keys.Valid()) {
      ctx.keyRx = keys.rx;
      ctx.keyTx = keys.tx;
      const auto tx_ready = ctx.txNonce.InitRandom();
      if (tx_ready.ok) {
        ctx.haveKeys = true;
        ctx.suite = CipherSuite::kXChaCha20Poly1305;
      }
    }
#else
    (void)keys;
#endif
    return ctx;
  }

private:
  CipherSuite suite = CipherSuite::kNone;
  bool haveKeys = false;
  [[maybe_unused]] SessionKey keyRx{};
  [[maybe_unused]] SessionKey keyTx{};
  NonceGenerator txNonce{};
  std::deque<Nonce> receivedNonces{};

  [[nodiscard]] bool NonceSeen(const Nonce& nonce) const {
    return std::ranges::find(receivedNonces, nonce) != receivedNonces.end();
  }

  void RememberNonce(const Nonce& nonce) {
    receivedNonces.push_back(nonce);
    while (receivedNonces.size() > kReplayWindowSize) {
      receivedNonces.pop_front();
    }
  }

  static void EncodeLe64(std::uint64_t v, unsigned char out[8]) {
    for (int i = 0; i < 8; ++i) {
      out[i] = static_cast<unsigned char>(v & 0xFFu);
      v >>= 8;
    }
  }
};

}  // namespace socketwire::crypto
