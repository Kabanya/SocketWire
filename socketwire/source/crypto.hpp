#pragma once
/*
  Lightweight authenticated encryption and client/server handshake built on top
  of libsodium. The public types keep fixed sizes even when libsodium support is
  disabled, so callers can configure crypto without conditional type branches.
*/

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
  #if !defined(SOCKETWIRE_CRYPTO_FORCE_NO_SODIUM)
    #if __has_include(<sodium.h>)
      #include <sodium.h>
      #define SOCKETWIRE_HAVE_LIBSODIUM 1
    #else
      #define SOCKETWIRE_HAVE_LIBSODIUM 0
    #endif
  #else
    #define SOCKETWIRE_HAVE_LIBSODIUM 0
  #endif
#endif

#if SOCKETWIRE_HAVE_LIBSODIUM
  #include <sodium.h>
#endif

namespace socketwire::crypto
{

constexpr std::uint8_t k_protocol_version_major = 1;
constexpr std::uint8_t k_protocol_version_minor = 0;

constexpr std::size_t k_public_key_size = 32;
constexpr std::size_t k_secret_key_size = 32;
constexpr std::size_t k_session_key_size = 32;
constexpr std::size_t k_nonce_size = 24;
constexpr std::size_t k_mac_size = 16;
constexpr std::size_t k_handshake_nonce_size = 32;
constexpr std::size_t k_max_handshake_message_size = 512;
constexpr std::size_t k_replay_window_size = 1024;

using PublicKey = std::array<unsigned char, k_public_key_size>;
using SecretKey = std::array<unsigned char, k_secret_key_size>;
using SessionKey = std::array<unsigned char, k_session_key_size>;
using Nonce = std::array<unsigned char, k_nonce_size>;
using HandshakeNonce = std::array<unsigned char, k_handshake_nonce_size>;

enum class CipherSuite : std::uint8_t
{
  None = 0,
  XChaCha20Poly1305 = 1
};

enum class HandshakeOpcode : std::uint8_t
{
  ClientHello  = 1,
  ServerHello  = 2,
  ServerReject = 3
};

enum class CryptoError : std::uint8_t
{
  None = 0,
  NotInitialized,
  UnsupportedSuite,
  InvalidState,
  DecodeError,
  KeyExchangeFailed,
  SodiumFailure,
  BufferTooSmall,
  SequenceExpired,
  DecryptFailed,
  NotReady,
  InvalidPeerKey,
  ReplayDetected
};

[[nodiscard]] const char* to_string(CryptoError error) noexcept;

struct Result
{
  bool ok;
  CryptoError error;

  static constexpr Result success() noexcept { return {true, CryptoError::None}; }
  static constexpr Result failure(CryptoError e) noexcept { return {false, e}; }
};

Result initialize();
bool cipher_suite_supported(CipherSuite s);

template<std::size_t N>
[[nodiscard]] inline bool all_zero(const std::array<unsigned char, N>& bytes) noexcept
{
  return std::all_of(bytes.begin(), bytes.end(), [](unsigned char b) { return b == 0; });
}

[[nodiscard]] inline bool valid_public_key(const PublicKey& key) noexcept
{
  return !all_zero(key);
}

[[nodiscard]] inline bool valid_secret_key(const SecretKey& key) noexcept
{
  return !all_zero(key);
}

struct KeyPair
{
  PublicKey publicKey{};
  SecretKey secretKey{};

  [[nodiscard]] bool valid() const noexcept
  {
    return valid_public_key(publicKey) && valid_secret_key(secretKey);
  }

  static Result generate(KeyPair& out)
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!initialize().ok)
      return Result::failure(CryptoError::SodiumFailure);
    if (crypto_kx_keypair(out.publicKey.data(), out.secretKey.data()) != 0)
    {
      out = {};
      return Result::failure(CryptoError::SodiumFailure);
    }
    return Result::success();
#else
    out = {};
    return Result::failure(CryptoError::NotInitialized);
#endif
  }

  static std::expected<KeyPair, CryptoError> try_generate()
  {
    KeyPair kp;
    const auto result = generate(kp);
    if (!result.ok)
      return std::unexpected(result.error);
    return kp;
  }

  static KeyPair generate()
  {
    KeyPair kp;
    (void)generate(kp);
    return kp;
  }
};

struct SessionKeys
{
  SessionKey rx{};
  SessionKey tx{};

  [[nodiscard]] bool valid() const noexcept
  {
    return !all_zero(rx) && !all_zero(tx);
  }
};

struct NonceGenerator
{
  Nonce base{};
  std::uint64_t counter = 0;
  bool initialized = false;

  Result init_random()
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!initialize().ok)
      return Result::failure(CryptoError::SodiumFailure);
    randombytes_buf(base.data(), base.size());
    counter = 0;
    initialized = true;
    return Result::success();
#else
    base.fill(0);
    counter = 0;
    initialized = false;
    return Result::failure(CryptoError::NotInitialized);
#endif
  }

  [[nodiscard]] Result fill_nonce(Nonce& out) const noexcept
  {
    if (!initialized)
      return Result::failure(CryptoError::NotReady);

    out = base;
    std::uint64_t c = counter;
    for (std::size_t i = 0; i < 8; ++i)
    {
      out[k_nonce_size - 8 + i] = static_cast<unsigned char>(c & 0xFFu);
      c >>= 8;
    }
    return Result::success();
  }

  Result next_nonce(Nonce& out) noexcept
  {
    if (counter == std::numeric_limits<std::uint64_t>::max())
      return Result::failure(CryptoError::SequenceExpired);

    const auto result = fill_nonce(out);
    if (!result.ok)
      return result;

    ++counter;
    return Result::success();
  }
};

enum class HandshakeRole : std::uint8_t
{
  None = 0,
  Client = 1,
  Server = 2
};

enum class HandshakePhase : std::uint8_t
{
  Empty = 0,
  ClientHelloSent,
  ServerHelloSent,
  Completed,
  Rejected
};

struct ClientHelloData
{
  std::uint8_t versionMajor = k_protocol_version_major;
  std::uint8_t versionMinor = k_protocol_version_minor;
  CipherSuite suite = CipherSuite::XChaCha20Poly1305;
  HandshakeNonce nonce{};
  PublicKey clientPub{};
};

struct ServerHelloData
{
  std::uint8_t versionMajor = k_protocol_version_major;
  std::uint8_t versionMinor = k_protocol_version_minor;
  CipherSuite suite = CipherSuite::XChaCha20Poly1305;
  HandshakeNonce nonce{};
  PublicKey serverPub{};
};

constexpr std::size_t k_client_hello_size =
  1 + 1 + 1 + 1 + k_handshake_nonce_size + k_public_key_size;
constexpr std::size_t k_server_hello_size =
  1 + 1 + 1 + 1 + k_handshake_nonce_size + k_public_key_size;

inline Result write_client_hello(BitStream& bs, const ClientHelloData& d)
{
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(HandshakeOpcode::ClientHello));
  bs.write<std::uint8_t>(d.versionMajor);
  bs.write<std::uint8_t>(d.versionMinor);
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(d.suite));
  bs.writeBytes(d.nonce.data(), d.nonce.size());
  bs.writeBytes(d.clientPub.data(), d.clientPub.size());
  return Result::success();
}

inline Result read_client_hello(const unsigned char* data, std::size_t len, ClientHelloData& out)
{
  if (data == nullptr || len != k_client_hello_size || len > k_max_handshake_message_size)
    return Result::failure(CryptoError::DecodeError);

  try
  {
    BitStream bs(data, len);
    std::uint8_t opcode = 0;
    bs.read<std::uint8_t>(opcode);
    if (opcode != static_cast<std::uint8_t>(HandshakeOpcode::ClientHello))
      return Result::failure(CryptoError::DecodeError);

    bs.read<std::uint8_t>(out.versionMajor);
    bs.read<std::uint8_t>(out.versionMinor);

    std::uint8_t suite_byte = 0;
    bs.read<std::uint8_t>(suite_byte);
    out.suite = static_cast<CipherSuite>(suite_byte);

    bs.readBytes(out.nonce.data(), out.nonce.size());
    bs.readBytes(out.clientPub.data(), out.clientPub.size());
    return Result::success();
  }
  catch (...)
  {
    return Result::failure(CryptoError::DecodeError);
  }
}

inline Result write_server_hello(BitStream& bs, const ServerHelloData& d)
{
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(HandshakeOpcode::ServerHello));
  bs.write<std::uint8_t>(d.versionMajor);
  bs.write<std::uint8_t>(d.versionMinor);
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(d.suite));
  bs.writeBytes(d.nonce.data(), d.nonce.size());
  bs.writeBytes(d.serverPub.data(), d.serverPub.size());
  return Result::success();
}

inline Result read_server_hello(const unsigned char* data, std::size_t len, ServerHelloData& out)
{
  if (data == nullptr || len != k_server_hello_size || len > k_max_handshake_message_size)
    return Result::failure(CryptoError::DecodeError);

  try
  {
    BitStream bs(data, len);
    std::uint8_t opcode = 0;
    bs.read<std::uint8_t>(opcode);
    if (opcode != static_cast<std::uint8_t>(HandshakeOpcode::ServerHello))
      return Result::failure(CryptoError::DecodeError);

    bs.read<std::uint8_t>(out.versionMajor);
    bs.read<std::uint8_t>(out.versionMinor);

    std::uint8_t suite_byte = 0;
    bs.read<std::uint8_t>(suite_byte);
    out.suite = static_cast<CipherSuite>(suite_byte);

    bs.readBytes(out.nonce.data(), out.nonce.size());
    bs.readBytes(out.serverPub.data(), out.serverPub.size());
    return Result::success();
  }
  catch (...)
  {
    return Result::failure(CryptoError::DecodeError);
  }
}

class HandshakeState
{
public:
  HandshakeState() = default;

  Result start_client(const KeyPair& client_keys,
                     const PublicKey& expected_server_public_key = {})
  {
    reset();
    role = HandshakeRole::Client;
    staticKeys = client_keys;
    if (!staticKeys.valid())
    {
      phase = HandshakePhase::Rejected;
      return Result::failure(CryptoError::InvalidState);
    }

    if (!all_zero(expected_server_public_key))
      expectedServerPub = expected_server_public_key;

    random_handshake_nonce(clientHello.nonce);
    clientHello.clientPub = staticKeys.publicKey;
    return Result::success();
  }

  Result start_server(const KeyPair& server_keys)
  {
    reset();
    role = HandshakeRole::Server;
    staticKeys = server_keys;
    if (!staticKeys.valid())
    {
      phase = HandshakePhase::Rejected;
      return Result::failure(CryptoError::InvalidState);
    }
    return Result::success();
  }

  Result write_client_hello(BitStream& out)
  {
    if (role != HandshakeRole::Client || !staticKeys.valid())
      return Result::failure(CryptoError::InvalidState);
    if (!cipher_suite_supported(CipherSuite::XChaCha20Poly1305))
      return Result::failure(CryptoError::UnsupportedSuite);

    clientHello.versionMajor = k_protocol_version_major;
    clientHello.versionMinor = k_protocol_version_minor;
    clientHello.suite = CipherSuite::XChaCha20Poly1305;
    out.clear();
    const auto result = ::socketwire::crypto::write_client_hello(out, clientHello);
    if (result.ok)
      phase = HandshakePhase::ClientHelloSent;
    return result;
  }

  Result write_server_hello(BitStream& out)
  {
    if (role != HandshakeRole::Server || !staticKeys.valid() || !session.valid())
      return Result::failure(CryptoError::InvalidState);
    if (!cipher_suite_supported(CipherSuite::XChaCha20Poly1305))
      return Result::failure(CryptoError::UnsupportedSuite);

    serverHello.versionMajor = k_protocol_version_major;
    serverHello.versionMinor = k_protocol_version_minor;
    serverHello.suite = CipherSuite::XChaCha20Poly1305;
    serverHello.serverPub = staticKeys.publicKey;
    random_handshake_nonce(serverHello.nonce);
    out.clear();
    const auto result = ::socketwire::crypto::write_server_hello(out, serverHello);
    if (result.ok)
      phase = HandshakePhase::Completed;
    return result;
  }

  Result process_client_hello(const unsigned char* data, std::size_t len)
  {
    if (role != HandshakeRole::Server || !staticKeys.valid())
      return Result::failure(CryptoError::InvalidState);

    ClientHelloData tmp;
    auto result = read_client_hello(data, len, tmp);
    if (!result.ok)
      return result;
    result = validate_peer_hello(tmp.versionMajor, tmp.versionMinor, tmp.suite, tmp.clientPub);
    if (!result.ok)
      return result;

    clientHello = tmp;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (crypto_kx_server_session_keys(session.rx.data(), session.tx.data(),
                                      staticKeys.publicKey.data(), staticKeys.secretKey.data(),
                                      clientHello.clientPub.data()) != 0)
    {
      phase = HandshakePhase::Rejected;
      session = {};
      return Result::failure(CryptoError::KeyExchangeFailed);
    }
    phase = HandshakePhase::Completed;
    return Result::success();
#else
    phase = HandshakePhase::Rejected;
    return Result::failure(CryptoError::NotInitialized);
#endif
  }

  Result process_server_hello(const unsigned char* data, std::size_t len)
  {
    if (role != HandshakeRole::Client || !staticKeys.valid())
      return Result::failure(CryptoError::InvalidState);

    ServerHelloData tmp;
    auto result = read_server_hello(data, len, tmp);
    if (!result.ok)
      return result;
    result = validate_peer_hello(tmp.versionMajor, tmp.versionMinor, tmp.suite, tmp.serverPub);
    if (!result.ok)
      return result;

    if (expectedServerPub.has_value() && *expectedServerPub != tmp.serverPub)
    {
      phase = HandshakePhase::Rejected;
      return Result::failure(CryptoError::InvalidPeerKey);
    }

    serverHello = tmp;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (crypto_kx_client_session_keys(session.rx.data(), session.tx.data(),
                                      staticKeys.publicKey.data(), staticKeys.secretKey.data(),
                                      serverHello.serverPub.data()) != 0)
    {
      phase = HandshakePhase::Rejected;
      session = {};
      return Result::failure(CryptoError::KeyExchangeFailed);
    }
    phase = HandshakePhase::Completed;
    return Result::success();
#else
    phase = HandshakePhase::Rejected;
    return Result::failure(CryptoError::NotInitialized);
#endif
  }

  [[nodiscard]] bool completed() const noexcept
  {
    return phase == HandshakePhase::Completed && session.valid();
  }

  [[nodiscard]] HandshakeRole get_role() const noexcept { return role; }
  [[nodiscard]] HandshakePhase get_phase() const noexcept { return phase; }
  [[nodiscard]] const SessionKeys& get_session_keys() const noexcept { return session; }
  [[nodiscard]] const PublicKey& remote_public_key() const noexcept
  {
    return role == HandshakeRole::Client ? serverHello.serverPub : clientHello.clientPub;
  }

  class CryptoContext create_client_crypto_context() const;
  class CryptoContext create_server_crypto_context() const;

private:
  HandshakeRole role = HandshakeRole::None;
  HandshakePhase phase = HandshakePhase::Empty;
  KeyPair staticKeys{};
  SessionKeys session{};
  ClientHelloData clientHello{};
  ServerHelloData serverHello{};
  std::optional<PublicKey> expectedServerPub{};

  void reset()
  {
    role = HandshakeRole::None;
    phase = HandshakePhase::Empty;
    staticKeys = {};
    session = {};
    clientHello = {};
    serverHello = {};
    expectedServerPub.reset();
  }

  static Result validate_peer_hello(std::uint8_t maj,
                                  std::uint8_t min,
                                  CipherSuite suite,
                                  const PublicKey& peer_key)
  {
    if (maj != k_protocol_version_major || min > k_protocol_version_minor)
      return Result::failure(CryptoError::DecodeError);
    if (suite != CipherSuite::XChaCha20Poly1305 || !cipher_suite_supported(suite))
      return Result::failure(CryptoError::UnsupportedSuite);
    if (!valid_public_key(peer_key))
      return Result::failure(CryptoError::InvalidPeerKey);
    return Result::success();
  }

  static void random_handshake_nonce(HandshakeNonce& out)
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    randombytes_buf(out.data(), out.size());
#else
    out.fill(0);
#endif
  }
};

class CryptoContext
{
public:
  CryptoContext() = default;

  [[nodiscard]] bool is_ready() const noexcept
  {
    return suite == CipherSuite::XChaCha20Poly1305 && haveKeys;
  }

  Result encrypt(const unsigned char* plain,
                 std::size_t plain_len,
                 const unsigned char* associated_data,
                 std::size_t associated_data_len,
                 BitStream& out)
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!is_ready())
      return Result::failure(CryptoError::NotReady);
    if ((plain_len > 0 && plain == nullptr) ||
        (associated_data_len > 0 && associated_data == nullptr))
      return Result::failure(CryptoError::InvalidState);

    Nonce nonce;
    auto result = txNonce.next_nonce(nonce);
    if (!result.ok)
      return result;

    std::vector<unsigned char> cipher(plain_len + k_mac_size);
    unsigned long long outLen = 0; // NOLINT
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(cipher.data(), &outLen,
                                                   plain, plain_len,
                                                   associated_data, associated_data_len,
                                                   nullptr, nonce.data(), keyTx.data()) != 0)
    {
      return Result::failure(CryptoError::SodiumFailure);
    }

    out.clear();
    out.writeBytes(nonce.data(), nonce.size());
    out.writeBytes(cipher.data(), static_cast<std::size_t>(outLen));
    return Result::success();
#else
    (void)plain;
    (void)plain_len;
    (void)associated_data;
    (void)associated_data_len;
    (void)out;
    return Result::failure(CryptoError::NotInitialized);
#endif
  }

  Result decrypt(const unsigned char* data,
                 std::size_t len,
                 const unsigned char* associated_data,
                 std::size_t associated_data_len,
                 BitStream& out_plain)
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!is_ready())
      return Result::failure(CryptoError::NotReady);
    if (data == nullptr || len < k_nonce_size + k_mac_size ||
        (associated_data_len > 0 && associated_data == nullptr))
      return Result::failure(CryptoError::DecodeError);

    Nonce nonce;
    std::memcpy(nonce.data(), data, nonce.size());
    if (nonce_seen(nonce))
      return Result::failure(CryptoError::ReplayDetected);

    const unsigned char* cipher = data + k_nonce_size;
    const std::size_t cipher_len = len - k_nonce_size;
    std::vector<unsigned char> plain(cipher_len);
    unsigned long long plainOut = 0; // NOLINT
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(), &plainOut,
                                                   nullptr,
                                                   cipher, cipher_len,
                                                   associated_data, associated_data_len,
                                                   nonce.data(), keyRx.data()) != 0)
    {
      return Result::failure(CryptoError::DecryptFailed);
    }

    remember_nonce(nonce);
    out_plain.clear();
    out_plain.writeBytes(plain.data(), static_cast<std::size_t>(plainOut));
    return Result::success();
#else
    (void)data;
    (void)len;
    (void)associated_data;
    (void)associated_data_len;
    (void)out_plain;
    return Result::failure(CryptoError::NotInitialized);
#endif
  }

  Result encrypt(std::uint64_t seq,
                 const unsigned char* plain,
                 std::size_t plain_len,
                 BitStream& out)
  {
    unsigned char ad[8];
    encode_le64(seq, ad);
    return encrypt(plain, plain_len, ad, sizeof(ad), out);
  }

  Result decrypt(std::uint64_t seq,
                 const unsigned char* data,
                 std::size_t len,
                 BitStream& out_plain)
  {
    unsigned char ad[8];
    encode_le64(seq, ad);
    return decrypt(data, len, ad, sizeof(ad), out_plain);
  }

  static CryptoContext from_client(const SessionKeys& keys)
  {
    CryptoContext ctx;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (keys.valid())
    {
      ctx.keyRx = keys.rx;
      ctx.keyTx = keys.tx;
      const auto tx_ready = ctx.txNonce.init_random();
      if (tx_ready.ok)
      {
        ctx.haveKeys = true;
        ctx.suite = CipherSuite::XChaCha20Poly1305;
      }
    }
#else
    (void)keys;
#endif
    return ctx;
  }

  static CryptoContext from_server(const SessionKeys& keys)
  {
    CryptoContext ctx;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (keys.valid())
    {
      ctx.keyRx = keys.rx;
      ctx.keyTx = keys.tx;
      const auto tx_ready = ctx.txNonce.init_random();
      if (tx_ready.ok)
      {
        ctx.haveKeys = true;
        ctx.suite = CipherSuite::XChaCha20Poly1305;
      }
    }
#else
    (void)keys;
#endif
    return ctx;
  }

private:
  CipherSuite suite = CipherSuite::None;
  bool haveKeys = false;
  [[maybe_unused]] SessionKey keyRx{};
  [[maybe_unused]] SessionKey keyTx{};
  NonceGenerator txNonce{};
  std::deque<Nonce> receivedNonces{};

  [[nodiscard]] bool nonce_seen(const Nonce& nonce) const
  {
    return std::find(receivedNonces.begin(), receivedNonces.end(), nonce) != receivedNonces.end();
  }

  void remember_nonce(const Nonce& nonce)
  {
    receivedNonces.push_back(nonce);
    while (receivedNonces.size() > k_replay_window_size)
      receivedNonces.pop_front();
  }

  static void encode_le64(std::uint64_t v, unsigned char out[8])
  {
    for (int i = 0; i < 8; ++i)
    {
      out[i] = static_cast<unsigned char>(v & 0xFFu);
      v >>= 8;
    }
  }
};

struct IdentitySignature
{
  std::vector<unsigned char> bytes;
};

} // namespace socketwire::crypto
