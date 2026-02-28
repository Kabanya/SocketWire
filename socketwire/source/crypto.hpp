#pragma once
/*
  Lightweight authenticated encryption and client/server handshake built on top
  of libsodium. Provides:
    - Key generation (static keypair for identity + session shared keys)
    - Client/Server handshake messages (Hello -> Hello/Reject)
    - Derivation of per-direction session keys (rx / tx)
    - AEAD (XChaCha20-Poly1305) encryption helpers for datagrams
    - Simple replay protection / sequence numbering skeleton
*/

#include <cstdint>
#include <array>
#include <vector>
#include <cstring>

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

// Protocol Constants
constexpr std::uint8_t kProtocolVersionMajor = 1;
constexpr std::uint8_t kProtocolVersionMinor = 0;

// Maximum size sanity for handshake messages
constexpr std::size_t kMaxHandshakeMessageSize = 512;

// AEAD algorithm selection (enum for extensibility)
enum class CipherSuite : std::uint8_t
{
  None = 0,
#if SOCKETWIRE_HAVE_LIBSODIUM
  XChaCha20Poly1305 = 1
#endif
};

// Handshake opcodes
enum class HandshakeOpcode : std::uint8_t
{
  ClientHello   = 1,
  ServerHello   = 2,
  ServerReject  = 3
};

// Error codes for handshake / crypto operations
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
  NotReady
};

// Convert CryptoError to human-readable string
[[nodiscard]] const char* to_string(CryptoError error) noexcept;

// Simple result wrapper
struct Result
{
  bool ok;
  CryptoError error;
  static Result success() { return {true, CryptoError::None}; }
  static Result failure(CryptoError e) { return {false, e}; }
};

// Key Structures
#if SOCKETWIRE_HAVE_LIBSODIUM
struct KeyPair
{
  std::array<unsigned char, crypto_kx_PUBLICKEYBYTES> publicKey{};
  std::array<unsigned char, crypto_kx_SECRETKEYBYTES> secretKey{};

  static KeyPair generate()
  {
    KeyPair kp;
    if (crypto_kx_keypair(kp.publicKey.data(), kp.secretKey.data()) != 0)
    {
      // Fallback: zeroed keys indicate generation failure
      kp.publicKey.fill(0);
      kp.secretKey.fill(0);
    }
    return kp;
  }

  bool valid() const
  {
    // Very basic validity check: not all zeros
    for (auto c : publicKey)
      if (c != 0) return true;
    return false;
  }
};

struct SessionKeys
{
  std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> rx{};
  std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> tx{};

  bool valid() const
  {
    bool nonZero = false;
    for (auto c : rx) if (c != 0) { nonZero = true; break; }
    for (auto c : tx) if (c != 0) { nonZero = true; break; }
    return nonZero;
  }
};
#else
struct KeyPair
{
  static KeyPair generate() { return {}; }
  bool valid() const { return false; }
};

struct SessionKeys
{
  bool valid() const { return false; }
};
#endif

/*Nonce Generator
  For XChaCha20-Poly1305 we need 24-byte nonces.
  We combine a random "base" (first 16 bytes) + 8-byte counter (little-endian).
  NOTE: Ensure monotonic increment per direction to avoid nonce reuse.
 */
struct NonceGenerator
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> base{};
#else
  std::array<unsigned char, 24> base{};
#endif
  std::uint64_t counter = 0;

  void initRandom()
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    randombytes_buf(base.data(), base.size());
#else
    // Non-crypto random fallback (not secure). Production code should fail.
    for (auto& b : base) b = static_cast<unsigned char>(std::rand() & 0xFF);
#endif
    counter = 0;
  }

  void fillNonce(unsigned char* out24)
  {
    std::memcpy(out24, base.data(), base.size());
    // Overwrite last 8 bytes with counter (little-endian)
    unsigned char* tail = out24 + (base.size() - 8);
    std::uint64_t c = counter;
    for (int i = 0; i < 8; ++i)
    {
      tail[i] = static_cast<unsigned char>(c & 0xFF);
      c >>= 8;
    }
  }

  void nextNonce(unsigned char* out24)
  {
    fillNonce(out24);
    counter++;
  }
};


//  Handshake State
//  Tracks progress and stores derived keys.
enum class HandshakeRole : std::uint8_t
{
  None  = 0,
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
  std::uint8_t versionMajor = kProtocolVersionMajor;
  std::uint8_t versionMinor = kProtocolVersionMinor;
#if SOCKETWIRE_HAVE_LIBSODIUM
  CipherSuite suite = CipherSuite::XChaCha20Poly1305;
#else
  CipherSuite suite = CipherSuite::None;
#endif
  std::array<unsigned char, 32> nonce{}; // arbitrary handshake nonce
  std::vector<unsigned char> clientPub;  // variable to avoid compile-time libsodium check
};

struct ServerHelloData
{
  std::uint8_t versionMajor = kProtocolVersionMajor;
  std::uint8_t versionMinor = kProtocolVersionMinor;
#if SOCKETWIRE_HAVE_LIBSODIUM
  CipherSuite suite = CipherSuite::XChaCha20Poly1305;
#else
  CipherSuite suite = CipherSuite::None;
#endif
  std::array<unsigned char, 32> nonce{};
  std::vector<unsigned char> serverPub;
};

// Serialization helpers for handshake messages into BitStream
inline void writeClientHello(BitStream& bs, const ClientHelloData& d)
{
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(HandshakeOpcode::ClientHello));
  bs.write<std::uint8_t>(d.versionMajor);
  bs.write<std::uint8_t>(d.versionMinor);
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(d.suite));
  bs.writeBytes(d.nonce.data(), d.nonce.size());
  std::uint16_t pkLen = static_cast<std::uint16_t>(d.clientPub.size());
  bs.write<std::uint16_t>(pkLen);
  if (pkLen != 0u)
    bs.writeBytes(d.clientPub.data(), pkLen);
}

inline bool readClientHello(const unsigned char* data, std::size_t len, ClientHelloData& out)
{
  try
  {
    BitStream bs(data, len);
    std::uint8_t opcode;
    bs.read<std::uint8_t>(opcode);
    if (opcode != static_cast<std::uint8_t>(HandshakeOpcode::ClientHello))
      return false;
    bs.read<std::uint8_t>(out.versionMajor);
    bs.read<std::uint8_t>(out.versionMinor);
    std::uint8_t suiteByte;
    bs.read<std::uint8_t>(suiteByte);
    out.suite = static_cast<CipherSuite>(suiteByte);
    bs.readBytes(out.nonce.data(), out.nonce.size());
    std::uint16_t pkLen;
    bs.read<std::uint16_t>(pkLen);
    if (pkLen > 1024) return false;
    out.clientPub.resize(pkLen);
    if (pkLen != 0u)
      bs.readBytes(out.clientPub.data(), pkLen);
    return true;
  }
  catch (...)
  {
    return false;
  }
}

inline void writeServerHello(BitStream& bs, const ServerHelloData& d)
{
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(HandshakeOpcode::ServerHello));
  bs.write<std::uint8_t>(d.versionMajor);
  bs.write<std::uint8_t>(d.versionMinor);
  bs.write<std::uint8_t>(static_cast<std::uint8_t>(d.suite));
  bs.writeBytes(d.nonce.data(), d.nonce.size());
  std::uint16_t pkLen = static_cast<std::uint16_t>(d.serverPub.size());
  bs.write<std::uint16_t>(pkLen);
  if (pkLen != 0u)
    bs.writeBytes(d.serverPub.data(), pkLen);
}

inline bool readServerHello(const unsigned char* data, std::size_t len, ServerHelloData& out)
{
  try
  {
    BitStream bs(data, len);
    std::uint8_t opcode;
    bs.read<std::uint8_t>(opcode);
    if (opcode != static_cast<std::uint8_t>(HandshakeOpcode::ServerHello))
      return false;
    bs.read<std::uint8_t>(out.versionMajor);
    bs.read<std::uint8_t>(out.versionMinor);
    std::uint8_t suiteByte;
    bs.read<std::uint8_t>(suiteByte);
    out.suite = static_cast<CipherSuite>(suiteByte);
    bs.readBytes(out.nonce.data(), out.nonce.size());
    std::uint16_t pkLen;
    bs.read<std::uint16_t>(pkLen);
    if (pkLen > 1024) return false;
    out.serverPub.resize(pkLen);
    if (pkLen != 0u)
      bs.readBytes(out.serverPub.data(), pkLen);
    return true;
  }
  catch (...)
  {
    return false;
  }
}

// Main handshake state machine
class HandshakeState
{
public:
  HandshakeState() = default;

  void startClient(const KeyPair& clientKeys)
  {
    role = HandshakeRole::Client;
    phase = HandshakePhase::Empty;
    staticKeys = clientKeys;
    randomHandshakeNonce(clientHello.nonce);
#if SOCKETWIRE_HAVE_LIBSODIUM
    clientHello.clientPub.assign(staticKeys.publicKey.begin(), staticKeys.publicKey.end());
#else
    clientHello.clientPub.clear();
#endif
  }

  void startServer(const KeyPair& serverKeys)
  {
    role = HandshakeRole::Server;
    phase = HandshakePhase::Empty;
    staticKeys = serverKeys;
  }

  Result writeClientHello(BitStream& out)
  {
    if (role != HandshakeRole::Client || !staticKeys.valid())
      return Result::failure(CryptoError::InvalidState);
    clientHello.versionMajor = kProtocolVersionMajor;
    clientHello.versionMinor = kProtocolVersionMinor;
    clientHello.suite = defaultSuite();
    ::socketwire::crypto::writeClientHello(out, clientHello);
    phase = HandshakePhase::ClientHelloSent;
    return Result::success();
  }

  Result writeServerHello(BitStream& out)
  {
    if (role != HandshakeRole::Server || !staticKeys.valid())
      return Result::failure(CryptoError::InvalidState);
    serverHello.versionMajor = kProtocolVersionMajor;
    serverHello.versionMinor = kProtocolVersionMinor;
    serverHello.suite = defaultSuite();
    randomHandshakeNonce(serverHello.nonce);
#if SOCKETWIRE_HAVE_LIBSODIUM
    serverHello.serverPub.assign(staticKeys.publicKey.begin(), staticKeys.publicKey.end());
#endif
    ::socketwire::crypto::writeServerHello(out, serverHello);
    phase = HandshakePhase::ServerHelloSent;
    return Result::success();
  }

  bool processClientHello(const unsigned char* data, std::size_t len)
  {
    if (role != HandshakeRole::Server) return false;
    ClientHelloData tmp;
    if (!readClientHello(data, len, tmp)) return false;
    if (!versionSupported(tmp.versionMajor, tmp.versionMinor)) return false;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (tmp.clientPub.size() != crypto_kx_PUBLICKEYBYTES) return false;
#endif
    clientHello = tmp;
    // Derive session keys (server side)
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (crypto_kx_server_session_keys(session.rx.data(), session.tx.data(),
                                      staticKeys.publicKey.data(), staticKeys.secretKey.data(),
                                      clientHello.clientPub.data()) != 0)
    {
      return false;
    }
#endif
    phase = HandshakePhase::Completed;
    return true;
  }

  bool processServerHello(const unsigned char* data, std::size_t len)
  {
    if (role != HandshakeRole::Client) return false;
    ServerHelloData tmp;
    if (!readServerHello(data, len, tmp)) return false;
    if (!versionSupported(tmp.versionMajor, tmp.versionMinor)) return false;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (tmp.serverPub.size() != crypto_kx_PUBLICKEYBYTES) return false;
#endif
    serverHello = tmp;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (crypto_kx_client_session_keys(session.rx.data(), session.tx.data(),
                                      staticKeys.publicKey.data(), staticKeys.secretKey.data(),
                                      serverHello.serverPub.data()) != 0)
    {
      return false;
    }
#endif
    phase = HandshakePhase::Completed;
    return true;
  }

  bool completed() const { return phase == HandshakePhase::Completed && session.valid(); }
  HandshakeRole getRole() const { return role; }

  /* Create CryptoContext after successful handshake */
  class CryptoContext createClientCryptoContext() const;
  class CryptoContext createServerCryptoContext() const;

  const SessionKeys& getSessionKeys() const { return session; }

private:
  HandshakeRole role = HandshakeRole::None;
  HandshakePhase phase = HandshakePhase::Empty;
  KeyPair staticKeys{};
  SessionKeys session{};
  ClientHelloData clientHello{};
  ServerHelloData serverHello{};

  static CipherSuite defaultSuite()
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    return CipherSuite::XChaCha20Poly1305;
#else
    return CipherSuite::None;
#endif
  }

  static bool versionSupported(std::uint8_t maj, std::uint8_t min)
  {
    // Strategy: accept same major, min <= current minor
    return maj == kProtocolVersionMajor && min <= kProtocolVersionMinor;
  }

  static void randomHandshakeNonce(std::array<unsigned char, 32>& out)
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    randombytes_buf(out.data(), out.size());
#else
    for (auto& b : out) b = static_cast<unsigned char>(std::rand() & 0xFF);
#endif
  }
};

/*
  CryptoContext
  Uses session keys to provide encryption/decryption of datagrams.
  Each direction has its own NonceGenerator (txNonce / rxNonce).
  Sequence numbers are external (provided by transport or reliability layer).
 */
class CryptoContext
{
public:
  CryptoContext() = default;

  bool isReady() const
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    return suite == CipherSuite::XChaCha20Poly1305 && haveKeys;
#else
    return false;
#endif
  }

  /*
    Encryption: produce ciphertext (BitStream) from plaintext buffer.
    AD (Associated Data) can include sequence number, channel id, etc.
    For simplicity, we treat seq as AD (little-endian 64-bit).
  */
  bool encrypt(std::uint64_t seq,
               const unsigned char* plain,
               std::size_t plainLen,
               BitStream& out) const
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!isReady()) return false;
    unsigned char ad[8];
    encodeLE64(seq, ad);

    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    // We mutate txNonceGenerator copy; logically encryption should be non-const.
    // Cast away const for internal counter update (safe controlled mutation).
    const_cast<NonceGenerator&>(txNonce).nextNonce(nonce); //NOLINT

    std::vector<unsigned char> cipher(plainLen + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long outLen = 0; //NOLINT
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(cipher.data(), &outLen,
                                                   plain, plainLen,
                                                   ad, sizeof(ad),
                                                   nullptr, nonce, keyTx.data()) != 0)
      return false;

    // Serialize: [nonce(24)] [cipher bytes]
    out.clear();
    out.writeBytes(nonce, sizeof(nonce));
    out.writeBytes(cipher.data(), static_cast<std::size_t>(outLen));
    return true;
#else
    (void)seq; (void)plain; (void)plainLen; (void)out;
    return false;
#endif
  }

  bool decrypt(std::uint64_t seq,
               const unsigned char* data,
               std::size_t len,
               BitStream& outPlain) const
  {
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (!isReady()) return false;
    if (len < crypto_aead_xchacha20poly1305_ietf_NPUBBYTES +
              crypto_aead_xchacha20poly1305_ietf_ABYTES)
      return false;

    unsigned char ad[8];
    encodeLE64(seq, ad);

    const unsigned char* nonce = data;
    const unsigned char* cipher = data + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
    std::size_t cipherLen = len - crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;

    std::vector<unsigned char> plain(cipherLen); // allocate max; will shrink to actual
    unsigned long long plainOut = 0; //NOLINT
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain.data(), &plainOut,
                                                   nullptr,
                                                   cipher, cipherLen,
                                                   ad, sizeof(ad),
                                                   nonce, keyRx.data()) != 0)
      return false;

    outPlain.clear();
    outPlain.writeBytes(plain.data(), static_cast<std::size_t>(plainOut));
    return true;
#else
    (void)seq; (void)data; (void)len; (void)outPlain;
    return false;
#endif
  }

  // Internal setup from handshake (role-specific direction mapping)
  static CryptoContext fromClient(const SessionKeys& keys)
  {
    CryptoContext ctx;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (keys.valid())
    {
      ctx.keyRx = keys.rx; // client receives with rx, sends with tx
      ctx.keyTx = keys.tx;
      ctx.txNonce.initRandom();
      ctx.rxNonce.initRandom();
      ctx.haveKeys = true;
      ctx.suite = CipherSuite::XChaCha20Poly1305;
    }
#else
    (void)keys;
#endif
    return ctx;
  }

  static CryptoContext fromServer(const SessionKeys& keys)
  {
    CryptoContext ctx;
#if SOCKETWIRE_HAVE_LIBSODIUM
    if (keys.valid())
    {
      // libsodium docs: crypto_kx_server_session_keys: server uses rx to receive, tx to send (same mapping)
      ctx.keyRx = keys.rx;
      ctx.keyTx = keys.tx;
      ctx.txNonce.initRandom();
      ctx.rxNonce.initRandom();
      ctx.haveKeys = true;
      ctx.suite = CipherSuite::XChaCha20Poly1305;
    }
#else
    (void)keys;
#endif
    return ctx;
  }

private:
  [[maybe_unused]] CipherSuite suite = CipherSuite::None;
  [[maybe_unused]] bool haveKeys = false;
#if SOCKETWIRE_HAVE_LIBSODIUM
  std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> keyRx{};
  std::array<unsigned char, crypto_kx_SESSIONKEYBYTES> keyTx{};
#else
  [[maybe_unused]] std::array<unsigned char, 32> keyRx{};
  [[maybe_unused]] std::array<unsigned char, 32> keyTx{};
#endif
  [[maybe_unused]] NonceGenerator txNonce{};
  [[maybe_unused]] NonceGenerator rxNonce{}; // reserved for future (e.g., verifying remote nonce space)

  static void encodeLE64(std::uint64_t v, unsigned char out[8])
  {
    for (int i = 0; i < 8; ++i)
    {
      out[i] = static_cast<unsigned char>(v & 0xFF);
      v >>= 8;
    }
  }
};

// Implementations that depend on HandshakeState (declared earlier)
// (defined in crypto.cpp)

// Initialization
Result initialize();

/* Helper: report suite availability */
bool cipherSuiteSupported(CipherSuite s);

// Optional Utility: Identity Signature
// Placeholder: In future, we can use Ed25519 for identity signatures.

struct IdentitySignature
{
  std::vector<unsigned char> bytes;
};

} // namespace socketwire::crypto
