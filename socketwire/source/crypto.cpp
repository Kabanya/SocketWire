#include "crypto.hpp"

namespace socketwire::crypto
{

CryptoContext HandshakeState::createClientCryptoContext() const
{
  return CryptoContext::fromClient(session);
}

CryptoContext HandshakeState::createServerCryptoContext() const
{
  return CryptoContext::fromServer(session);
}

Result initialize()
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  if (sodium_init() < 0)
    return Result::failure(CryptoError::SodiumFailure);
  return Result::success();
#else
  return Result::failure(CryptoError::NotInitialized);
#endif
}

bool cipherSuiteSupported(CipherSuite s)
{
#if SOCKETWIRE_HAVE_LIBSODIUM
  return s == CipherSuite::XChaCha20Poly1305;
#else
  (void)s;
  return false;
#endif
}

const char* to_string(CryptoError error) noexcept
{
  switch (error)
  {
    case CryptoError::None: return "None";
    case CryptoError::NotInitialized: return "NotInitialized";
    case CryptoError::UnsupportedSuite: return "UnsupportedSuite";
    case CryptoError::InvalidState: return "InvalidState";
    case CryptoError::DecodeError: return "DecodeError";
    case CryptoError::KeyExchangeFailed: return "KeyExchangeFailed";
    case CryptoError::SodiumFailure: return "SodiumFailure";
    case CryptoError::BufferTooSmall: return "BufferTooSmall";
    case CryptoError::SequenceExpired: return "SequenceExpired";
    case CryptoError::DecryptFailed: return "DecryptFailed";
    case CryptoError::NotReady: return "NotReady";
    default: return "Unknown";
  }
}

} // namespace socketwire::crypto
