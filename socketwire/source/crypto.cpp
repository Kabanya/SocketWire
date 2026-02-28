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

} // namespace socketwire::crypto
