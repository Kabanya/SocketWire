#include "crypto.hpp"

namespace socketwire::crypto {

CryptoContext HandshakeState::CreateClientCryptoContext() const {
  return CryptoContext::FromClient(session);
}

CryptoContext HandshakeState::CreateServerCryptoContext() const {
  return CryptoContext::FromServer(session);
}

Result Initialize() {
#if SOCKETWIRE_HAVE_LIBSODIUM
  if (sodium_init() < 0) return Result::Failure(CryptoError::kSodiumFailure);
  return Result::Success();
#else
  return Result::failure(CryptoError::NotInitialized);
#endif
}

bool CipherSuiteSupported(CipherSuite s) {
#if SOCKETWIRE_HAVE_LIBSODIUM
  return s == CipherSuite::kXChaCha20Poly1305;
#else
  (void)s;
  return false;
#endif
}

const char* ToString(CryptoError error) noexcept {
  switch (error) {
    case CryptoError::kNone:
      return "None";
    case CryptoError::kNotInitialized:
      return "NotInitialized";
    case CryptoError::kUnsupportedSuite:
      return "UnsupportedSuite";
    case CryptoError::kInvalidState:
      return "InvalidState";
    case CryptoError::kDecodeError:
      return "DecodeError";
    case CryptoError::kKeyExchangeFailed:
      return "KeyExchangeFailed";
    case CryptoError::kSodiumFailure:
      return "SodiumFailure";
    case CryptoError::kBufferTooSmall:
      return "BufferTooSmall";
    case CryptoError::kSequenceExpired:
      return "SequenceExpired";
    case CryptoError::kDecryptFailed:
      return "DecryptFailed";
    case CryptoError::kNotReady:
      return "NotReady";
    case CryptoError::kInvalidPeerKey:
      return "InvalidPeerKey";
    case CryptoError::kReplayDetected:
      return "ReplayDetected";
    default:
      return "Unknown";
  }
}

}  // namespace socketwire::crypto
