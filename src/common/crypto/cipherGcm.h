/***********************************************************************************************************************************
Streaming AEAD Cipher

Tink's AES-GCM-HKDF streaming AEAD with the parameters of its AES256_GCM_HKDF_1MB key template, unchanged, so that Tink can decrypt
what is written here and the reverse (https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming):

- each stream has a header of 40 bytes: the header size, a random 32-byte salt, and a random 7-byte nonce prefix
- the stream key is HKDF-SHA256 of the key, with the salt as the salt and the associated data as the info
- the plaintext is split into segments that are each encrypted with AES-256-GCM and a 16-byte tag, so that a stream of any size can
  be processed with bounded memory. The first segment holds 40 bytes less so that it ends on the same boundary as the others.
- the nonce of a segment is the nonce prefix, the segment number, and a byte that is set only for the last segment

The associated data is not encrypted but it must be the same on decrypt. It binds a stream to its identity so a stream copied to
another identity does not decrypt. A modified, truncated, extended, or reordered stream does not decrypt either.

Plaintext is never released from a segment before its tag has been verified. A stream is only known to be complete when the last
segment has been verified, so the output of a stream that fails must not be used even when some segments were released.
***********************************************************************************************************************************/
#ifndef COMMON_CRYPTO_CIPHERGCM_H
#define COMMON_CRYPTO_CIPHERGCM_H

#include <openssl/opensslv.h>

#include "common/crypto/common.h"
#include "common/io/filter/filter.h"
#include "common/type/stringList.h"

/***********************************************************************************************************************************
Filter type constant
***********************************************************************************************************************************/
#define CIPHER_GCM_FILTER_TYPE                                      STRID5("cipher-gcm", 0x1a33ee45441230)

/***********************************************************************************************************************************
Defined when the cipher can be built. It needs HKDF from OpenSSL 3.0.8, since earlier versions limit the associated data it can
bind, OpenSSL 3.0.0 to 3.0.7 to 2048 bytes.
***********************************************************************************************************************************/
#if OPENSSL_VERSION_NUMBER >= 0x30000080L
#define CIPHER_GCM_SUPPORTED
#endif

/***********************************************************************************************************************************
Sizes
***********************************************************************************************************************************/
// Size of the key. A key is always random bytes and never a passphrase, so no key derivation other than HKDF is needed.
#define CIPHER_GCM_KEY_SIZE                                         32

// Largest associated data. OpenSSL 3.0.8 does not accept a larger HKDF info and the associated data is never hashed to fit.
#define CIPHER_GCM_AD_SIZE_MAX                                      32768

/***********************************************************************************************************************************
Constructors
***********************************************************************************************************************************/
// Encrypt or decrypt a stream bound to the associated data. The key must be CIPHER_GCM_KEY_SIZE bytes, see cipherGcmKeyDecode().
FN_EXTERN IoFilter *cipherGcmNew(CipherMode mode, const Buffer *key, const Buffer *ad);
FN_EXTERN IoFilter *cipherGcmNewPack(const Pack *paramList);

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
// Associated data from a list of fields that identify the stream. Each field is terminated by a zero byte, so no field may contain
// one, and the fields are preceded by the project, the repository format, and the cipher type so that a stream cannot be decrypted
// as a different format or cipher.
FN_EXTERN Buffer *cipherGcmAdNew(const StringList *fieldList);

// Decode a key from its base64 text. The key must be the canonical base64 of exactly CIPHER_GCM_KEY_SIZE bytes, i.e. encoding the
// result must give back exactly the same text, so that a passphrase cannot be used as a key by mistake. The caller clears the
// result.
FN_EXTERN Buffer *cipherGcmKeyDecode(const Buffer *key);

// Is the text the canonical base64 of a key? See cipherGcmKeyDecode().
FN_EXTERN bool cipherGcmKeyValid(const Buffer *key);

// Generate a random key encoded as base64
FN_EXTERN String *cipherGcmKeyNew(void);

#endif
