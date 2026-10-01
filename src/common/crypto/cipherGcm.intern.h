/***********************************************************************************************************************************
Streaming AEAD Cipher Internal

The parameters of the construction. Production always uses the AES256_GCM_HKDF_1MB parameters, which no published test vector uses,
so the parameters can be set here for known-answer testing with Tink's vectors, which use smaller keys and segments and other
digests. The parameters are not stored in a stream, so a stream can only be decrypted with the parameters it was encrypted with.
***********************************************************************************************************************************/
#ifndef COMMON_CRYPTO_CIPHERGCM_INTERN_H
#define COMMON_CRYPTO_CIPHERGCM_INTERN_H

#include "common/crypto/cipherGcm.h"

/***********************************************************************************************************************************
Parameters
***********************************************************************************************************************************/
typedef struct CipherGcmParam
{
    const char *digest;                                             // HKDF digest name, e.g. SHA256
    size_t keySize;                                                 // Key size, at least the derived key size
    size_t derivedKeySize;                                          // Derived key size, which selects AES-128 or AES-256
    size_t segmentSize;                                             // Ciphertext segment size
} CipherGcmParam;

// The AES256_GCM_HKDF_1MB parameters
#define CIPHER_GCM_PARAM_DEFAULT                                                                                                   \
    ((CipherGcmParam){.digest = "SHA256", .keySize = CIPHER_GCM_KEY_SIZE, .derivedKeySize = 32, .segmentSize = 1024 * 1024})

/***********************************************************************************************************************************
Constructors
***********************************************************************************************************************************/
FN_EXTERN IoFilter *cipherGcmNewParam(CipherMode mode, const Buffer *key, const Buffer *ad, CipherGcmParam param);

#endif
