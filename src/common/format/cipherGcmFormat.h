/***********************************************************************************************************************************
Cipher GCM Format

Encryption of a stream at repository format 7, which is written with the aes-256-gcm cipher only. A standalone object, i.e. a file
in the repository, begins with a plaintext prefix of eight bytes: PGBR, the format, and G for the cipher, followed by the Tink
ciphertext. A raw stream has no prefix. It is a stream that is only ever part of another object, e.g. a file in a bundle, a super
block, or a block map, and is reached only through the authenticated manifest.

The prefix is framing rather than part of the ciphertext, and nothing in it is trusted. The cipher is chosen from the configuration,
never from the prefix, so a prefix cannot select another cipher or format, and the reader checks that the prefix is exactly the one
it expects before anything is decrypted. The format and the cipher are also bound into the associated data, so a stream that was
written for another format or cipher does not decrypt whatever prefix is put in front of it.
***********************************************************************************************************************************/
#ifndef COMMON_FORMAT_CIPHERGCMFORMAT_H
#define COMMON_FORMAT_CIPHERGCMFORMAT_H

#include "common/crypto/common.h"
#include "common/io/filter/filter.h"
#include "common/type/pack.h"

/***********************************************************************************************************************************
Filter type constant
***********************************************************************************************************************************/
#define CIPHER_GCM_FORMAT_FILTER_TYPE                               STRID5("cipher-gfmt", 0x51a63ee45441230)

/***********************************************************************************************************************************
Prefix of a standalone object
***********************************************************************************************************************************/
#define CIPHER_GCM_FORMAT_PREFIX                                    "PGBR007G"
#define CIPHER_GCM_FORMAT_PREFIX_SIZE                               (sizeof(CIPHER_GCM_FORMAT_PREFIX) - 1)

/***********************************************************************************************************************************
Constructors
***********************************************************************************************************************************/
typedef struct CipherGcmFormatNewParam
{
    VAR_PARAM_HEADER;
    bool raw;                                                       // A stream inside another object, which has no prefix
} CipherGcmFormatNewParam;

#define cipherGcmFormatNewP(mode, key, ad, ...)                                                                                    \
    cipherGcmFormatNew(mode, key, ad, (CipherGcmFormatNewParam){VAR_PARAM_INIT, __VA_ARGS__})

// Encrypt or decrypt a stream bound to the associated data, see cipherGcmNew()
FN_EXTERN IoFilter *cipherGcmFormatNew(CipherMode mode, const Buffer *key, const Buffer *ad, CipherGcmFormatNewParam param);
FN_EXTERN IoFilter *cipherGcmFormatNewPack(const Pack *paramList);

#endif
