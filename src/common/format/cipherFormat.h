/***********************************************************************************************************************************
Cipher Format

The cipher a stream in the repository is encrypted with, chosen from the cipher spec, i.e. from the configuration and never from
anything read from the repository. The block cipher is added as each caller added it before. A stream encrypted with aes-256-gcm
is bound to its identity: the stanza from the spec, the kind of stream, and the fields that name it, e.g. {"archive", <name>}. A
copy of the stream under another identity does not decrypt.
***********************************************************************************************************************************/
#ifndef COMMON_FORMAT_CIPHERFORMAT_H
#define COMMON_FORMAT_CIPHERFORMAT_H

#include "common/crypto/spec.h"
#include "common/io/filter/group.h"
#include "common/type/stringList.h"

/***********************************************************************************************************************************
The kind of a stream, i.e. the first field of its identity, and the states of a manifest. These are what every stream encrypted
with aes-256-gcm is bound to, so they are defined in one place and never change once written.
***********************************************************************************************************************************/
#define CIPHER_IDENTITY_ARCHIVE                                     "archive"
#define CIPHER_IDENTITY_BLOCK_MAP                                   "block-map"
#define CIPHER_IDENTITY_FILE                                        "file"
#define CIPHER_IDENTITY_INFO                                        "info"
#define CIPHER_IDENTITY_MANIFEST                                    "manifest"
#define CIPHER_IDENTITY_MANIFEST_FINAL                              "final"
#define CIPHER_IDENTITY_MANIFEST_HISTORY                            "manifest-history"
#define CIPHER_IDENTITY_MANIFEST_IN_PROGRESS                        "in-progress"
#define CIPHER_IDENTITY_SUPER_BLOCK                                 "super-block"

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
// Add the cipher of a standalone stream, i.e. a file in the repository, to a filter group. Nothing is added when the repository is
// not encrypted. The block cipher writes its magic in front of the stream and aes-256-gcm its format prefix.
FN_EXTERN IoFilterGroup *cipherFormatFilterGroupAdd(
    IoFilterGroup *filterGroup, CipherMode mode, const CipherSpec *cipherSpec, const StringList *identity);

// The cipher of a stream as a filter. The repository must be encrypted. A standalone stream has the magic or prefix in front of it
// as for cipherFormatFilterGroupAdd(), and a raw stream, i.e. a stream that is part of another object such as a file in a bundle,
// has neither.
typedef struct CipherFormatNewParam
{
    VAR_PARAM_HEADER;
    bool raw;                                                       // A stream inside another object, which has no magic or prefix
} CipherFormatNewParam;

#define cipherFormatNewP(mode, cipherSpec, identity, ...)                                                                          \
    cipherFormatNew(mode, cipherSpec, identity, (CipherFormatNewParam){VAR_PARAM_INIT, __VA_ARGS__})

FN_EXTERN IoFilter *cipherFormatNew(
    CipherMode mode, const CipherSpec *cipherSpec, const StringList *identity, CipherFormatNewParam param);

// Add encryption of an info file, e.g. archive.info, at a format. The block cipher writes the header of the format into the buffer
// the file is written into, and aes-256-gcm writes its prefix itself and binds the file to its name. Nothing is added when the
// repository is not encrypted.
FN_EXTERN void cipherFormatInfoWriteAdd(
    Buffer *buffer, IoFilterGroup *filterGroup, const CipherSpec *cipherSpec, unsigned int format, const char *infoName);

// Add decryption of an info file whose format has yet to be read. Nothing is added when the repository is not encrypted.
FN_EXTERN IoFilterGroup *cipherFormatInfoReadAdd(IoFilterGroup *filterGroup, const CipherSpec *cipherSpec, const char *infoName);

#endif
