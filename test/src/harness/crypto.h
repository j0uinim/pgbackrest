/***********************************************************************************************************************************
Crypto Harness
***********************************************************************************************************************************/
#ifndef TEST_HARNESS_CRYPTO_H
#define TEST_HARNESS_CRYPTO_H

#include "common/type/buffer.h"
#include "common/type/stringList.h"

/***********************************************************************************************************************************
Macros
***********************************************************************************************************************************/
// Fields of an aes-256-gcm identity, or of the associated data made from one, separated by |. Tests write the fields out rather
// than build them with the code under test so that a difference in either shows.
#define HRN_CIPHER_IDENTITY(fields)                                 strLstNewSplitZ(STRDEF(fields), "|")

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
// Set the bytes returned by the next call to cryptoRandomBytes(), e.g. the salt and nonce prefix of a known-answer test. The next
// call must ask for exactly this many bytes and later calls are random again.
void hrnCryptoRandomBytesSet(const Buffer *random);

#endif
