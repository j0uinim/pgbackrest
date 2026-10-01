/***********************************************************************************************************************************
Stanza Commands Handler
***********************************************************************************************************************************/
#ifndef COMMAND_STANZA_COMMON_H
#define COMMAND_STANZA_COMMON_H

#include "info/infoPg.h"
#include "postgres/interface.h"

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
// Generate a sub pass for a file at this format. The sub pass has the cipher type and the stanza of the spec that encrypts the file
// it is stored in, as when the file is read back. For the block cipher the format also sets the digest, since that is what will
// derive the key when the file is read back, and for aes-256-gcm the sub pass is a key of random bytes.
FN_EXTERN CipherSpec *cipherSpecGen(const CipherSpec *cipherSpecParent, unsigned int format);

// Validate and return database information
FN_EXTERN PgControl pgValidate(void);

#endif
