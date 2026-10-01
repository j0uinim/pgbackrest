/***********************************************************************************************************************************
Crypto Harness
***********************************************************************************************************************************/
#include <build.h>

#include <string.h>

#include "harness/crypto.h"
#include "harness/debug.h"

/***********************************************************************************************************************************
Include shimmed C modules
***********************************************************************************************************************************/
{[SHIM_MODULE]}

static struct
{
    const Buffer *random;                                           // Bytes to return from the next cryptoRandomBytes()
} hrnCryptoLocal;

/**********************************************************************************************************************************/
void
hrnCryptoRandomBytesSet(const Buffer *const random)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(BUFFER, random);
    FUNCTION_HARNESS_END();

    ASSERT(hrnCryptoLocal.random == NULL);
    ASSERT(random != NULL);

    hrnCryptoLocal.random = random;

    FUNCTION_HARNESS_RETURN_VOID();
}

/**********************************************************************************************************************************/
void
cryptoRandomBytes(uint8_t *const buffer, const size_t size)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM_P(VOID, buffer);
        FUNCTION_HARNESS_PARAM(SIZE, size);
    FUNCTION_HARNESS_END();

    // Return random bytes
    if (hrnCryptoLocal.random == NULL)
    {
        cryptoRandomBytes_SHIMMED(buffer, size);
    }
    // Else return the bytes that were set, once
    else
    {
        ASSERT(bufUsed(hrnCryptoLocal.random) == size);

        memcpy(buffer, bufPtrConst(hrnCryptoLocal.random), size);
        hrnCryptoLocal.random = NULL;
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
