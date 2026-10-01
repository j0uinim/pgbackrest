/***********************************************************************************************************************************
Cipher GCM Format
***********************************************************************************************************************************/
#include <build.h>

#include <string.h>

#include <openssl/crypto.h>

#include "common/crypto/cipherGcm.h"
#include "common/debug.h"
#include "common/format/cipherGcmFormat.h"
#include "common/format/format.h"
#include "common/log.h"
#include "common/type/convert.h"
#include "common/type/object.h"

// The prefix is the size of format 6's header, so the two are told apart by what they say rather than by where the content begins
static_assert(CIPHER_GCM_FORMAT_PREFIX_SIZE == 8, "prefix must be the size of the format 6 header");
static_assert(REPOSITORY_FORMAT_7 == 7, "prefix must name format 7");

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct CipherGcmFormat
{
    CipherMode mode;                                                // Encrypt or decrypt
    bool raw;                                                       // A stream inside another object, which has no prefix
    IoFilter *cipher;                                               // Cipher the stream behind the prefix is processed by
    uint8_t prefix[CIPHER_GCM_FORMAT_PREFIX_SIZE];                  // Prefix bytes read so far on decrypt
    size_t prefixSize;                                              // Prefix bytes read or written so far
    size_t sourceOffset;                                            // Bytes of the current source taken for the prefix
    bool inputSame;                                                 // Is the same input required on the next call?
} CipherGcmFormat;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
static void
cipherGcmFormatToLog(const CipherGcmFormat *const this, StringStatic *const debugLog)
{
    strStcFmt(debugLog, "{raw: %s, prefixSize: %zu}", cvtBoolToConstZ(this->raw), this->prefixSize);
}

#define FUNCTION_LOG_CIPHER_GCM_FORMAT_TYPE                                                                                        \
    CipherGcmFormat *
#define FUNCTION_LOG_CIPHER_GCM_FORMAT_FORMAT(value, buffer, bufferSize)                                                           \
    FUNCTION_LOG_OBJECT_FORMAT(value, cipherGcmFormatToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Write the prefix in front of the ciphertext, as much as fits in the destination
***********************************************************************************************************************************/
static void
cipherGcmFormatPrefixWrite(CipherGcmFormat *const this, Buffer *const destination)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM_FORMAT, this);
        FUNCTION_TEST_PARAM(BUFFER, destination);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(destination != NULL);

    const size_t prefixRemains = CIPHER_GCM_FORMAT_PREFIX_SIZE - this->prefixSize;
    const size_t size = prefixRemains < bufRemains(destination) ? prefixRemains : bufRemains(destination);

    bufCatC(destination, (const uint8_t *)CIPHER_GCM_FORMAT_PREFIX, this->prefixSize, size);
    this->prefixSize += size;

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Read the prefix from the source and check it before anything is decrypted. It is compared whole, so a format 5 magic, a format 6
header, a format 7 header for another cipher, and anything else are all refused the same way.
***********************************************************************************************************************************/
static void
cipherGcmFormatPrefixRead(CipherGcmFormat *const this, const Buffer *const source)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM_FORMAT, this);
        FUNCTION_TEST_PARAM(BUFFER, source);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(source != NULL);

    const size_t prefixRemains = CIPHER_GCM_FORMAT_PREFIX_SIZE - this->prefixSize;

    this->sourceOffset = prefixRemains < bufUsed(source) ? prefixRemains : bufUsed(source);

    memcpy(this->prefix + this->prefixSize, bufPtrConst(source), this->sourceOffset);
    this->prefixSize += this->sourceOffset;

    if (this->prefixSize == CIPHER_GCM_FORMAT_PREFIX_SIZE &&
        memcmp(this->prefix, CIPHER_GCM_FORMAT_PREFIX, CIPHER_GCM_FORMAT_PREFIX_SIZE) != 0)
    {
        THROW(FormatError, "cipher header is not repository format 7 with cipher type aes-256-gcm");
    }

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Process function used by C filter
***********************************************************************************************************************************/
static void
cipherGcmFormatProcess(THIS_VOID, const Buffer *const source, Buffer *const destination)
{
    THIS(CipherGcmFormat);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CIPHER_GCM_FORMAT, this);
        FUNCTION_LOG_PARAM(BUFFER, source);
        FUNCTION_LOG_PARAM(BUFFER, destination);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(destination != NULL);
    ASSERT(bufRemains(destination) > 0);

    this->inputSame = false;

    // A raw stream is only the ciphertext
    if (this->raw)
    {
        ioFilterProcessInOut(this->cipher, source, destination);
        this->inputSame = ioFilterInputSame(this->cipher);
    }
    // On encrypt the prefix is written first. The same input is asked for again until it has all been written and there is room for
    // what follows.
    else if (this->mode == cipherModeEncrypt)
    {
        if (this->prefixSize < CIPHER_GCM_FORMAT_PREFIX_SIZE)
            cipherGcmFormatPrefixWrite(this, destination);

        if (bufRemains(destination) == 0)
            this->inputSame = true;
        else
        {
            ioFilterProcessInOut(this->cipher, source, destination);
            this->inputSame = ioFilterInputSame(this->cipher);
        }
    }
    // On decrypt the prefix is read and checked first, then what follows it is decrypted
    else if (source != NULL)
    {
        if (this->prefixSize < CIPHER_GCM_FORMAT_PREFIX_SIZE)
            cipherGcmFormatPrefixRead(this, source);

        // Decrypt whatever of the source the prefix did not take
        if (this->sourceOffset < bufUsed(source))
        {
            ioFilterProcessInOut(
                this->cipher, BUF(bufPtrConst(source) + this->sourceOffset, bufUsed(source) - this->sourceOffset), destination);
            this->inputSame = ioFilterInputSame(this->cipher);
        }

        // The prefix is taken from the source only once
        if (!this->inputSame)
            this->sourceOffset = 0;
    }
    // Else all the input has been seen, so the cipher is flushed. A stream too short to hold the prefix cannot have one.
    else
    {
        if (this->prefixSize < CIPHER_GCM_FORMAT_PREFIX_SIZE)
            THROW(FormatError, "cipher header is not repository format 7 with cipher type aes-256-gcm");

        ioFilterProcessInOut(this->cipher, NULL, destination);
        this->inputSame = ioFilterInputSame(this->cipher);
    }

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is the filter done?
***********************************************************************************************************************************/
static bool
cipherGcmFormatDone(const THIS_VOID)
{
    THIS(const CipherGcmFormat);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM_FORMAT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, !this->inputSame && ioFilterDone(this->cipher));
}

/***********************************************************************************************************************************
Should the same input be provided again?
***********************************************************************************************************************************/
static bool
cipherGcmFormatInputSame(const THIS_VOID)
{
    THIS(const CipherGcmFormat);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM_FORMAT, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
cipherGcmFormatNew(const CipherMode mode, const Buffer *const key, const Buffer *const ad, const CipherGcmFormatNewParam param)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STRING_ID, mode);
        FUNCTION_TEST_PARAM(BUFFER, key);                           // Not logged since the key is secret
        FUNCTION_LOG_PARAM(BUFFER, ad);
        FUNCTION_LOG_PARAM(BOOL, param.raw);
    FUNCTION_LOG_END();

    OBJ_NEW_BEGIN(CipherGcmFormat, .childQty = MEM_CONTEXT_QTY_MAX)
    {
        // The cipher checks the mode, the key, and the associated data, which can arrive in a pack, in every build
        *this = (CipherGcmFormat)
        {
            .mode = mode,
            .raw = param.raw,
            .cipher = cipherGcmNew(mode, key, ad),
        };
    }
    OBJ_NEW_END();

    // Create param list
    Pack *paramList;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackWrite *const packWrite = pckWriteNewP();

        pckWriteU64P(packWrite, mode);
        pckWriteBinP(packWrite, key);
        pckWriteBinP(packWrite, ad);
        pckWriteBoolP(packWrite, param.raw);
        pckWriteEndP(packWrite);

        paramList = pckMove(pckWriteResult(packWrite), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            CIPHER_GCM_FORMAT_FILTER_TYPE, this, paramList, .done = cipherGcmFormatDone, .inOut = cipherGcmFormatProcess,
            .inputSame = cipherGcmFormatInputSame));
}

FN_EXTERN IoFilter *
cipherGcmFormatNewPack(const Pack *const paramList)
{
    IoFilter *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackRead *const paramListPack = pckReadNew(paramList);
        const CipherMode mode = (CipherMode)pckReadU64P(paramListPack);
        Buffer *const key = pckReadBinP(paramListPack);
        const Buffer *const ad = pckReadBinP(paramListPack);
        const bool raw = pckReadBoolP(paramListPack);

        // Clear the key read from the pack once the filter has its own copy, or when the filter was refused
        TRY_BEGIN()
        {
            result = ioFilterMove(cipherGcmFormatNewP(mode, key, ad, .raw = raw), memContextPrior());
        }
        FINALLY()
        {
            if (key != NULL)
                OPENSSL_cleanse(bufPtr(key), bufUsed(key));
        }
        TRY_END();
    }
    MEM_CONTEXT_TEMP_END();

    return result;
}
