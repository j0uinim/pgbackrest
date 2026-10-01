/***********************************************************************************************************************************
Streaming AEAD Cipher
***********************************************************************************************************************************/
#include <build.h>

#include <inttypes.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

// The same condition as CIPHER_GCM_SUPPORTED, which is defined by a header included below
#if OPENSSL_VERSION_NUMBER >= 0x30000080L
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#endif

#include "common/crypto/cipherGcm.intern.h"
#include "common/crypto/common.h"
#include "common/debug.h"
#include "common/encode.h"
#include "common/log.h"
#include "common/type/convert.h"
#include "common/type/object.h"

/***********************************************************************************************************************************
Associated data that precedes the fields of every stream: the project, the repository format, and the cipher type. They are fixed
here rather than taken from build constants so that nothing but a change to this cipher can change what a stream is bound to.
***********************************************************************************************************************************/
#define CIPHER_GCM_AD_PROJECT                                       "pgbackrest"
#define CIPHER_GCM_AD_FORMAT                                        "007"
#define CIPHER_GCM_AD_TYPE                                          "aes-256-gcm"

/***********************************************************************************************************************************
Sizes that do not depend on the parameters
***********************************************************************************************************************************/
#define CIPHER_GCM_NONCE_PREFIX_SIZE                                7
#define CIPHER_GCM_NONCE_SIZE                                       12
#define CIPHER_GCM_TAG_SIZE                                         16
#define CIPHER_GCM_DERIVED_KEY_SIZE_MAX                             32
// Size byte, salt, and nonce prefix, where the salt is the size of the derived key
#define CIPHER_GCM_HEADER_SIZE_MAX                                  (CIPHER_GCM_DERIVED_KEY_SIZE_MAX + 8)

// Largest HKDF digest name, including the terminator
#define CIPHER_GCM_DIGEST_SIZE_MAX                                  16

// Standard base64 alphabet without the padding character
#define CIPHER_GCM_KEY_ALPHABET                                                                                                    \
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

// Size of the canonical base64 of a key. The key size is not a multiple of three, so it ends with a single padding character.
#define CIPHER_GCM_KEY_BASE64_SIZE                                  ((CIPHER_GCM_KEY_SIZE + 2) / 3 * 4)

/**********************************************************************************************************************************/
FN_EXTERN Buffer *
cipherGcmAdNew(const StringList *const fieldList)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING_LIST, fieldList);
    FUNCTION_TEST_END();

    ASSERT(fieldList != NULL);

    Buffer *const result = bufNew(0);

    // Each field is followed by a zero byte, including the fixed fields
    bufCatC(result, (const uint8_t *)CIPHER_GCM_AD_PROJECT, 0, sizeof(CIPHER_GCM_AD_PROJECT));
    bufCatC(result, (const uint8_t *)CIPHER_GCM_AD_FORMAT, 0, sizeof(CIPHER_GCM_AD_FORMAT));
    bufCatC(result, (const uint8_t *)CIPHER_GCM_AD_TYPE, 0, sizeof(CIPHER_GCM_AD_TYPE));

    for (unsigned int fieldIdx = 0; fieldIdx < strLstSize(fieldList); fieldIdx++)
    {
        const String *const field = strLstGet(fieldList, fieldIdx);

        // A zero byte inside a field would allow two different field lists to give the same associated data
        CHECK(AssertError, memchr(strZ(field), 0, strSize(field)) == NULL, "associated data field contains a zero byte");

        bufCatC(result, (const uint8_t *)strZ(field), 0, strSize(field) + 1);
    }

    // The associated data is passed to HKDF whole, so it must not be larger than OpenSSL accepts
    if (bufUsed(result) > CIPHER_GCM_AD_SIZE_MAX)
    {
        THROW_FMT(
            CryptoError, "cipher associated data size %zu exceeds maximum of %d", bufUsed(result), CIPHER_GCM_AD_SIZE_MAX);
    }

    FUNCTION_TEST_RETURN(BUFFER, result);
}

/***********************************************************************************************************************************
Decode a key when it is the canonical base64 of exactly CIPHER_GCM_KEY_SIZE bytes, and copy it to the result when there is one.
Every other copy of the key made here is cleared.
***********************************************************************************************************************************/
static bool
cipherGcmKeyDecodeTo(const Buffer *const key, Buffer *const result)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BUFFER, key);
        FUNCTION_TEST_PARAM(BUFFER, result);
    FUNCTION_TEST_END();

    ASSERT(key != NULL);
    ASSERT(result == NULL || bufSize(result) == CIPHER_GCM_KEY_SIZE);

    bool valid = false;

    // The canonical base64 of the key is always the same size, only the standard alphabet is allowed, and the padding can only be a
    // single character. The decoder is never given anything else.
    if (bufUsed(key) == CIPHER_GCM_KEY_BASE64_SIZE)
    {
        // The key is copied to local arrays so that it is terminated for the decoder and so that each copy can be cleared
        char text[CIPHER_GCM_KEY_BASE64_SIZE + 1];
        char encoded[CIPHER_GCM_KEY_BASE64_SIZE + 1];
        uint8_t decoded[CIPHER_GCM_KEY_SIZE];

        memcpy(text, bufPtrConst(key), CIPHER_GCM_KEY_BASE64_SIZE);
        text[CIPHER_GCM_KEY_BASE64_SIZE] = '\0';

        if (strspn(text, CIPHER_GCM_KEY_ALPHABET) == CIPHER_GCM_KEY_BASE64_SIZE - 1 && text[CIPHER_GCM_KEY_BASE64_SIZE - 1] == '=')
        {
            decodeToBin(encodingBase64, text, decoded);

            // Encoding again must give back the same text, which it does not when the unused bits are not zero
            encodeToStr(encodingBase64, decoded, CIPHER_GCM_KEY_SIZE, encoded);
            valid = strcmp(encoded, text) == 0;

            if (valid && result != NULL)
            {
                memcpy(bufPtr(result), decoded, CIPHER_GCM_KEY_SIZE);
                bufUsedSet(result, CIPHER_GCM_KEY_SIZE);
            }
        }

        OPENSSL_cleanse(text, sizeof(text));
        OPENSSL_cleanse(encoded, sizeof(encoded));
        OPENSSL_cleanse(decoded, sizeof(decoded));
    }

    FUNCTION_TEST_RETURN(BOOL, valid);
}

/**********************************************************************************************************************************/
FN_EXTERN Buffer *
cipherGcmKeyDecode(const Buffer *const key)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BUFFER, key);
    FUNCTION_TEST_END();

    ASSERT(key != NULL);

    Buffer *const result = bufNew(CIPHER_GCM_KEY_SIZE);

    // The key is not included in the error since it is secret
    if (!cipherGcmKeyDecodeTo(key, result))
        THROW(CryptoError, "cipher key must be the base64 of exactly " STRINGIFY(CIPHER_GCM_KEY_SIZE) " random bytes");

    FUNCTION_TEST_RETURN(BUFFER, result);
}

/**********************************************************************************************************************************/
FN_EXTERN bool
cipherGcmKeyValid(const Buffer *const key)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(BUFFER, key);
    FUNCTION_TEST_END();

    ASSERT(key != NULL);

    FUNCTION_TEST_RETURN(BOOL, cipherGcmKeyDecodeTo(key, NULL));
}

/**********************************************************************************************************************************/
FN_EXTERN String *
cipherGcmKeyNew(void)
{
    FUNCTION_TEST_VOID();

    String *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        Buffer *const key = bufNew(CIPHER_GCM_KEY_SIZE);

        cryptoRandomBytes(bufPtr(key), CIPHER_GCM_KEY_SIZE);
        bufUsedSet(key, CIPHER_GCM_KEY_SIZE);

        MEM_CONTEXT_PRIOR_BEGIN()
        {
            result = strNewEncode(encodingBase64, key);
        }
        MEM_CONTEXT_PRIOR_END();

        OPENSSL_cleanse(bufPtr(key), CIPHER_GCM_KEY_SIZE);
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(STRING, result);
}

#ifdef CIPHER_GCM_SUPPORTED

/***********************************************************************************************************************************
Object type
***********************************************************************************************************************************/
typedef struct CipherGcm
{
    CipherMode mode;                                                // Encrypt or decrypt
    CipherGcmParam param;                                           // Parameters of the construction
    char digest[CIPHER_GCM_DIGEST_SIZE_MAX];                        // HKDF digest name, which the parameters point to
    Buffer *key;                                                    // Key the stream key is derived from
    Buffer *ad;                                                     // Associated data the stream is bound to
    size_t headerSize;                                              // Header size, which depends on the derived key size
    uint8_t header[CIPHER_GCM_HEADER_SIZE_MAX];                     // Header, which is written or read before any segment
    size_t headerRead;                                              // Header bytes read so far on decrypt
    bool headerDone;                                                // Has the header been written or read?
    const EVP_CIPHER *cipher;                                       // AES-GCM with the derived key size
    EVP_CIPHER_CTX *cipherContext;                                  // Context holding the stream key
    uint64_t segmentNo;                                             // Number of the next segment
    Buffer *segment;                                                // Input of the next segment
    Buffer *output;                                                 // Output that has not yet been copied to the destination
    size_t outputOffset;                                            // Output bytes already copied to the destination
    size_t sourceOffset;                                            // Bytes of the current source already consumed
    bool sourceDone;                                                // Has all of the current source been consumed?
    bool flushDone;                                                 // Has the last segment been processed?
    bool failed;                                                    // Has processing failed? A failure is final.
    bool inputSame;                                                 // Is the same input required on the next call?
} CipherGcm;

/***********************************************************************************************************************************
Macros for function logging
***********************************************************************************************************************************/
static void
cipherGcmToLog(const CipherGcm *const this, StringStatic *const debugLog)
{
    strStcFmt(
        debugLog, "{segmentNo: %" PRIu64 ", inputSame: %s, flushDone: %s}", this->segmentNo, cvtBoolToConstZ(this->inputSame),
        cvtBoolToConstZ(this->flushDone));
}

#define FUNCTION_LOG_CIPHER_GCM_TYPE                                                                                               \
    CipherGcm *
#define FUNCTION_LOG_CIPHER_GCM_FORMAT(value, buffer, bufferSize)                                                                  \
    FUNCTION_LOG_OBJECT_FORMAT(value, cipherGcmToLog, buffer, bufferSize)

/***********************************************************************************************************************************
Free the cipher context and clear the secrets and the plaintext held by the object
***********************************************************************************************************************************/
static void
cipherGcmFreeResource(THIS_VOID)
{
    THIS(CipherGcm);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CIPHER_GCM, this);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);

    EVP_CIPHER_CTX_free(this->cipherContext);

    OPENSSL_cleanse(bufPtr(this->key), bufSize(this->key));
    OPENSSL_cleanse(bufPtr(this->segment), bufSize(this->segment));
    OPENSSL_cleanse(bufPtr(this->output), bufSize(this->output));

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Size of the input of the next segment when it is not the last: the plaintext on encrypt, the ciphertext on decrypt. The first
segment is smaller by the header so that every segment of the stream ends on a multiple of the segment size.
***********************************************************************************************************************************/
static size_t
cipherGcmSegmentSize(const CipherGcm *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    size_t result = this->param.segmentSize - (this->segmentNo == 0 ? this->headerSize : 0);

    if (this->mode == cipherModeEncrypt)
        result -= CIPHER_GCM_TAG_SIZE;

    FUNCTION_TEST_RETURN(SIZE, result);
}

/***********************************************************************************************************************************
Derive the stream key from the key, the salt in the header, and the associated data, and initialize the cipher with it
***********************************************************************************************************************************/
static void
cipherGcmKeyDerive(CipherGcm *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(this->header[0] == this->headerSize);

    // Create the context first so no error can be thrown between deriving the stream key and clearing it
    cryptoError(!(this->cipherContext = EVP_CIPHER_CTX_new()), "unable to create context");

    // HKDF with the associated data as info. OpenSSL wants a non-NULL pointer even when the associated data is empty.
    uint8_t derivedKey[CIPHER_GCM_DERIVED_KEY_SIZE_MAX] = {0};
    static uint8_t adEmpty = 0;

    OSSL_PARAM kdfParam[] =
    {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, this->digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, bufPtr(this->key), bufUsed(this->key)),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, this->header + 1, this->param.derivedKeySize),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, bufEmpty(this->ad) ? &adEmpty : bufPtr(this->ad), bufUsed(this->ad)),
        OSSL_PARAM_construct_end(),
    };

    EVP_KDF *const kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    cryptoError(kdf == NULL, "unable to load hkdf");

    EVP_KDF_CTX *const kdfContext = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    cryptoError(kdfContext == NULL, "unable to create hkdf context");

    // Initialize the cipher with the stream key, and clear the stream key before checking either result. The nonce is set for each
    // segment.
    const int kdfResult = EVP_KDF_derive(kdfContext, derivedKey, this->param.derivedKeySize, kdfParam);
    EVP_KDF_CTX_free(kdfContext);

    const int initResult = EVP_CipherInit_ex(
        this->cipherContext, this->cipher, NULL, derivedKey, NULL, this->mode == cipherModeEncrypt);
    OPENSSL_cleanse(derivedKey, sizeof(derivedKey));

    cryptoError(kdfResult != 1, "unable to derive key");
    cryptoError(initResult != 1, "unable to initialize cipher");

    this->headerDone = true;

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Process the input of the next segment into the output. On decrypt the plaintext is added to the output only after the tag has been
verified, so no plaintext of a segment that fails is ever released.
***********************************************************************************************************************************/
static void
cipherGcmSegment(CipherGcm *const this, const bool last)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM, this);
        FUNCTION_TEST_PARAM(BOOL, last);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(this->headerDone);

    // The segment number is only 32 bits in the nonce
    if (this->segmentNo > UINT32_MAX)
        THROW(CryptoError, "cipher stream exceeds maximum segments");

    // Nonce is the prefix from the header, the segment number, and whether this is the last segment
    uint8_t nonce[CIPHER_GCM_NONCE_SIZE];

    memcpy(nonce, this->header + 1 + this->param.derivedKeySize, CIPHER_GCM_NONCE_PREFIX_SIZE);
    nonce[7] = (uint8_t)(this->segmentNo >> 24);
    nonce[8] = (uint8_t)(this->segmentNo >> 16);
    nonce[9] = (uint8_t)(this->segmentNo >> 8);
    nonce[10] = (uint8_t)this->segmentNo;
    nonce[11] = last ? 1 : 0;

    cryptoError(EVP_CipherInit_ex(this->cipherContext, NULL, NULL, NULL, nonce, -1) != 1, "unable to initialize cipher");

    int updateSize = 0;
    int finalSize = 0;

    if (this->mode == cipherModeEncrypt)
    {
        // Ciphertext followed by the tag
        cryptoError(
            EVP_CipherUpdate(
                this->cipherContext, bufRemainsPtr(this->output), &updateSize, bufPtrConst(this->segment),
                (int)bufUsed(this->segment)) != 1,
            "unable to process cipher");
        cryptoError(
            EVP_CipherFinal_ex(this->cipherContext, bufRemainsPtr(this->output) + updateSize, &finalSize) != 1,
            "unable to flush cipher");
        bufUsedInc(this->output, (size_t)(updateSize + finalSize));

        cryptoError(
            EVP_CIPHER_CTX_ctrl(this->cipherContext, EVP_CTRL_GCM_GET_TAG, CIPHER_GCM_TAG_SIZE, bufRemainsPtr(this->output)) != 1,
            "unable to get tag");
        bufUsedInc(this->output, CIPHER_GCM_TAG_SIZE);
    }
    else
    {
        // The last segment can be shorter than a tag when the stream was truncated. Other segments are always full.
        if (bufUsed(this->segment) < CIPHER_GCM_TAG_SIZE)
            THROW(CryptoError, "cipher stream is truncated");

        const size_t ciphertextSize = bufUsed(this->segment) - CIPHER_GCM_TAG_SIZE;

        cryptoError(
            EVP_CIPHER_CTX_ctrl(
                this->cipherContext, EVP_CTRL_GCM_SET_TAG, CIPHER_GCM_TAG_SIZE, bufPtr(this->segment) + ciphertextSize) != 1,
            "unable to set tag");

        // The plaintext is written past the end of the output and only added to it when the tag verifies
        cryptoError(
            EVP_CipherUpdate(
                this->cipherContext, bufRemainsPtr(this->output), &updateSize, bufPtrConst(this->segment),
                (int)ciphertextSize) != 1,
            "unable to process cipher");

        if (EVP_CipherFinal_ex(this->cipherContext, bufRemainsPtr(this->output) + updateSize, &finalSize) != 1)
        {
            OPENSSL_cleanse(bufRemainsPtr(this->output), ciphertextSize);
            THROW_FMT(CryptoError, "cipher segment %" PRIu64 " failed authentication", this->segmentNo);
        }

        bufUsedInc(this->output, (size_t)(updateSize + finalSize));
    }

    OPENSSL_cleanse(bufPtr(this->segment), bufUsed(this->segment));
    bufUsedZero(this->segment);
    this->segmentNo++;

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Consume the source until a segment is processed or the source is exhausted. A full segment is processed only when there is more
input after it, since the last segment is processed differently and only the end of the input says which segment is the last.
***********************************************************************************************************************************/
static void
cipherGcmConsume(CipherGcm *const this, const Buffer *const source)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM, this);
        FUNCTION_TEST_PARAM(BUFFER, source);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(source != NULL);
    ASSERT(bufEmpty(this->output));

    while (this->sourceOffset < bufUsed(source))
    {
        // Read the header on decrypt. The header size is checked as soon as it is read so nothing else is done with a stream that
        // was not written with these parameters.
        if (!this->headerDone)
        {
            ASSERT(this->mode == cipherModeDecrypt);

            const size_t sourceRemains = bufUsed(source) - this->sourceOffset;
            const size_t headerRemains = this->headerSize - this->headerRead;
            const size_t size = headerRemains < sourceRemains ? headerRemains : sourceRemains;

            memcpy(this->header + this->headerRead, bufPtrConst(source) + this->sourceOffset, size);
            this->headerRead += size;
            this->sourceOffset += size;

            if (this->header[0] != this->headerSize)
                THROW_FMT(CryptoError, "cipher header size %u is invalid", (unsigned int)this->header[0]);

            if (this->headerRead == this->headerSize)
                cipherGcmKeyDerive(this);

            continue;
        }

        // Process a full segment when more input follows it
        const size_t segmentSize = cipherGcmSegmentSize(this);

        if (bufUsed(this->segment) == segmentSize)
        {
            cipherGcmSegment(this, false);
            break;
        }

        // Else add input to the segment
        const size_t sourceRemains = bufUsed(source) - this->sourceOffset;
        const size_t segmentRemains = segmentSize - bufUsed(this->segment);
        const size_t size = segmentRemains < sourceRemains ? segmentRemains : sourceRemains;

        bufCatSub(this->segment, source, this->sourceOffset, size);
        this->sourceOffset += size;
    }

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Process the last segment when all input has been consumed
***********************************************************************************************************************************/
static void
cipherGcmFlush(CipherGcm *const this)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(bufEmpty(this->output));

    // A stream must at least hold the header, which is also true of an empty stream. The segment checks that it holds a tag.
    if (this->mode == cipherModeDecrypt && !this->headerDone)
        THROW(CryptoError, "cipher stream is truncated");

    cipherGcmSegment(this, true);
    this->flushDone = true;

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Copy as much output as fits into the destination
***********************************************************************************************************************************/
static void
cipherGcmOutput(CipherGcm *const this, Buffer *const destination)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM, this);
        FUNCTION_TEST_PARAM(BUFFER, destination);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);
    ASSERT(destination != NULL);

    const size_t outputRemains = bufUsed(this->output) - this->outputOffset;
    const size_t size = outputRemains < bufRemains(destination) ? outputRemains : bufRemains(destination);

    bufCatSub(destination, this->output, this->outputOffset, size);
    this->outputOffset += size;

    // When all output has been copied, clear it so the next segment can be processed
    if (this->outputOffset == bufUsed(this->output))
    {
        OPENSSL_cleanse(bufPtr(this->output), bufUsed(this->output));
        bufUsedZero(this->output);
        this->outputOffset = 0;
    }

    FUNCTION_TEST_RETURN_VOID();
}

/***********************************************************************************************************************************
Process function used by C filter
***********************************************************************************************************************************/
static void
cipherGcmProcess(THIS_VOID, const Buffer *const source, Buffer *const destination)
{
    THIS(CipherGcm);

    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(CIPHER_GCM, this);
        FUNCTION_LOG_PARAM(BUFFER, source);
        FUNCTION_LOG_PARAM(BUFFER, destination);
    FUNCTION_LOG_END();

    ASSERT(this != NULL);
    ASSERT(destination != NULL);
    ASSERT(bufRemains(destination) > 0);

    // A stream that failed must not be processed further since it cannot be trusted from that point on
    CHECK(AssertError, !this->failed, "cipher failed on a prior call");

    TRY_BEGIN()
    {
        // On encrypt the header is written first, even for an empty stream
        if (this->mode == cipherModeEncrypt && !this->headerDone)
        {
            this->header[0] = (uint8_t)this->headerSize;
            cryptoRandomBytes(this->header + 1, this->param.derivedKeySize + CIPHER_GCM_NONCE_PREFIX_SIZE);
            bufCatC(this->output, this->header, 0, this->headerSize);

            cipherGcmKeyDerive(this);
        }

        // Fill the destination with output, processing a segment whenever all prior output has been copied
        while (true)
        {
            cipherGcmOutput(this, destination);

            // Stop when the destination is full
            if (!bufEmpty(this->output))
                break;

            // Process the last segment on flush
            if (source == NULL)
            {
                if (this->flushDone)
                    break;

                cipherGcmFlush(this);
            }
            // Else consume the source unless it has already been consumed
            else
            {
                if (this->sourceDone)
                    break;

                cipherGcmConsume(this, source);
                this->sourceDone = this->sourceOffset == bufUsed(source);
            }
        }

        // The same input is required while there is output left. The loop only stops with no output left when the source has been
        // consumed or the stream flushed, so the next call will bring new input.
        this->inputSame = !bufEmpty(this->output);

        if (!this->inputSame)
        {
            this->sourceOffset = 0;
            this->sourceDone = false;
        }
    }
    CATCH_ANY()
    {
        this->failed = true;
        RETHROW();
    }
    TRY_END();

    FUNCTION_LOG_RETURN_VOID();
}

/***********************************************************************************************************************************
Is the cipher done?
***********************************************************************************************************************************/
static bool
cipherGcmDone(const THIS_VOID)
{
    THIS(const CipherGcm);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->flushDone && !this->inputSame);
}

/***********************************************************************************************************************************
Should the same input be provided again?
***********************************************************************************************************************************/
static bool
cipherGcmInputSame(const THIS_VOID)
{
    THIS(const CipherGcm);

    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(CIPHER_GCM, this);
    FUNCTION_TEST_END();

    ASSERT(this != NULL);

    FUNCTION_TEST_RETURN(BOOL, this->inputSame);
}

#endif // CIPHER_GCM_SUPPORTED

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
cipherGcmNewParam(const CipherMode mode, const Buffer *const key, const Buffer *const ad, const CipherGcmParam param)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STRING_ID, mode);
        FUNCTION_TEST_PARAM(BUFFER, key);                           // Not logged since the key is secret
        FUNCTION_LOG_PARAM(BUFFER, ad);
        FUNCTION_LOG_PARAM(STRINGZ, param.digest);
        FUNCTION_LOG_PARAM(SIZE, param.keySize);
        FUNCTION_LOG_PARAM(SIZE, param.derivedKeySize);
        FUNCTION_LOG_PARAM(SIZE, param.segmentSize);
    FUNCTION_LOG_END();

#ifdef CIPHER_GCM_SUPPORTED
    ASSERT(param.digest != NULL && strlen(param.digest) < CIPHER_GCM_DIGEST_SIZE_MAX);
    ASSERT(param.derivedKeySize == 16 || param.derivedKeySize == 32);
    ASSERT(param.keySize >= param.derivedKeySize);
    ASSERT(param.segmentSize > param.derivedKeySize + 24 && param.segmentSize <= INT_MAX);

    // The mode, the key, and the associated data can arrive in a pack, so they are checked in every build
    CHECK(AssertError, mode == cipherModeEncrypt || mode == cipherModeDecrypt, "cipher mode is invalid");
    CHECK(AssertError, key != NULL && bufUsed(key) == param.keySize, "cipher key size is invalid");
    CHECK(AssertError, ad != NULL, "cipher associated data is missing");

    if (bufUsed(ad) > CIPHER_GCM_AD_SIZE_MAX)
        THROW_FMT(CryptoError, "cipher associated data size %zu exceeds maximum of %d", bufUsed(ad), CIPHER_GCM_AD_SIZE_MAX);

    // Init crypto subsystem
    cryptoInit();

    OBJ_NEW_BEGIN(CipherGcm, .childQty = MEM_CONTEXT_QTY_MAX, .callbackQty = 1)
    {
        *this = (CipherGcm)
        {
            .mode = mode,
            .param = param,
            .key = bufDup(key),
            .ad = bufDup(ad),
            .headerSize = 1 + param.derivedKeySize + CIPHER_GCM_NONCE_PREFIX_SIZE,
            .cipher = param.derivedKeySize == 16 ? EVP_aes_128_gcm() : EVP_aes_256_gcm(),
            .segment = bufNew(param.segmentSize),
            .output = bufNew(param.segmentSize),
        };

        // OpenSSL takes the digest name as a string that is not const, so the object keeps its own copy
        memcpy(this->digest, param.digest, strlen(param.digest) + 1);
        this->param.digest = this->digest;

        // Set free callback to ensure the cipher context is freed and secrets are cleared
        memContextCallbackSet(objMemContext(this), cipherGcmFreeResource, this);
    }
    OBJ_NEW_END();

    // Create param list
    Pack *paramList;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackWrite *const packWrite = pckWriteNewP();

        // Only the mode, the key, and the associated data are packed. The parameters are never taken from a pack, so a filter made
        // from one always has the production parameters.
        pckWriteU64P(packWrite, mode);
        pckWriteBinP(packWrite, key);
        pckWriteBinP(packWrite, ad);
        pckWriteEndP(packWrite);

        paramList = pckMove(pckWriteResult(packWrite), memContextPrior());
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(
        IO_FILTER,
        ioFilterNewP(
            CIPHER_GCM_FILTER_TYPE, this, paramList, .done = cipherGcmDone, .inOut = cipherGcmProcess,
            .inputSame = cipherGcmInputSame));
#else
    (void)mode;
    (void)key;
    (void)ad;
    (void)param;

    THROW(CryptoError, "cipher type " CIPHER_GCM_AD_TYPE " requires OpenSSL 3.0.8 or later");
#endif
}

FN_EXTERN IoFilter *
cipherGcmNew(const CipherMode mode, const Buffer *const key, const Buffer *const ad)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING_ID, mode);
        FUNCTION_TEST_PARAM(BUFFER, key);
        FUNCTION_TEST_PARAM(BUFFER, ad);
    FUNCTION_TEST_END();

    FUNCTION_TEST_RETURN(IO_FILTER, cipherGcmNewParam(mode, key, ad, CIPHER_GCM_PARAM_DEFAULT));
}

FN_EXTERN IoFilter *
cipherGcmNewPack(const Pack *const paramList)
{
    IoFilter *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        PackRead *const paramListPack = pckReadNew(paramList);
        const CipherMode mode = (CipherMode)pckReadU64P(paramListPack);
        Buffer *const key = pckReadBinP(paramListPack);
        const Buffer *const ad = pckReadBinP(paramListPack);

        // Clear the key read from the pack once the filter has its own copy, or when the filter was refused. The pack itself keeps
        // a copy for as long as the filter exists, as for the block cipher.
        TRY_BEGIN()
        {
            result = ioFilterMove(cipherGcmNew(mode, key, ad), memContextPrior());
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
