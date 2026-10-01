/***********************************************************************************************************************************
Cipher Format
***********************************************************************************************************************************/
#include <build.h>

#include <openssl/crypto.h>

#include "common/crypto/cipherBlock.h"
#include "common/crypto/cipherGcm.h"
#include "common/debug.h"
#include "common/format/cipherBlockFormat.h"
#include "common/format/cipherFormat.h"
#include "common/format/cipherGcmFormat.h"
#include "common/format/format.h"
#include "common/log.h"

/***********************************************************************************************************************************
The aes-256-gcm filter for a stream with the identity given. The associated data is the stanza followed by the identity, and the key
is decoded from the pass, which was checked when the configuration was loaded or when the pass was read from an info file.
***********************************************************************************************************************************/
static IoFilter *
cipherFormatGcmNew(const CipherMode mode, const CipherSpec *const cipherSpec, const StringList *const identity, const bool raw)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING_ID, mode);
        FUNCTION_TEST_PARAM(CIPHER_SPEC, cipherSpec);
        FUNCTION_TEST_PARAM(STRING_LIST, identity);
        FUNCTION_TEST_PARAM(BOOL, raw);
    FUNCTION_TEST_END();

    ASSERT(cipherSpec != NULL);

    // The fields of an identity can come from a job's parameters, so they are checked when the stream is bound rather than only
    // where they were read
    CHECK(AssertError, identity != NULL && !strLstEmpty(identity), "identity is required to bind a stream");

    for (unsigned int fieldIdx = 0; fieldIdx < strLstSize(identity); fieldIdx++)
        CHECK_FMT(AssertError, strLstGet(identity, fieldIdx) != NULL, "identity field %u is missing", fieldIdx);

    // Every stanza of a repository shares its key, so a stream that is not bound to its stanza could be opened as another's
    CHECK(AssertError, cipherSpecStanza(cipherSpec) != NULL, "stanza is required to bind a stream");
    CHECK(AssertError, cipherSpecPass(cipherSpec) != NULL, "key is required to bind a stream");

    IoFilter *result = NULL;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        Buffer *const key = cipherGcmKeyDecode(cipherSpecPass(cipherSpec));
        StringList *const fieldList = strLstDup(identity);

        strLstInsert(fieldList, 0, cipherSpecStanza(cipherSpec));

        TRY_BEGIN()
        {
            result = ioFilterMove(cipherGcmFormatNewP(mode, key, cipherGcmAdNew(fieldList), .raw = raw), memContextPrior());
        }
        FINALLY()
        {
            OPENSSL_cleanse(bufPtr(key), bufUsed(key));
        }
        TRY_END();
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(IO_FILTER, result);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilterGroup *
cipherFormatFilterGroupAdd(
    IoFilterGroup *const filterGroup, const CipherMode mode, const CipherSpec *const cipherSpec, const StringList *const identity)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(IO_FILTER_GROUP, filterGroup);
        FUNCTION_LOG_PARAM(STRING_ID, mode);
        FUNCTION_LOG_PARAM(CIPHER_SPEC, cipherSpec);
        FUNCTION_LOG_PARAM(STRING_LIST, identity);
    FUNCTION_LOG_END();

    FUNCTION_AUDIT_HELPER();

    ASSERT(filterGroup != NULL);
    ASSERT(cipherSpec != NULL);

    // The block cipher is added as it was before aes-256-gcm, which adds nothing when there is no cipher
    if (cipherSpecType(cipherSpec) == cipherTypeAes256Gcm)
        ioFilterGroupAdd(filterGroup, cipherFormatNewP(mode, cipherSpec, identity));
    else
        cipherBlockFilterGroupAdd(filterGroup, mode, cipherSpec);

    FUNCTION_LOG_RETURN(IO_FILTER_GROUP, filterGroup);
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilter *
cipherFormatNew(
    const CipherMode mode, const CipherSpec *const cipherSpec, const StringList *const identity, const CipherFormatNewParam param)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(STRING_ID, mode);
        FUNCTION_LOG_PARAM(CIPHER_SPEC, cipherSpec);
        FUNCTION_LOG_PARAM(STRING_LIST, identity);
        FUNCTION_LOG_PARAM(BOOL, param.raw);
    FUNCTION_LOG_END();

    ASSERT(cipherSpec != NULL);
    ASSERT(cipherSpecType(cipherSpec) != cipherTypeNone);

    IoFilter *result;

    if (cipherSpecType(cipherSpec) == cipherTypeAes256Gcm)
        result = cipherFormatGcmNew(mode, cipherSpec, identity, param.raw);
    else
        result = cipherBlockNewP(mode, cipherSpec, .header = param.raw ? cipherBlockHeaderNone : cipherBlockHeaderMagic);

    FUNCTION_LOG_RETURN(IO_FILTER, result);
}

/***********************************************************************************************************************************
The identity of an info file, which is its name. The file and its copy are written from the same bytes, so the copy has the same
identity.
***********************************************************************************************************************************/
static StringList *
cipherFormatInfoIdentity(const char *const infoName)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRINGZ, infoName);
    FUNCTION_TEST_END();

    ASSERT(infoName != NULL);

    StringList *const result = strLstNew();

    strLstAddZ(result, CIPHER_IDENTITY_INFO);
    strLstAddZ(result, infoName);

    FUNCTION_TEST_RETURN(STRING_LIST, result);
}

/**********************************************************************************************************************************/
FN_EXTERN void
cipherFormatInfoWriteAdd(
    Buffer *const buffer, IoFilterGroup *const filterGroup, const CipherSpec *const cipherSpec, const unsigned int format,
    const char *const infoName)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(BUFFER, buffer);
        FUNCTION_LOG_PARAM(IO_FILTER_GROUP, filterGroup);
        FUNCTION_LOG_PARAM(CIPHER_SPEC, cipherSpec);
        FUNCTION_LOG_PARAM(UINT, format);
        FUNCTION_LOG_PARAM(STRINGZ, infoName);
    FUNCTION_LOG_END();

    FUNCTION_AUDIT_HELPER();

    ASSERT(cipherSpec != NULL);

    // The format follows the cipher in the configuration, but the cipher of a remote repository is set after the configuration is
    // loaded, so this is checked wherever an info file is written
    CHECK_FMT(
        AssertError, (cipherSpecType(cipherSpec) == cipherTypeAes256Gcm) == (format >= REPOSITORY_FORMAT_7),
        "format %u is not the format of cipher type %s", format, strZ(strNewStrId(cipherSpecType(cipherSpec))));

    if (cipherSpecType(cipherSpec) == cipherTypeAes256Gcm)
    {
        MEM_CONTEXT_TEMP_BEGIN()
        {
            cipherFormatFilterGroupAdd(filterGroup, cipherModeEncrypt, cipherSpec, cipherFormatInfoIdentity(infoName));
        }
        MEM_CONTEXT_TEMP_END();
    }
    else
        cipherBlockFormatFilterGroupWriteAdd(buffer, filterGroup, cipherSpec, format);

    FUNCTION_LOG_RETURN_VOID();
}

/**********************************************************************************************************************************/
FN_EXTERN IoFilterGroup *
cipherFormatInfoReadAdd(IoFilterGroup *const filterGroup, const CipherSpec *const cipherSpec, const char *const infoName)
{
    FUNCTION_LOG_BEGIN(logLevelTrace);
        FUNCTION_LOG_PARAM(IO_FILTER_GROUP, filterGroup);
        FUNCTION_LOG_PARAM(CIPHER_SPEC, cipherSpec);
        FUNCTION_LOG_PARAM(STRINGZ, infoName);
    FUNCTION_LOG_END();

    FUNCTION_AUDIT_HELPER();

    ASSERT(cipherSpec != NULL);

    if (cipherSpecType(cipherSpec) == cipherTypeAes256Gcm)
    {
        MEM_CONTEXT_TEMP_BEGIN()
        {
            cipherFormatFilterGroupAdd(filterGroup, cipherModeDecrypt, cipherSpec, cipherFormatInfoIdentity(infoName));
        }
        MEM_CONTEXT_TEMP_END();
    }
    else
        cipherBlockFormatFilterGroupReadAdd(filterGroup, cipherSpec);

    FUNCTION_LOG_RETURN(IO_FILTER_GROUP, filterGroup);
}
