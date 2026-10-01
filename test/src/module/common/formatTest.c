/***********************************************************************************************************************************
Test Repository Format
***********************************************************************************************************************************/
#include "common/crypto/cipherBlock.h"
#include "common/crypto/cipherGcm.h"
#include "common/io/bufferRead.h"
#include "common/io/bufferWrite.h"
#include "common/io/io.h"
#include "version.h"

#include "harness/config.h"
#include "harness/crypto.h"
#include "harness/filter.h"

/***********************************************************************************************************************************
Data for testing
***********************************************************************************************************************************/
#define TEST_PASS                                                   "areallybadpassphrase"
#define TEST_PLAINTEXT                                              "plaintext"
#define TEST_BUFFER_SIZE                                            256

// Key and associated data for the aes-256-gcm format

// Parts of the identities that aes-256-gcm streams are bound to
#define TEST_ID_LABEL                                               "20260101-000000F"
#define TEST_ID_LABEL_DIFF                                          TEST_ID_LABEL "_20260102-000000D"
#define TEST_ID_SHA1                                                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define TEST_ID_SHA1_OTHER                                          "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define TEST_ID_WAL_PATH                                            "18-1/0000000100000001/"
#define TEST_ID_WAL                                                 TEST_ID_WAL_PATH "000000010000000100000001-" TEST_ID_SHA1
#define TEST_ID_FILE                                                "|pg_data/base/1/2"

/***********************************************************************************************************************************
Write and read a buffer through a filter group that cipherFormatFilterGroupAdd() adds to, as the commands do
***********************************************************************************************************************************/
static Buffer *
testFormatWrite(const CipherSpec *const cipherSpec, const StringList *const identity, const Buffer *const plaintext)
{
    Buffer *const result = bufNew(0);
    IoWrite *const write = ioBufferWriteNew(result);

    cipherFormatFilterGroupAdd(ioWriteFilterGroup(write), cipherModeEncrypt, cipherSpec, identity);
    ioWriteOpen(write);
    ioWrite(write, plaintext);
    ioWriteClose(write);

    return result;
}

static Buffer *
testFormatRead(const CipherSpec *const cipherSpec, const StringList *const identity, const Buffer *const ciphertext)
{
    IoRead *const read = ioBufferReadNew(ciphertext);

    cipherFormatFilterGroupAdd(ioReadFilterGroup(read), cipherModeDecrypt, cipherSpec, identity);
    ioReadOpen(read);

    return ioReadBuf(read);
}

#ifdef CIPHER_GCM_SUPPORTED

/***********************************************************************************************************************************
Encrypt or decrypt a raw aes-256-gcm stream bound to the fields given, the first being the stanza and the rest the identity
***********************************************************************************************************************************/
static Buffer *
testFormatGcmField(const CipherMode mode, const StringList *const fieldList, const Buffer *const input)
{
    StringList *const identity = strLstDup(fieldList);

    strLstRemoveIdx(identity, 0);

    return hrnFilterProcess(
        cipherFormatNewP(
            mode, cipherSpecNewP(cipherTypeAes256Gcm, BUFSTRDEF(TEST_CIPHER_KEY), .stanza = strLstGet(fieldList, 0)), identity,
            .raw = true),
        input, 64, 64);
}

#endif

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    // *****************************************************************************************************************************
    if (testBegin("repoFormatValidate()"))
    {
        TEST_ERROR(
            repoFormatValidate(REPOSITORY_FORMAT_MIN - 1), FormatError,
            "repository format 4 is no longer supported by " PROJECT_NAME "\n"
            "HINT: " PROJECT_NAME " " PROJECT_VERSION " supports repository format 5 to 7.");
        TEST_ERROR(
            repoFormatValidate(REPOSITORY_FORMAT_MAX + 1), FormatError,
            "repository format 8 requires a newer version of " PROJECT_NAME "\n"
            "HINT: " PROJECT_NAME " " PROJECT_VERSION " supports repository format 5 to 7.");

        TEST_RESULT_VOID(repoFormatValidate(REPOSITORY_FORMAT_5), "format 5 is readable");
        TEST_RESULT_VOID(repoFormatValidate(REPOSITORY_FORMAT_6), "format 6 is readable");
        TEST_RESULT_VOID(repoFormatValidate(REPOSITORY_FORMAT_7), "format 7 is readable");
    }

    // *****************************************************************************************************************************
    if (testBegin("repoFormatDigest()"))
    {
        TEST_RESULT_UINT(repoFormatDigest(REPOSITORY_FORMAT_5), hashTypeSha1, "format 5 derives with sha1");
        TEST_RESULT_UINT(repoFormatDigest(REPOSITORY_FORMAT_6), hashTypeSha256, "format 6 derives with sha256");
    }

    // *****************************************************************************************************************************
    if (testBegin("cipherBlockFormatNew()"))
    {
        const Buffer *const testPlainText = BUFSTRDEF(TEST_PLAINTEXT);
        const Buffer *const testPass = BUFSTRDEF(TEST_PASS);
        const CipherSpec *const cipherSpec = cipherSpecNewP(cipherTypeAes256Cbc, testPass);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("nothing is added when the repository is not encrypted");

        Buffer *plain = bufNew(0);
        IoWrite *plainWrite = ioBufferWriteNew(plain);

        TEST_RESULT_VOID(
            cipherBlockFormatFilterGroupWriteAdd(plain, ioWriteFilterGroup(plainWrite), cipherSpecNewNone(), REPOSITORY_FORMAT_6),
            "add write filter for no cipher");
        ioWriteOpen(plainWrite);
        ioWrite(plainWrite, testPlainText);
        ioWriteClose(plainWrite);

        TEST_RESULT_STR_Z(strNewBuf(plain), TEST_PLAINTEXT, "content is stored as it is");

        IoWrite *plainRead = ioBufferWriteNew(bufNew(0));
        TEST_RESULT_PTR_NE(
            cipherBlockFormatFilterGroupReadAdd(ioWriteFilterGroup(plainRead), cipherSpecNewNone()), NULL,
            "add read filter for no cipher");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("write a header and read the format back from it");

        Buffer *headerBuffer = bufNew(0);
        IoWrite *headerWrite = ioBufferWriteNew(headerBuffer);

        cipherBlockFormatFilterGroupWriteAdd(headerBuffer, ioWriteFilterGroup(headerWrite), cipherSpec, REPOSITORY_FORMAT_6);
        ioWriteOpen(headerWrite);
        ioWrite(headerWrite, testPlainText);
        ioWriteClose(headerWrite);

        TEST_RESULT_BOOL(
            memcmp(bufPtrConst(headerBuffer), CIPHER_BLOCK_FORMAT_MAGIC "006_", CIPHER_BLOCK_FORMAT_HEADER_SIZE) == 0, true,
            "header names the format");

        // The format is not given on decrypt, so it comes from the header and is what the pass derives with
        Buffer *headerResult = bufNew(0);
        IoWrite *headerRead = ioBufferWriteNew(headerResult);
        IoFilterGroup *headerFilterGroup = ioWriteFilterGroup(headerRead);

        cipherBlockFormatFilterGroupReadAdd(headerFilterGroup, cipherSpec);
        ioWriteOpen(headerRead);
        ioWrite(headerRead, headerBuffer);
        ioWriteClose(headerRead);

        TEST_RESULT_STR_Z(strNewBuf(headerResult), TEST_PLAINTEXT, "content decrypted with the digest the header called for");
        TEST_RESULT_UINT(
            cipherBlockFormatResult(ioFilterGroupResultP(headerFilterGroup, CIPHER_BLOCK_FORMAT_FILTER_TYPE)),
            REPOSITORY_FORMAT_6, "filter reports the format");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("content is handed on in pieces when the destination cannot take it whole");

        // Content long enough that decryption has output to hand on while input is still arriving, so the destination fills before
        // the source has been consumed
        Buffer *const piecesPlainText = bufNew(TEST_BUFFER_SIZE);
        memset(bufPtr(piecesPlainText), 'x', bufSize(piecesPlainText));
        bufUsedSet(piecesPlainText, bufSize(piecesPlainText));

        Buffer *const piecesBuffer = bufNew(0);
        IoWrite *const piecesWrite = ioBufferWriteNew(piecesBuffer);

        cipherBlockFormatFilterGroupWriteAdd(piecesBuffer, ioWriteFilterGroup(piecesWrite), cipherSpec, REPOSITORY_FORMAT_6);
        ioWriteOpen(piecesWrite);
        ioWrite(piecesWrite, piecesPlainText);
        ioWriteClose(piecesWrite);

        IoRead *const readPieces = ioBufferReadNew(piecesBuffer);
        Buffer *const piecesResult = bufNew(0);
        Buffer *const piece = bufNew(4);

        cipherBlockFormatFilterGroupReadAdd(ioReadFilterGroup(readPieces), cipherSpec);

        ioBufferSizeSet(4);
        ioReadOpen(readPieces);

        while (!ioReadEof(readPieces))
        {
            bufUsedZero(piece);
            ioRead(readPieces, piece);
            bufCat(piecesResult, piece);
        }

        ioReadClose(readPieces);
        ioBufferSizeSet(TEST_BUFFER_SIZE);

        TEST_RESULT_BOOL(bufEq(piecesResult, piecesPlainText), true, "content decrypted in pieces");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("the header is read no matter how the input is split");

        Buffer *const splitResult = bufNew(0);
        IoWrite *const splitWrite = ioBufferWriteNew(splitResult);

        cipherBlockFormatFilterGroupReadAdd(ioWriteFilterGroup(splitWrite), cipherSpec);

        // Write in pieces smaller than the header so it arrives in more than one part, then a piece that completes it exactly, so
        // that what follows arrives with the header already read
        ioBufferSizeSet(4);
        ioWriteOpen(splitWrite);
        ioWrite(splitWrite, BUF(bufPtrConst(headerBuffer), 4));
        ioWrite(splitWrite, BUF(bufPtrConst(headerBuffer) + 4, 4));
        ioWrite(splitWrite, BUF(bufPtrConst(headerBuffer) + 8, bufUsed(headerBuffer) - 8));
        ioWriteClose(splitWrite);
        ioBufferSizeSet(TEST_BUFFER_SIZE);

        TEST_RESULT_STR_Z(strNewBuf(splitResult), TEST_PLAINTEXT, "content decrypted from split input");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("a file that begins with the magic was written before there was a header");

        Buffer *magicBuffer = bufNew(0);
        IoWrite *magicWrite = ioBufferWriteNew(magicBuffer);

        cipherBlockFormatFilterGroupWriteAdd(magicBuffer, ioWriteFilterGroup(magicWrite), cipherSpec, REPOSITORY_FORMAT_5);
        ioWriteOpen(magicWrite);
        ioWrite(magicWrite, testPlainText);
        ioWriteClose(magicWrite);

        TEST_RESULT_BOOL(
            memcmp(bufPtrConst(magicBuffer), CIPHER_BLOCK_MAGIC, CIPHER_BLOCK_MAGIC_SIZE) == 0, true,
            "a format before the header writes the magic");

        headerResult = bufNew(0);
        headerRead = ioBufferWriteNew(headerResult);
        headerFilterGroup = ioWriteFilterGroup(headerRead);

        cipherBlockFormatFilterGroupReadAdd(headerFilterGroup, cipherSpec);
        ioWriteOpen(headerRead);
        ioWrite(headerRead, magicBuffer);
        ioWriteClose(headerRead);

        TEST_RESULT_STR_Z(strNewBuf(headerResult), TEST_PLAINTEXT, "content decrypted");
        TEST_RESULT_UINT(
            cipherBlockFormatResult(ioFilterGroupResultP(headerFilterGroup, CIPHER_BLOCK_FORMAT_FILTER_TYPE)),
            REPOSITORY_FORMAT_5, "filter reports the format before the header");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("a format given on decrypt must be the one the header names");

        IoWrite *const headerMismatch = ioBufferWriteNew(bufNew(0));

        ioFilterGroupAdd(
            ioWriteFilterGroup(headerMismatch), cipherBlockFormatNewP(cipherSpec, .format = REPOSITORY_FORMAT_5));
        ioWriteOpen(headerMismatch);

        TEST_ERROR(ioWrite(headerMismatch, headerBuffer), FormatError, "expected repository format 5 but found 6");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("a format given on decrypt that the header agrees with is accepted, here from a pack");

        headerResult = bufNew(0);
        headerRead = ioBufferWriteNew(headerResult);

        ioFilterGroupAdd(
            ioWriteFilterGroup(headerRead),
            cipherBlockFormatNewPack(
                ioFilterParamList(cipherBlockFormatNewP(cipherSpec, .format = REPOSITORY_FORMAT_6))));
        ioWriteOpen(headerRead);
        ioWrite(headerRead, headerBuffer);
        ioWriteClose(headerRead);

        TEST_RESULT_STR_Z(strNewBuf(headerResult), TEST_PLAINTEXT, "content decrypted");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("a file too short to hold a header cannot have one");

        IoWrite *const headerShort = ioBufferWriteNew(bufNew(0));

        cipherBlockFormatFilterGroupReadAdd(ioWriteFilterGroup(headerShort), cipherSpec);
        ioWriteOpen(headerShort);
        ioWrite(headerShort, BUFSTRDEF("PGBR"));

        TEST_ERROR(ioWriteClose(headerShort), CryptoError, "cipher header missing");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("damaged headers");

        // Decrypt the buffer above after damaging a byte of the header, which is the same buffer for each case
        #define TEST_HEADER_DAMAGE(damageIdx, damageChar, errorType, errorMessage)                                                 \
            do                                                                                                                     \
            {                                                                                                                      \
                Buffer *const damaged = bufDup(headerBuffer);                                                                      \
                bufPtr(damaged)[damageIdx] = damageChar;                                                                           \
                                                                                                                                   \
                IoWrite *const write = ioBufferWriteNew(bufNew(0));                                                                \
                cipherBlockFormatFilterGroupReadAdd(ioWriteFilterGroup(write), cipherSpec);                                    \
                ioWriteOpen(write);                                                                                                \
                                                                                                                                   \
                TEST_ERROR(ioWrite(write, damaged), errorType, errorMessage);                                                      \
            }                                                                                                                      \
            while (0)

        // Where the format should be, so this version cannot tell what it is looking at
        TEST_HEADER_DAMAGE(CIPHER_BLOCK_FORMAT_MAGIC_SIZE, 'X', FormatError, "invalid cipher header");

        // The byte held back for later, which must be the one this version writes
        TEST_HEADER_DAMAGE(CIPHER_BLOCK_FORMAT_HEADER_SIZE - 1, 'X', FormatError, "invalid cipher header");

        // A format newer than this version can read, reported before anything is decrypted
        TEST_HEADER_DAMAGE(
            CIPHER_BLOCK_FORMAT_HEADER_SIZE - 2, '8', FormatError,
            "repository format 8 requires a newer version of " PROJECT_NAME "\n"
            "HINT: " PROJECT_NAME " " PROJECT_VERSION " supports repository format 5 to 7.");

        // Format 7 is only written with aes-256-gcm, so a block cipher header at that format is refused rather than trusted
        TEST_HEADER_DAMAGE(
            CIPHER_BLOCK_FORMAT_HEADER_SIZE - 2, '7', FormatError, "repository format 7 is not written with the block cipher");

        // A format older than this version can read
        TEST_HEADER_DAMAGE(
            CIPHER_BLOCK_FORMAT_HEADER_SIZE - 2, '4', FormatError,
            "repository format 4 is no longer supported by " PROJECT_NAME "\n"
            "HINT: " PROJECT_NAME " " PROJECT_VERSION " supports repository format 5 to 7.");

        // Neither a header nor the magic, which is what a file that was never encrypted looks like from here
        TEST_HEADER_DAMAGE(0, 'X', CryptoError, "cipher header invalid");

        #undef TEST_HEADER_DAMAGE
    }

    // *****************************************************************************************************************************
    if (testBegin("cipherGcmFormatNew()"))
    {
#ifdef CIPHER_GCM_SUPPORTED
        const Buffer *const key = cipherGcmKeyDecode(BUFSTRDEF(TEST_CIPHER_KEY));
        const Buffer *const ad = cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|info|archive.info"));
        const Buffer *const plaintext = BUFSTRDEF(TEST_PLAINTEXT);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("standalone object is prefix and Tink stream, in chunks and by pack");

        const size_t chunkList[] = {1, 3, 8, 64};

        for (unsigned int inputIdx = 0; inputIdx < LENGTH_OF(chunkList); inputIdx++)
        {
            for (unsigned int outputIdx = 0; outputIdx < LENGTH_OF(chunkList); outputIdx++)
            {
                const Buffer *const object = hrnFilterProcess(
                    cipherGcmFormatNewPack(ioFilterParamList(cipherGcmFormatNewP(cipherModeEncrypt, key, ad))), plaintext,
                    chunkList[inputIdx], chunkList[outputIdx]);

                TEST_RESULT_STR_Z(
                    strNewBuf(BUF(bufPtrConst(object), CIPHER_GCM_FORMAT_PREFIX_SIZE)), "PGBR007G",
                    zNewFmt("prefix, input %zu, output %zu", chunkList[inputIdx], chunkList[outputIdx]));

                // What follows the prefix is exactly a Tink stream, so the prefix is framing and nothing else
                TEST_RESULT_STR(
                    strNewBuf(
                        hrnFilterProcess(
                            cipherGcmNew(cipherModeDecrypt, key, ad),
                            BUF(
                                bufPtrConst(object) + CIPHER_GCM_FORMAT_PREFIX_SIZE,
                                bufUsed(object) - CIPHER_GCM_FORMAT_PREFIX_SIZE),
                            64, 64)),
                    STR(TEST_PLAINTEXT), "a Tink stream follows the prefix");

                TEST_RESULT_STR(
                    strNewBuf(
                        hrnFilterProcess(
                            cipherGcmFormatNewPack(ioFilterParamList(cipherGcmFormatNewP(cipherModeDecrypt, key, ad))), object,
                            chunkList[inputIdx], chunkList[outputIdx])),
                    STR(TEST_PLAINTEXT), "decrypt");
            }
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("a stream of more than one segment, with less room for output than a segment");

        Buffer *const plaintextLarge = bufNew(2 * 1024 * 1024);

        for (size_t byteIdx = 0; byteIdx < bufSize(plaintextLarge); byteIdx++)
            bufPtr(plaintextLarge)[byteIdx] = (uint8_t)(byteIdx * 31 + (byteIdx >> 8));

        bufUsedSet(plaintextLarge, bufSize(plaintextLarge));

        const Buffer *const objectLarge = hrnFilterProcess(
            cipherGcmFormatNewP(cipherModeEncrypt, key, ad), plaintextLarge, 65536, 1024);

        TEST_RESULT_UINT(
            bufUsed(objectLarge), CIPHER_GCM_FORMAT_PREFIX_SIZE + 40 + bufUsed(plaintextLarge) + 16 * 3, "three segments");
        TEST_RESULT_BOOL(
            bufEq(hrnFilterProcess(cipherGcmFormatNewP(cipherModeDecrypt, key, ad), objectLarge, 65536, 1024), plaintextLarge),
            true, "round trip");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("a raw stream has no prefix");

        const Buffer *const raw = hrnFilterProcess(cipherGcmFormatNewP(cipherModeEncrypt, key, ad, .raw = true), plaintext, 64, 64);

        TEST_RESULT_UINT(bufPtrConst(raw)[0], 40, "Tink header first");
        TEST_RESULT_STR(
            strNewBuf(
                hrnFilterProcess(
                    cipherGcmFormatNewPack(ioFilterParamList(cipherGcmFormatNewP(cipherModeDecrypt, key, ad, .raw = true))), raw,
                    1, 1)),
            STR(TEST_PLAINTEXT), "decrypt raw");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("anything but exactly the prefix is refused before anything is decrypted");

        const Buffer *const object = hrnFilterProcess(cipherGcmFormatNewP(cipherModeEncrypt, key, ad), plaintext, 64, 64);
        const char *const prefixList[] = {"Salted__", "PGBR006_", "PGBR007_", "PGBR007H", "PGBR008G", "pgbr007g"};

        for (unsigned int prefixIdx = 0; prefixIdx < LENGTH_OF(prefixList); prefixIdx++)
        {
            Buffer *const tamper = bufDup(object);

            memcpy(bufPtr(tamper), prefixList[prefixIdx], CIPHER_GCM_FORMAT_PREFIX_SIZE);

            TEST_ERROR(
                hrnFilterProcess(cipherGcmFormatNewP(cipherModeDecrypt, key, ad), tamper, 64, 64), FormatError,
                "cipher header is not repository format 7 with cipher type aes-256-gcm");
        }

        // A raw stream is not a standalone object
        TEST_ERROR(
            hrnFilterProcess(cipherGcmFormatNewP(cipherModeDecrypt, key, ad), raw, 64, 64), FormatError,
            "cipher header is not repository format 7 with cipher type aes-256-gcm");

        // Too short to hold the prefix, the prefix alone, and nothing at all
        TEST_ERROR(
            hrnFilterProcess(cipherGcmFormatNewP(cipherModeDecrypt, key, ad), BUF(bufPtrConst(object), 7), 64, 64), FormatError,
            "cipher header is not repository format 7 with cipher type aes-256-gcm");
        TEST_ERROR(
            hrnFilterProcess(cipherGcmFormatNewP(cipherModeDecrypt, key, ad), BUF(bufPtrConst(object), 8), 64, 64), CryptoError,
            "cipher stream is truncated");
        TEST_ERROR(
            hrnFilterProcess(cipherGcmFormatNewP(cipherModeDecrypt, key, ad), bufNew(0), 64, 64), FormatError,
            "cipher header is not repository format 7 with cipher type aes-256-gcm");

        // The prefix does not authenticate the stream: another identity fails in the cipher
        TEST_ERROR(
            hrnFilterProcess(
                cipherGcmFormatNewP(cipherModeDecrypt, key, cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|info|backup.info"))),
                object, 64, 64),
            CryptoError, "cipher segment 0 failed authentication");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("segments begin after the prefix - cut at a boundary, bit flipped");

        const size_t segmentSize = 1024 * 1024;

        TEST_ERROR(
            hrnFilterProcess(
                cipherGcmFormatNewP(cipherModeDecrypt, key, ad),
                BUF(bufPtrConst(objectLarge), CIPHER_GCM_FORMAT_PREFIX_SIZE + segmentSize), 65536, 65536),
            CryptoError, "cipher segment 0 failed authentication");
        TEST_ERROR(
            hrnFilterProcess(
                cipherGcmFormatNewP(cipherModeDecrypt, key, ad),
                BUF(bufPtrConst(objectLarge), CIPHER_GCM_FORMAT_PREFIX_SIZE + 2 * segmentSize), 65536, 65536),
            CryptoError, "cipher segment 1 failed authentication");

        // A cut at what would be the boundary had the prefix been counted in segment 0 is a cut inside segment 1
        TEST_ERROR(
            hrnFilterProcess(
                cipherGcmFormatNewP(cipherModeDecrypt, key, ad), BUF(bufPtrConst(objectLarge), segmentSize), 65536, 65536),
            CryptoError, "cipher segment 0 failed authentication");
        TEST_ERROR(
            hrnFilterProcess(
                cipherGcmFormatNewP(cipherModeDecrypt, key, ad), BUF(bufPtrConst(objectLarge), 2 * segmentSize), 65536, 65536),
            CryptoError, "cipher segment 1 failed authentication");

        // The last byte of segment 0 and the first of segment 1 are either side of the first boundary, and the last segment is the
        // third
        const struct
        {
            size_t offset;                                          // Offset of the byte to flip a bit in
            unsigned int segment;                                   // Segment expected to fail
        } flipList[] =
        {
            {CIPHER_GCM_FORMAT_PREFIX_SIZE + 1, 0},
            {CIPHER_GCM_FORMAT_PREFIX_SIZE + segmentSize - 1, 0},
            {CIPHER_GCM_FORMAT_PREFIX_SIZE + segmentSize, 1},
            {CIPHER_GCM_FORMAT_PREFIX_SIZE + 2 * segmentSize - 1, 1},
            {CIPHER_GCM_FORMAT_PREFIX_SIZE + 2 * segmentSize, 2},
            {bufUsed(objectLarge) - 1, 2},
        };

        for (unsigned int flipIdx = 0; flipIdx < LENGTH_OF(flipList); flipIdx++)
        {
            Buffer *const tamper = bufDup(objectLarge);

            bufPtr(tamper)[flipList[flipIdx].offset] ^= 0x01;

            TEST_ERROR_FMT(
                hrnFilterProcess(cipherGcmFormatNewP(cipherModeDecrypt, key, ad), tamper, 65536, 65536), CryptoError,
                "cipher segment %u failed authentication", flipList[flipIdx].segment);
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("no plaintext is released from an object whose first segment fails");

        IoFilter *const filterRelease = cipherGcmFormatNewP(
            cipherModeDecrypt, key, cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|info|backup.info")));
        Buffer *const released = bufNew(2 * segmentSize);

        TEST_ERROR(
            ioFilterProcessInOut(filterRelease, objectLarge, released), CryptoError, "cipher segment 0 failed authentication");
        TEST_RESULT_UINT(bufUsed(released), 0, "no output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("a pack with a missing key is refused");

        PackWrite *const packNull = pckWriteNewP();

        pckWriteU64P(packNull, cipherModeDecrypt);
        pckWriteBinP(packNull, NULL);
        pckWriteBinP(packNull, ad);
        pckWriteBoolP(packNull, false);
        pckWriteEndP(packNull);

        TEST_ERROR(cipherGcmFormatNewPack(pckWriteResult(packNull)), AssertError, "cipher key size is invalid");

        // A pack that is refused for an error that is not fatal, so the key read from it is cleared on the way out as well
        Buffer *const adTooLarge = bufNew(CIPHER_GCM_AD_SIZE_MAX + 1);

        memset(bufPtr(adTooLarge), 'x', bufSize(adTooLarge));
        bufUsedSet(adTooLarge, bufSize(adTooLarge));

        PackWrite *const packAdTooLarge = pckWriteNewP();

        pckWriteU64P(packAdTooLarge, cipherModeDecrypt);
        pckWriteBinP(packAdTooLarge, key);
        pckWriteBinP(packAdTooLarge, adTooLarge);
        pckWriteBoolP(packAdTooLarge, false);
        pckWriteEndP(packAdTooLarge);

        TEST_ERROR(
            cipherGcmFormatNewPack(pckWriteResult(packAdTooLarge)), CryptoError,
            "cipher associated data size 32769 exceeds maximum of 32768");
#endif
    }

    // *****************************************************************************************************************************
    if (testBegin("cipherFormatFilterGroupAdd() and cipherFormatNewP()"))
    {
        const Buffer *const plaintext = BUFSTRDEF(TEST_PLAINTEXT);
        const StringList *const identity = HRN_CIPHER_IDENTITY("archive|18-1/segment");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("nothing is added when the repository is not encrypted");

        TEST_RESULT_STR_Z(
            strNewBuf(testFormatWrite(cipherSpecNewNone(), identity, plaintext)), TEST_PLAINTEXT, "written as it is");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("block cipher as before - magic when standalone, none when raw");

        const CipherSpec *const cipherSpecCbc = cipherSpecNewP(cipherTypeAes256Cbc, BUFSTRDEF(TEST_PASS), .digest = hashTypeSha256);

        const Buffer *const cbcStandalone = testFormatWrite(cipherSpecCbc, identity, plaintext);

        TEST_RESULT_BOOL(memcmp(bufPtrConst(cbcStandalone), CIPHER_BLOCK_MAGIC, CIPHER_BLOCK_MAGIC_SIZE) == 0, true, "magic");
        TEST_RESULT_STR_Z(strNewBuf(testFormatRead(cipherSpecCbc, identity, cbcStandalone)), TEST_PLAINTEXT, "decrypts");

        const Buffer *const cbc = hrnFilterProcess(
            cipherFormatNewP(cipherModeEncrypt, cipherSpecCbc, identity, .raw = true), plaintext, 64, 64);

        TEST_RESULT_BOOL(memcmp(bufPtrConst(cbc), CIPHER_BLOCK_MAGIC, CIPHER_BLOCK_MAGIC_SIZE) != 0, true, "raw has no magic");
        TEST_RESULT_STR_Z(
            strNewBuf(hrnFilterProcess(cipherFormatNewP(cipherModeDecrypt, cipherSpecCbc, identity, .raw = true), cbc, 64, 64)),
            TEST_PLAINTEXT, "raw decrypts");

#ifdef CIPHER_GCM_SUPPORTED
        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("aes-256-gcm binds the stream to the stanza and the identity");

        const CipherSpec *const cipherSpec = cipherSpecNewP(
            cipherTypeAes256Gcm, BUFSTRDEF(TEST_CIPHER_KEY), .stanza = STRDEF("demo"));
        const Buffer *const key = cipherGcmKeyDecode(BUFSTRDEF(TEST_CIPHER_KEY));

        const Buffer *const object = testFormatWrite(cipherSpec, identity, plaintext);

        TEST_RESULT_STR_Z(
            strNewBuf(BUF(bufPtrConst(object), CIPHER_GCM_FORMAT_PREFIX_SIZE)), CIPHER_GCM_FORMAT_PREFIX, "standalone has prefix");
        TEST_RESULT_STR_Z(strNewBuf(testFormatRead(cipherSpec, identity, object)), TEST_PLAINTEXT, "decrypts");

        // The associated data is the stanza and then the identity, exactly
        const Buffer *const raw = hrnFilterProcess(
            cipherFormatNewP(cipherModeEncrypt, cipherSpec, identity, .raw = true), plaintext, 64, 64);

        TEST_RESULT_UINT(bufPtrConst(raw)[0], 40, "raw has no prefix");
        TEST_RESULT_STR_Z(
            strNewBuf(
                hrnFilterProcess(
                    cipherGcmNew(cipherModeDecrypt, key, cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|archive|18-1/segment"))),
                    raw, 64, 64)),
            TEST_PLAINTEXT, "bound to stanza and identity");

        // Another stanza or another identity does not decrypt
        TEST_ERROR(
            hrnFilterProcess(
                cipherFormatNewP(
                    cipherModeDecrypt, cipherSpecNewP(cipherTypeAes256Gcm, BUFSTRDEF(TEST_CIPHER_KEY), .stanza = STRDEF("other")),
                    identity, .raw = true),
                raw, 64, 64),
            CryptoError, "cipher segment 0 failed authentication");
        TEST_ERROR(
            hrnFilterProcess(
                cipherFormatNewP(
                    cipherModeDecrypt, cipherSpec, HRN_CIPHER_IDENTITY("archive|18-1/other"), .raw = true),
                raw, 64, 64),
            CryptoError, "cipher segment 0 failed authentication");

        // A stream cannot be bound without a stanza, and an identity too large to bind is refused
        TEST_ERROR(
            cipherFormatNewP(
                cipherModeEncrypt, cipherSpecNewP(cipherTypeAes256Gcm, BUFSTRDEF(TEST_CIPHER_KEY)), identity, .raw = true),
            AssertError, "stanza is required to bind a stream");

        // Nor without an identity, e.g. one missing from the parameters of a job, which are not only checked by assertions
        TEST_ERROR(
            cipherFormatNewP(cipherModeEncrypt, cipherSpec, NULL, .raw = true), AssertError,
            "identity is required to bind a stream");
        TEST_ERROR(
            cipherFormatNewP(cipherModeEncrypt, cipherSpec, strLstNew(), .raw = true), AssertError,
            "identity is required to bind a stream");

        StringList *const identityFieldMissing = HRN_CIPHER_IDENTITY("file|20200101-000000F");
        strLstAdd(identityFieldMissing, NULL);

        TEST_ERROR(
            cipherFormatNewP(cipherModeEncrypt, cipherSpec, identityFieldMissing, .raw = true), AssertError,
            "identity field 2 is missing");

        // Nor without a key, e.g. one missing from the parameters of a job
        PackWrite *const specNoKeyWrite = pckWriteNewP();

        pckWriteStrIdP(specNoKeyWrite, cipherTypeAes256Gcm);
        pckWriteStrIdP(specNoKeyWrite, hashTypeSha256);
        pckWriteBinP(specNoKeyWrite, NULL);
        pckWriteStrP(specNoKeyWrite, STRDEF("demo"));
        pckWriteEndP(specNoKeyWrite);

        TEST_ERROR(
            cipherFormatNewP(
                cipherModeEncrypt, cipherSpecNewPack(pckReadNew(pckWriteResult(specNoKeyWrite))), identity, .raw = true),
            AssertError, "key is required to bind a stream");

        StringList *const identityTooLarge = strLstNew();
        String *const field = strNew();

        for (unsigned int fieldIdx = 0; fieldIdx < CIPHER_GCM_AD_SIZE_MAX; fieldIdx++)
            strCatChr(field, 'x');

        strLstAdd(identityTooLarge, field);

        TEST_ERROR(
            cipherFormatNewP(cipherModeEncrypt, cipherSpec, identityTooLarge, .raw = true), CryptoError,
            "cipher associated data size 32801 exceeds maximum of 32768");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("aes-256-gcm - stream read as another kind or value does not decrypt");

        // The identities the commands bind each kind of stream to, the stanza first. Each pair is a stream and what it is read as.
        const struct
        {
            const char *written;                                    // Identity the stream is written with
            const char *read;                                       // Identity the stream is read with
        } identityPairList[] =
        {
            // Stanza
            {"demo|info|archive.info", "other|info|archive.info"},
            {"demo|archive|" TEST_ID_WAL, "other|archive|" TEST_ID_WAL},
            {"demo|file|" TEST_ID_LABEL TEST_ID_FILE, "other|file|" TEST_ID_LABEL TEST_ID_FILE},
            // Info file
            {"demo|info|archive.info", "demo|info|backup.info"},
            {"demo|info|backup.info", "demo|info|archive.info"},
            // Archive: archive id, WAL directory, segment, checksum, compression extension, partial, history and backup files
            {"demo|archive|" TEST_ID_WAL, "demo|archive|18-2/0000000100000001/000000010000000100000001-" TEST_ID_SHA1},
            {"demo|archive|" TEST_ID_WAL, "demo|archive|18-1/0000000100000002/000000010000000100000001-" TEST_ID_SHA1},
            {"demo|archive|" TEST_ID_WAL, "demo|archive|" TEST_ID_WAL_PATH "000000010000000100000002-" TEST_ID_SHA1},
            {"demo|archive|" TEST_ID_WAL, "demo|archive|" TEST_ID_WAL_PATH "000000010000000100000001-" TEST_ID_SHA1_OTHER},
            {"demo|archive|" TEST_ID_WAL, "demo|archive|" TEST_ID_WAL ".gz"},
            {"demo|archive|" TEST_ID_WAL ".gz", "demo|archive|" TEST_ID_WAL},
            {"demo|archive|" TEST_ID_WAL ".gz", "demo|archive|" TEST_ID_WAL ".lz4"},
            {"demo|archive|" TEST_ID_WAL, "demo|archive|" TEST_ID_WAL_PATH "000000010000000100000001.partial-" TEST_ID_SHA1},
            {"demo|archive|18-1/00000002.history", "demo|archive|18-1/00000003.history"},
            {"demo|archive|18-1/00000002.history", "demo|archive|18-2/00000002.history"},
            {
                "demo|archive|" TEST_ID_WAL_PATH "000000010000000100000001.00000028.backup",
                "demo|archive|" TEST_ID_WAL_PATH "000000010000000100000002.00000028.backup",
            },
            // Backup file: label, name, and the kinds that share its fields
            {"demo|file|" TEST_ID_LABEL TEST_ID_FILE, "demo|file|" TEST_ID_LABEL_DIFF TEST_ID_FILE},
            {"demo|file|" TEST_ID_LABEL TEST_ID_FILE, "demo|file|" TEST_ID_LABEL "|pg_data/base/1/3"},
            {"demo|file|" TEST_ID_LABEL TEST_ID_FILE, "demo|block-map|" TEST_ID_LABEL TEST_ID_FILE},
            {"demo|file|" TEST_ID_LABEL TEST_ID_FILE, "demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|0"},
            // Super block: label, name, offset, and an offset that is the same number written another way
            {"demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|8192", "demo|super-block|" TEST_ID_LABEL_DIFF TEST_ID_FILE "|8192"},
            {"demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|8192", "demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "x|8192"},
            {"demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|8192", "demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|0"},
            {"demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|8192", "demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|08192"},
            {"demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|8192", "demo|block-map|" TEST_ID_LABEL TEST_ID_FILE},
            // Block map: label, name, and the file it is part of
            {"demo|block-map|" TEST_ID_LABEL TEST_ID_FILE, "demo|block-map|" TEST_ID_LABEL_DIFF TEST_ID_FILE},
            {"demo|block-map|" TEST_ID_LABEL TEST_ID_FILE, "demo|block-map|" TEST_ID_LABEL "|pg_data/base/1/3"},
            {"demo|block-map|" TEST_ID_LABEL TEST_ID_FILE, "demo|file|" TEST_ID_LABEL TEST_ID_FILE},
            // Manifest: label, whether it is final, and its copy in the history
            {"demo|manifest|" TEST_ID_LABEL "|final", "demo|manifest|" TEST_ID_LABEL_DIFF "|final"},
            {"demo|manifest|" TEST_ID_LABEL "|final", "demo|manifest|" TEST_ID_LABEL "|in-progress"},
            {"demo|manifest|" TEST_ID_LABEL "|in-progress", "demo|manifest|" TEST_ID_LABEL "|final"},
            {"demo|manifest|" TEST_ID_LABEL "|final", "demo|manifest-history|" TEST_ID_LABEL},
            {"demo|manifest-history|" TEST_ID_LABEL, "demo|manifest-history|" TEST_ID_LABEL_DIFF},
            {"demo|manifest-history|" TEST_ID_LABEL, "demo|manifest|" TEST_ID_LABEL "|final"},
        };

        for (unsigned int pairIdx = 0; pairIdx < LENGTH_OF(identityPairList); pairIdx++)
        {
            const StringList *const written = strLstNewSplitZ(STR(identityPairList[pairIdx].written), "|");
            const Buffer *const stream = testFormatGcmField(cipherModeEncrypt, written, plaintext);

            TEST_RESULT_STR_Z(
                strNewBuf(testFormatGcmField(cipherModeDecrypt, written, stream)), TEST_PLAINTEXT,
                zNewFmt("decrypts as %s", identityPairList[pairIdx].written));
            TEST_ERROR(
                testFormatGcmField(cipherModeDecrypt, strLstNewSplitZ(STR(identityPairList[pairIdx].read), "|"), stream),
                CryptoError, "cipher segment 0 failed authentication");
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("aes-256-gcm - identity fields cannot be moved, merged, or split");

        // An identity with the most fields. Every field in turn, the stanza included, is changed in each way a field can change
        // while the bytes of the fields stay the same or nearly so, to show that the fields are bound one by one and in order.
        const StringList *const fieldList = strLstNewSplitZ(
            STRDEF("demo|super-block|" TEST_ID_LABEL TEST_ID_FILE "|8192"), "|");
        const Buffer *const fieldStream = testFormatGcmField(cipherModeEncrypt, fieldList, plaintext);

        TEST_RESULT_STR_Z(strNewBuf(testFormatGcmField(cipherModeDecrypt, fieldList, fieldStream)), TEST_PLAINTEXT, "decrypts");

        for (unsigned int fieldIdx = 0; fieldIdx < strLstSize(fieldList); fieldIdx++)
        {
            const String *const field = strLstGet(fieldList, fieldIdx);

            // A character added to the field
            StringList *tamperList = strLstDup(fieldList);

            strLstRemoveIdx(tamperList, fieldIdx);
            strLstInsert(tamperList, fieldIdx, strNewFmt("%sx", strZ(field)));
            TEST_ERROR(
                testFormatGcmField(cipherModeDecrypt, tamperList, fieldStream), CryptoError,
                "cipher segment 0 failed authentication");

            // The last character removed from the field
            tamperList = strLstDup(fieldList);
            strLstRemoveIdx(tamperList, fieldIdx);
            strLstInsert(tamperList, fieldIdx, strSubN(field, 0, strSize(field) - 1));
            TEST_ERROR(
                testFormatGcmField(cipherModeDecrypt, tamperList, fieldStream), CryptoError,
                "cipher segment 0 failed authentication");

            // The field removed
            tamperList = strLstDup(fieldList);
            strLstRemoveIdx(tamperList, fieldIdx);
            TEST_ERROR(
                testFormatGcmField(cipherModeDecrypt, tamperList, fieldStream), CryptoError,
                "cipher segment 0 failed authentication");

            // An empty field added after the field
            tamperList = strLstDup(fieldList);
            strLstInsert(tamperList, fieldIdx + 1, STRDEF(""));
            TEST_ERROR(
                testFormatGcmField(cipherModeDecrypt, tamperList, fieldStream), CryptoError,
                "cipher segment 0 failed authentication");

            if (fieldIdx + 1 < strLstSize(fieldList))
            {
                const String *const fieldNext = strLstGet(fieldList, fieldIdx + 1);

                // The last character of the field moved to the next field, so the bytes of the two fields together are the same
                tamperList = strLstDup(fieldList);
                strLstRemoveIdx(tamperList, fieldIdx);
                strLstRemoveIdx(tamperList, fieldIdx);
                strLstInsert(tamperList, fieldIdx, strSubN(field, 0, strSize(field) - 1));
                strLstInsert(
                    tamperList, fieldIdx + 1, strNewFmt("%s%s", strZ(strSub(field, strSize(field) - 1)), strZ(fieldNext)));
                TEST_ERROR(
                    testFormatGcmField(cipherModeDecrypt, tamperList, fieldStream), CryptoError,
                    "cipher segment 0 failed authentication");

                // The field merged with the next
                tamperList = strLstDup(fieldList);
                strLstRemoveIdx(tamperList, fieldIdx);
                strLstRemoveIdx(tamperList, fieldIdx);
                strLstInsert(tamperList, fieldIdx, strNewFmt("%s%s", strZ(field), strZ(fieldNext)));
                TEST_ERROR(
                    testFormatGcmField(cipherModeDecrypt, tamperList, fieldStream), CryptoError,
                    "cipher segment 0 failed authentication");

                // The field and the next exchanged
                tamperList = strLstDup(fieldList);
                strLstRemoveIdx(tamperList, fieldIdx);
                strLstInsert(tamperList, fieldIdx + 1, field);
                TEST_ERROR(
                    testFormatGcmField(cipherModeDecrypt, tamperList, fieldStream), CryptoError,
                    "cipher segment 0 failed authentication");
            }
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("an object of another cipher type, or of none, is refused by what it begins with");

        // What the block cipher wrote, at the format before its header and at the format with it, is not read as aes-256-gcm
        TEST_ERROR(
            testFormatRead(cipherSpec, identity, cbcStandalone), FormatError,
            "cipher header is not repository format 7 with cipher type aes-256-gcm");

        for (unsigned int format = REPOSITORY_FORMAT_5; format <= REPOSITORY_FORMAT_6; format++)
        {
            Buffer *const infoBlock = bufNew(0);
            IoWrite *const infoBlockWrite = ioBufferWriteNew(infoBlock);

            cipherFormatInfoWriteAdd(infoBlock, ioWriteFilterGroup(infoBlockWrite), cipherSpecCbc, format, "archive.info");
            ioWriteOpen(infoBlockWrite);
            ioWrite(infoBlockWrite, plaintext);
            ioWriteClose(infoBlockWrite);

            TEST_RESULT_STR_Z(
                strNewBuf(BUF(bufPtrConst(infoBlock), 8)), format == REPOSITORY_FORMAT_5 ? CIPHER_BLOCK_MAGIC : "PGBR006_",
                zNewFmt("format %u info file of the block cipher", format));

            IoRead *const infoBlockRead = ioBufferReadNew(infoBlock);

            cipherFormatInfoReadAdd(ioReadFilterGroup(infoBlockRead), cipherSpec, "archive.info");
            ioReadOpen(infoBlockRead);
            TEST_ERROR(
                ioReadBuf(infoBlockRead), FormatError, "cipher header is not repository format 7 with cipher type aes-256-gcm");
        }

        // Nor is what was not encrypted, whether or not it is long enough to hold a prefix
        TEST_ERROR(
            testFormatRead(cipherSpec, identity, BUFSTRDEF("[backrest]\nbackrest-format=5\n")), FormatError,
            "cipher header is not repository format 7 with cipher type aes-256-gcm");
        TEST_ERROR(
            testFormatRead(cipherSpec, identity, BUFSTRDEF("[db]\n")), FormatError,
            "cipher header is not repository format 7 with cipher type aes-256-gcm");

        // An aes-256-gcm object is not read by the block cipher, which expects its magic or, for an info file, its header
        TEST_ERROR(testFormatRead(cipherSpecCbc, identity, object), CryptoError, "cipher header invalid");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("info files - aes-256-gcm binds name, block cipher header as before");

        Buffer *const info = bufNew(0);
        IoWrite *const infoWrite = ioBufferWriteNew(info);

        // The format of an info file must be the format of its cipher, which a remote repository sets after the configuration is
        // loaded
        TEST_ERROR(
            cipherFormatInfoWriteAdd(info, ioWriteFilterGroup(infoWrite), cipherSpec, REPOSITORY_FORMAT_6, "archive.info"),
            AssertError, "format 6 is not the format of cipher type aes-256-gcm");

        cipherFormatInfoWriteAdd(info, ioWriteFilterGroup(infoWrite), cipherSpec, REPOSITORY_FORMAT_7, "archive.info");
        ioWriteOpen(infoWrite);
        ioWrite(infoWrite, plaintext);
        ioWriteClose(infoWrite);

        TEST_RESULT_STR_Z(strNewBuf(BUF(bufPtrConst(info), CIPHER_GCM_FORMAT_PREFIX_SIZE)), CIPHER_GCM_FORMAT_PREFIX, "prefix");

        IoRead *infoRead = ioBufferReadNew(info);

        cipherFormatInfoReadAdd(ioReadFilterGroup(infoRead), cipherSpec, "archive.info");
        ioReadOpen(infoRead);
        TEST_RESULT_STR_Z(strNewBuf(ioReadBuf(infoRead)), TEST_PLAINTEXT, "read");

        infoRead = ioBufferReadNew(info);
        cipherFormatInfoReadAdd(ioReadFilterGroup(infoRead), cipherSpec, "backup.info");
        ioReadOpen(infoRead);
        TEST_ERROR(ioReadBuf(infoRead), CryptoError, "cipher segment 0 failed authentication");

        // Nor is it read by the block cipher, which takes the cipher from the configuration and not from what the file begins with
        infoRead = ioBufferReadNew(info);
        cipherFormatInfoReadAdd(ioReadFilterGroup(infoRead), cipherSpecCbc, "archive.info");
        ioReadOpen(infoRead);
        TEST_ERROR(ioReadBuf(infoRead), FormatError, "repository format 7 is not written with the block cipher");
#endif

        // The block cipher writes the header of the format into the buffer and reads it back
        Buffer *const infoCbc = bufNew(0);
        IoWrite *const infoCbcWrite = ioBufferWriteNew(infoCbc);

        cipherFormatInfoWriteAdd(infoCbc, ioWriteFilterGroup(infoCbcWrite), cipherSpecCbc, REPOSITORY_FORMAT_6, "archive.info");
        ioWriteOpen(infoCbcWrite);
        ioWrite(infoCbcWrite, plaintext);
        ioWriteClose(infoCbcWrite);

        TEST_RESULT_STR_Z(strNewBuf(BUF(bufPtrConst(infoCbc), 8)), "PGBR006_", "format 6 header");

        IoRead *const infoCbcRead = ioBufferReadNew(infoCbc);

        cipherFormatInfoReadAdd(ioReadFilterGroup(infoCbcRead), cipherSpecCbc, "archive.info");
        ioReadOpen(infoCbcRead);
        TEST_RESULT_STR_Z(strNewBuf(ioReadBuf(infoCbcRead)), TEST_PLAINTEXT, "read");
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
