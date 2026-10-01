/***********************************************************************************************************************************
Test Block Cipher
***********************************************************************************************************************************/
#include "common/io/bufferRead.h"
#include "common/io/bufferWrite.h"
#include "common/io/filter/filter.h"
#include "common/io/io.h"
#include "common/type/json.h"
#include "version.h"

#include "harness/crypto.h"
#include "harness/filter.h"

/***********************************************************************************************************************************
Data for testing
***********************************************************************************************************************************/
#define TEST_CIPHER                                                 "aes-256-cbc"
#define TEST_PASS                                                   "areallybadpassphrase"
#define TEST_PLAINTEXT                                              "plaintext"
#define TEST_BUFFER_SIZE                                            256

// What a file that is not raw begins with, i.e. the magic and the salt behind it
#define TEST_HEADER_SIZE                                            (CIPHER_BLOCK_MAGIC_SIZE + PKCS5_SALT_LEN)

// Cipher spec for the test pass, digest SHA-256
#define TEST_CIPHER_SPEC()                                                                                                         \
    cipherSpecNewP(cipherTypeAes256Cbc, testPass, .digest = hashTypeSha256)

#ifdef CIPHER_GCM_SUPPORTED

/***********************************************************************************************************************************
Tink's known-answer vectors for AES-GCM-HKDF streaming, from AesGcmHkdfStreamingTestUtil in tink-java at commit
93ff48ee3c53183c0c4d08168f88368df3565f7d, dumped by running it. None uses the production parameters, which is why the parameters can
be set.
***********************************************************************************************************************************/
static const struct
{
    const char *digest;                                             // HKDF digest
    size_t keySize;                                                 // Key size
    size_t derivedKeySize;                                          // Derived key size
    size_t segmentSize;                                             // Ciphertext segment size
    const char *key;                                                // Key (hex)
    const char *plaintext;                                          // Plaintext (hex)
    const char *ad;                                                 // Associated data (hex)
    const char *ciphertext;                                         // Ciphertext (hex), which begins with the header
} testCipherGcmVector[] =
{
    {
        .digest = "SHA1", .keySize = 16, .derivedKeySize = 16, .segmentSize = 64,
        .key = "6eb56cdc726dfbe5d57f2fcdc6e9345b",
        .plaintext =
            "54686973206973206120666169726c79206c6f6e6720706c61696e746578742e204974206973206f6620746865206578616374206c656e67"
            "746820746f20637265617465207468726565206f757470757420626c6f636b732e20",
        .ad = "616164",
        .ciphertext =
            "1893b3af5e14ab378d065addfc8484da642c0862877baea8db92d9c77406a406168478821c4298eab3e6d531277f4c1a051714faebcaefcb"
            "ca7b7be05e9445eaa0bb2904153398a25084dd80ae0edcd1c3079fcea2cd3770630ee36f7539207b8ec9d754956d486b71cdf989f0ed6fba"
            "6779b63558be0a66e668df14e1603cd2af8944844078345286d0b292e772e7190775c51a0f83e40c0b75821027e7e538e111",
    },
    {
        .digest = "SHA1", .keySize = 16, .derivedKeySize = 16, .segmentSize = 64,
        .key = "6eb56cdc726dfbe5d57f2fcdc6e9345b",
        .plaintext = "",
        .ad = "",
        .ciphertext = "18ec99b2c3884194023bd41bb9bff309205354c750fa0cb3c0d02609abf71f88eaeaa48d7deca27f",
    },
    {
        .digest = "SHA256", .keySize = 16, .derivedKeySize = 16, .segmentSize = 64,
        .key = "6eb56cdc726dfbe5d57f2fcdc6e9345b",
        .plaintext = "",
        .ad = "",
        .ciphertext = "18be78bce0cab6fd38a9041eea8ab0ffc4cf17e3c00b661d3927f5f79069f41a210fedc40b25648c",
    },
    {
        .digest = "SHA512", .keySize = 16, .derivedKeySize = 16, .segmentSize = 64,
        .key = "6eb56cdc726dfbe5d57f2fcdc6e9345b",
        .plaintext = "",
        .ad = "",
        .ciphertext = "18fec8139ccb406e0f140d7e2bcc41e1b899bc1b121574cc31d1c78ed2ca1cdf324665b8dce21095",
    },
    {
        .digest = "SHA1", .keySize = 32, .derivedKeySize = 16, .segmentSize = 64,
        .key = "00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b",
        .plaintext = "",
        .ad = "",
        .ciphertext = "180880e85a24207a7b72cefde26306ed09d7d76e58104b751d005a3ffd72dd6151f0d9c8ccf163f7",
    },
    {
        .digest = "SHA1", .keySize = 32, .derivedKeySize = 32, .segmentSize = 64,
        .key = "00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b",
        .plaintext = "",
        .ad = "",
        .ciphertext =
            "28fae780c70a82d1256c8303a1261ac6a98cf557b4e173967a62f3c149517ba5b2431da93b3c6e90f508b34dc14bfda59bab05681c6ad3fa",
    },
    {
        .digest = "SHA1", .keySize = 32, .derivedKeySize = 32, .segmentSize = 128,
        .key = "00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b",
        .plaintext = "",
        .ad = "",
        .ciphertext =
            "28fae780c70a82d1256c8303a1261ac6a98cf557b4e173967a62f3c149517ba5b2431da93b3c6e90f508b34dc14bfda59bab05681c6ad3fa",
    },
    {
        .digest = "SHA1", .keySize = 32, .derivedKeySize = 32, .segmentSize = 120,
        .key = "00112233445566778899aabbccddeeff6eb56cdc726dfbe5d57f2fcdc6e9345b",
        .plaintext =
            "424c4f434b20312e424c4f434b20322e424c4f434b20332e424c4f434b20342e424c4f434b20352e424c4f434b20362e424c4f434b20372e"
            "424c4f434b20382e",
        .ad = "00010203",
        .ciphertext =
            "28782994617714a80fa085e15051a16854522330d6d0f26c049b2192f09cdd98b2eb90c753bfff277a29e54fa4afb15d648c28477eb07f01"
            "2535c767f5fdce24ffffae318480c1d37357d6d3c511159318afa09ef38aa3f5456fd7817c5c02dd6e1a7fef174c8bd24e38b5982ac10549"
            "7c0101ac5581fe5b",
    },
};

/***********************************************************************************************************************************
Known answers at the production parameters, AES256_GCM_HKDF_1MB, made by tink-java at commit
93ff48ee3c53183c0c4d08168f88368df3565f7d with the key 000102...1f, the associated data of cipherGcmAdNew() for {"demo", "archive",
"18-1/segment"}, and the plaintext of testCipherGcmPlaintext() of each size: empty, one byte, a first segment that is exactly full,
and one byte more, the smallest stream of two segments. The ciphertext is given by its SHA-256.
***********************************************************************************************************************************/
static const struct
{
    size_t size;                                                    // Plaintext size
    const char *header;                                             // Header (hex): its size, the salt, and the nonce prefix
    const char *ciphertextSha256;                                   // SHA-256 of the ciphertext (hex)
} testCipherGcmVectorProd[] =
{
    {
        .size = 0,
        .header = "28510c78c48f1170b3f845cbf6c8daad3d424746e7e1792d7ba6fdbaf551e1ec217539360bbc5200",
        .ciphertextSha256 = "452ae2d7c6c8b17da025343878067628f7a7043dd089c0bee9937bafa052e016",
    },
    {
        .size = 1,
        .header = "28f0160d080660db0d0814a32644df5e16e3984a2e25cc4f85330b4298dfe0969872b55305e8fe80",
        .ciphertextSha256 = "8ed13d3565ae69238346e2bf594d44d8a8d5a11f3f66a99382d795d2b2f96708",
    },
    {
        .size = 1048520,
        .header = "28a6e85d484ce697f0240194d24ebc1189fa9256168a9fc4a268eab2f5f75006dbc8c8f0eaf676f1",
        .ciphertextSha256 = "1b3d5f45618c581b3a87e86aa439e8f74162cf94f6c558825e264db7951b1720",
    },
    {
        .size = 1048521,
        .header = "28daa33b3c647f7da91f40b197e40a34b3f87ed6b74595522ebefdf9fac83f1d9f889073477505f6",
        .ciphertextSha256 = "ad94679d0e2e390288d7c8741f42ff3fe828b3e0f9e214708988d73673badb74",
    },
};

// Process a whole buffer with the input at once and plenty of room for output
static Buffer *
testCipherGcmAll(IoFilter *const filter, const Buffer *const input)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(IO_FILTER, filter);
        FUNCTION_HARNESS_PARAM(BUFFER, input);
    FUNCTION_HARNESS_END();

    FUNCTION_HARNESS_RETURN(BUFFER, hrnFilterProcess(filter, input, bufUsed(input) == 0 ? 1 : bufUsed(input), 2 * 1024 * 1024));
}

// Copy a buffer with one bit flipped
static Buffer *
testCipherGcmFlip(const Buffer *const input, const size_t offset)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(BUFFER, input);
        FUNCTION_HARNESS_PARAM(SIZE, offset);
    FUNCTION_HARNESS_END();

    Buffer *const result = bufDup(input);

    bufPtr(result)[offset] ^= 0x01;

    FUNCTION_HARNESS_RETURN(BUFFER, result);
}

// Plaintext that is the same on every run and does not repeat within a segment
static Buffer *
testCipherGcmPlaintext(const size_t size)
{
    FUNCTION_HARNESS_BEGIN();
        FUNCTION_HARNESS_PARAM(SIZE, size);
    FUNCTION_HARNESS_END();

    Buffer *const result = bufNew(size);

    for (size_t byteIdx = 0; byteIdx < size; byteIdx++)
        bufPtr(result)[byteIdx] = (uint8_t)(byteIdx * 31 + (byteIdx >> 8) * 7 + (byteIdx >> 16));

    bufUsedSet(result, size);

    FUNCTION_HARNESS_RETURN(BUFFER, result);
}

#endif

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    const Buffer *testPass = BUFSTRDEF(TEST_PASS);
    const Buffer *testPlainText = BUFSTRDEF(TEST_PLAINTEXT);

    // *****************************************************************************************************************************
    if (testBegin("Common"))
    {
        TEST_RESULT_VOID(cryptoInit(), "initialize crypto");
        TEST_RESULT_VOID(cryptoInit(), "initialize crypto again");

        // -------------------------------------------------------------------------------------------------------------------------
        cryptoInit();

        TEST_RESULT_VOID(cryptoError(false, "no error here"), "no error");

        EVP_MD_CTX *context = EVP_MD_CTX_new();
        TEST_ERROR(
            cryptoError(EVP_DigestInit_ex(context, NULL, NULL) != 1, "unable to initialize hash context"), CryptoError,
            "unable to initialize hash context: "
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            "[50331787]"
#else
            "[101187723]"
#endif
            " no digest set");
        EVP_MD_CTX_free(context);

        TEST_ERROR(cryptoError(true, "no error"), CryptoError, "no error: [0] no details available");

        // Test if the buffer was overrun
        // -------------------------------------------------------------------------------------------------------------------------
        uint8_t buffer[256] = {0};

        cryptoRandomBytes(buffer, sizeof(buffer) - 1);
        TEST_RESULT_BOOL(
            buffer[sizeof(buffer) - 1] == 0, true, "check that buffer did not overrun (though random byte could be 0)");

        // Count bytes that are not zero (there shouldn't be all zeroes)
        // -------------------------------------------------------------------------------------------------------------------------
        int nonZeroTotal = 0;

        for (unsigned int charIdx = 0; charIdx < sizeof(buffer) - 1; charIdx++)
            if (buffer[charIdx] != 0)                               // {uncoverable_branch - ok if there are no zeros}
                nonZeroTotal++;

        TEST_RESULT_INT_NE(nonZeroTotal, 0, "check that there are non-zero values in the buffer");
    }

    // *****************************************************************************************************************************
    if (testBegin("CipherBlock"))
    {
        // Cipher and digest errors
        // -------------------------------------------------------------------------------------------------------------------------
        TEST_ERROR(
            cipherBlockNewP(cipherModeEncrypt, cipherSpecNewP(strIdFromZ(BOGUS_STR), testPass, .digest = hashTypeSha256)),
            AssertError, "unable to load cipher 'BOGUS'");
        TEST_ERROR(
            cipherBlockNewP(cipherModeEncrypt, cipherSpecNewP(cipherTypeAes256Cbc, testPass, .digest = strIdFromZ(BOGUS_STR))),
            AssertError, "unable to load digest 'BOGUS'");

        // Initialization of object
        // -------------------------------------------------------------------------------------------------------------------------
        // Build from a duplicate to show the copy contains the type, digest, and pass of the original
        TEST_RESULT_UINT(cipherSpecType(cipherSpecDupP(cipherSpecNewNone())), cipherTypeNone, "dup of none");

        const CipherSpec *const cipherSpec = cipherSpecDupP(TEST_CIPHER_SPEC());

        TEST_RESULT_UINT(cipherSpecDigest(cipherSpec), hashTypeSha256, "dup digest");
        TEST_RESULT_UINT(
            cipherSpecDigest(cipherSpecDupP(cipherSpecNewP(cipherTypeAes256Cbc, testPass))), 0, "dup with no digest");

        // The default digest is used only when the spec has none
        TEST_RESULT_UINT(
            cipherSpecDigest(cipherSpecDupP(cipherSpecNewP(cipherTypeAes256Cbc, testPass), .digestDefault = hashTypeSha1)),
            hashTypeSha1, "dup with default digest");
        TEST_RESULT_UINT(
            cipherSpecDigest(cipherSpecDupP(cipherSpec, .digestDefault = hashTypeSha1)), hashTypeSha256, "dup keeps digest");

        // A pack contains nothing but the type when there is no cipher
        PackWrite *packWrite = pckWriteNewP();

        cipherSpecPack(packWrite, cipherSpecNewNone());
        pckWriteEndP(packWrite);

        TEST_RESULT_UINT(
            cipherSpecType(cipherSpecNewPack(pckReadNew(pckWriteResult(packWrite)))), cipherTypeNone, "unpack none");

        // Else it contains the type, digest, and pass
        packWrite = pckWriteNewP();

        cipherSpecPack(packWrite, cipherSpecNewP(cipherTypeAes256Cbc, testPass, .digest = hashTypeSha1));
        pckWriteEndP(packWrite);

        const CipherSpec *const cipherSpecUnpack = cipherSpecNewPack(pckReadNew(pckWriteResult(packWrite)));

        TEST_RESULT_UINT(cipherSpecType(cipherSpecUnpack), cipherTypeAes256Cbc, "unpack type");
        TEST_RESULT_UINT(cipherSpecDigest(cipherSpecUnpack), hashTypeSha1, "unpack digest");
        TEST_RESULT_STR_Z(strNewBuf(cipherSpecPass(cipherSpecUnpack)), TEST_PASS, "unpack pass");
        TEST_RESULT_PTR(cipherSpecStanza(cipherSpecUnpack), NULL, "unpack no stanza");

        // The stanza is packed and duplicated with the rest of the spec, and logged
        packWrite = pckWriteNewP();

        cipherSpecPack(packWrite, cipherSpecNewP(cipherTypeAes256Cbc, testPass, .stanza = STRDEF("demo")));
        pckWriteEndP(packWrite);

        const CipherSpec *const cipherSpecStanzaUnpack = cipherSpecDupP(cipherSpecNewPack(pckReadNew(pckWriteResult(packWrite))));

        TEST_RESULT_STR_Z(cipherSpecStanza(cipherSpecStanzaUnpack), "demo", "unpack stanza");

        char logBuffer[STACK_TRACE_PARAM_MAX];

        TEST_RESULT_VOID(
            FUNCTION_LOG_OBJECT_FORMAT(cipherSpecStanzaUnpack, cipherSpecToLog, logBuffer, sizeof(logBuffer)), "log with stanza");
        TEST_RESULT_Z(logBuffer, "{type: aes-256-cbc, stanza: demo}", "check log");
        TEST_RESULT_VOID(
            FUNCTION_LOG_OBJECT_FORMAT(cipherSpecUnpack, cipherSpecToLog, logBuffer, sizeof(logBuffer)), "log without stanza");
        TEST_RESULT_Z(logBuffer, "{type: aes-256-cbc, digest: sha1, stanza: null}", "check log");

        CipherBlock *cipherBlock = (CipherBlock *)ioFilterDriver(cipherBlockNewP(cipherModeEncrypt, cipherSpec));
        TEST_RESULT_UINT(cipherBlock->mode, cipherModeEncrypt, "mode is valid");
        TEST_RESULT_UINT(bufSize(cipherBlock->pass), strlen(TEST_PASS), "passphrase size is valid");
        TEST_RESULT_BOOL(memcmp(bufPtrConst(cipherBlock->pass), TEST_PASS, strlen(TEST_PASS)) == 0, true, "passphrase is valid");
        TEST_RESULT_BOOL(cipherBlock->saltDone, false, "salt done is false");
        TEST_RESULT_BOOL(cipherBlock->processDone, false, "process done is false");
        TEST_RESULT_UINT(cipherBlock->headerSize, 0, "header size is 0");
        TEST_RESULT_PTR_NE(cipherBlock->cipher, NULL, "cipher is set");
        TEST_RESULT_PTR_NE(cipherBlock->digest, NULL, "digest is set");
        TEST_RESULT_PTR(cipherBlock->cipherContext, NULL, "cipher context is not set");

        // Encrypt
        // -------------------------------------------------------------------------------------------------------------------------
        Buffer *encryptBuffer = bufNew(TEST_BUFFER_SIZE);

        IoFilter *blockEncryptFilter = cipherBlockNewP(cipherModeEncrypt, TEST_CIPHER_SPEC());
        blockEncryptFilter = cipherBlockNewPack(ioFilterParamList(blockEncryptFilter));
        CipherBlock *blockEncrypt = (CipherBlock *)ioFilterDriver(blockEncryptFilter);

        TEST_RESULT_UINT(
            cipherBlockProcessSize(blockEncrypt, strlen(TEST_PLAINTEXT)),
            strlen(TEST_PLAINTEXT) + EVP_MAX_BLOCK_LENGTH + CIPHER_BLOCK_MAGIC_SIZE + PKCS5_SALT_LEN, "check process size");

        bufLimitSet(encryptBuffer, CIPHER_BLOCK_MAGIC_SIZE);
        ioFilterProcessInOut(blockEncryptFilter, testPlainText, encryptBuffer);
        TEST_RESULT_UINT(bufUsed(encryptBuffer), CIPHER_BLOCK_MAGIC_SIZE, "cipher size is magic size");
        TEST_RESULT_BOOL(ioFilterInputSame(blockEncryptFilter), true, "filter needs same input");

        bufLimitSet(encryptBuffer, CIPHER_BLOCK_MAGIC_SIZE + PKCS5_SALT_LEN);
        ioFilterProcessInOut(blockEncryptFilter, testPlainText, encryptBuffer);
        TEST_RESULT_BOOL(ioFilterInputSame(blockEncryptFilter), false, "filter does not need same input");

        TEST_RESULT_BOOL(blockEncrypt->saltDone, true, "salt done is true");
        TEST_RESULT_BOOL(blockEncrypt->processDone, true, "process done is true");
        TEST_RESULT_UINT(blockEncrypt->headerSize, 0, "header size is 0");
        TEST_RESULT_UINT(bufUsed(encryptBuffer), TEST_HEADER_SIZE, "cipher size is header len");

        TEST_RESULT_UINT(
            cipherBlockProcessSize(blockEncrypt, strlen(TEST_PLAINTEXT)),
            strlen(TEST_PLAINTEXT) + EVP_MAX_BLOCK_LENGTH, "check process size");

        bufLimitSet(
            encryptBuffer, CIPHER_BLOCK_MAGIC_SIZE + PKCS5_SALT_LEN + (size_t)EVP_CIPHER_block_size(blockEncrypt->cipher) / 2);
        ioFilterProcessInOut(blockEncryptFilter, testPlainText, encryptBuffer);
        bufLimitSet(
            encryptBuffer, CIPHER_BLOCK_MAGIC_SIZE + PKCS5_SALT_LEN + (size_t)EVP_CIPHER_block_size(blockEncrypt->cipher));
        ioFilterProcessInOut(blockEncryptFilter, testPlainText, encryptBuffer);
        bufLimitClear(encryptBuffer);

        TEST_RESULT_UINT(
            bufUsed(encryptBuffer), TEST_HEADER_SIZE + (size_t)EVP_CIPHER_block_size(blockEncrypt->cipher),
            "cipher size increases by one block");
        TEST_RESULT_BOOL(ioFilterDone(blockEncryptFilter), false, "filter is not done");

        ioFilterProcessInOut(blockEncryptFilter, NULL, encryptBuffer);
        TEST_RESULT_UINT(
            bufUsed(encryptBuffer), TEST_HEADER_SIZE + (size_t)(EVP_CIPHER_block_size(blockEncrypt->cipher) * 2),
            "cipher size increases by one block on flush");
        TEST_RESULT_BOOL(ioFilterDone(blockEncryptFilter), true, "filter is done");

        ioFilterFree(blockEncryptFilter);

        // Decrypt in one pass
        // -------------------------------------------------------------------------------------------------------------------------
        Buffer *decryptBuffer = bufNew(TEST_BUFFER_SIZE);

        IoFilter *blockDecryptFilter = cipherBlockNewP(cipherModeDecrypt, TEST_CIPHER_SPEC());
        blockDecryptFilter = cipherBlockNewPack(ioFilterParamList(blockDecryptFilter));
        CipherBlock *blockDecrypt = (CipherBlock *)ioFilterDriver(blockDecryptFilter);

        TEST_RESULT_UINT(
            cipherBlockProcessSize(blockDecrypt, bufUsed(encryptBuffer)), bufUsed(encryptBuffer) + EVP_MAX_BLOCK_LENGTH,
            "check process size");

        ioFilterProcessInOut(blockDecryptFilter, encryptBuffer, decryptBuffer);
        TEST_RESULT_UINT_INT(bufUsed(decryptBuffer), EVP_CIPHER_block_size(blockDecrypt->cipher), "decrypt size is one block");

        ioFilterProcessInOut(blockDecryptFilter, NULL, decryptBuffer);
        TEST_RESULT_UINT(bufUsed(decryptBuffer), strlen(TEST_PLAINTEXT) * 2, "check final decrypt size");

        TEST_RESULT_STR_Z(strNewBuf(decryptBuffer), TEST_PLAINTEXT TEST_PLAINTEXT, "check final decrypt buffer");

        ioFilterFree(blockDecryptFilter);

        // Decrypt in small chunks to test buffering
        // -------------------------------------------------------------------------------------------------------------------------
        blockDecryptFilter = cipherBlockNewP(cipherModeDecrypt, TEST_CIPHER_SPEC());
        blockDecrypt = (CipherBlock *)ioFilterDriver(blockDecryptFilter);

        bufUsedZero(decryptBuffer);

        ioFilterProcessInOut(blockDecryptFilter, bufNewC(bufPtr(encryptBuffer), CIPHER_BLOCK_MAGIC_SIZE), decryptBuffer);
        TEST_RESULT_UINT(bufUsed(decryptBuffer), 0, "no decrypt since header read is not complete");
        TEST_RESULT_BOOL(blockDecrypt->saltDone, false, "salt done is false");
        TEST_RESULT_BOOL(blockDecrypt->processDone, false, "process done is false");
        TEST_RESULT_UINT(blockDecrypt->headerSize, CIPHER_BLOCK_MAGIC_SIZE, "check header size");
        TEST_RESULT_BOOL(
            memcmp(blockDecrypt->header, CIPHER_BLOCK_MAGIC, CIPHER_BLOCK_MAGIC_SIZE) == 0, true, "check header magic");

        ioFilterProcessInOut(
            blockDecryptFilter, bufNewC(bufPtr(encryptBuffer) + CIPHER_BLOCK_MAGIC_SIZE, PKCS5_SALT_LEN), decryptBuffer);
        TEST_RESULT_UINT(bufUsed(decryptBuffer), 0, "no decrypt since no data processed yet");
        TEST_RESULT_BOOL(blockDecrypt->saltDone, true, "salt done is true");
        TEST_RESULT_BOOL(blockDecrypt->processDone, false, "process done is false");
        TEST_RESULT_UINT(blockDecrypt->headerSize, CIPHER_BLOCK_MAGIC_SIZE, "check header size (not increased)");
        TEST_RESULT_BOOL(
            memcmp(
                blockDecrypt->header + CIPHER_BLOCK_MAGIC_SIZE, bufPtr(encryptBuffer) + CIPHER_BLOCK_MAGIC_SIZE,
                PKCS5_SALT_LEN) == 0,
            true, "check header salt");

        ioFilterProcessInOut(
            blockDecryptFilter,
            bufNewC(bufPtr(encryptBuffer) + TEST_HEADER_SIZE, bufUsed(encryptBuffer) - TEST_HEADER_SIZE),
            decryptBuffer);
        TEST_RESULT_UINT_INT(bufUsed(decryptBuffer), EVP_CIPHER_block_size(blockDecrypt->cipher), "decrypt size is one block");

        ioFilterProcessInOut(blockDecryptFilter, NULL, decryptBuffer);
        TEST_RESULT_UINT(bufUsed(decryptBuffer), strlen(TEST_PLAINTEXT) * 2, "check final decrypt size");

        TEST_RESULT_STR_Z(strNewBuf(decryptBuffer), TEST_PLAINTEXT TEST_PLAINTEXT, "check final decrypt buffer");

        ioFilterFree(blockDecryptFilter);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("encrypt zero byte file with no magic");

        blockEncryptFilter = cipherBlockNewP(
            cipherModeEncrypt, TEST_CIPHER_SPEC(), .header = cipherBlockHeaderNone);
        blockEncrypt = (CipherBlock *)ioFilterDriver(blockEncryptFilter);

        bufUsedZero(encryptBuffer);

        ioFilterProcessInOut(blockEncryptFilter, NULL, encryptBuffer);
        TEST_RESULT_UINT(bufUsed(encryptBuffer), 24, "check remaining size");

        ioFilterFree(blockEncryptFilter);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error on decrypt expecting magic");

        blockDecryptFilter = cipherBlockNewP(cipherModeDecrypt, TEST_CIPHER_SPEC());
        TEST_ERROR(ioFilterProcessInOut(blockDecryptFilter, encryptBuffer, decryptBuffer), CryptoError, "cipher header invalid");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("decrypt zero byte file with no magic");

        blockDecryptFilter = cipherBlockNewP(
            cipherModeDecrypt, TEST_CIPHER_SPEC(), .header = cipherBlockHeaderNone);
        blockDecrypt = (CipherBlock *)ioFilterDriver(blockDecryptFilter);

        bufUsedZero(decryptBuffer);

        ioFilterProcessInOut(blockDecryptFilter, encryptBuffer, decryptBuffer);
        TEST_RESULT_UINT(bufUsed(decryptBuffer), 0, "0 bytes processed");
        ioFilterProcessInOut(blockDecryptFilter, NULL, decryptBuffer);
        TEST_RESULT_UINT(bufUsed(decryptBuffer), 0, "0 bytes on flush");

        ioFilterFree(blockDecryptFilter);

        // Invalid cipher header
        // -------------------------------------------------------------------------------------------------------------------------
        blockDecryptFilter = cipherBlockNewP(cipherModeDecrypt, TEST_CIPHER_SPEC());
        blockDecrypt = (CipherBlock *)ioFilterDriver(blockDecryptFilter);

        TEST_ERROR(
            ioFilterProcessInOut(blockDecryptFilter, BUFSTRDEF("1234567890123456"), decryptBuffer), CryptoError,
            "cipher header invalid");

        ioFilterFree(blockDecryptFilter);

        // Invalid encrypted data cannot be flushed
        // -------------------------------------------------------------------------------------------------------------------------
        blockDecryptFilter = cipherBlockNewP(cipherModeDecrypt, TEST_CIPHER_SPEC());
        blockDecrypt = (CipherBlock *)ioFilterDriver(blockDecryptFilter);

        bufUsedZero(decryptBuffer);

        ioFilterProcessInOut(blockDecryptFilter, BUFSTRDEF(CIPHER_BLOCK_MAGIC "12345678"), decryptBuffer);
        ioFilterProcessInOut(blockDecryptFilter, BUFSTRDEF("1234567890123456"), decryptBuffer);

        TEST_ERROR(ioFilterProcessInOut(blockDecryptFilter, NULL, decryptBuffer), CryptoError, "unable to flush");

        ioFilterFree(blockDecryptFilter);

        // File with no header should not flush
        // -------------------------------------------------------------------------------------------------------------------------
        blockDecryptFilter = cipherBlockNewP(cipherModeDecrypt, TEST_CIPHER_SPEC());
        blockDecrypt = (CipherBlock *)ioFilterDriver(blockDecryptFilter);

        bufUsedZero(decryptBuffer);

        TEST_ERROR(ioFilterProcessInOut(blockDecryptFilter, NULL, decryptBuffer), CryptoError, "cipher header missing");

        ioFilterFree(blockDecryptFilter);

        // File with header only should error
        // -------------------------------------------------------------------------------------------------------------------------
        blockDecryptFilter = cipherBlockNewP(cipherModeDecrypt, TEST_CIPHER_SPEC());
        blockDecrypt = (CipherBlock *)ioFilterDriver(blockDecryptFilter);

        bufUsedZero(decryptBuffer);

        ioFilterProcessInOut(blockDecryptFilter, BUFSTRDEF(CIPHER_BLOCK_MAGIC "12345678"), decryptBuffer);
        TEST_ERROR(ioFilterProcessInOut(blockDecryptFilter, NULL, decryptBuffer), CryptoError, "unable to flush");

        ioFilterFree(blockDecryptFilter);

        // Helper function
        // -------------------------------------------------------------------------------------------------------------------------
        IoFilterGroup *filterGroup = ioFilterGroupNew();

        TEST_RESULT_PTR(
            cipherBlockFilterGroupAdd(
                filterGroup, cipherModeEncrypt, cipherSpecNewNone()), filterGroup, "   no filter add");
        TEST_RESULT_UINT(ioFilterGroupSize(filterGroup), 0, "    check no filter add");

        TEST_RESULT_VOID(
            cipherBlockFilterGroupAdd(
                filterGroup, cipherModeEncrypt,
                cipherSpecNewP(cipherTypeAes256Cbc, BUFSTRDEF("X"), .digest = hashTypeSha256)), "   filter add");
        TEST_RESULT_UINT(ioFilterGroupSize(filterGroup), 1, "    check filter add");
    }

    // *****************************************************************************************************************************
    if (testBegin("CipherGcm"))
    {
        const Buffer *const key = bufNewDecode(
            encodingHex, STRDEF("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        const Buffer *const ad = cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|archive|18-1/segment"));

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("associated data");

        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, cipherGcmAdNew(strLstNew())), "70676261636b7265737400303037006165732d3235362d67636d00",
            "fixed fields only");
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, cipherGcmAdNew(HRN_CIPHER_IDENTITY("a||bc"))),
            "70676261636b7265737400303037006165732d3235362d67636d00" "610000626300", "fields are each terminated");
        // A string list copies up to the first zero byte, so add the string to the list directly to show the check holds anyway
        StringList *const fieldZero = strLstNew();
        const String *const fieldZeroStr = strNewZN("a\0b", 3);

        lstAdd((List *)fieldZero, &fieldZeroStr);
        TEST_ERROR(cipherGcmAdNew(fieldZero), AssertError, "associated data field contains a zero byte");

        // The fixed fields take 27 bytes and each field one more than its size
        String *const fieldMax = strNew();

        for (unsigned int fieldIdx = 0; fieldIdx < CIPHER_GCM_AD_SIZE_MAX - 27 - 1; fieldIdx++)
            strCatChr(fieldMax, 'x');

        StringList *fieldMaxList = strLstNew();

        strLstAdd(fieldMaxList, fieldMax);
        TEST_RESULT_UINT(bufUsed(cipherGcmAdNew(fieldMaxList)), CIPHER_GCM_AD_SIZE_MAX, "largest associated data");

        strCatChr(fieldMax, 'x');
        fieldMaxList = strLstNew();
        strLstAdd(fieldMaxList, fieldMax);
        TEST_ERROR(cipherGcmAdNew(fieldMaxList), CryptoError, "cipher associated data size 32769 exceeds maximum of 32768");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("key");

        const String *const keyStr = STRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");

        TEST_RESULT_BOOL(bufEq(cipherGcmKeyDecode(BUFSTR(keyStr)), key), true, "decode key");

        const char *const keyError = "cipher key must be the base64 of exactly 32 random bytes";

        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==")), CryptoError, keyError);
        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g")), CryptoError, keyError);
        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")), CryptoError, keyError);
        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n")), CryptoError, keyError);
        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8!")), CryptoError, keyError);
        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMU FRYXGBkaGxwdHh8=")), CryptoError, keyError);
        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMU-RYXGBkaGxwdHh8=")), CryptoError, keyError);
        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=")), CryptoError, keyError);
        TEST_ERROR(
            cipherGcmKeyDecode(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMU\0RYXGBkaGxwdHh8=")), CryptoError, keyError);
        TEST_ERROR(cipherGcmKeyDecode(BUFSTRDEF("correct horse battery staple is not a key!!")), CryptoError, keyError);

        TEST_RESULT_BOOL(cipherGcmKeyValid(BUFSTR(keyStr)), true, "key is valid");
        TEST_RESULT_BOOL(cipherGcmKeyValid(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=")), false, "unused bits set");
        TEST_RESULT_BOOL(cipherGcmKeyValid(BUFSTRDEF("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")), false, "too short");

        const String *const keyNew = cipherGcmKeyNew();

        TEST_RESULT_UINT(bufUsed(cipherGcmKeyDecode(BUFSTR(keyNew))), CIPHER_GCM_KEY_SIZE, "new key decodes");
        TEST_RESULT_BOOL(strEq(keyNew, cipherGcmKeyNew()), false, "new keys differ");

#ifdef CIPHER_GCM_SUPPORTED

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("Tink known-answer vectors, input and output in chunks");

        for (unsigned int vectorIdx = 0; vectorIdx < LENGTH_OF(testCipherGcmVector); vectorIdx++)
        {
            const CipherGcmParam param =
            {
                .digest = testCipherGcmVector[vectorIdx].digest,
                .keySize = testCipherGcmVector[vectorIdx].keySize,
                .derivedKeySize = testCipherGcmVector[vectorIdx].derivedKeySize,
                .segmentSize = testCipherGcmVector[vectorIdx].segmentSize,
            };
            const Buffer *const vectorKey = bufNewDecode(encodingHex, STR(testCipherGcmVector[vectorIdx].key));
            const Buffer *const plaintext = bufNewDecode(encodingHex, STR(testCipherGcmVector[vectorIdx].plaintext));
            const Buffer *const vectorAd = bufNewDecode(encodingHex, STR(testCipherGcmVector[vectorIdx].ad));
            const Buffer *const ciphertext = bufNewDecode(encodingHex, STR(testCipherGcmVector[vectorIdx].ciphertext));
            const size_t chunkList[] = {1, 7, 64, 1024};

            for (unsigned int inputIdx = 0; inputIdx < LENGTH_OF(chunkList); inputIdx++)
            {
                for (unsigned int outputIdx = 0; outputIdx < LENGTH_OF(chunkList); outputIdx++)
                {
                    // Encrypt with the salt and nonce prefix of the vector, taken from its header
                    hrnCryptoRandomBytesSet(BUF(bufPtrConst(ciphertext) + 1, param.derivedKeySize + 7));

                    TEST_RESULT_STR_Z(
                        strNewEncode(
                            encodingHex,
                            hrnFilterProcess(
                                cipherGcmNewParam(cipherModeEncrypt, vectorKey, vectorAd, param), plaintext, chunkList[inputIdx],
                                chunkList[outputIdx])),
                        testCipherGcmVector[vectorIdx].ciphertext,
                        zNewFmt("encrypt vector %u, input %zu, output %zu", vectorIdx, chunkList[inputIdx], chunkList[outputIdx]));

                    TEST_RESULT_STR_Z(
                        strNewEncode(
                            encodingHex,
                            hrnFilterProcess(
                                cipherGcmNewParam(cipherModeDecrypt, vectorKey, vectorAd, param), ciphertext, chunkList[inputIdx],
                                chunkList[outputIdx])),
                        testCipherGcmVector[vectorIdx].plaintext,
                        zNewFmt("decrypt vector %u, input %zu, output %zu", vectorIdx, chunkList[inputIdx], chunkList[outputIdx]));
                }
            }
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("Tink known-answer vectors at the production parameters");

        const Buffer *const adProd = cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|archive|18-1/segment"));

        for (unsigned int vectorIdx = 0; vectorIdx < LENGTH_OF(testCipherGcmVectorProd); vectorIdx++)
        {
            const size_t size = testCipherGcmVectorProd[vectorIdx].size;
            const Buffer *const plaintext = testCipherGcmPlaintext(size);
            const Buffer *const header = bufNewDecode(encodingHex, STR(testCipherGcmVectorProd[vectorIdx].header));

            // Encrypt with the salt and nonce prefix of the vector, taken from its header
            hrnCryptoRandomBytesSet(BUF(bufPtrConst(header) + 1, bufUsed(header) - 1));

            const Buffer *const ciphertext = testCipherGcmAll(cipherGcmNew(cipherModeEncrypt, key, adProd), plaintext);

            TEST_RESULT_STR_Z(
                strNewEncode(encodingHex, cryptoHashOne(hashTypeSha256, ciphertext)),
                testCipherGcmVectorProd[vectorIdx].ciphertextSha256, zNewFmt("encrypt %zu bytes", size));
            TEST_RESULT_BOOL(
                bufEq(testCipherGcmAll(cipherGcmNew(cipherModeDecrypt, key, adProd), ciphertext), plaintext), true,
                zNewFmt("decrypt %zu bytes", size));
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("production parameters at every segment boundary, through a pack");

        const size_t sizeList[] = {0, 1, 1048520, 1048521, 2097080, 2097081};
        const size_t segmentList[] = {1, 1, 1, 2, 2, 3};
        const Buffer *const plaintextLarge = testCipherGcmPlaintext(2097081);

        for (unsigned int sizeIdx = 0; sizeIdx < LENGTH_OF(sizeList); sizeIdx++)
        {
            const Buffer *const plaintext = BUF(bufPtrConst(plaintextLarge), sizeList[sizeIdx]);
            const Buffer *ciphertext = NULL;

            TEST_ASSIGN(
                ciphertext,
                hrnFilterProcess(
                    cipherGcmNewPack(ioFilterParamList(cipherGcmNew(cipherModeEncrypt, key, ad))), plaintext, 65536, 65536),
                zNewFmt("encrypt %zu bytes", sizeList[sizeIdx]));
            TEST_RESULT_UINT(
                bufUsed(ciphertext), 40 + sizeList[sizeIdx] + 16 * segmentList[sizeIdx],
                zNewFmt("%zu segment(s)", segmentList[sizeIdx]));
            TEST_RESULT_UINT(bufPtrConst(ciphertext)[0], 40, "header size");
            TEST_RESULT_BOOL(
                bufEq(
                    hrnFilterProcess(
                        cipherGcmNewPack(ioFilterParamList(cipherGcmNew(cipherModeDecrypt, key, ad))), ciphertext, 65536, 65536),
                    plaintext),
                true, "decrypt");
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("empty associated data by pack, largest through HKDF");

        const Buffer *const adEmpty = bufNew(0);

        TEST_RESULT_BOOL(
            bufEq(
                testCipherGcmAll(
                    cipherGcmNewPack(ioFilterParamList(cipherGcmNew(cipherModeDecrypt, key, adEmpty))),
                    testCipherGcmAll(
                        cipherGcmNewPack(ioFilterParamList(cipherGcmNew(cipherModeEncrypt, key, adEmpty))), plaintextLarge)),
                plaintextLarge),
            true, "empty associated data");

        // The largest associated data, 27 fixed bytes and one field of 32740 bytes and its terminator
        String *const fieldLargest = strNew();

        for (unsigned int fieldIdx = 0; fieldIdx < CIPHER_GCM_AD_SIZE_MAX - 27 - 1; fieldIdx++)
            strCatChr(fieldLargest, 'x');

        StringList *const fieldLargestList = strLstNew();

        strLstAdd(fieldLargestList, fieldLargest);

        const Buffer *const adLargest = cipherGcmAdNew(fieldLargestList);

        TEST_RESULT_UINT(bufUsed(adLargest), CIPHER_GCM_AD_SIZE_MAX, "largest associated data");
        TEST_RESULT_BOOL(
            bufEq(
                testCipherGcmAll(
                    cipherGcmNew(cipherModeDecrypt, key, adLargest),
                    testCipherGcmAll(cipherGcmNew(cipherModeEncrypt, key, adLargest), plaintextLarge)),
                plaintextLarge),
            true, "largest associated data encrypts and decrypts");

        // The filter checks what can arrive in a pack itself, since a pack does not come through cipherGcmAdNew()
        Buffer *const adTooLarge = bufDup(adLargest);

        bufCat(adTooLarge, BUFSTRDEF("x"));
        TEST_ERROR(
            cipherGcmNew(cipherModeEncrypt, key, adTooLarge), CryptoError,
            "cipher associated data size 32769 exceeds maximum of 32768");
        TEST_ERROR(
            cipherGcmNew(cipherModeEncrypt, BUF(bufPtrConst(key), 31), ad), AssertError, "cipher key size is invalid");
        TEST_ERROR(cipherGcmNew(cipherModeEncrypt, NULL, ad), AssertError, "cipher key size is invalid");
        TEST_ERROR(cipherGcmNew(cipherModeEncrypt, key, NULL), AssertError, "cipher associated data is missing");
        TEST_ERROR(cipherGcmNew((CipherMode)12345, key, ad), AssertError, "cipher mode is invalid");

        // A pack whose fields are null is refused the same way
        PackWrite *packNull = pckWriteNewP();

        pckWriteU64P(packNull, cipherModeDecrypt);
        pckWriteBinP(packNull, NULL);
        pckWriteBinP(packNull, ad);
        pckWriteEndP(packNull);

        TEST_ERROR(cipherGcmNewPack(pckWriteResult(packNull)), AssertError, "cipher key size is invalid");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("tamper - header, segment, tag, cut, extend, order, splice, identity");

        // Small segments so a stream has many of them. Segment 0 holds 8 plaintext bytes and later ones 48.
        const CipherGcmParam paramSmall = {.digest = "SHA256", .keySize = 32, .derivedKeySize = 32, .segmentSize = 64};
        const Buffer *const plaintextSmall = BUF(bufPtrConst(plaintextLarge), 8 + 48 + 48 + 20);
        const Buffer *const streamX = testCipherGcmAll(
            cipherGcmNewParam(cipherModeEncrypt, key, ad, paramSmall), plaintextSmall);
        const Buffer *const streamY = testCipherGcmAll(
            cipherGcmNewParam(cipherModeEncrypt, key, ad, paramSmall), plaintextSmall);

        TEST_RESULT_UINT(bufUsed(streamX), 64 * 3 + 20 + 16, "four segments");
        TEST_RESULT_BOOL(
            bufEq(testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), streamX), plaintextSmall), true,
            "untampered stream decrypts");

        // The segment each byte belongs to: the header is part of segment 0 for authentication since the salt and prefix feed it
        for (size_t byteIdx = 0; byteIdx < bufUsed(streamX); byteIdx++)
        {
            if (byteIdx == 0)
            {
                TEST_ERROR(
                    testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), testCipherGcmFlip(streamX, 0)),
                    CryptoError, "cipher header size 41 is invalid");
            }
            else
            {
                TEST_ERROR_FMT(
                    testCipherGcmAll(
                        cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), testCipherGcmFlip(streamX, byteIdx)),
                    CryptoError, "cipher segment %zu failed authentication", byteIdx < 64 ? 0 : byteIdx / 64);
            }
        }

        // Truncation at every segment boundary makes the segment before it the last, which fails since it was not written as last
        for (size_t segmentIdx = 1; segmentIdx < 4; segmentIdx++)
        {
            TEST_ERROR_FMT(
                testCipherGcmAll(
                    cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), BUF(bufPtrConst(streamX), 64 * segmentIdx)),
                CryptoError, "cipher segment %zu failed authentication", segmentIdx - 1);
        }

        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), BUF(bufPtrConst(streamX), 40 + 15)),
            CryptoError, "cipher stream is truncated");
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), BUF(bufPtrConst(streamX), 40)),
            CryptoError, "cipher stream is truncated");
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), BUF(bufPtrConst(streamX), 20)),
            CryptoError, "cipher stream is truncated");

        IoFilter *filter = cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall);
        Buffer *output = bufNew(1024);

        TEST_ERROR(ioFilterProcessInOut(filter, NULL, output), CryptoError, "cipher stream is truncated");

        // Extension: one byte appended, and a whole segment inserted before the last
        Buffer *tamper = bufDup(streamX);

        bufCat(tamper, BUFSTRDEF("x"));
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamper), CryptoError,
            "cipher segment 3 failed authentication");

        tamper = bufDup(BUF(bufPtrConst(streamX), 64 * 3));
        bufCat(tamper, BUF(bufPtrConst(streamX) + 64, 64));
        bufCat(tamper, BUF(bufPtrConst(streamX) + 64 * 3, bufUsed(streamX) - 64 * 3));
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamper), CryptoError,
            "cipher segment 3 failed authentication");

        // Order: two segments swapped, and a segment duplicated in place of another
        tamper = bufDup(streamX);
        memcpy(bufPtr(tamper) + 64, bufPtrConst(streamX) + 128, 64);
        memcpy(bufPtr(tamper) + 128, bufPtrConst(streamX) + 64, 64);
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamper), CryptoError,
            "cipher segment 1 failed authentication");

        tamper = bufDup(streamX);
        memcpy(bufPtr(tamper) + 128, bufPtrConst(streamX) + 64, 64);
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamper), CryptoError,
            "cipher segment 2 failed authentication");

        // Splice from another stream with the same key, associated data, and plaintext: a segment, and the header
        tamper = bufDup(streamX);
        memcpy(bufPtr(tamper) + 64, bufPtrConst(streamY) + 64, 64);
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamper), CryptoError,
            "cipher segment 1 failed authentication");

        tamper = bufDup(streamX);
        memcpy(bufPtr(tamper), bufPtrConst(streamY), 40);
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamper), CryptoError,
            "cipher segment 0 failed authentication");

        // Identity: another associated data or key fails at segment 0
        TEST_ERROR(
            testCipherGcmAll(
                cipherGcmNewParam(
                    cipherModeDecrypt, key, cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|archive|18-1/other")),
                    paramSmall),
                streamX),
            CryptoError, "cipher segment 0 failed authentication");
        TEST_ERROR(
            testCipherGcmAll(
                cipherGcmNewParam(cipherModeDecrypt, cipherGcmKeyDecode(BUFSTR(cipherGcmKeyNew())), ad, paramSmall), streamX),
            CryptoError, "cipher segment 0 failed authentication");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("tamper - segment appended, cut inside a segment, one byte at a time");

        // A segment appended to a stream whose last segment is not full moves the segment boundaries, so the last segment fails
        tamper = bufDup(streamX);
        bufCat(tamper, BUF(bufPtrConst(streamX) + 64, 64));
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamper), CryptoError,
            "cipher segment 3 failed authentication");

        // A stream whose last segment is full, so an appended segment leaves every boundary where it was. The segment that was
        // written as the last is now read as one that is not, and fails before the appended segment is looked at.
        const Buffer *const streamFull = testCipherGcmAll(
            cipherGcmNewParam(cipherModeEncrypt, key, ad, paramSmall), BUF(bufPtrConst(plaintextLarge), 8 + 48 * 3));

        TEST_RESULT_UINT(bufUsed(streamFull), 64 * 4, "four full segments");
        TEST_RESULT_UINT(
            bufUsed(testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), streamFull)), 8 + 48 * 3,
            "untampered stream decrypts");

        tamper = bufDup(streamFull);
        bufCat(tamper, BUF(bufPtrConst(streamFull) + 64 * 3, 64));
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamper), CryptoError,
            "cipher segment 3 failed authentication");

        // A cut inside a segment makes what is left of it the last segment: its tag is no longer where it was, or is incomplete
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), BUF(bufPtrConst(streamX), 64 * 2 + 30)),
            CryptoError, "cipher segment 2 failed authentication");
        TEST_ERROR(
            testCipherGcmAll(
                cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), BUF(bufPtrConst(streamX), bufUsed(streamX) - 1)),
            CryptoError, "cipher segment 3 failed authentication");
        TEST_ERROR(
            testCipherGcmAll(cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), BUF(bufPtrConst(streamX), 64 * 3 + 15)),
            CryptoError, "cipher stream is truncated");

        // Fed one byte at a time and read one byte at a time, a tampered stream fails with the same error and has released the
        // same plaintext, that of the segments before the one that fails, as when it is given whole
        const struct
        {
            const Buffer *stream;                                   // Tampered stream
            const char *error;                                      // Error expected
            size_t released;                                        // Plaintext released before the error
        } tamperList[] =
        {
            {testCipherGcmFlip(streamX, 0), "cipher header size 41 is invalid", 0},
            {testCipherGcmFlip(streamX, 20), "cipher segment 0 failed authentication", 0},
            {testCipherGcmFlip(streamX, 64 + 10), "cipher segment 1 failed authentication", 8},
            {testCipherGcmFlip(streamX, 64 * 3 - 1), "cipher segment 2 failed authentication", 8 + 48},
            {testCipherGcmFlip(streamX, bufUsed(streamX) - 1), "cipher segment 3 failed authentication", 8 + 48 * 2},
            {BUF(bufPtrConst(streamX), 64 * 3), "cipher segment 2 failed authentication", 8 + 48},
            {BUF(bufPtrConst(streamX), 40), "cipher stream is truncated", 0},
            {tamper, "cipher segment 3 failed authentication", 8 + 48 * 2},
        };

        for (unsigned int tamperIdx = 0; tamperIdx < LENGTH_OF(tamperList); tamperIdx++)
        {
            Buffer *const releasedWhole = bufNew(0);
            Buffer *const releasedByte = bufNew(0);

            TEST_ERROR(
                hrnFilterProcessTo(
                    cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamperList[tamperIdx].stream,
                    bufUsed(tamperList[tamperIdx].stream), 1024, releasedWhole),
                CryptoError, tamperList[tamperIdx].error);
            TEST_ERROR(
                hrnFilterProcessTo(
                    cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall), tamperList[tamperIdx].stream, 1, 1, releasedByte),
                CryptoError, tamperList[tamperIdx].error);

            TEST_RESULT_UINT(
                bufUsed(releasedWhole), tamperList[tamperIdx].released, zNewFmt("tamper %u, released when given whole", tamperIdx));
            TEST_RESULT_BOOL(
                bufEq(releasedByte, releasedWhole) &&
                bufEq(releasedByte, BUF(bufPtrConst(plaintextLarge), tamperList[tamperIdx].released)),
                true, zNewFmt("tamper %u, the same plaintext released one byte at a time", tamperIdx));
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("tamper at the production parameters, through a pack");

        // Four segments: segment 0 ends at 1MiB, segments 1 and 2 are 1MiB each, and the last holds what remains
        const size_t segmentSize = 1024 * 1024;
        const Buffer *const plaintextProd = testCipherGcmPlaintext(3 * segmentSize);
        const Buffer *const streamProdX = hrnFilterProcess(
            cipherGcmNewPack(ioFilterParamList(cipherGcmNew(cipherModeEncrypt, key, ad))), plaintextProd, 65536, 65536);
        const Buffer *const streamProdY = hrnFilterProcess(
            cipherGcmNewPack(ioFilterParamList(cipherGcmNew(cipherModeEncrypt, key, ad))), plaintextProd, 65536, 65536);

        TEST_RESULT_UINT(bufUsed(streamProdX), 40 + 3 * segmentSize + 16 * 4, "four segments");
        TEST_RESULT_BOOL(
            bufEq(
                hrnFilterProcess(
                    cipherGcmNewPack(ioFilterParamList(cipherGcmNew(cipherModeDecrypt, key, ad))), streamProdX, 65536, 65536),
                plaintextProd),
            true, "untampered stream decrypts");

        #define TEST_CIPHER_GCM_PROD_ERROR(stream, errorMessage)                                                                   \
            TEST_ERROR(                                                                                                            \
                hrnFilterProcess(                                                                                                  \
                    cipherGcmNewPack(ioFilterParamList(cipherGcmNew(cipherModeDecrypt, key, ad))), stream, 65536, 65536),          \
                CryptoError, errorMessage)

        // A bit flipped in each header field, and in the first and last byte of the ciphertext and of the tag of each segment
        TEST_CIPHER_GCM_PROD_ERROR(testCipherGcmFlip(streamProdX, 0), "cipher header size 41 is invalid");

        const struct
        {
            size_t offset;                                          // Offset of the byte to flip a bit in
            unsigned int segment;                                   // Segment expected to fail
        } flipList[] =
        {
            // Salt, first and last byte, and nonce prefix, first and last byte
            {1, 0}, {32, 0}, {33, 0}, {39, 0},
            // Segment 0: ciphertext and tag
            {40, 0}, {segmentSize - 17, 0}, {segmentSize - 16, 0}, {segmentSize - 1, 0},
            // Segment 1
            {segmentSize, 1}, {2 * segmentSize - 17, 1}, {2 * segmentSize - 16, 1}, {2 * segmentSize - 1, 1},
            // Segment 2
            {2 * segmentSize, 2}, {3 * segmentSize - 17, 2}, {3 * segmentSize - 16, 2}, {3 * segmentSize - 1, 2},
            // Segment 3, the last
            {3 * segmentSize, 3}, {bufUsed(streamProdX) - 17, 3}, {bufUsed(streamProdX) - 16, 3}, {bufUsed(streamProdX) - 1, 3},
        };

        for (unsigned int flipIdx = 0; flipIdx < LENGTH_OF(flipList); flipIdx++)
        {
            TEST_CIPHER_GCM_PROD_ERROR(
                testCipherGcmFlip(streamProdX, flipList[flipIdx].offset),
                zNewFmt("cipher segment %u failed authentication", flipList[flipIdx].segment));
        }

        // Truncation at every segment boundary, to the header and less than a tag, to the header, and to nothing
        for (unsigned int segmentIdx = 1; segmentIdx < 4; segmentIdx++)
        {
            TEST_CIPHER_GCM_PROD_ERROR(
                BUF(bufPtrConst(streamProdX), segmentIdx * segmentSize),
                zNewFmt("cipher segment %u failed authentication", segmentIdx - 1));
        }

        TEST_CIPHER_GCM_PROD_ERROR(BUF(bufPtrConst(streamProdX), 40 + 15), "cipher stream is truncated");
        TEST_CIPHER_GCM_PROD_ERROR(BUF(bufPtrConst(streamProdX), 40), "cipher stream is truncated");
        TEST_CIPHER_GCM_PROD_ERROR(bufNew(0), "cipher stream is truncated");

        // Extension: one byte appended, and a whole segment appended
        Buffer *tamperProd = bufDup(streamProdX);

        bufCat(tamperProd, BUFSTRDEF("x"));
        TEST_CIPHER_GCM_PROD_ERROR(tamperProd, "cipher segment 3 failed authentication");

        tamperProd = bufDup(streamProdX);
        bufCat(tamperProd, BUF(bufPtrConst(streamProdX) + segmentSize, segmentSize));
        TEST_CIPHER_GCM_PROD_ERROR(tamperProd, "cipher segment 3 failed authentication");

        // Order: segments 1 and 2 swapped, segment 1 in place of segment 2, and segment 1 dropped
        tamperProd = bufDup(streamProdX);
        memcpy(bufPtr(tamperProd) + segmentSize, bufPtrConst(streamProdX) + 2 * segmentSize, segmentSize);
        memcpy(bufPtr(tamperProd) + 2 * segmentSize, bufPtrConst(streamProdX) + segmentSize, segmentSize);
        TEST_CIPHER_GCM_PROD_ERROR(tamperProd, "cipher segment 1 failed authentication");

        tamperProd = bufDup(streamProdX);
        memcpy(bufPtr(tamperProd) + 2 * segmentSize, bufPtrConst(streamProdX) + segmentSize, segmentSize);
        TEST_CIPHER_GCM_PROD_ERROR(tamperProd, "cipher segment 2 failed authentication");

        tamperProd = bufDup(BUF(bufPtrConst(streamProdX), segmentSize));
        bufCat(tamperProd, BUF(bufPtrConst(streamProdX) + 2 * segmentSize, bufUsed(streamProdX) - 2 * segmentSize));
        TEST_CIPHER_GCM_PROD_ERROR(tamperProd, "cipher segment 1 failed authentication");

        // Splice from another stream with the same key, associated data, and plaintext: a segment, and the header
        tamperProd = bufDup(streamProdX);
        memcpy(bufPtr(tamperProd) + segmentSize, bufPtrConst(streamProdY) + segmentSize, segmentSize);
        TEST_CIPHER_GCM_PROD_ERROR(tamperProd, "cipher segment 1 failed authentication");

        tamperProd = bufDup(streamProdX);
        memcpy(bufPtr(tamperProd), bufPtrConst(streamProdY), 40);
        TEST_CIPHER_GCM_PROD_ERROR(tamperProd, "cipher segment 0 failed authentication");

        #undef TEST_CIPHER_GCM_PROD_ERROR

        // Identity: another associated data or key fails at segment 0
        TEST_ERROR(
            hrnFilterProcess(
                cipherGcmNewPack(
                    ioFilterParamList(
                        cipherGcmNew(
                            cipherModeDecrypt, key, cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|archive|18-1/other"))))),
                streamProdX, 65536, 65536),
            CryptoError, "cipher segment 0 failed authentication");
        TEST_ERROR(
            hrnFilterProcess(
                cipherGcmNewPack(
                    ioFilterParamList(cipherGcmNew(cipherModeDecrypt, cipherGcmKeyDecode(BUFSTR(cipherGcmKeyNew())), ad))),
                streamProdX, 65536, 65536),
            CryptoError, "cipher segment 0 failed authentication");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("header of another key size is refused before the key is derived");

        const CipherGcmParam paramAes128 = {.digest = "SHA256", .keySize = 32, .derivedKeySize = 16, .segmentSize = 64};
        const Buffer *const stream18 = testCipherGcmAll(
            cipherGcmNewParam(cipherModeEncrypt, key, ad, paramAes128), plaintextSmall);

        TEST_RESULT_UINT(bufPtrConst(stream18)[0], 0x18, "header size of AES-128");

        // The whole stream is given so that a check made only after the header had been read would have derived a key first
        filter = cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall);
        TEST_ERROR(ioFilterProcessInOut(filter, stream18, output), CryptoError, "cipher header size 24 is invalid");
        TEST_RESULT_BOOL(((CipherGcm *)ioFilterDriver(filter))->cipherContext == NULL, true, "no key derived");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("no plaintext is released from a segment that fails, and a failure is final");

        filter = cipherGcmNewParam(
            cipherModeDecrypt, key, cipherGcmAdNew(HRN_CIPHER_IDENTITY("demo|archive|18-1/other")),
            paramSmall);
        bufUsedZero(output);

        TEST_ERROR(ioFilterProcessInOut(filter, streamX, output), CryptoError, "cipher segment 0 failed authentication");
        TEST_RESULT_UINT(bufUsed(output), 0, "no output");

        // Nor is it held for release, which would leave the stream one step from releasing it, and what was decrypted is cleared
        const uint8_t zeroList[8] = {0};

        TEST_RESULT_UINT(bufUsed(((CipherGcm *)ioFilterDriver(filter))->output), 0, "no plaintext held");
        TEST_RESULT_BOOL(
            memcmp(bufPtr(((CipherGcm *)ioFilterDriver(filter))->output), zeroList, sizeof(zeroList)) == 0, true,
            "plaintext of the failed segment cleared");
        TEST_ERROR(ioFilterProcessInOut(filter, streamX, output), AssertError, "cipher failed on a prior call");

        // Segments before the one that fails are released, which is why the output of a stream that fails must not be used
        filter = cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall);
        bufUsedZero(output);

        TEST_ERROR(
            ioFilterProcessInOut(filter, testCipherGcmFlip(streamX, 64 * 2 + 10), output), CryptoError,
            "cipher segment 2 failed authentication");
        TEST_RESULT_UINT(bufUsed(output), 8 + 48, "segments 0 and 1 released");
        TEST_RESULT_UINT(bufUsed(((CipherGcm *)ioFilterDriver(filter))->output), 0, "segment 2 not held");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("segment limit");

        filter = cipherGcmNewParam(cipherModeEncrypt, key, ad, paramSmall);
        bufUsedZero(output);

        // Write segment 0, which is written once a byte follows it, then continue as if the stream were at the last segment number
        ioFilterProcessInOut(filter, BUF(bufPtrConst(plaintextSmall), 8), output);
        ioFilterProcessInOut(filter, BUF(bufPtrConst(plaintextSmall), 1), output);
        TEST_RESULT_UINT(((CipherGcm *)ioFilterDriver(filter))->segmentNo, 1, "segment 0 written");

        ((CipherGcm *)ioFilterDriver(filter))->segmentNo = UINT32_MAX;

        // Fill that segment, and write it when more input arrives
        ioFilterProcessInOut(filter, BUF(bufPtrConst(plaintextSmall), 47), output);
        ioFilterProcessInOut(filter, BUF(bufPtrConst(plaintextSmall), 1), output);
        TEST_RESULT_UINT(
            ((CipherGcm *)ioFilterDriver(filter))->segmentNo, (uint64_t)UINT32_MAX + 1, "segment UINT32_MAX written");

        // The next segment would need a number that the nonce cannot hold
        TEST_ERROR(ioFilterProcessInOut(filter, NULL, output), CryptoError, "cipher stream exceeds maximum segments");

        // Decrypt the same way: the header, segment 0, and segment UINT32_MAX (not the last) written above are valid, and the
        // segment after them is refused for its number before its tag is checked
        TEST_RESULT_UINT(bufUsed(output), 40 + 24 + 64, "header, segment 0, and segment UINT32_MAX");

        Buffer *const streamLimit = bufDup(output);

        bufCat(streamLimit, BUFSTRDEF("0123456789abcdef0"));

        filter = cipherGcmNewParam(cipherModeDecrypt, key, ad, paramSmall);
        bufUsedZero(output);

        ioFilterProcessInOut(filter, BUF(bufPtrConst(streamLimit), 65), output);
        TEST_RESULT_UINT(((CipherGcm *)ioFilterDriver(filter))->segmentNo, 1, "segment 0 decrypted");

        ((CipherGcm *)ioFilterDriver(filter))->segmentNo = UINT32_MAX;
        ioFilterProcessInOut(filter, BUF(bufPtrConst(streamLimit) + 65, bufUsed(streamLimit) - 65), output);
        TEST_RESULT_UINT(
            ((CipherGcm *)ioFilterDriver(filter))->segmentNo, (uint64_t)UINT32_MAX + 1, "segment UINT32_MAX decrypted");
        TEST_ERROR(ioFilterProcessInOut(filter, NULL, output), CryptoError, "cipher stream exceeds maximum segments");
#else
        TEST_ERROR(
            cipherGcmNew(cipherModeEncrypt, key, ad), CryptoError, "cipher type aes-256-gcm requires OpenSSL 3.0.8 or later");
#endif
    }

    // *****************************************************************************************************************************
    if (testBegin("CryptoHash"))
    {
        IoFilter *hash = NULL;

        TEST_ERROR(cryptoHashNew(STRID5("bogus", 0x13a9de20)), AssertError, "unable to load digest 'bogus'");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_ASSIGN(hash, cryptoHashNew(hashTypeSha1), "create sha1 hash");
        TEST_RESULT_VOID(ioFilterFree(hash), "    free hash");

        // -------------------------------------------------------------------------------------------------------------------------
        PackWrite *packWrite = pckWriteNewP();
        pckWriteStrIdP(packWrite, hashTypeSha1);
        pckWriteEndP(packWrite);

        TEST_ASSIGN(hash, cryptoHashNewPack(pckWriteResult(packWrite)), "create sha1 hash");
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, cryptoHash((CryptoHash *)ioFilterDriver(hash))), HASH_TYPE_SHA1_ZERO, "    check empty hash");
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, cryptoHash((CryptoHash *)ioFilterDriver(hash))), HASH_TYPE_SHA1_ZERO,
            "    check empty hash again");
        TEST_RESULT_VOID(ioFilterFree(hash), "    free hash");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_ASSIGN(hash, cryptoHashNew(hashTypeSha1), "create sha1 hash");
        TEST_RESULT_VOID(ioFilterProcessIn(hash, BUFSTRZ("1")), "    add 1");
        TEST_RESULT_VOID(ioFilterProcessIn(hash, BUFSTR(STRDEF("2"))), "    add 2");
        TEST_RESULT_VOID(ioFilterProcessIn(hash, BUFSTRDEF("3")), "    add 3");
        TEST_RESULT_VOID(ioFilterProcessIn(hash, BUFSTRDEF("4")), "    add 4");
        TEST_RESULT_VOID(ioFilterProcessIn(hash, BUFSTRDEF("5")), "    add 5");

        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(pckReadNew(ioFilterResult(hash)))), "8cb2237d0679ca88db6464eac60da96345513964",
            "    check small hash");
        TEST_RESULT_VOID(ioFilterFree(hash), "    free hash");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("md5 hash - zero bytes");

        TEST_ASSIGN(hash, cryptoHashNew(hashTypeMd5), "create md5 hash");
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(pckReadNew(ioFilterResult(hash)))), HASH_TYPE_MD5_ZERO, "check empty hash");

        // Exercise most of the conditions in the local MD5 code
        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("md5 hash - mixed bytes");

        TEST_ASSIGN(hash, cryptoHashNew(hashTypeMd5), "create md5 hash");
        TEST_RESULT_VOID(ioFilterProcessIn(hash, BUFSTRZ("1")), "add 1");
        TEST_RESULT_VOID(ioFilterProcessIn(hash, BUFSTRZ("123456789012345678901234567890123")), "add 32 bytes");
        TEST_RESULT_VOID(
            ioFilterProcessIn(
                hash,
                BUFSTRZ(
                    "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"
                    "12345678901234567890123456789012345678901234567890")),
            "add 160 bytes");
        TEST_RESULT_VOID(
            ioFilterProcessIn(hash, BUFSTRZ("12345678901234567890123456789001234567890012345678901234")), "add 58 bytes");

        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(pckReadNew(ioFilterResult(hash)))), "3318600bc9c1d379e91e4bae90721243",
            "check hash");

        // Full coverage of local MD5 requires processing > 511MB of data but that makes the test run too long. Instead we'll cheat
        // a bit and initialize the context at 511MB to start. This does not produce a valid MD5 hash but does provide coverage of
        // that one condition cheaply.
        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("md5 hash - > 0x1fffffff bytes");

        TEST_ASSIGN(hash, cryptoHashNew(hashTypeMd5), "create md5 hash");
        ((CryptoHash *)ioFilterDriver(hash))->md5Context.lo = 0x1fffffff;

        TEST_RESULT_VOID(ioFilterProcessIn(hash, BUFSTRZ("1")), "add 1");
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(pckReadNew(ioFilterResult(hash)))), "5c99876f9cafa7f485eac9c7a8a2764c",
            "check hash");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_ASSIGN(hash, cryptoHashNew(hashTypeSha256), "create sha256 hash");
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(pckReadNew(ioFilterResult(hash)))), HASH_TYPE_SHA256_ZERO,
            "    check empty hash");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, cryptoHashOne(hashTypeSha1, BUFSTRDEF("12345"))), "8cb2237d0679ca88db6464eac60da96345513964",
            "    check small hash");
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, cryptoHashOne(hashTypeSha1, BUFSTRDEF(""))), HASH_TYPE_SHA1_ZERO, "    check empty hash");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_RESULT_STR_Z(
            strNewEncode(
                encodingHex,
                cryptoHmacOne(
                    hashTypeSha256,
                    BUFSTRDEF("AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
                    BUFSTRDEF("20170412"))),
            "8b05c497afe9e1f42c8ada4cb88392e118649db1e5c98f0f0fb0a158bdd2dd76",
            "    check hmac");
    }

    // *****************************************************************************************************************************
    if (testBegin("XxHash"))
    {
        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("xxHashOne");

        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, xxHashOne(16, BUFSTRDEF(""))), "99aa06d3014798d86001c324468d497f", "check empty hash 16");
        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, xxHashOne(16, BUFSTRDEF("12345\n"))), "1a3e11127b8856b804f0f99dc9fa4b56",
            "check small hash 16");

        TEST_RESULT_STR_Z(strNewEncode(encodingHex, xxHashOne(5, BUFSTRDEF(""))), "99aa06d301", "check empty hash 5");
        TEST_RESULT_STR_Z(strNewEncode(encodingHex, xxHashOne(5, BUFSTRDEF("12345\n"))), "1a3e11127b", "check small hash 5");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("XxHash");

        ioBufferSizeSet(2);

        const Buffer *message = BUFSTRDEF("");
        IoRead *read = ioBufferReadNew(message);
        ioFilterGroupAdd(ioReadFilterGroup(read), xxHashNew(16));

        ioReadDrain(read);

        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(ioFilterGroupResultP(ioReadFilterGroup(read), XX_HASH_FILTER_TYPE))),
            "99aa06d3014798d86001c324468d497f", "check empty hash 16");

        message = BUFSTRDEF("12345\n");
        read = ioBufferReadNew(message);
        ioFilterGroupAdd(ioReadFilterGroup(read), xxHashNew(16));

        ioReadDrain(read);

        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(ioFilterGroupResultP(ioReadFilterGroup(read), XX_HASH_FILTER_TYPE))),
            "1a3e11127b8856b804f0f99dc9fa4b56", "check small hash 16");

        message = BUFSTRDEF("");
        read = ioBufferReadNew(message);
        ioFilterGroupAdd(ioReadFilterGroup(read), xxHashNew(5));

        ioReadDrain(read);

        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(ioFilterGroupResultP(ioReadFilterGroup(read), XX_HASH_FILTER_TYPE))),
            "99aa06d301", "check empty hash 5");

        message = BUFSTRDEF("12345\n");
        read = ioBufferReadNew(message);
        ioFilterGroupAdd(ioReadFilterGroup(read), xxHashNew(5));

        ioReadDrain(read);

        TEST_RESULT_STR_Z(
            strNewEncode(encodingHex, pckReadBinP(ioFilterGroupResultP(ioReadFilterGroup(read), XX_HASH_FILTER_TYPE))),
            "1a3e11127b", "check small hash 5");
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
