/***********************************************************************************************************************************
Test Repo Commands
***********************************************************************************************************************************/

#include "command/archive/common.h"
#include "command/backup/common.h"
#include "common/crypto/cipherGcm.h"
#include "common/io/bufferRead.h"
#include "common/io/bufferWrite.h"
#include "storage/posix/storage.h"

#include "harness/config.h"
#include "harness/crypto.h"
#include "harness/info.h"
#include "harness/storageHelper.h"

#include "info/infoArchive.h"
#include "info/infoBackup.h"

/***********************************************************************************************************************************
aes-256-gcm keys: the key of the repository, and the subkeys of the archive, of the manifests and of each backup
***********************************************************************************************************************************/
#define TEST_GCM_LABEL_1                                            "20200101-000000F"
#define TEST_GCM_LABEL_2                                            "20200102-000000F"
#define TEST_GCM_WAL_1                                                                                                             \
    "12-1/0000000100000001/000000010000000100000001-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define TEST_GCM_WAL_2                                                                                                             \
    "12-1/0000000100000001/000000010000000100000002-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define TEST_GCM_FILE_CHECKSUM                                      "184473f470864e067ee3a22e64b47b0a1c356f29"

/***********************************************************************************************************************************
Test Run
***********************************************************************************************************************************/
static void
testRun(void)
{
    FUNCTION_HARNESS_VOID();

    // *****************************************************************************************************************************
    if (testBegin("cmdStorageList() and storageListRender()"))
    {
        hrnStorageHelperRepoShimSet(true);

        StringList *argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawZ(argList, cfgOptOutput, "text");
        hrnCfgArgRawZ(argList, cfgOptSort, "none");
        HRN_CFG_LOAD(cfgCmdRepoLs, argList);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("missing directory");

        Buffer *output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "missing directory (text)");
        TEST_RESULT_STR_Z(strNewBuf(output), "", "check output");

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_JSON_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "missing directory (json)");
        TEST_RESULT_STR_Z(
            strNewBuf(output),
            // {uncrustify_off - indentation}
            "{"
                "\".\":{\"type\":\"path\"}"
            "}\n",
            // {uncrustify_on}
            "check output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("empty directory");

        HRN_STORAGE_PATH_CREATE(storageRepoWrite(), NULL, .mode = 0700);

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "empty directory (text)");
        TEST_RESULT_STR_Z(strNewBuf(output), "", "check output");

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_JSON_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "empty directory (json)");
        TEST_RESULT_STR_Z(
            strNewBuf(output),
            // {uncrustify_off - indentation}
            "{"
                "\".\":{\"type\":\"path\"}"
            "}\n",
            // {uncrustify_on}
            "check output");

        output = bufNew(0);
        cfgOptionSet(cfgOptFilter, cfgSourceParam, VARSTRDEF("\\."));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "empty directory with filter match (json)");
        TEST_RESULT_STR_Z(
            strNewBuf(output),
            // {uncrustify_off - indentation}
            "{"
                "\".\":{\"type\":\"path\"}"
            "}\n",
            // {uncrustify_on}
            "check output");

        output = bufNew(0);
        cfgOptionSet(cfgOptFilter, cfgSourceParam, VARSTRDEF("2$"));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "empty directory with no filter match (json)");
        TEST_RESULT_STR_Z(strNewBuf(output), "{}\n", "check output");

        cfgOptionSet(cfgOptFilter, cfgSourceParam, NULL);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("exact repo path");

        StringList *argListTmp = strLstDup(argList);
        strLstAddZ(argListTmp, TEST_PATH "/repo");
        HRN_CFG_LOAD(cfgCmdRepoLs, argListTmp);

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "empty directory (text)");
        TEST_RESULT_STR_Z(strNewBuf(output), "", "check output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("add path and file");

        cfgOptionSet(cfgOptSort, cfgSourceParam, VARUINT64(CFGOPTVAL_SORT_ASC_STRID));

        HRN_STORAGE_PATH_CREATE(storageRepoWrite(), "bbb");
        HRN_STORAGE_PUT_Z(storageRepoWrite(), "aaa", "TESTDATA", .timeModified = 1578671569);
        HRN_STORAGE_PUT_Z(storageRepoWrite(), "bbb/ccc", "TESTDATA2");

        HRN_SYSTEM("ln -s ../bbb " TEST_PATH "/repo/link");
        HRN_SYSTEM("mkfifo " TEST_PATH "/repo/pipe");

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "path and file (text)");
        TEST_RESULT_STR_Z(strNewBuf(output), "aaa\nbbb\nlink\npipe\n", "check output");

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_JSON_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "path and file (json)");
        TEST_RESULT_STR_Z(
            strNewBuf(output),
            // {uncrustify_off - indentation}
            "{"
                "\".\":{\"type\":\"path\"},"
                "\"aaa\":{\"type\":\"file\",\"size\":8,\"time\":1578671569},"
                "\"bbb\":{\"type\":\"path\"},"
                "\"link\":{\"type\":\"link\",\"destination\":\"../bbb\"},"
                "\"pipe\":{\"type\":\"special\"}"
            "}\n",
            // {uncrustify_on}
            "check output");

        HRN_SYSTEM("rm -f " TEST_PATH "/repo/link " TEST_PATH "/repo/pipe");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("reverse sort");

        cfgOptionSet(cfgOptSort, cfgSourceParam, VARUINT64(CFGOPTVAL_SORT_DESC_STRID));

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "path and file (text)");
        TEST_RESULT_STR_Z(strNewBuf(output), "bbb\naaa\n", "check output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("recurse");

        cfgOptionSet(cfgOptRecurse, cfgSourceParam, BOOL_TRUE_VAR);

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "filter");
        TEST_RESULT_STR_Z(strNewBuf(output), "bbb/ccc\nbbb\naaa\n", "check output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("filter");

        cfgOptionSet(cfgOptFilter, cfgSourceParam, VARSTRDEF("^aaa$"));

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "filter");
        TEST_RESULT_STR_Z(strNewBuf(output), "aaa\n", "check output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error on /");

        argListTmp = strLstDup(argList);
        strLstAddZ(argListTmp, "/");
        HRN_CFG_LOAD(cfgCmdRepoLs, argListTmp);

        TEST_ERROR(
            storageListRender(ioBufferWriteNew(output)), ParamInvalidError,
            "absolute path '/' is not in base path '" TEST_PATH "/repo'");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error on path that starts with repo path");

        argListTmp = strLstDup(argList);
        strLstAddZ(argListTmp, TEST_PATH "/reposub");
        HRN_CFG_LOAD(cfgCmdRepoLs, argListTmp);

        TEST_ERROR(
            storageListRender(ioBufferWriteNew(output)), ParamInvalidError,
            "absolute path '" TEST_PATH "/reposub' is not in base path '" TEST_PATH "/repo'");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error on //");

        argListTmp = strLstDup(argList);
        strLstAddZ(argListTmp, "bbb//");
        HRN_CFG_LOAD(cfgCmdRepoLs, argListTmp);

        TEST_ERROR(
            storageListRender(ioBufferWriteNew(output)), ParamInvalidError, "path 'bbb//' cannot contain //");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("subdirectory");

        argListTmp = strLstDup(argList);
        strLstAddZ(argListTmp, "bbb");
        HRN_CFG_LOAD(cfgCmdRepoLs, argListTmp);

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "subdirectory");
        TEST_RESULT_STR_Z(strNewBuf(output), "ccc\n", "check output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("subdirectory with /");

        argListTmp = strLstDup(argList);
        strLstAddZ(argListTmp, "bbb/");
        HRN_CFG_LOAD(cfgCmdRepoLs, argListTmp);

        output = bufNew(0);
        cfgOptionSet(cfgOptOutput, cfgSourceParam, VARUINT64(CFGOPTVAL_OUTPUT_TEXT_STRID));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "subdirectory");
        TEST_RESULT_STR_Z(strNewBuf(output), "ccc\n", "check output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("redirect stdout to a file");

        int stdoutSave = dup(STDOUT_FILENO);

        THROW_ON_SYS_ERROR(freopen(TEST_PATH "/stdout.txt", "w", stdout) == NULL, FileWriteError, "unable to reopen stdout");

        // Not in a test wrapper to avoid writing to stdout
        cmdStorageList();

        // Close the fd to make sure the error gets caught
        close(STDOUT_FILENO);

        // Not in a test wrapper to avoid writing to stdout
        cmdStorageList();

        // Restore normal stdout
        dup2(stdoutSave, STDOUT_FILENO);

        TEST_STORAGE_GET(storagePosixNewP(TEST_PATH_STR), "stdout.txt", "ccc\n", .comment = "check text");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("too many paths");

        strLstAddZ(argListTmp, "ccc");
        HRN_CFG_LOAD(cfgCmdRepoLs, argListTmp);

        TEST_ERROR(storageListRender(ioBufferWriteNew(output)), ParamInvalidError, "only one path may be specified");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("file info - json");

        argList = strLstNew();
        hrnCfgArgKeyRawZ(argList, cfgOptRepoPath, 1, TEST_PATH "/bogus");
        hrnCfgArgKeyRawZ(argList, cfgOptRepoPath, 2, TEST_PATH "/repo/aaa");
        hrnCfgArgRawZ(argList, cfgOptRepo, "2");
        hrnCfgArgRawZ(argList, cfgOptOutput, "json");
        HRN_CFG_LOAD(cfgCmdRepoLs, argList);

        output = bufNew(0);
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "file (json)");
        TEST_RESULT_STR_Z(
            strNewBuf(output),
            // {uncrustify_off - indentation}
            "{"
                "\".\":{\"type\":\"file\",\"size\":8,\"time\":1578671569}"
            "}\n",
            // {uncrustify_on}
            "check output");

        output = bufNew(0);
        cfgOptionSet(cfgOptFilter, cfgSourceParam, VARSTRDEF("\\/aaa$"));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "file (json)");
        TEST_RESULT_STR_Z(
            strNewBuf(output),
            // {uncrustify_off - indentation}
            "{"
                "\".\":{\"type\":\"file\",\"size\":8,\"time\":1578671569}"
            "}\n",
            // {uncrustify_on}
            "check output");

        output = bufNew(0);
        cfgOptionSet(cfgOptFilter, cfgSourceParam, VARSTRDEF("bbb$"));
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "file (json)");
        TEST_RESULT_STR_Z(strNewBuf(output), "{}\n", "check output");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("target time");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawZ(argList, cfgOptOutput, "json");
        hrnCfgArgRawZ(argList, cfgOptRepo, "1");
        hrnCfgArgRawZ(argList, cfgOptRepoTargetTime, "2024-08-04 02:54:09+00");
        HRN_CFG_LOAD(cfgCmdRepoLs, argList);

        output = bufNew(0);
        TEST_RESULT_VOID(storageListRender(ioBufferWriteNew(output)), "file (json)");
        TEST_RESULT_STR_Z(
            strNewBuf(output),
            // {uncrustify_off - indentation}
            "{"
                "\".\":{\"type\":\"path\"},"
                "\"aaa\":{\"type\":\"file\",\"size\":8,\"time\":1578671569,\"version\":\"v0001\"},"
                "\"bbb\":{\"type\":\"path\"}"
            "}\n",
            // {uncrustify_on}
            "check output");

        hrnStorageHelperRepoShimSet(false);
    }

    // *****************************************************************************************************************************
    if (testBegin("cmdStorageGet()"))
    {
        // Set buffer size small so copy loops get exercised
        size_t oldBufferSize = ioBufferSize();
        ioBufferSizeSet(8);

        // Needed for tests
        hrnCfgEnvKeyRawZ(cfgOptRepoCipherPass, 1, TEST_CIPHER_PASS);
        hrnCfgEnvKeyRawZ(cfgOptRepoCipherPass, 2, TEST_CIPHER_PASS);

        // Test files and buffers
        const String *fileName = STRDEF("file.txt");
        const Buffer *fileBuffer = BUFSTRDEF("TESTFILE");

        const String *fileRawName = STRDEF("file-raw.txt");
        const char *fileRawContent = "TESTFILE-RAW";

        const Buffer *archiveInfoFileBuffer = BUFSTRDEF(
            "[cipher]\n"
            "cipher-pass=\"custom\"\n"
            "\n"
            "[db]\n"
            "db-id=1\n"
            "db-system-id=6846378200844646865\n"
            "db-version=\"12\"\n"
            "\n"
            "[db:history]\n"
            "1={\"db-id\":6846378200844646865,\"db-version\":\"12\"}\n"
            "\n"
            "[backrest]\n"
            "backrest-checksum=\"9d37594e0e77ff16024abd2224b75dfc0323c864\"\n"
            "backrest-format=5\n");

        const Buffer *backupInfoFileBuffer = BUFSTRDEF(
            "[cipher]\n"
            "cipher-pass=\"custom\"\n"
            "\n"
            "[db]\n"
            "db-catalog-version=201909212\n"
            "db-control-version=1201\n"
            "db-id=1\n"
            "db-system-id=6846378200844646865\n"
            "db-version=\"12\"\n"
            "\n"
            "[db:history]\n"
            "1={\"db-catalog-version\":201909212,\"db-control-version\":1201,\"db-system-id\":6846378200844646865"
            ",\"db-version\":\"12\"}\n"
            "\n"
            "[backrest]\n"
            "backrest-checksum=\"8e22e1574dbec45405c5ddca389e3ae6c6dd6e3c\"\n"
            "backrest-format=5\n");

        const Buffer *manifestFileBuffer = BUFSTRDEF(
            "[cipher]\n"
            "cipher-pass=\"custom2\"\n"
            "\n"
            "[backup:db]\n"
            "db-catalog-version=201909212\n"
            "db-control-version=1201\n"
            "db-id=1\n"
            "db-system-id=6846378200844646865\n"
            "db-version=\"12\"\n"
            "\n"
            "[backup:target]\n"
            "pg_data={\"path\":\"/var/lib/pgsql/12/data\",\"type\":\"path\"}\n"
            "\n"
            "[backrest]\n"
            "backrest-checksum=\"ec7b178fd6d568bf592f16c36329ef6b533a2232\"\n"
            "backrest-format=5\n");

        const Buffer *backupLabelBuffer = BUFSTRDEF("BACKUP-LABEL");

        // Create WAL segment. Keep it small since encryption/decryption takes time (esp on 32-bit).
        Buffer *archiveFileBuffer = bufNew(1024);
        memset(bufPtr(archiveFileBuffer), 0, bufSize(archiveFileBuffer));
        bufUsedSet(archiveFileBuffer, bufSize(archiveFileBuffer));

        // Build a repository for the get tests. Each file is encrypted with the passphrase that opens it, i.e. the repo
        // passphrase for the info files and the sub passphrase named in the file above it for everything else.
        Storage *const storageFixture = storagePosixNewP(STRDEF(TEST_PATH "/repo"), .write = true);

        HRN_STORAGE_PUT(storageFixture, strZ(fileName), fileBuffer);
        HRN_STORAGE_PUT_Z(storageFixture, strZ(fileRawName), fileRawContent);
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_ARCHIVE "/test/" INFO_ARCHIVE_FILE, archiveInfoFileBuffer, .cipherSpec = TEST_CIPHER_SPEC);
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_ARCHIVE "/test/" INFO_ARCHIVE_FILE ".copy", archiveInfoFileBuffer,
            .cipherSpec = TEST_CIPHER_SPEC);
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_BACKUP "/test/" INFO_BACKUP_FILE, backupInfoFileBuffer, .cipherSpec = TEST_CIPHER_SPEC);
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_BACKUP "/test/" INFO_BACKUP_FILE ".copy", backupInfoFileBuffer,
            .cipherSpec = TEST_CIPHER_SPEC);
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_ARCHIVE "/test/12-1/000000010000000100000001-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            archiveFileBuffer, .cipherSpec = TEST_CIPHER_SPEC_PASS("custom"));
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_BACKUP "/test/latest/" BACKUP_MANIFEST_FILE, manifestFileBuffer,
            .cipherSpec = TEST_CIPHER_SPEC_PASS("custom"));
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_BACKUP "/test/latest/" BACKUP_MANIFEST_FILE ".copy", manifestFileBuffer,
            .cipherSpec = TEST_CIPHER_SPEC_PASS("custom"));
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_BACKUP "/test/backup.history/2020/label.manifest.gz", manifestFileBuffer,
            .cipherSpec = TEST_CIPHER_SPEC_PASS("custom"));
        HRN_STORAGE_PUT(
            storageFixture, STORAGE_PATH_BACKUP "/test/latest/pg_data/backup_label", backupLabelBuffer,
            .cipherSpec = TEST_CIPHER_SPEC_PASS("custom2"));

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error when missing source");

        StringList *argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        TEST_ERROR(storageGetProcess(ioBufferWriteNew(bufNew(0))), ParamRequiredError, "source file required");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get a file");

        strLstAdd(argList, fileName);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        Buffer *writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, fileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get a file with / repo");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, "/");
        strLstAddFmt(argList, TEST_PATH "/repo/%s", strZ(fileName));
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, fileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get a raw file");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        hrnCfgArgRawBool(argList, cfgOptRaw, true);
        strLstAdd(argList, fileRawName);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        TEST_LOG("get");

        // Redirect stdout to a file
        int stdoutSave = dup(STDOUT_FILENO);

        THROW_ON_SYS_ERROR(freopen(TEST_PATH "/repo/stdout.txt", "w", stdout) == NULL, FileWriteError, "unable to reopen stdout");

        // Not in a test wrapper to avoid writing to stdout
        ASSERT(cmdStorageGet() == 0);

        // Close the fd to make sure the error gets caught
        close(STDOUT_FILENO);

        // Not in a test wrapper to avoid writing to stdout
        ASSERT(cmdStorageGet() == 1);

        // Restore normal stdout
        dup2(stdoutSave, STDOUT_FILENO);

        TEST_STORAGE_GET(storageRepo(), "stdout.txt", fileRawContent, .comment = "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("ignore missing file");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawBool(argList, cfgOptIgnoreMissing, true);
        strLstAddZ(argList, BOGUS_STR);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(bufNew(0))), 1, "get");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get file outside of the repo error");

        argList = strLstNew();
        hrnCfgArgKeyRawZ(argList, cfgOptRepoPath, 1, TEST_PATH "/bogus");
        hrnCfgArgKeyRawZ(argList, cfgOptRepoPath, 2, TEST_PATH "/repo");
        hrnCfgArgRawZ(argList, cfgOptRepo, "2");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, "/somewhere/" INFO_ARCHIVE_FILE);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_ERROR(
            storageGetProcess(ioBufferWriteNew(writeBuffer)), ParamInvalidError,
            "absolute path '/somewhere/" INFO_ARCHIVE_FILE "' is not in base path '" TEST_PATH "/repo'");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get file in repo root directory error");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAdd(argList, fileName);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_ERROR(
            storageGetProcess(ioBufferWriteNew(writeBuffer)), OptionInvalidValueError,
            zNewFmt("unable to determine cipher passphrase for '%s'", strZ(fileName)));

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted archive.info - stanza mismatch");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawZ(argList, cfgOptStanza, "test2");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_ARCHIVE "/test/" INFO_ARCHIVE_FILE);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_ERROR(
            storageGetProcess(ioBufferWriteNew(writeBuffer)), OptionInvalidValueError,
            "stanza name 'test2' given in option doesn't match the given path");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted archive.info");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_ARCHIVE "/test/" INFO_ARCHIVE_FILE);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, archiveInfoFileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted archive.info.copy");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawZ(argList, cfgOptStanza, "test");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_ARCHIVE "/test/" INFO_ARCHIVE_FILE ".copy");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, archiveInfoFileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted backup.info");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/" INFO_BACKUP_FILE);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, backupInfoFileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted backup.info.copy");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/" INFO_BACKUP_FILE ".copy");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, backupInfoFileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted WAL file");

        // Set higher buffer size for the WAL archive tests
        ioBufferSizeSet(oldBufferSize);

        TEST_TITLE("get encrypted WAL archive file");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddFmt(
            argList, "%s/repo/" STORAGE_PATH_ARCHIVE "/test/12-1/000000010000000100000001-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            TEST_PATH);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, archiveFileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted backup.manifest");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/latest/" BACKUP_MANIFEST_FILE);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, manifestFileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted backup.manifest.copy");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/latest/" BACKUP_MANIFEST_FILE ".copy");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, manifestFileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted backup.history manifest");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/backup.history/2020/label.manifest.gz");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, manifestFileBuffer), true, "get matches put");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("get encrypted backup_label");

        argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        hrnCfgArgRawStrId(argList, cfgOptRepoCipherType, cipherTypeAes256Cbc);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/latest/pg_data/backup_label");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        writeBuffer = bufNew(0);
        TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, "get");
        TEST_RESULT_BOOL(bufEq(writeBuffer, backupLabelBuffer), true, "get matches put");

#ifdef CIPHER_GCM_SUPPORTED
        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("aes-256-gcm repository");

        // Each file is bound to the identity its place in the repository gives it, with the stanza from the path, so no stanza
        // option is given below
        hrnCfgEnvKeyRawZ(cfgOptRepoCipherPass, 1, TEST_CIPHER_KEY);

        const Storage *const storageGcm = storagePosixNewP(STRDEF(TEST_PATH "/repo-enc"), .write = true);
        const CipherSpec *const cipherSpecGcm = cipherSpecNewP(
            cipherTypeAes256Gcm, BUFSTRDEF(TEST_CIPHER_KEY), .stanza = STRDEF("test"));
        const CipherSpec *const cipherSpecGcmArchive = cipherSpecNewP(
            cipherTypeAes256Gcm, BUFSTRDEF(TEST_CIPHER_KEY_ARCHIVE), .stanza = STRDEF("test"));
        const CipherSpec *const cipherSpecGcmManifest = cipherSpecNewP(
            cipherTypeAes256Gcm, BUFSTRDEF(TEST_CIPHER_KEY_MANIFEST), .stanza = STRDEF("test"));
        const CipherSpec *const cipherSpecGcmBackup = cipherSpecNewP(
            cipherTypeAes256Gcm, BUFSTRDEF(TEST_CIPHER_KEY_BACKUP), .stanza = STRDEF("test"));

        const char *const archiveInfoGcm =
            "[cipher]\n"
            "cipher-pass=\"" TEST_CIPHER_KEY_ARCHIVE "\"\n"
            "cipher-type=\"aes-256-gcm\"\n"
            "\n"
            "[db]\n"
            "db-id=1\n"
            "\n"
            "[db:history]\n"
            "1={\"db-id\":6846378200844646865,\"db-version\":\"12\"}\n";
        const char *const backupInfoGcm =
            "[cipher]\n"
            "cipher-pass=\"" TEST_CIPHER_KEY_MANIFEST "\"\n"
            "cipher-type=\"aes-256-gcm\"\n"
            "\n"
            "[db]\n"
            "db-catalog-version=201909212\n"
            "db-control-version=1201\n"
            "db-id=1\n"
            "db-system-id=6846378200844646865\n"
            "db-version=\"12\"\n"
            "\n"
            "[db:history]\n"
            "1={\"db-catalog-version\":201909212,\"db-control-version\":1201,\"db-system-id\":6846378200844646865"
            ",\"db-version\":\"12\"}\n";

        // Backup 1 is not compressed. It has a file with the name of a manifest, a block incremental file, and files whose names
        // end with the extension of a block incremental file.
        const char *const manifestGcm1 =
            "[cipher]\n"
            "cipher-pass=\"" TEST_CIPHER_KEY_BACKUP "\"\n"
            "cipher-type=\"aes-256-gcm\"\n"
            "\n"
            "[backup:db]\n"
            "db-catalog-version=201909212\n"
            "db-control-version=1201\n"
            "db-id=1\n"
            "db-system-id=6846378200844646865\n"
            "db-version=\"12\"\n"
            "\n"
            "[backup:option]\n"
            "option-compress-type=\"none\"\n"
            "\n"
            "[backup:target]\n"
            "pg_data={\"path\":\"/var/lib/pgsql/12/data\",\"type\":\"path\"}\n"
            "\n"
            "[target:file]\n"
            "pg_data/backup.manifest={\"checksum\":\"" TEST_GCM_FILE_CHECKSUM "\",\"size\":4,\"timestamp\":1565282114}\n"
            "pg_data/base/1/2={\"bi\":1,\"bim\":31,\"checksum\":\"" TEST_GCM_FILE_CHECKSUM "\",\"size\":8192"
            ",\"timestamp\":1565282114}\n"
            "pg_data/base/1/3={\"checksum\":\"" TEST_GCM_FILE_CHECKSUM "\",\"size\":4,\"timestamp\":1565282114}\n"
            "pg_data/base/1/3.pgbi={\"checksum\":\"" TEST_GCM_FILE_CHECKSUM "\",\"size\":4,\"timestamp\":1565282114}\n"
            "pg_data/base/1/4.pgbi={\"checksum\":\"" TEST_GCM_FILE_CHECKSUM "\",\"size\":4,\"timestamp\":1565282114}\n"
            "\n"
            "[target:file:default]\n"
            "group=\"group1\"\n"
            "mode=\"0600\"\n"
            "user=\"user1\"\n";

        // Backup 2 is compressed with gz
        const char *const manifestGcm2 =
            "[cipher]\n"
            "cipher-pass=\"" TEST_CIPHER_KEY_BACKUP "\"\n"
            "cipher-type=\"aes-256-gcm\"\n"
            "\n"
            "[backup:db]\n"
            "db-catalog-version=201909212\n"
            "db-control-version=1201\n"
            "db-id=1\n"
            "db-system-id=6846378200844646865\n"
            "db-version=\"12\"\n"
            "\n"
            "[backup:option]\n"
            "option-compress-type=\"gz\"\n"
            "\n"
            "[backup:target]\n"
            "pg_data={\"path\":\"/var/lib/pgsql/12/data\",\"type\":\"path\"}\n"
            "\n"
            "[target:file]\n"
            "pg_data/PG_VERSION={\"checksum\":\"" TEST_GCM_FILE_CHECKSUM "\",\"size\":4,\"timestamp\":1565282114}\n"
            "pg_data/base/1/3.pgbi={\"checksum\":\"" TEST_GCM_FILE_CHECKSUM "\",\"size\":4,\"timestamp\":1565282114}\n"
            "pg_data/base/1/5={\"checksum\":\"" TEST_GCM_FILE_CHECKSUM "\",\"reference\":\"" TEST_GCM_LABEL_1 "\",\"size\":4"
            ",\"timestamp\":1565282114}\n"
            "\n"
            "[target:file:default]\n"
            "group=\"group1\"\n"
            "mode=\"0600\"\n"
            "user=\"user1\"\n";

        const Buffer *const fileGcm = BUFSTRDEF("GCMFILE");

        HRN_INFO_PUT(storageGcm, STORAGE_PATH_ARCHIVE "/test/" INFO_ARCHIVE_FILE, archiveInfoGcm, .cipherSpec = cipherSpecGcm);
        HRN_INFO_PUT(storageGcm, STORAGE_PATH_BACKUP "/test/" INFO_BACKUP_FILE, backupInfoGcm, .cipherSpec = cipherSpecGcm);
        HRN_INFO_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" INFO_BACKUP_FILE INFO_COPY_EXT, backupInfoGcm, .cipherSpec = cipherSpecGcm);
        HRN_INFO_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/" BACKUP_MANIFEST_FILE, manifestGcm1,
            .cipherSpec = cipherSpecGcmManifest);
        HRN_INFO_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/" BACKUP_MANIFEST_FILE INFO_COPY_EXT, manifestGcm1,
            .cipherSpec = cipherSpecGcmManifest);
        HRN_INFO_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/" BACKUP_MANIFEST_FILE, manifestGcm2,
            .cipherSpec = cipherSpecGcmManifest);

        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_ARCHIVE "/test/" TEST_GCM_WAL_1, fileGcm, .cipherSpec = cipherSpecGcmArchive,
            .cipherIdentity = HRN_CIPHER_IDENTITY("archive|" TEST_GCM_WAL_1));
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_ARCHIVE "/test/" TEST_GCM_WAL_2, fileGcm, .cipherSpec = cipherSpecGcmArchive,
            .cipherIdentity = HRN_CIPHER_IDENTITY("archive|" TEST_GCM_WAL_1), .comment = "segment 1 stored as segment 2");
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" BACKUP_PATH_HISTORY "/2020/" TEST_GCM_LABEL_1 ".manifest.gz", fileGcm,
            .cipherSpec = cipherSpecGcmManifest, .cipherIdentity = HRN_CIPHER_IDENTITY("manifest-history|" TEST_GCM_LABEL_1));
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/pg_data/backup.manifest", fileGcm,
            .cipherSpec = cipherSpecGcmBackup,
            .cipherIdentity = HRN_CIPHER_IDENTITY("file|" TEST_GCM_LABEL_1 "|pg_data/backup.manifest"));
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/pg_data/base/1/3.pgbi", fileGcm,
            .cipherSpec = cipherSpecGcmBackup,
            .cipherIdentity = HRN_CIPHER_IDENTITY("file|" TEST_GCM_LABEL_1 "|pg_data/base/1/3.pgbi"));
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/pg_data/base/1/4.pgbi", fileGcm,
            .cipherSpec = cipherSpecGcmBackup,
            .cipherIdentity = HRN_CIPHER_IDENTITY("file|" TEST_GCM_LABEL_1 "|pg_data/base/1/3.pgbi"),
            .comment = "3.pgbi stored as 4.pgbi");
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/pg_data/PG_VERSION.gz", fileGcm,
            .cipherSpec = cipherSpecGcmBackup,
            .cipherIdentity = HRN_CIPHER_IDENTITY("file|" TEST_GCM_LABEL_2 "|pg_data/PG_VERSION"));
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/pg_data/base/1/3.pgbi.gz", fileGcm,
            .cipherSpec = cipherSpecGcmBackup,
            .cipherIdentity = HRN_CIPHER_IDENTITY("file|" TEST_GCM_LABEL_1 "|pg_data/base/1/3.pgbi"),
            .comment = "backup 1 file stored in backup 2");
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/pg_data/base/1/5.gz", fileGcm,
            .cipherSpec = cipherSpecGcmBackup, .cipherIdentity = HRN_CIPHER_IDENTITY("file|" TEST_GCM_LABEL_1 "|pg_data/base/1/5"),
            .comment = "backup 1 file hard linked into backup 2");

        StringList *const argListGcm = strLstNew();
        hrnCfgArgRawZ(argListGcm, cfgOptRepoPath, TEST_PATH "/repo-enc");
        hrnCfgArgRawStrId(argListGcm, cfgOptRepoCipherType, cipherTypeAes256Gcm);

        // Each file the path of which is given gets the content that was put
        const char *const fileGcmList[] =
        {
            STORAGE_PATH_ARCHIVE "/test/" TEST_GCM_WAL_1,
            STORAGE_PATH_BACKUP "/test/" BACKUP_PATH_HISTORY "/2020/" TEST_GCM_LABEL_1 ".manifest.gz",
            STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/pg_data/backup.manifest",
            STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/pg_data/base/1/3.pgbi",
            STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/pg_data/PG_VERSION.gz",
            STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/pg_data/base/1/5.gz",
        };

        for (unsigned int fileIdx = 0; fileIdx < LENGTH_OF(fileGcmList); fileIdx++)
        {
            argList = strLstDup(argListGcm);
            hrnCfgArgRawZ(argList, cfgOptStanza, "test");
            strLstAddZ(argList, fileGcmList[fileIdx]);
            HRN_CFG_LOAD(cfgCmdRepoGet, argList);

            writeBuffer = bufNew(0);
            TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, zNewFmt("get %s", fileGcmList[fileIdx]));
            TEST_RESULT_BOOL(bufEq(writeBuffer, fileGcm), true, "get matches put");
        }

        // Each info file and manifest gets its content, with its checksum
        const char *const infoGcmList[][2] =
        {
            {STORAGE_PATH_ARCHIVE "/test/" INFO_ARCHIVE_FILE, archiveInfoGcm},
            {STORAGE_PATH_BACKUP "/test/" INFO_BACKUP_FILE, backupInfoGcm},
            {STORAGE_PATH_BACKUP "/test/" INFO_BACKUP_FILE INFO_COPY_EXT, backupInfoGcm},
            {STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/" BACKUP_MANIFEST_FILE, manifestGcm1},
            {STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/" BACKUP_MANIFEST_FILE INFO_COPY_EXT, manifestGcm1},
        };

        for (unsigned int infoIdx = 0; infoIdx < LENGTH_OF(infoGcmList); infoIdx++)
        {
            argList = strLstDup(argListGcm);
            strLstAddZ(argList, infoGcmList[infoIdx][0]);
            HRN_CFG_LOAD(cfgCmdRepoGet, argList);

            writeBuffer = bufNew(0);
            TEST_RESULT_INT(storageGetProcess(ioBufferWriteNew(writeBuffer)), 0, zNewFmt("get %s", infoGcmList[infoIdx][0]));
            TEST_RESULT_BOOL(
                bufEq(writeBuffer, harnessInfoChecksumFormat(REPOSITORY_FORMAT_7, STR(infoGcmList[infoIdx][1]))), true,
                "get matches put");
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("aes-256-gcm file under another identity");

        // Each file was put under the identity of another file: archive.info of stanza test in the path of stanza other, and the
        // final manifest of backup 1 as the in-progress copy of backup 2
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_ARCHIVE "/other/" INFO_ARCHIVE_FILE,
            storageGetP(storageNewReadP(storageGcm, STRDEF(STORAGE_PATH_ARCHIVE "/test/" INFO_ARCHIVE_FILE))));
        HRN_STORAGE_PUT(
            storageGcm, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/" BACKUP_MANIFEST_FILE INFO_COPY_EXT,
            storageGetP(
                storageNewReadP(storageGcm, STRDEF(STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/" BACKUP_MANIFEST_FILE))));

        const char *const fileGcmSwapList[] =
        {
            STORAGE_PATH_ARCHIVE "/other/" INFO_ARCHIVE_FILE,
            STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/" BACKUP_MANIFEST_FILE INFO_COPY_EXT,
            STORAGE_PATH_ARCHIVE "/test/" TEST_GCM_WAL_2,
            STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/pg_data/base/1/4.pgbi",
            STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/pg_data/base/1/3.pgbi.gz",
        };

        for (unsigned int fileIdx = 0; fileIdx < LENGTH_OF(fileGcmSwapList); fileIdx++)
        {
            argList = strLstDup(argListGcm);
            strLstAddZ(argList, fileGcmSwapList[fileIdx]);
            HRN_CFG_LOAD(cfgCmdRepoGet, argList);

            TEST_ERROR(
                storageGetProcess(ioBufferWriteNew(bufNew(0))), CryptoError, "cipher segment 0 failed authentication");
        }

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("aes-256-gcm file that cannot be fetched alone");

        argList = strLstDup(argListGcm);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/latest/" BACKUP_MANIFEST_FILE);
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        TEST_ERROR(
            storageGetProcess(ioBufferWriteNew(bufNew(0))), OptionInvalidValueError,
            "unable to determine cipher identity for '" STORAGE_PATH_BACKUP "/test/latest/" BACKUP_MANIFEST_FILE "'\n"
            "HINT: a backup encrypted with aes-256-gcm is bound to its label, so give the label rather than 'latest'.");

        argList = strLstDup(argListGcm);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/bundle/1");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        TEST_ERROR(
            storageGetProcess(ioBufferWriteNew(bufNew(0))), OptionInvalidValueError,
            "unable to determine cipher identity for '" STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/bundle/1'\n"
            "HINT: a bundle holds each of its files as a stream of its own, so it cannot be fetched alone.");

        argList = strLstDup(argListGcm);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/pg_data/base/1/2.pgbi");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        TEST_ERROR(
            storageGetProcess(ioBufferWriteNew(bufNew(0))), OptionInvalidValueError,
            "unable to determine cipher identity for '" STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/pg_data/base/1/2.pgbi'\n"
            "HINT: a block incremental file holds each of its super blocks and its map as a stream of its own, so it cannot be"
            " fetched alone.");

        argList = strLstDup(argListGcm);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/backup_label");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        TEST_ERROR(
            storageGetProcess(ioBufferWriteNew(bufNew(0))), OptionInvalidValueError,
            "unable to determine cipher identity for '" STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_1 "/backup_label'\n"
            "HINT: a file of a backup is stored in a path of the backup, e.g. pg_data.");

        argList = strLstDup(argListGcm);
        strLstAddZ(argList, STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/pg_data/base/1/6.gz");
        HRN_CFG_LOAD(cfgCmdRepoGet, argList);

        TEST_ERROR(
            storageGetProcess(ioBufferWriteNew(bufNew(0))), OptionInvalidValueError,
            "unable to determine cipher identity for '" STORAGE_PATH_BACKUP "/test/" TEST_GCM_LABEL_2 "/pg_data/base/1/6.gz'\n"
            "HINT: the file is not in the manifest of its backup.");
#endif

        // -------------------------------------------------------------------------------------------------------------------------
        // Reset env
        hrnCfgEnvKeyRemoveRaw(cfgOptRepoCipherPass, 1);
        hrnCfgEnvKeyRemoveRaw(cfgOptRepoCipherPass, 2);

        // Reset buffer size
        ioBufferSizeSet(oldBufferSize);
    }

    // *****************************************************************************************************************************
    if (testBegin("cmdStorageRemove()"))
    {
        StringList *argList = strLstNew();
        hrnCfgArgRawZ(argList, cfgOptRepoPath, TEST_PATH "/repo");
        HRN_CFG_LOAD(cfgCmdRepoRm, argList);

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("remove missing path");

        TEST_RESULT_VOID(cmdStorageRemove(), "remove");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("remove empty path");

        strLstAddZ(argList, "path");
        HRN_CFG_LOAD(cfgCmdRepoRm, argList);

        HRN_STORAGE_PATH_CREATE(storageRepoWrite(), "path", .comment = "add path");
        TEST_RESULT_VOID(cmdStorageRemove(), "remove path");
        TEST_STORAGE_LIST_EMPTY(storageRepo(), NULL, .comment = "check path removed");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("fail when path is not empty and no recurse");

        HRN_STORAGE_PUT_Z(storageRepoWrite(), "path/aaa.txt", "TESTDATA", .comment = "add path/file");
        TEST_ERROR(cmdStorageRemove(), OptionInvalidError, "recurse option must be used to delete non-empty path");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("succeed when path is not empty and no recurse");

        cfgOptionSet(cfgOptRecurse, cfgSourceParam, BOOL_TRUE_VAR);
        TEST_RESULT_VOID(cmdStorageRemove(), "remove path");
        TEST_STORAGE_LIST_EMPTY(storageRepo(), NULL, .comment = "check path removed");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("error on more than one path");

        strLstAddZ(argList, "repo2");
        HRN_CFG_LOAD(cfgCmdRepoRm, argList);

        TEST_ERROR(cmdStorageRemove(), ParamInvalidError, "only one path may be specified");

        // -------------------------------------------------------------------------------------------------------------------------
        TEST_TITLE("remove file");

        argList = strLstNew();
        hrnCfgArgKeyRawZ(argList, cfgOptRepoPath, 1, TEST_PATH "/bogus");
        hrnCfgArgKeyRawZ(argList, cfgOptRepoPath, 2, TEST_PATH "/repo");
        hrnCfgArgRawZ(argList, cfgOptRepo, "2");
        strLstAddZ(argList, "path/aaa.txt");
        HRN_CFG_LOAD(cfgCmdRepoRm, argList);

        HRN_STORAGE_PUT_Z(storageRepoWrite(), "path/aaa.txt", "TESTDATA", .comment = "add path/file");
        TEST_RESULT_VOID(cmdStorageRemove(), "remove file");
        TEST_STORAGE_LIST(storageRepo(), NULL, "path/\n", .comment = "check path exists and file removed");
    }

    FUNCTION_HARNESS_RETURN_VOID();
}
