/***********************************************************************************************************************************
Repository Get Command
***********************************************************************************************************************************/
#include <build.h>

#include <unistd.h>

#include "command/archive/common.h"
#include "command/backup/common.h"
#include "command/repo/common.h"
#include "command/repo/get.h"
#include "common/compress/helper.h"
#include "common/debug.h"
#include "common/format/cipherFormat.h"
#include "common/io/fdWrite.h"
#include "common/io/io.h"
#include "common/log.h"
#include "common/memContext.h"
#include "config/config.h"
#include "storage/helper.h"

#include "info/info.h"
#include "info/infoArchive.h"
#include "info/infoBackup.h"

/***********************************************************************************************************************************
Is the file a named file of the repository, e.g. archive.info, or its copy? The block cipher matches the end of the path. A file
encrypted with aes-256-gcm is bound to its place in the repository, so only the file at that place, i.e. at the given depth of the
path, is taken for it and a file of the same name in a backup is not.
***********************************************************************************************************************************/
static bool
storageGetFileIs(
    const String *const file, const StringList *const filePathSplitLst, const bool cipherGcm, const unsigned int depth,
    const char *const name)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, file);
        FUNCTION_TEST_PARAM(STRING_LIST, filePathSplitLst);
        FUNCTION_TEST_PARAM(BOOL, cipherGcm);
        FUNCTION_TEST_PARAM(UINT, depth);
        FUNCTION_TEST_PARAM(STRINGZ, name);
    FUNCTION_TEST_END();

    bool result = false;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        const String *const nameCopy = strNewFmt("%s" INFO_COPY_EXT, name);

        if (!cipherGcm)
            result = strEndsWithZ(file, name) || strEndsWith(file, nameCopy);
        else if (strLstSize(filePathSplitLst) == depth)
        {
            const String *const fileName = strLstGet(filePathSplitLst, depth - 1);

            result = strEqZ(fileName, name) || strEq(fileName, nameCopy);
        }
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(BOOL, result);
}

/***********************************************************************************************************************************
The identity a file of a backup encrypted with aes-256-gcm is bound to, i.e. the label and the name of the file in the manifest,
worked out from the path. A bundle and a block incremental file each hold more than one stream, so they cannot be fetched alone.
***********************************************************************************************************************************/
static StringList *
storageGetBackupFileCipherIdentity(
    const String *const file, const StringList *const filePathSplitLst, const String *const stanzaFile,
    const Manifest *const manifest)
{
    FUNCTION_TEST_BEGIN();
        FUNCTION_TEST_PARAM(STRING, file);
        FUNCTION_TEST_PARAM(STRING_LIST, filePathSplitLst);
        FUNCTION_TEST_PARAM(STRING, stanzaFile);
        FUNCTION_TEST_PARAM(MANIFEST, manifest);
    FUNCTION_TEST_END();

    StringList *result;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        // A file of a backup is stored in a path of the backup, e.g. pg_data, and a bundle in the bundle path
        if (strLstSize(filePathSplitLst) < 5)
        {
            THROW_FMT(
                OptionInvalidValueError,
                "unable to determine cipher identity for '%s'\n"
                "HINT: a file of a backup is stored in a path of the backup, e.g. pg_data.",
                strZ(file));
        }

        // The label, and the name of the file in the path of the backup
        const String *const backupLabel = strLstGet(filePathSplitLst, 2);
        const String *const repoName = strSub(stanzaFile, strSize(backupLabel) + 1);

        if (strEqZ(strLstGet(filePathSplitLst, 3), MANIFEST_PATH_BUNDLE))
        {
            THROW_FMT(
                OptionInvalidValueError,
                "unable to determine cipher identity for '%s'\n"
                "HINT: a bundle holds each of its files as a stream of its own, so it cannot be fetched alone.",
                strZ(file));
        }

        // A block incremental file is stored under its name and an extension of its own, whatever the compression
        if (strEndsWithZ(repoName, BACKUP_BLOCK_INCR_EXT))
        {
            const ManifestFilePack *const filePack = manifestFilePackFindDefault(
                manifest, strSubN(repoName, 0, strSize(repoName) - (sizeof(BACKUP_BLOCK_INCR_EXT) - 1)));

            if (filePack != NULL && manifestFileUnpack(manifest, filePack).blockIncrMapSize != 0)
            {
                THROW_FMT(
                    OptionInvalidValueError,
                    "unable to determine cipher identity for '%s'\n"
                    "HINT: a block incremental file holds each of its super blocks and its map as a stream of its own, so it cannot"
                    " be fetched alone.",
                    strZ(file));
            }
        }

        // The file is bound to the backup that wrote it, which is not the backup it is stored in when it was hard linked from an
        // earlier backup
        const String *const manifestName = compressExtStrip(repoName, manifestData(manifest)->backupOptionCompressType);
        const ManifestFilePack *const filePack = manifestFilePackFindDefault(manifest, manifestName);

        if (filePack == NULL)
        {
            THROW_FMT(
                OptionInvalidValueError,
                "unable to determine cipher identity for '%s'\n"
                "HINT: the file is not in the manifest of its backup.",
                strZ(file));
        }

        const String *const fileLabel = manifestFileUnpack(manifest, filePack).reference;

        MEM_CONTEXT_PRIOR_BEGIN()
        {
            result = backupFileCipherIdentity(fileLabel != NULL ? fileLabel : backupLabel, manifestName);
        }
        MEM_CONTEXT_PRIOR_END();
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_TEST_RETURN(STRING_LIST, result);
}

/***********************************************************************************************************************************
Write source file to destination IO
***********************************************************************************************************************************/
static int
storageGetProcess(IoWrite *const destination)
{
    FUNCTION_LOG_BEGIN(logLevelDebug);
        FUNCTION_LOG_PARAM(IO_READ, destination);
    FUNCTION_LOG_END();

    // Get source file
    if (strLstSize(cfgCommandParam()) != 1)
        THROW(ParamRequiredError, "source file required");

    const String *file = strLstGet(cfgCommandParam(), 0);

    // Assume the file is missing
    int result = 1;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        // Is path valid for repo?
        file = repoPathIsValid(file);

        // Create new file read
        IoRead *const source = storageReadIo(
            storageNewReadP(storageRepo(), file, .ignoreMissing = cfgOptionBool(cfgOptIgnoreMissing)));

        // The name of the info file when the file is one, i.e. when it has a header in front of its content
        const char *infoName = NULL;

        // Add decryption if needed
        if (!cfgOptionBool(cfgOptRaw))
        {
            const CipherType repoCipherType = cfgOptionStrId(cfgOptRepoCipherType);

            if (repoCipherType != cipherTypeNone)
            {
                // Determine the passphrase using the following pattern:
                //
                // REPO / (main passphrase)
                //      / archive / (main passphrase)
                //      / archive / stanza / (archive passphrase)
                //      / backup  / (main passphrase)
                //      / backup  / stanza / (manifest passphrase)
                //      / backup  / stanza / set / (backup passphrase)
                //      / backup  / stanza / backup.history / (manifest passphrase)
                //
                // Nothing should be stored at the top level of the repo except the backup/archive paths. The backup/archive paths
                // should contain only stanza paths.
                //
                // A file encrypted with aes-256-gcm is also bound to an identity, which is worked out from the path the same way.
                // -----------------------------------------------------------------------------------------------------------------
                const CipherSpec *cipherSpec = NULL;
                const StringList *cipherIdentity = NULL;
                const bool cipherGcm = repoCipherType == cipherTypeAes256Gcm;
                const StringList *const filePathSplitLst = strLstNewSplit(file, FSLASH_STR);

                // At a minimum the path must contain archive/backup, a stanza, and a file
                if (strLstSize(filePathSplitLst) > 2)
                {
                    const String *const stanza = strLstGet(filePathSplitLst, 1);

                    // If stanza option is specified then it must match the given file path
                    if (cfgOptionStrNull(cfgOptStanza) != NULL && !strEq(stanza, cfgOptionStr(cfgOptStanza)))
                    {
                        THROW_FMT(
                            OptionInvalidValueError, "stanza name '%s' given in option doesn't match the given path",
                            strZ(cfgOptionDisplay(cfgOptStanza)));
                    }

                    // The streams of aes-256-gcm are bound to their stanza, which is the one in the path
                    const CipherSpec *const cipherSpecMain = cipherSpecDupStanza(cfgCipherSpecMain(), stanza);

                    // The path of the file following archive/<stanza>/ or backup/<stanza>/
                    const String *const stanzaFile = strSub(file, strSize(strLstGet(filePathSplitLst, 0)) + strSize(stanza) + 2);

                    // Archive path
                    if (strEq(strLstGet(filePathSplitLst, 0), STORAGE_PATH_ARCHIVE_STR))
                    {
                        cipherSpec = cipherSpecMain;

                        // Find the archive passphrase
                        if (!storageGetFileIs(file, filePathSplitLst, cipherGcm, 3, INFO_ARCHIVE_FILE))
                        {
                            const InfoArchive *const info = infoArchiveLoadFile(
                                storageRepo(), strNewFmt(STORAGE_PATH_ARCHIVE "/%s/%s", strZ(stanza), INFO_ARCHIVE_FILE),
                                cipherSpecMain);
                            cipherSpec = infoArchiveCipherSpec(info);

                            // A file in the archive is bound to its name in the archive
                            if (cipherGcm)
                                cipherIdentity = archiveCipherIdentity(stanzaFile);
                        }
                        // Else the file is the archive info, which the repo passphrase opens
                        else
                            infoName = INFO_ARCHIVE_FILE;
                    }

                    // Backup path
                    if (strEq(strLstGet(filePathSplitLst, 0), STORAGE_PATH_BACKUP_STR))
                    {
                        cipherSpec = cipherSpecMain;

                        if (!storageGetFileIs(file, filePathSplitLst, cipherGcm, 3, INFO_BACKUP_FILE))
                        {
                            const String *const backupLabel = strLstGet(filePathSplitLst, 2);
                            const bool fileIsHistory = strEqZ(backupLabel, BACKUP_PATH_HISTORY);

                            // A file of a backup encrypted with aes-256-gcm is bound to the label of the backup, which the latest
                            // link is not
                            if (cipherGcm && strEqZ(backupLabel, BACKUP_LINK_LATEST))
                            {
                                THROW_FMT(
                                    OptionInvalidValueError,
                                    "unable to determine cipher identity for '%s'\n"
                                    "HINT: a backup encrypted with aes-256-gcm is bound to its label, so give the label rather than"
                                    " '" BACKUP_LINK_LATEST "'.",
                                    strZ(file));
                            }

                            // Find the manifest passphrase
                            const InfoBackup *const info = infoBackupLoadFile(
                                storageRepo(), strNewFmt(STORAGE_PATH_BACKUP "/%s/%s", strZ(stanza), INFO_BACKUP_FILE),
                                cipherSpecMain);
                            const CipherSpec *const cipherSpecManifest = infoBackupCipherSpec(info);

                            // Find the backup passphrase if not a manifest
                            if (!fileIsHistory && !storageGetFileIs(file, filePathSplitLst, cipherGcm, 4, BACKUP_MANIFEST_FILE))
                            {
                                const Manifest *const manifest = manifestLoadFileP(
                                    storageRepo(),
                                    strNewFmt(
                                        STORAGE_PATH_BACKUP "/%s/%s/%s", strZ(stanza), strZ(backupLabel), BACKUP_MANIFEST_FILE),
                                    cipherSpecManifest);
                                cipherSpec = manifestCipherSpec(manifest);

                                if (cipherGcm)
                                {
                                    cipherIdentity = storageGetBackupFileCipherIdentity(
                                        file, filePathSplitLst, stanzaFile, manifest);
                                }
                            }
                            // Else use the manifest passphrase
                            else
                            {
                                cipherSpec = cipherSpecManifest;

                                if (cipherGcm)
                                {
                                    // A manifest in backup.history is bound to its label, i.e. the name of the file up to its
                                    // extensions
                                    if (fileIsHistory)
                                    {
                                        cipherIdentity = backupManifestHistoryCipherIdentity(
                                            strLstGet(strLstNewSplitZ(strBase(file), "."), 0));
                                    }
                                    // Else a manifest of a backup is bound to its label and whether it is the in-progress copy
                                    else
                                        cipherIdentity = manifestCipherIdentity(file);
                                }
                            }
                        }
                        // Else the file is the backup info, which the repo passphrase opens
                        else
                            infoName = INFO_BACKUP_FILE;
                    }
                }

                // Error when unable to determine cipher passphrase
                if (cipherSpec == NULL)
                    THROW_FMT(OptionInvalidValueError, "unable to determine cipher passphrase for '%s'", strZ(file));

                ASSERT(cipherSpecType(cipherSpec) != cipherTypeNone);

                // Add the decryption filter. An info file is read through the filter that reads its header.
                if (infoName != NULL)
                    cipherFormatInfoReadAdd(ioReadFilterGroup(source), cipherSpec, infoName);
                else
                    cipherFormatFilterGroupAdd(ioReadFilterGroup(source), cipherModeDecrypt, cipherSpec, cipherIdentity);
            }
        }

        // Open source
        if (ioReadOpen(source))
        {
            // Open the destination file now that we know the source exists and is readable
            ioWriteOpen(destination);

            // Copy data from source to destination
            ioCopyP(source, destination);

            // Close the source and destination
            ioReadClose(source);
            ioWriteClose(destination);

            // Source file exists
            result = 0;
        }
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(INT, result);
}

/**********************************************************************************************************************************/
FN_EXTERN int
cmdStorageGet(void)
{
    FUNCTION_LOG_VOID(logLevelDebug);

    // Assume the file is missing
    int result = 1;

    MEM_CONTEXT_TEMP_BEGIN()
    {
        TRY_BEGIN()
        {
            result = storageGetProcess(ioFdWriteNew(STRDEF("stdout"), STDOUT_FILENO, cfgOptionUInt64(cfgOptIoTimeout)));
        }
        // Ignore write errors because it's possible (even likely) that this output is being piped to something like head which will
        // exit when it gets what it needs and leave us writing to a broken pipe. It would be better to just ignore the broken pipe
        // error but currently we don't store system error codes.
        CATCH(FileWriteError)
        {
        }
        TRY_END();
    }
    MEM_CONTEXT_TEMP_END();

    FUNCTION_LOG_RETURN(INT, result);
}
