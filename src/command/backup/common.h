/***********************************************************************************************************************************
Common Functions and Definitions for Backup and Expire Commands
***********************************************************************************************************************************/
#ifndef COMMAND_BACKUP_COMMON_H
#define COMMAND_BACKUP_COMMON_H

#include <stdbool.h>
#include <time.h>

#include "common/compress/helper.h"
#include "common/type/string.h"
#include "common/type/stringList.h"
#include "info/infoBackup.h"

/***********************************************************************************************************************************
Backup constants
***********************************************************************************************************************************/
#define BACKUP_PATH_HISTORY                                         "backup.history"
#define BACKUP_BLOCK_INCR_EXT                                       ".pgbi"
#define BACKUP_LINK_LATEST                                          "latest"

// Date and time must be in %Y%m%d-%H%M%S format, for example 20220901-193409
#define DATE_TIME_REGEX                                             "[0-9]{8}\\-[0-9]{6}"
#define DATE_TIME_LEN                                               (8 + 1 + 6)

/***********************************************************************************************************************************
Functions
***********************************************************************************************************************************/
// Determine the path/file where the file is backed up in the repo
typedef struct BackupFileRepoPathParam
{
    const String *manifestName;                                     // File name in manifest
    uint64_t bundleId;                                              // Is the file bundled?
    CompressType compressType;                                      // Is the file compressed?
    bool blockIncr;                                                 // Is the file a block incremental?
} BackupFileRepoPathParam;

#define backupFileRepoPathP(backupLabel, ...)                                                                                      \
    backupFileRepoPath(backupLabel, (BackupFileRepoPathParam){__VA_ARGS__})

FN_EXTERN String *backupFileRepoPath(const String *backupLabel, BackupFileRepoPathParam param);

// The identity an aes-256-gcm backup file is bound to, whether stored alone or in a bundle: {"file", <label>, <manifest name>},
// e.g. {"file", "20260930-081500F", "pg_data/base/1/1259"}. The label is the backup that wrote the file, i.e. the reference of a
// file in a later backup. Both come from the manifest, so the reader binds the file to what the writer did. The name is unique in a
// backup, so a copy to another name or another backup does not decrypt.
FN_EXTERN StringList *backupFileCipherIdentity(const String *backupLabel, const String *manifestName);

// The identity an aes-256-gcm super block of a block incremental file is bound to: {"super-block", <label>, <manifest name>,
// <offset>}, e.g. {"super-block", "20260930-081500F", "pg_data/base/1/1259", "131072"}. The label is the backup that wrote the
// super block and the offset is where it begins in the repository file, in decimal, both as recorded in the block map item that
// points to it. A super block moved to another offset, file or backup does not decrypt.
FN_EXTERN StringList *backupSuperBlockCipherIdentity(const String *backupLabel, const String *manifestName, uint64_t offset);

// The identity an aes-256-gcm block map is bound to: {"block-map", <label>, <manifest name>}, the label being the backup that wrote
// the map, i.e. the reference of the file in a later backup
FN_EXTERN StringList *backupBlockMapCipherIdentity(const String *backupLabel, const String *manifestName);

// The identity an aes-256-gcm history manifest, i.e. backup.history/<yyyy>/<label>.manifest.gz, is bound to:
// {"manifest-history", <label>}
FN_EXTERN StringList *backupManifestHistoryCipherIdentity(const String *backupLabel);

// Format a backup label from a type and timestamp with an optional prior label
FN_EXTERN String *backupLabelFormat(BackupType type, const String *backupLabelPrior, time_t timestamp);

// Returns an anchored regex string for filtering backups based on the type (at least one type is required to be true)
typedef struct BackupRegExpParam
{
    bool full;
    bool differential;
    bool incremental;
    bool noAnchorEnd;
} BackupRegExpParam;

#define backupRegExpP(...)                                                                                                         \
    backupRegExp((BackupRegExpParam){__VA_ARGS__})

FN_EXTERN String *backupRegExp(BackupRegExpParam param);

// Create a symlink to the specified backup (if symlinks are supported)
FN_EXTERN void backupLinkLatest(const String *backupLabel, unsigned int repoIdx);

#endif
