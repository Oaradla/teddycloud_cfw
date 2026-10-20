#include "tonie_audio_playlist.h"

#include "fs_port.h"
#include "str.h"
#include "toniefile.h"
#include "server_helpers.h"
#include "cJSON.h"
#include "json_helper.h"
#include "handler.h"
#include "taf_remux.h"
#include "date_time.h"
#include "path_ext.h"

static OsMutex tap_build_mutex;

void tap_init(void)
{
    osCreateMutex(&tap_build_mutex);
}

void tap_deinit(void)
{
    osDeleteMutex(&tap_build_mutex);
}

/* Upper bound on playlist entries, matching the fixed source array the
   ffmpeg encoder (ffmpeg_stream/ffmpeg_convert) operates on. */
#define TAP_MAX_FILES 99

bool_t is_valid_tap_file(char *filename)
{

    tonie_audio_playlist_t tap;
    osMemset(&tap, 0, sizeof(tap));
    tap_load(filename, &tap);
    if (tap._valid)
    {
        tap_free(&tap);
        return true;
    }
    return false;
}

/* playlists only point into the library (and, for files, to tonie content); the
   path must not leave it */
static bool_t tap_path_allowed(const char *path, bool_t output)
{
    if (path == NULL || osStrstr(path, "..") != NULL)
    {
        return false;
    }
    if (osStrncmp(path, "lib://", 6) == 0)
    {
        return true;
    }
    return !output && osStrncmp(path, "content://", 10) == 0;
}

static bool_t has_taf_extension(const char *path)
{
    size_t len = osStrlen(path);
    return len >= 4 && osStrcasecmp(&path[len - 4], ".taf") == 0;
}

/* the modification time of a file, 0 when it is missing */
static time_t file_mtime(const char *path)
{
    FsFileStat stat;
    if (fsGetFileStat(path, &stat) != NO_ERROR)
    {
        return 0;
    }
    return convertDateToUnixTime(&stat.modified);
}

/* the playlist TAF is current when it is no older than the playlist and every file in it */
static bool_t tap_is_current(const char *filename, tonie_audio_playlist_t *tap)
{
    time_t built = file_mtime(tap->_filepath_resolved);
    if (built == 0 || file_mtime(filename) > built)
    {
        return false;
    }
    for (size_t i = 0; i < tap->filesCount; i++)
    {
        if (file_mtime(tap->files[i]._filepath_resolved) > built)
        {
            return false;
        }
    }
    return true;
}

error_t tap_load(char *filename, tonie_audio_playlist_t *tap)
{
    size_t fileSize = 0;
    error_t error = fsGetFileSize(filename, (uint32_t *)(&fileSize));
    tap->_cached = false;
    tap->_valid = false;

    if (error != NO_ERROR)
    {
        return error;
    }

    FsFile *fsFile = fsOpenFile(filename, FS_FILE_MODE_READ);
    if (fsFile == NULL)
    {
        return ERROR_FILE_OPENING_FAILED;
    }

    size_t sizeRead;
    char *data = osAllocMem(fileSize);
    size_t pos = 0;

    while (pos < fileSize)
    {
        if (fsReadFile(fsFile, &data[pos], fileSize - pos, &sizeRead) != NO_ERROR || sizeRead == 0)
        {
            break;
        }
        pos += sizeRead;
    }
    fsCloseFile(fsFile);

    cJSON *tapJson = cJSON_ParseWithLengthOpts(data, fileSize, 0, 0);
    osFreeMem(data);
    if (tapJson == NULL)
    {
        // const char *error_ptr = cJSON_GetErrorPtr();
        TRACE_ERROR("Json parse error\r\n");
        error = ERROR_INVALID_FILE;
    }
    else
    {
        tap->type = jsonGetString(tapJson, "type");
        if (osStrcmp(tap->type, "tap") == 0)
        {
            tap->audio_id = jsonGetUInt32(tapJson, "audio_id");
            tap->filepath = jsonGetString(tapJson, "filepath");
            if (!has_taf_extension(tap->filepath))
            {
                /* older editors stored a directory here: the playlist TAF then goes next to the playlist */
                char *lib = get_settings()->internal.librarydirfull;
                size_t lib_len = osStrlen(lib);
                size_t len = osStrlen(filename);
                if (osStrncmp(filename, lib, lib_len) == 0 && len > lib_len + 4)
                {
                    TRACE_WARNING("TAP %s has no TAF as filepath, using the playlist name\r\n", filename);
                    osFreeMem(tap->filepath);
                    tap->filepath = custom_asprintf("lib://%.*s.taf", (int)(len - lib_len - 1 - 4), &filename[lib_len + 1]);
                }
            }
            if (!tap_path_allowed(tap->filepath, true) || !has_taf_extension(tap->filepath))
            {
                TRACE_ERROR("TAP %s: filepath must be a .taf in lib://\r\n", filename);
                error = ERROR_INVALID_FILE;
            }

            tap->_filepath_resolved = strdup(tap->filepath);
            resolveSpecialPathPrefix(&tap->_filepath_resolved, get_settings());

            tap->name = jsonGetString(tapJson, "name");
            const cJSON *filesJson = cJSON_GetObjectItemCaseSensitive(tapJson, "files");
            tap->filesCount = cJSON_GetArraySize(filesJson);
            /* The downstream encoder works on a fixed char[TAP_MAX_FILES][PATH_LEN]
               array, so never load more entries than it can process. */
            if (tap->filesCount > TAP_MAX_FILES)
            {
                TRACE_WARNING("TAP has %" PRIuSIZE " files, truncating to %d\r\n", tap->filesCount, TAP_MAX_FILES);
                tap->filesCount = TAP_MAX_FILES;
            }
            if (tap->filesCount > 0)
            {
                tap->files = osAllocMem(tap->filesCount * sizeof(tap_file_t));
                size_t i = 0;
                cJSON *fileJson;
                cJSON_ArrayForEach(fileJson, filesJson)
                {
                    if (i >= tap->filesCount)
                    {
                        break;
                    }
                    tap->files[i].filepath = jsonGetString(fileJson, "filepath");
                    if (!tap_path_allowed(tap->files[i].filepath, false))
                    {
                        TRACE_ERROR("TAP %s: file %s is not in lib:// or content://\r\n", filename, tap->files[i].filepath);
                        error = ERROR_INVALID_FILE;
                    }
                    tap->files[i]._filepath_resolved = strdup(tap->files[i].filepath);
                    resolveSpecialPathPrefix(&tap->files[i]._filepath_resolved, get_settings());
                    tap->files[i].name = jsonGetString(fileJson, "name");
                    i++;
                }
            }
        }
        else
        {
            error = ERROR_INVALID_FILE;
        }
    }

    cJSON_Delete(tapJson);
    if (error == NO_ERROR)
    {
        if (isValidTaf(tap->_filepath_resolved, get_settings()->core.tap_taf_validation) && tap_is_current(filename, tap))
        {
            tap->_cached = true;
        }
        tap->_valid = true;
    }
    return error;
}
error_t tap_save(char *filename, tonie_audio_playlist_t *tap)
{

    cJSON *tapJson = cJSON_CreateObject();
    error_t error = NO_ERROR;

    cJSON_AddStringToObject(tapJson, "type", TAP_TYPE_TAP);
    cJSON_AddNumberToObject(tapJson, "audio_id", tap->audio_id);
    cJSON_AddStringToObject(tapJson, "filepath", tap->filepath);
    cJSON_AddStringToObject(tapJson, "name", tap->name);
    if (tap->files != NULL)
    {
        cJSON *filesJson = cJSON_AddArrayToObject(tapJson, "files");
        for (size_t i = 0; i < tap->filesCount; i++)
        {
            cJSON *fileJson = cJSON_CreateObject();
            cJSON_AddStringToObject(fileJson, "filepath", tap->files[i].filepath);
            cJSON_AddStringToObject(fileJson, "name", tap->files[i].name);
            cJSON_AddItemToArray(filesJson, fileJson);
        }
    }
    char *jsonRaw = cJSON_Print(tapJson);

    FsFile *fsFile = fsOpenFile(filename, FS_FILE_MODE_WRITE);
    if (fsFile == NULL)
    {
        error = ERROR_FILE_OPENING_FAILED;
    }
    else
    {
        error = fsWriteFile(fsFile, jsonRaw, osStrlen(jsonRaw));
        fsCloseFile(fsFile);
    }

    cJSON_Delete(tapJson);
    osFreeMem(jsonRaw);
    return error;
}

void tap_free(tonie_audio_playlist_t *tap)
{
    for (size_t i = 0; i < tap->filesCount; i++)
    {
        osFreeMem(tap->files[i].filepath);
        osFreeMem(tap->files[i]._filepath_resolved);
        osFreeMem(tap->files[i].name);
    }
    if (tap->filesCount > 0)
    {
        tap->filesCount = 0;
        osFreeMem(tap->files);
    }
    if (tap->type != NULL)
    {
        osFreeMem(tap->type);
    }
    if (tap->filepath != NULL)
    {
        osFreeMem(tap->filepath);
    }
    if (tap->_filepath_resolved != NULL)
    {
        osFreeMem(tap->_filepath_resolved);
    }
    if (tap->name != NULL)
    {
        osFreeMem(tap->name);
    }

    osMemset(tap, 0, sizeof(tonie_audio_playlist_t));
}

error_t tap_generate_taf(tonie_audio_playlist_t *tap, size_t *current_source, bool_t *active, bool_t force)
{
    error_t error = NO_ERROR;
    bool_t sweep = false;
    tonie_info_t *tonieInfo = getTonieInfo(tap->_filepath_resolved, false, get_settings());

    // TODO custom audio id resolving
    if (force || !tonieInfo->valid || tonieInfo->tafHeader->audio_id != tap->audio_id)
    {
        char *tmp_taf = custom_asprintf("%s.tmp", tap->_filepath_resolved);
        /* ~400 KB: never on the stack of the stream task (see ffmpeg_stream_task) */
        char(*source)[PATH_LEN] = osAllocMem(sizeof(char[TAP_MAX_FILES][PATH_LEN]));
        if (source == NULL || tap->filesCount == 0 || tap->filesCount > TAP_MAX_FILES)
        {
            osFreeMem(source);
            osFreeMem(tmp_taf);
            freeTonieInfo(tonieInfo);
            return source == NULL ? ERROR_OUT_OF_MEMORY : ERROR_INVALID_FILE;
        }

        for (size_t i = 0; i < tap->filesCount; i++)
        {
            strSafeCopy(source[i], tap->files[i]._filepath_resolved, PATH_LEN);
        }
        // toniefile_t *taf = toniefile_create(tmp_taf, tap->audio_id, false, 0);
        error = ffmpeg_stream(source, tap->filesCount, current_source, tmp_taf, 0, active, &sweep, false, false);
        osFreeMem(source);
        if (error == NO_ERROR && *current_source < tap->filesCount)
        {
            /* playback stopped before the end: never keep a cut off playlist as its TAF */
            TRACE_INFO("TAP encoding aborted at file %" PRIuSIZE "/%" PRIuSIZE "\r\n", *current_source + 1, tap->filesCount);
            error = ERROR_ABORTED;
        }
        if (error != NO_ERROR)
        {
            fsDeleteFile(tmp_taf);
        }
        else
        {
            error = fsMoveFile(tmp_taf, tap->_filepath_resolved, true);
        }
        osFreeMem(tmp_taf);
        freeTonieInfo(tonieInfo);
    }
    return error;
}

void tap_generate_task(void *param)
{
    stream_ctx_t *stream_ctx = (stream_ctx_t *)param;
    tap_generate_param_t *tap_ctx = (tap_generate_param_t *)stream_ctx->ctx;

    stream_ctx->error = tap_generate_taf(tap_ctx->tap, &stream_ctx->current_source, &stream_ctx->active, tap_ctx->force);
    stream_ctx->quit = true;
    osDeleteTask((OsTaskId) OS_SELF_TASK_ID);
}

bool_t tap_can_remux(tonie_audio_playlist_t *tap)
{
    if (tap->filesCount == 0)
    {
        return false;
    }
    for (size_t i = 0; i < tap->filesCount; i++)
    {
        if (!isValidTaf(tap->files[i]._filepath_resolved, false))
        {
            return false;
        }
    }
    return true;
}

error_t tap_build(char *filename, tonie_audio_playlist_t *tap)
{
    if (!tap->_valid || tap->filesCount == 0)
    {
        return ERROR_INVALID_FILE;
    }

    osAcquireMutex(&tap_build_mutex);

    /* another request may have built it meanwhile */
    error_t error = NO_ERROR;
    if (!(isValidTaf(tap->_filepath_resolved, false) && tap_is_current(filename, tap)))
    {
        const char **sources = osAllocMem(tap->filesCount * sizeof(char *));
        char *tmp_taf = custom_asprintf("%s.build", tap->_filepath_resolved);
        if (sources == NULL)
        {
            error = ERROR_OUT_OF_MEMORY;
        }
        else
        {
            for (size_t i = 0; i < tap->filesCount; i++)
            {
                sources[i] = tap->files[i]._filepath_resolved;
            }

            /* a new audio id, so boxes notice the changed content */
            uint32_t audio_id = (uint32_t)(time(NULL) - TEDDY_BENCH_AUDIO_ID_DEDUCT);
            tonie_info_t *old = getTonieInfo(tap->_filepath_resolved, false, get_settings());
            if (old->valid && old->tafHeader != NULL && old->tafHeader->audio_id >= audio_id)
            {
                audio_id = old->tafHeader->audio_id + 1;
            }
            freeTonieInfo(old);

            TRACE_INFO("Build TAP %s (%" PRIuSIZE " files) into %s\r\n", filename, tap->filesCount, tap->_filepath_resolved);
            error = taf_remux_concat(sources, tap->filesCount, tmp_taf, audio_id);
            if (error == NO_ERROR)
            {
                error = fsMoveFile(tmp_taf, tap->_filepath_resolved, true);
            }
            if (error != NO_ERROR)
            {
                TRACE_ERROR("Could not build TAP %s: %s\r\n", filename, error2text(error));
                fsDeleteFile(tmp_taf);
            }
            osFreeMem(sources);
        }
        osFreeMem(tmp_taf);
    }
    if (error == NO_ERROR)
    {
        tap->_cached = true;
    }

    osReleaseMutex(&tap_build_mutex);
    return error;
}

static bool_t tap_has_suffix(const char *path, const char *suffix)
{
    size_t len = osStrlen(path);
    size_t suffixLen = osStrlen(suffix);
    return len > suffixLen && !osStrcasecmp(&path[len - suffixLen], suffix);
}

bool_t tap_is_built_taf(const char *path)
{
    if (!tap_has_suffix(path, ".tap" TAP_BUILT_SUFFIX))
    {
        return false;
    }
    char *tapPath = strdup(path);
    tapPath[osStrlen(tapPath) - osStrlen(TAP_BUILT_SUFFIX)] = '\0';
    bool_t exists = fsFileExists(tapPath);
    osFreeMem(tapPath);
    return exists;
}

void tap_deleted(const char *tapPath)
{
    if (!tap_has_suffix(tapPath, ".tap"))
    {
        return;
    }
    char *built = custom_asprintf("%s%s", tapPath, TAP_BUILT_SUFFIX);
    if (fsFileExists(built) && fsDeleteFile(built) == NO_ERROR)
    {
        TRACE_INFO("Deleted %s with its playlist\r\n", built);
    }
    osFreeMem(built);
}

/* path with the prefix from (the path itself or below it) as to + rest; NULL when it does not match */
static char *tap_path_moved(const char *path, const char *from, const char *to)
{
    size_t fromLen = osStrlen(from);
    if (path == NULL || osStrncmp(path, from, fromLen) != 0)
    {
        return NULL;
    }
    char next = path[fromLen];
    if (next != '\0' && next != '/' && next != PATH_SEPARATOR)
    {
        return NULL;
    }
    return custom_asprintf("%s%s", to, &path[fromLen]);
}

static bool_t tap_replace_path(char **path, const char *from, const char *to)
{
    char *moved = tap_path_moved(*path, from, to);
    if (moved == NULL)
    {
        return false;
    }
    osFreeMem(*path);
    *path = moved;
    return true;
}

/* every playlist below dir that names something under from (lib://...) names it under to now */
static void tap_rewrite_dir(const char *dir, const char *from, const char *to, int depth)
{
    FsDir *fsDir = fsOpenDir(dir);
    if (fsDir == NULL)
    {
        return;
    }
    FsDirEntry entry;
    while (fsReadDir(fsDir, &entry) == NO_ERROR)
    {
        if (!osStrcmp(entry.name, ".") || !osStrcmp(entry.name, ".."))
        {
            continue;
        }
        char *path = custom_asprintf("%s%c%s", dir, PATH_SEPARATOR, entry.name);
        if (entry.attributes & FS_FILE_ATTR_DIRECTORY)
        {
            if (depth < 32)
            {
                tap_rewrite_dir(path, from, to, depth + 1);
            }
        }
        else if (tap_has_suffix(entry.name, ".tap"))
        {
            tonie_audio_playlist_t tap;
            osMemset(&tap, 0, sizeof(tap));
            if (tap_load(path, &tap) == NO_ERROR && tap._valid)
            {
                bool_t changed = tap_replace_path(&tap.filepath, from, to);
                for (size_t i = 0; i < tap.filesCount; i++)
                {
                    changed |= tap_replace_path(&tap.files[i].filepath, from, to);
                }
                if (changed && tap_save(path, &tap) != NO_ERROR)
                {
                    TRACE_WARNING("Could not update the paths in %s\r\n", path);
                }
            }
            tap_free(&tap);
        }
        osFreeMem(path);
    }
    fsCloseDir(fsDir);
}

void tap_moved(const char *fromPath, const char *toPath)
{
    const char *lib = get_settings()->internal.librarydirfull;
    size_t libLen = osStrlen(lib);
    if (osStrncmp(fromPath, lib, libLen) != 0 || fromPath[libLen] != PATH_SEPARATOR ||
        osStrncmp(toPath, lib, libLen) != 0 || toPath[libLen] != PATH_SEPARATOR)
    {
        return;
    }

    /* a playlist takes the TAF it built next to itself along */
    if (tap_has_suffix(fromPath, ".tap") && tap_has_suffix(toPath, ".tap"))
    {
        char *oldBuilt = custom_asprintf("%s%s", fromPath, TAP_BUILT_SUFFIX);
        char *newBuilt = custom_asprintf("%s%s", toPath, TAP_BUILT_SUFFIX);
        if (fsFileExists(oldBuilt))
        {
            if (fsMoveFile(oldBuilt, newBuilt, false) == NO_ERROR)
            {
                tap_moved(oldBuilt, newBuilt);
            }
            else
            {
                TRACE_WARNING("Could not move %s along with its playlist\r\n", oldBuilt);
            }
        }
        else
        {
            /* not built yet: the playlist builds it at the new place */
            char *from = custom_asprintf("lib://%s", &oldBuilt[libLen + 1]);
            char *to = custom_asprintf("lib://%s", &newBuilt[libLen + 1]);
            tap_rewrite_dir(lib, from, to, 0);
            osFreeMem(from);
            osFreeMem(to);
        }
        osFreeMem(oldBuilt);
        osFreeMem(newBuilt);
    }

    char *from = custom_asprintf("lib://%s", &fromPath[libLen + 1]);
    char *to = custom_asprintf("lib://%s", &toPath[libLen + 1]);
    osAcquireMutex(&tap_build_mutex);
    tap_rewrite_dir(lib, from, to, 0);
    osReleaseMutex(&tap_build_mutex);
    osFreeMem(from);
    osFreeMem(to);
}
