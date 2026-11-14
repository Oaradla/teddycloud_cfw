#include "tonie_audio_playlist.h"

#include "fs_port.h"
#include "str.h"
#include "toniefile.h"
#include "server_helpers.h"
#include "cJSON.h"
#include "json_helper.h"
#include "handler.h"
#include "rand.h"
#include "taf_remux.h"
#include "date_time.h"
#include "error_text.h"
#include "path_ext.h"

static OsMutex tap_build_mutex;

/* playlists waiting for tap_build_later() */
#define TAP_BUILD_PENDING_MAX 8
static OsMutex tap_pending_mutex;
static char *tap_pending[TAP_BUILD_PENDING_MAX];

/* playlists whose TAF could not be put together: they are encoded instead until they or their files change */
static struct
{
    char *taf;
    time_t inputs;
} tap_failed[TAP_BUILD_PENDING_MAX];
static size_t tap_failed_next;

void tap_init(void)
{
    osCreateMutex(&tap_build_mutex);
    osCreateMutex(&tap_pending_mutex);
}

void tap_deinit(void)
{
    for (size_t i = 0; i < TAP_BUILD_PENDING_MAX; i++)
    {
        osFreeMem(tap_failed[i].taf);
        tap_failed[i].taf = NULL;
    }
    osDeleteMutex(&tap_build_mutex);
    osDeleteMutex(&tap_pending_mutex);
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
    if (path == NULL || fsPathHasParent(path))
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

/* the newest change of the files of a playlist, at least the given time */
static time_t tap_newest(time_t newest, tonie_audio_playlist_t *tap)
{
    for (size_t i = 0; i < tap->filesCount; i++)
    {
        time_t changed = file_mtime(tap->files[i]._filepath_resolved);
        if (changed > newest)
        {
            newest = changed;
        }
    }
    return newest;
}

/* the playlist TAF is current when it is no older than the playlist and every file in it */
static bool_t tap_is_current(tonie_audio_playlist_t *tap)
{
    time_t built = file_mtime(tap->_filepath_resolved);
    return built != 0 && built >= tap->_inputs;
}

error_t tap_load(char *filename, tonie_audio_playlist_t *tap)
{
    size_t fileSize = 0;
    error_t error = fsGetFileSize(filename, (uint32_t *)(&fileSize));
    time_t changed = file_mtime(filename);
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
        tap->_random = (osStrcmp(tap->type, TAP_TYPE_RANDOM) == 0);
        if (osStrcmp(tap->type, TAP_TYPE_TAP) == 0 || tap->_random)
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

            if (tap->_random)
            {
                tap->directory = jsonGetString(tapJson, "directory");
                resolveSpecialPathPrefix(&tap->directory, get_settings());
            }

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
        tap->_inputs = tap_newest(changed, tap);
        if (isValidTaf(tap->_filepath_resolved, get_settings()->core.tap_taf_validation) && tap_is_current(tap))
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
    if (tap->directory != NULL)
    {
        osFreeMem(tap->directory);
    }

    osMemset(tap, 0, sizeof(tonie_audio_playlist_t));
}

/* Reads the audio id and hash of a pool candidate that is a complete TAF: one still being encoded
   or uploaded already has a header, but its file is shorter than the header says. Small files
   (also pipes and devices, which report size 0) are never opened. Only files under the data
   directory can be served. */
static bool_t tap_random_header(const char *path, settings_t *settings, uint32_t *audio_id, uint8_t sha1[20])
{
    uint32_t fileSize = 0;
    if (osStrncmp(path, settings->internal.datadirfull, osStrlen(settings->internal.datadirfull)) != 0 ||
        fsGetFileSize(path, &fileSize) != NO_ERROR || fileSize <= 4096)
    {
        return false;
    }
    FsFile *file = fsOpenFile(path, FS_FILE_MODE_READ);
    if (file == NULL)
    {
        return false;
    }
    TonieboxAudioFileHeader *tafHeader = readTafHeader(file, path);
    fsCloseFile(file);
    bool_t complete = tafHeader != NULL && tafHeader->sha1_hash.len == 20 && (uint64_t)(fileSize - 4096) == tafHeader->num_bytes;
    if (complete)
    {
        *audio_id = tafHeader->audio_id;
        osMemcpy(sha1, tafHeader->sha1_hash.data, 20);
    }
    if (tafHeader != NULL)
    {
        toniebox_audio_file_header__free_unpacked(tafHeader, NULL);
    }
    return complete;
}

static void tap_random_add(char ***paths, size_t *count, size_t *capacity, char *path)
{
    if (*count == *capacity)
    {
        *capacity = (*capacity == 0) ? 64 : *capacity * 2;
        *paths = realloc(*paths, *capacity * sizeof(char *));
    }
    (*paths)[(*count)++] = path;
}

/* The candidates of a pool: the files directly in its directory (no subfolders) and its listed
   files; a listed file that is also in the directory is taken once. Nothing is opened yet. */
static size_t tap_random_candidates(const tonie_audio_playlist_t *tap, char ***paths)
{
    size_t count = 0;
    size_t capacity = 0;
    *paths = NULL;

    if (tap->directory[0] != '\0')
    {
        /* Without its trailing separator, so that a listed file in the folder compares equal. */
        char *dirPath = strdup(tap->directory);
        size_t dirLen = osStrlen(dirPath);
        while (dirLen > 1 && (dirPath[dirLen - 1] == '/' || dirPath[dirLen - 1] == '\\'))
        {
            dirPath[--dirLen] = '\0';
        }
        FsDir *dir = fsOpenDir(dirPath);
        if (dir != NULL)
        {
            FsDirEntry entry;
            while (fsReadDir(dir, &entry) == NO_ERROR)
            {
                if (!(entry.attributes & FS_FILE_ATTR_DIRECTORY))
                {
                    tap_random_add(paths, &count, &capacity, custom_asprintf("%s%c%s", dirPath, PATH_SEPARATOR, entry.name));
                }
            }
            fsCloseDir(dir);
        }
        else
        {
            TRACE_WARNING("Random TAP folder %s cannot be read\r\n", dirPath);
        }
        osFreeMem(dirPath);
    }
    size_t inDirectory = count;
    for (size_t i = 0; i < tap->filesCount; i++)
    {
        bool_t listedTwice = false;
        for (size_t j = 0; j < inDirectory && !listedTwice; j++)
        {
            listedTwice = (osStrcmp((*paths)[j], tap->files[i]._filepath_resolved) == 0);
        }
        if (!listedTwice)
        {
            tap_random_add(paths, &count, &capacity, strdup(tap->files[i]._filepath_resolved));
        }
    }
    return count;
}

/* The candidate a request that continues an earlier pick asks for: the one whose SHA1 starts with
   sha1_prefix (TAP_RANDOM_SHA1_PREFIX bytes) when that is given, else the one with audio_id. Two
   different TAFs that both match (audio ids are often encode times in seconds) make it ambiguous:
   then none is returned, as continuing the wrong one would splice two files. */
static char *tap_random_find(char **paths, size_t count, uint32_t audio_id, const uint8_t *sha1_prefix, settings_t *settings)
{
    char *found = NULL;
    uint8_t foundSha1[20];
    for (size_t i = 0; i < count; i++)
    {
        uint32_t id = 0;
        uint8_t sha1[20];
        if (!tap_random_header(paths[i], settings, &id, sha1) ||
            (sha1_prefix != NULL ? osMemcmp(sha1, sha1_prefix, TAP_RANDOM_SHA1_PREFIX) != 0 : id != audio_id))
        {
            continue;
        }
        if (found != NULL && osMemcmp(sha1, foundSha1, 20) != 0)
        {
            TRACE_WARNING("Random TAP: %s and %s both match the requested TAF\r\n", found, paths[i]);
            return NULL;
        }
        found = paths[i];
        osMemcpy(foundSha1, sha1, 20);
    }
    return found;
}

/* Picks one TAF of a random pool, each equally likely. Only the drawn candidate is opened; one that
   is no complete TAF (a cover, an unfinished encode) is dropped and another drawn, so a request
   costs a few opens, not one per file of the folder. With audio_id != 0 or a sha1_prefix the TAF
   an earlier pick served is picked instead (tap_random_find). Returns ERROR_NOT_FOUND when no TAF
   fits; the caller frees *picked otherwise. */
error_t tap_random_pick(const tonie_audio_playlist_t *tap, uint32_t audio_id, const uint8_t *sha1_prefix, settings_t *settings, char **picked)
{
    char **paths;
    size_t count = tap_random_candidates(tap, &paths);
    bool_t continuing = (audio_id != 0 || sha1_prefix != NULL);
    *picked = NULL;

    if (continuing)
    {
        char *found = tap_random_find(paths, count, audio_id, sha1_prefix, settings);
        if (found != NULL)
        {
            *picked = strdup(found);
        }
    }
    while (!continuing && count > 0 && *picked == NULL)
    {
        /* A failed draw leaves 0 and takes the first candidate. */
        uint32_t draw = 0;
        rand_get_algo()->generate(rand_get_context(), (uint8_t *)&draw, sizeof(draw));
        size_t index = draw % count;
        uint32_t id;
        uint8_t sha1[20];
        if (tap_random_header(paths[index], settings, &id, sha1))
        {
            *picked = paths[index];
        }
        else
        {
            osFreeMem(paths[index]);
        }
        paths[index] = paths[--count];
    }
    for (size_t i = 0; i < count; i++)
    {
        osFreeMem(paths[i]);
    }
    osFreeMem(paths);

    return (*picked != NULL) ? NO_ERROR : ERROR_NOT_FOUND;
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

/* the slot of a playlist in tap_failed, -1 when it is not there; under tap_pending_mutex */
static int tap_failed_slot(tonie_audio_playlist_t *tap)
{
    for (int i = 0; i < TAP_BUILD_PENDING_MAX; i++)
    {
        if (tap_failed[i].taf != NULL && !osStrcmp(tap_failed[i].taf, tap->_filepath_resolved))
        {
            return i;
        }
    }
    return -1;
}

static void tap_build_failed(tonie_audio_playlist_t *tap, bool_t failed)
{
    osAcquireMutex(&tap_pending_mutex);
    int slot = tap_failed_slot(tap);
    if (failed && slot < 0)
    {
        slot = tap_failed_next;
        tap_failed_next = (tap_failed_next + 1) % TAP_BUILD_PENDING_MAX;
        osFreeMem(tap_failed[slot].taf);
        tap_failed[slot].taf = strdup(tap->_filepath_resolved);
    }
    if (failed)
    {
        tap_failed[slot].inputs = tap->_inputs;
    }
    else if (slot >= 0)
    {
        osFreeMem(tap_failed[slot].taf);
        tap_failed[slot].taf = NULL;
    }
    osReleaseMutex(&tap_pending_mutex);
}

bool_t tap_can_remux(tonie_audio_playlist_t *tap)
{
    if (tap->filesCount == 0)
    {
        return false;
    }
    osAcquireMutex(&tap_pending_mutex);
    int slot = tap_failed_slot(tap);
    bool_t failed = slot >= 0 && tap_failed[slot].inputs == tap->_inputs;
    osReleaseMutex(&tap_pending_mutex);
    if (failed)
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
    if (!(isValidTaf(tap->_filepath_resolved, false) && tap_is_current(tap)))
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
            uint32_t audio_id = toniefile_new_audio_ids(1);
            tonie_info_t *old = getTonieInfo(tap->_filepath_resolved, false, get_settings());
            if (old->valid && old->tafHeader != NULL && old->tafHeader->audio_id >= audio_id)
            {
                audio_id = old->tafHeader->audio_id + 1;
            }
            freeTonieInfo(old);

            TRACE_INFO("Build TAP %s (%" PRIuSIZE " files) into %s\r\n", filename, tap->filesCount, tap->_filepath_resolved);
            error = taf_remux_concat(sources, tap->filesCount, tmp_taf, audio_id);
            if (error == NO_ERROR && tap_newest(file_mtime(filename), tap) != tap->_inputs)
            {
                /* changed since it was loaded: the result would count as current, the next request builds again */
                error = ERROR_ABORTED;
            }
            if (error == NO_ERROR)
            {
                error = fsMoveFile(tmp_taf, tap->_filepath_resolved, true);
            }
            if (error != NO_ERROR)
            {
                TRACE_ERROR("Could not build TAP %s: %s\r\n", filename, error2text(error));
                fsDeleteFile(tmp_taf);
            }
            if (error != ERROR_ABORTED)
            {
                tap_build_failed(tap, error != NO_ERROR);
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

static void tap_build_task(void *param)
{
    char *path = param;
    tonie_audio_playlist_t tap;
    osMemset(&tap, 0, sizeof(tap));
    if (tap_load(path, &tap) == NO_ERROR && tap._valid && !tap._cached && tap_can_remux(&tap))
    {
        tap_build(path, &tap);
    }
    tap_free(&tap);

    osAcquireMutex(&tap_pending_mutex);
    for (size_t i = 0; i < TAP_BUILD_PENDING_MAX; i++)
    {
        if (tap_pending[i] == path)
        {
            tap_pending[i] = NULL;
        }
    }
    osReleaseMutex(&tap_pending_mutex);
    osFreeMem(path);
    osDeleteTask((OsTaskId)OS_SELF_TASK_ID);
}

void tap_build_later(const char *filename)
{
    char *path = NULL;
    osAcquireMutex(&tap_pending_mutex);
    bool_t pending = false;
    int slot = -1;
    for (int i = 0; i < TAP_BUILD_PENDING_MAX; i++)
    {
        pending |= tap_pending[i] != NULL && !osStrcmp(tap_pending[i], filename);
        if (tap_pending[i] == NULL && slot < 0)
        {
            slot = i;
        }
    }
    if (!pending && slot >= 0)
    {
        path = strdup(filename);
        tap_pending[slot] = path;
    }
    osReleaseMutex(&tap_pending_mutex);
    if (path == NULL)
    {
        return; /* already waiting, or too many: a later request asks again */
    }

    OsTaskParameters params = OS_TASK_DEFAULT_PARAMS;
    params.stackSize = 32 * 1024;
    if (osCreateTask("TAP build", tap_build_task, path, &params) == OS_INVALID_TASK_ID)
    {
        osAcquireMutex(&tap_pending_mutex);
        tap_pending[slot] = NULL;
        osReleaseMutex(&tap_pending_mutex);
        osFreeMem(path);
    }
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

static bool_t tap_is_separator(char c)
{
    return c == '/' || c == PATH_SEPARATOR;
}

/* path with the prefix from (the path itself or below it) as to + rest; NULL when it does not match.
   from has the native separator, playlists may hold either */
static char *tap_path_moved(const char *path, const char *from, const char *to)
{
    size_t fromLen = osStrlen(from);
    if (path == NULL)
    {
        return NULL;
    }
    for (size_t i = 0; i < fromLen; i++)
    {
        if (path[i] != from[i] && !(tap_is_separator(path[i]) && tap_is_separator(from[i])))
        {
            return NULL;
        }
    }
    char next = path[fromLen];
    if (next != '\0' && !tap_is_separator(next))
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
            osAcquireMutex(&tap_build_mutex);
            tap_rewrite_dir(lib, from, to, 0);
            osReleaseMutex(&tap_build_mutex);
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

/* scratch folders of the web UI's parts upload ("_upload-*") that a closed tab left behind */
#define TAP_UPLOAD_PREFIX "_upload-"
#define TAP_UPLOAD_MAX_AGE (24 * 60 * 60)
#define TAP_UPLOAD_SWEEP_INTERVAL (6 * 60 * 60)

/* only what the parts upload leaves: "_upload-<milliseconds since 1970 in base 36>", older than a day, with part files only */
static bool tap_stale_upload(const char *path, const char *name, time_t now)
{
    const char *stamp = name + osStrlen(TAP_UPLOAD_PREFIX);
    size_t len = osStrlen(stamp);
    if (len < 8 || len > 9 || strspn(stamp, "0123456789abcdefghijklmnopqrstuvwxyz") != len ||
        now - (time_t)(strtoll(stamp, NULL, 36) / 1000) <= TAP_UPLOAD_MAX_AGE)
    {
        return false;
    }
    FsDir *dir = fsOpenDir(path);
    if (dir == NULL)
    {
        return false;
    }
    bool parts = true;
    FsDirEntry entry;
    while (parts && fsReadDir(dir, &entry) == NO_ERROR)
    {
        const char *ext = strrchr(entry.name, '.');
        parts = !osStrcmp(entry.name, ".") || !osStrcmp(entry.name, "..") ||
                (!(entry.attributes & FS_FILE_ATTR_DIRECTORY) && ext != NULL &&
                 (!osStrcasecmp(ext, ".taf") || !osStrcasecmp(ext, ".tap") || !osStrcasecmp(ext, ".json")));
    }
    fsCloseDir(dir);
    return parts;
}

static void tap_sweep_uploads(const char *path, time_t now)
{
    FsDir *dir = fsOpenDir(path);
    if (dir == NULL)
    {
        return;
    }
    FsDirEntry entry;
    while (fsReadDir(dir, &entry) == NO_ERROR)
    {
        if (!(entry.attributes & FS_FILE_ATTR_DIRECTORY) || !osStrcmp(entry.name, ".") || !osStrcmp(entry.name, ".."))
        {
            continue;
        }
        char *child = custom_asprintf("%s%c%s", path, PATH_SEPARATOR, entry.name);
        if (osStrncmp(entry.name, TAP_UPLOAD_PREFIX, osStrlen(TAP_UPLOAD_PREFIX)) != 0)
        {
            tap_sweep_uploads(child, now);
        }
        else if (tap_stale_upload(child, entry.name, now))
        {
            TRACE_INFO("Removing the stale upload folder %s\r\n", child);
            fsRemoveTree(child);
        }
        osFreeMem(child);
    }
    fsCloseDir(dir);
}

static void tap_sweep_task(void *param)
{
    (void)param;
    while (!settings_get_bool("internal.exit"))
    {
        tap_sweep_uploads(settings_get_string("internal.librarydirfull"), time(NULL));
        for (int i = 0; i < TAP_UPLOAD_SWEEP_INTERVAL && !settings_get_bool("internal.exit"); i++)
        {
            osDelayTask(1000);
        }
    }
    osDeleteTask((OsTaskId)OS_SELF_TASK_ID);
}

void tap_sweep_uploads_start(void)
{
    OsTaskParameters params = OS_TASK_DEFAULT_PARAMS;
    params.stackSize = 32 * 1024;
    osCreateTask("Upload sweep", tap_sweep_task, NULL, &params);
}
