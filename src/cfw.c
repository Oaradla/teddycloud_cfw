#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfw_internal.h"
#include "cfw_mqtt.h"
#include "date_time.h"
#include "debug.h"
#include "fs_ext.h"
#include "handler_sse.h"
#include "mutex_manager.h"
#include "os_port.h"
#include "server_helpers.h"

#define CFW_ANSWER_LIMIT 1024
#define CFW_SYNC_INTERVAL 30
#define CFW_SYNC_UNANSWERED_MAX 3
#define CFW_ONLINE_TIMEOUT 120

#define CFW_LOG_GROUP 22
#define CFW_FUNC_HELLO 32257
#define CFW_FUNC_SETTINGS_CHANGED 32258
#define CFW_FUNC_LOCKED_GESTURE 32259
#define CFW_FUNC_REMOTE_RESULT 32260
#define CFW_FUNC_STATUS 32261
#define CFW_FUNC_BATTERY 32262

static cfw_box_t cfw_boxes[MAX_OVERLAYS];

void cfw_lock(void)
{
    mutex_lock(MUTEX_CFW);
}

void cfw_unlock(void)
{
    mutex_unlock(MUTEX_CFW);
}

/* temporary files of an earlier run (an upload, a download or a write cut off by a stop) in <firmwaredir>/cfw/ */
static void remove_temp_files(void)
{
    char *dir = custom_asprintf("%s%ccfw", get_settings()->internal.firmwaredirfull, PATH_SEPARATOR);
    FsDir *fsDir = dir ? fsOpenDir(dir) : NULL;
    FsDirEntry entry;
    while (fsDir != NULL && fsReadDir(fsDir, &entry) == NO_ERROR)
    {
        size_t length = osStrlen(entry.name);
        if (!(entry.attributes & FS_FILE_ATTR_DIRECTORY) && length > 4 && osStrcmp(&entry.name[length - 4], ".tmp") == 0)
        {
            char *path = custom_asprintf("%s%c%s", dir, PATH_SEPARATOR, entry.name);
            if (path != NULL && fsDeleteFile(path) == NO_ERROR)
            {
                TRACE_INFO("CFW: removed the leftover %s\r\n", path);
            }
            osFreeMem(path);
        }
    }
    if (fsDir != NULL)
    {
        fsCloseDir(fsDir);
    }
    osFreeMem(dir);
}

void cfw_init(void)
{
    osMemset(cfw_boxes, 0, sizeof(cfw_boxes));
    remove_temp_files();
}

/* a number of its own for each temporary file; not under the CFW lock, as cfw_write_file runs under it */
uint32_t cfw_temp_number(void)
{
    static uint32_t counter = 0;
    mutex_lock(MUTEX_CFW_TMP);
    uint32_t number = ++counter;
    mutex_unlock(MUTEX_CFW_TMP);
    return number;
}

void cfw_deinit(void)
{
    cfw_lock();
    for (size_t i = 0; i < MAX_OVERLAYS; i++)
    {
        osFreeMem(cfw_boxes[i].known);
    }
    osMemset(cfw_boxes, 0, sizeof(cfw_boxes));
    cfw_unlock();
    cfw_firmware_deinit();
}

char *cfw_dir(const char *base, const char *sub)
{
    char *dir = custom_asprintf("%s%ccfw%c%s", base, PATH_SEPARATOR, PATH_SEPARATOR, sub);
    if (dir != NULL && !fsDirExists(dir))
    {
        fsCreateDirEx(dir, true);
    }
    return dir;
}

/* the whole file; NULL when it is missing, unreadable or longer than maxLength */
uint8_t *cfw_read_file(const char *path, size_t maxLength, size_t *length)
{
    uint32_t size = 0;
    if (fsGetFileSize(path, &size) != NO_ERROR || size > maxLength)
    {
        return NULL;
    }
    uint8_t *data = osAllocMem(size + 1);
    FsFile *file = data ? fsOpenFile(path, FS_FILE_MODE_READ) : NULL;
    if (file == NULL)
    {
        osFreeMem(data);
        return NULL;
    }
    size_t total = 0;
    size_t read = 0;
    while (total < size && fsReadFile(file, &data[total], size - total, &read) == NO_ERROR && read > 0)
    {
        total += read;
    }
    fsCloseFile(file);
    if (total != size)
    {
        osFreeMem(data);
        return NULL;
    }
    data[size] = '\0';
    *length = size;
    return data;
}

/* written to a temporary file of its own first, so that a power loss never leaves a half file and two writers of
   the same file never share one */
bool cfw_write_file(const char *path, const void *data, size_t length)
{
    char *tmp = custom_asprintf("%s.%" PRIu32 ".tmp", path, cfw_temp_number());
    FsFile *file = tmp ? fsOpenFile(tmp, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC) : NULL;
    if (file == NULL)
    {
        osFreeMem(tmp);
        return false;
    }
    error_t err = fsWriteFile(file, (void *)data, length);
    fsCloseFile(file);
    if (err == NO_ERROR)
    {
        err = fsMoveFile(tmp, path, true);
    }
    if (err != NO_ERROR)
    {
        fsDeleteFile(tmp);
    }
    osFreeMem(tmp);
    return err == NO_ERROR;
}

/* the time stamp of a changed file: the newer file wins, also against a box clock ahead */
uint32_t cfw_next_timestamp(uint32_t previous)
{
    uint32_t now = (uint32_t)time(NULL);
    return now > previous ? now : previous + 1;
}

bool cfw_parse_ruid(const char *text, uint64_t *ruid)
{
    if (text == NULL || osStrlen(text) != 16)
    {
        return false;
    }
    for (size_t i = 0; i < 16; i++)
    {
        if (!isxdigit((unsigned char)text[i]))
        {
            return false;
        }
    }
    *ruid = strtoull(text, NULL, 16);
    return true;
}

void cfw_format_ruid(uint64_t ruid, char text[17])
{
    osSprintf(text, "%016" PRIX64, ruid);
}

/* tag settings files: <configdir>/cfw/tags/<RUID>.TBS */
static char *tag_path(uint64_t ruid)
{
    char text[17];
    cfw_format_ruid(ruid, text);
    char *dir = cfw_dir(get_settings()->internal.configdirfull, "tags");
    char *path = dir ? custom_asprintf("%s%c%s.TBS", dir, PATH_SEPARATOR, text) : NULL;
    osFreeMem(dir);
    return path;
}

bool cfw_store_read_tag(uint64_t ruid, uint8_t *file, size_t *length)
{
    char *path = tag_path(ruid);
    size_t size = 0;
    uint8_t *data = path ? cfw_read_file(path, CFW_TBS_MAX, &size) : NULL;
    bool valid = data != NULL && cfw_tbs_valid(data, size);
    if (valid)
    {
        osMemcpy(file, data, size);
        *length = size;
    }
    osFreeMem(data);
    osFreeMem(path);
    return valid;
}

bool cfw_store_write_tag(uint64_t ruid, const uint8_t *file, size_t length)
{
    char *path = tag_path(ruid);
    bool written = path != NULL && cfw_write_file(path, file, length);
    osFreeMem(path);
    return written;
}

bool cfw_tag_is_event(settings_t *settings, uint64_t ruid)
{
    if (settings == NULL || !settings->cfw.enabled)
    {
        return false;
    }
    uint8_t file[CFW_TBS_MAX];
    size_t length = 0;
    return cfw_store_read_tag(ruid, file, &length) && file[4] == CFW_TBS_KIND_EVENT;
}

bool cfw_tag_is_event_ruid(settings_t *settings, const char *ruid)
{
    uint64_t value;
    return cfw_parse_ruid(ruid, &value) && cfw_tag_is_event(settings, value);
}

/* the content request of an event tag: a box with the CFW runs the event and gets no content (404), any
   other box the notice file <wwwdir>/cfw/event-notice-<language>.taf */
bool cfw_event_content(HttpConnection *connection, const char_t *uri, client_ctx_t *client_ctx, const char *ruid, error_t *result)
{
    settings_t *settings = client_ctx->settings;
    if (!cfw_tag_is_event_ruid(settings, ruid))
    {
        return false;
    }
    static const char *languages[] = {"de", "en", "fr"};
    uint32_t language = settings->cfw.event_notice_language;
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    bool isCfw = box != NULL && box->isCfw;
    cfw_unlock();
    char *dir = isCfw ? NULL : cfw_dir(settings->internal.wwwdirfull, "");
    char *path = dir ? custom_asprintf("%sevent-notice-%s.taf", dir, languages[language < 3 ? language : 0]) : NULL;
    osFreeMem(dir);
    if (path != NULL && fsFileExists(path))
    {
        TRACE_INFO("CFW: tag %s is an event tag, serving the notice %s\r\n", ruid, path);
        *result = httpSendResponseStreamUnsafe(connection, uri, path, false);
    }
    else
    {
        TRACE_INFO("CFW: tag %s is an event tag, no content%s\r\n", ruid, isCfw ? "" : " (notice missing)");
        httpPrepareHeader(connection, NULL, 0);
        connection->response.statusCode = 404;
        *result = httpWriteResponse(connection, NULL, 0, false);
    }
    osFreeMem(path);
    return true;
}

size_t cfw_store_list_tags(uint64_t **ruids)
{
    size_t count = 0;
    size_t size = 0;
    *ruids = NULL;

    char *dir = cfw_dir(get_settings()->internal.configdirfull, "tags");
    FsDir *fsDir = dir ? fsOpenDir(dir) : NULL;
    osFreeMem(dir);
    if (fsDir == NULL)
    {
        return 0;
    }
    FsDirEntry entry;
    while (fsReadDir(fsDir, &entry) == NO_ERROR)
    {
        char text[17];
        uint64_t ruid;
        if ((entry.attributes & FS_FILE_ATTR_DIRECTORY) || osStrlen(entry.name) != 20 || osStrcasecmp(&entry.name[16], ".TBS"))
        {
            continue;
        }
        osStrncpy(text, entry.name, 16);
        text[16] = '\0';
        if (!cfw_parse_ruid(text, &ruid))
        {
            continue;
        }
        if (count == size)
        {
            size = size ? size * 2 : 16;
            uint64_t *grown = osAllocMem(size * sizeof(uint64_t));
            if (grown == NULL)
            {
                break;
            }
            if (count > 0)
            {
                osMemcpy(grown, *ruids, count * sizeof(uint64_t));
            }
            osFreeMem(*ruids);
            *ruids = grown;
        }
        (*ruids)[count++] = ruid;
    }
    fsCloseDir(fsDir);
    return count;
}

/* box state: <configdir>/cfw/boxes/<box>.json (box ids are sanitized by the settings) */
static char *box_state_path(const char *boxId)
{
    char *dir = cfw_dir(get_settings()->internal.configdirfull, "boxes");
    char *path = dir ? custom_asprintf("%s%c%s.json", dir, PATH_SEPARATOR, boxId) : NULL;
    osFreeMem(dir);
    return path;
}

static double json_number(cJSON *json, const char *name)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, name);
    return cJSON_IsNumber(item) ? item->valuedouble : 0;
}

static void box_load(cfw_box_t *box)
{
    char *path = box_state_path(box->id);
    size_t length = 0;
    char *text = path ? (char *)cfw_read_file(path, 4096, &length) : NULL;
    cJSON *json = text ? cJSON_Parse(text) : NULL;
    osFreeMem(text);
    osFreeMem(path);
    if (json == NULL)
    {
        return;
    }
    box->isCfw = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "isCfw"));
    box->version = json_number(json, "version");
    box->capabilities = json_number(json, "capabilities");
    box->updateResult = json_number(json, "updateResult");
    box->rolledBackBuild = json_number(json, "rolledBackBuild");
    box->helloTime = json_number(json, "helloTime");
    box->helloUptime = json_number(json, "helloUptime");
    box->helloSequence = json_number(json, "helloSequence");
    box->offeredBuild = json_number(json, "offeredBuild");
    box->esp32Delivered = json_number(json, "esp32Delivered");
    box->pageVersion = json_number(json, "pageVersion");
    box->esp32 = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "esp32"));
    box->offerTime = json_number(json, "offerTime");
    box->offerAttempts = json_number(json, "offerAttempts");
    box->offerStarted = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "offerStarted"));
    cJSON *build;
    cJSON_ArrayForEach(build, cJSON_GetObjectItemCaseSensitive(json, "rolledBack"))
    {
        if (box->rolledBackCount < CFW_ROLLED_BACK_MAX && cJSON_IsNumber(build))
        {
            box->rolledBack[box->rolledBackCount++] = build->valuedouble;
        }
    }
    box->globalTimestamp = json_number(json, "globalTimestamp");
    box->globalOrigin = json_number(json, "globalOrigin");
    cJSON *byte;
    cJSON_ArrayForEach(byte, cJSON_GetObjectItemCaseSensitive(json, "globalBody"))
    {
        if (box->globalLength < sizeof(box->globalBody) && cJSON_IsNumber(byte))
        {
            box->globalBody[box->globalLength++] = (uint8_t)byte->valueint;
        }
    }
    cJSON_Delete(json);
}

void cfw_box_seen_request(settings_t *settings, uint32_t build, uint32_t cfwBuild)
{
    if (!settings->cfw.enabled)
    {
        return;
    }
    /* only the CFW sends X-CFW-Build, with its own build; without it the request is the original
       firmware's, with the build of its User-Agent (none for the ESP32) */
    bool isCfw = cfwBuild != 0;
    uint32_t version = isCfw ? cfwBuild : build;
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box != NULL && (box->isCfw != isCfw || box->version != version))
    {
        if (box->isCfw != isCfw)
        {
            TRACE_INFO("CFW: box %s runs the %s firmware (build %" PRIu32 ")\r\n", box->id, isCfw ? "custom" : "original", version);
        }
        if (!isCfw)
        {
            box->helloValid = false;
        }
        box->isCfw = isCfw;
        box->version = version;
        cfw_box_save(box);
    }
    cfw_unlock();
}

/* the Host header of the last accepted box request: the name or address under which the boxes reach
   this server, offered when a new box is set up (behind a reverse proxy the web address differs) */
static char box_host[96];

void cfw_box_host_seen(const char *host)
{
    if (host == NULL || host[0] == '\0')
    {
        return;
    }
    cfw_lock();
    osStrncpy(box_host, host, sizeof(box_host) - 1);
    box_host[sizeof(box_host) - 1] = '\0';
    cfw_unlock();
}

void cfw_box_host_get(char *host, size_t size)
{
    cfw_lock();
    osStrncpy(host, box_host, size - 1);
    host[size - 1] = '\0';
    cfw_unlock();
}

void cfw_box_seen_platform(settings_t *settings)
{
    settings_box_type ic = settings->internal.toniebox_firmware.boxIC;
    if (!settings->cfw.enabled || (ic != BOX_ESP32 && ic != BOX_CC3200 && ic != BOX_CC3235))
    {
        return;
    }
    bool esp32 = ic == BOX_ESP32;
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box != NULL && box->esp32 != esp32)
    {
        box->esp32 = esp32;
        cfw_box_save(box);
    }
    cfw_unlock();
}

void cfw_box_save(cfw_box_t *box)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "isCfw", box->isCfw);
    cJSON_AddNumberToObject(json, "version", box->version);
    cJSON_AddNumberToObject(json, "capabilities", box->capabilities);
    cJSON_AddNumberToObject(json, "updateResult", box->updateResult);
    cJSON_AddNumberToObject(json, "rolledBackBuild", box->rolledBackBuild);
    cJSON_AddNumberToObject(json, "helloTime", (double)box->helloTime);
    cJSON_AddNumberToObject(json, "helloUptime", (double)box->helloUptime);
    cJSON_AddNumberToObject(json, "helloSequence", box->helloSequence);
    cJSON_AddNumberToObject(json, "offeredBuild", box->offeredBuild);
    cJSON_AddNumberToObject(json, "esp32Delivered", box->esp32Delivered);
    cJSON_AddNumberToObject(json, "pageVersion", box->pageVersion);
    cJSON_AddBoolToObject(json, "esp32", box->esp32);
    cJSON_AddNumberToObject(json, "offerTime", (double)box->offerTime);
    cJSON_AddNumberToObject(json, "offerAttempts", box->offerAttempts);
    cJSON_AddBoolToObject(json, "offerStarted", box->offerStarted);
    cJSON *rolledBack = cJSON_AddArrayToObject(json, "rolledBack");
    for (size_t i = 0; i < box->rolledBackCount; i++)
    {
        cJSON_AddItemToArray(rolledBack, cJSON_CreateNumber(box->rolledBack[i]));
    }
    cJSON_AddNumberToObject(json, "globalTimestamp", box->globalTimestamp);
    cJSON_AddNumberToObject(json, "globalOrigin", box->globalOrigin);
    cJSON *body = cJSON_AddArrayToObject(json, "globalBody");
    for (size_t i = 0; i < box->globalLength; i++)
    {
        cJSON_AddItemToArray(body, cJSON_CreateNumber(box->globalBody[i]));
    }
    char *text = cJSON_Print(json);
    cJSON_Delete(json);

    char *path = box_state_path(box->id);
    if (text == NULL || path == NULL || !cfw_write_file(path, text, osStrlen(text)))
    {
        TRACE_ERROR("CFW: could not save the state of box %s\r\n", box->id);
    }
    osFreeMem(path);
    osFreeMem(text);
}

cfw_box_t *cfw_box_get(settings_t *settings)
{
    uint8_t number = settings->internal.overlayNumber;
    const char *id = settings->internal.overlayUniqueId;
    if (number == 0 || number >= MAX_OVERLAYS || id == NULL || id[0] == '\0')
    {
        return NULL;
    }
    cfw_box_t *box = &cfw_boxes[number];
    if (box->loaded && osStrcmp(box->id, id) != 0)
    {
        /* the overlay now belongs to another box */
        osFreeMem(box->known);
        osMemset(box, 0, sizeof(*box));
    }
    if (!box->loaded)
    {
        osStrncpy(box->id, id, sizeof(box->id) - 1);
        box_load(box);
        box->loaded = true;
    }
    return box;
}

bool cfw_box_is_rolled_back(const cfw_box_t *box, uint32_t build)
{
    for (size_t i = 0; i < box->rolledBackCount; i++)
    {
        if (box->rolledBack[i] == build)
        {
            return true;
        }
    }
    return false;
}

/* the builds the box rolled back are not offered again (the oldest is forgotten when the list is full);
   one that runs later is taken off the list; the rollback shown for the box ends once it runs that build
   or a newer one */
void cfw_box_rolled_back(cfw_box_t *box, uint32_t build, bool rolledBack)
{
    if (!rolledBack && build >= box->rolledBackBuild)
    {
        box->rolledBackBuild = 0;
    }
    for (size_t i = 0; i < box->rolledBackCount; i++)
    {
        if (box->rolledBack[i] == build)
        {
            box->rolledBack[i] = box->rolledBack[--box->rolledBackCount];
        }
    }
    if (rolledBack)
    {
        if (box->rolledBackCount == CFW_ROLLED_BACK_MAX)
        {
            osMemmove(&box->rolledBack[0], &box->rolledBack[1], (CFW_ROLLED_BACK_MAX - 1) * sizeof(uint32_t));
            box->rolledBackCount--;
        }
        box->rolledBack[box->rolledBackCount++] = build;
        box->rolledBackBuild = build;
    }
}

bool cfw_box_online(const cfw_box_t *box)
{
    return box->lastLogTime != 0 && time(NULL) - box->lastLogTime < CFW_ONLINE_TIMEOUT;
}

/* the version of each settings file the box holds, as far as the server knows; in memory only, so after
   a server restart every box gets every file once more */
static bool known_get(const cfw_box_t *box, uint64_t ruid, uint32_t *timestamp)
{
    for (size_t i = 0; i < box->knownCount; i++)
    {
        if (box->known[i].ruid == ruid)
        {
            *timestamp = box->known[i].timestamp;
            return true;
        }
    }
    return false;
}

static void known_set(cfw_box_t *box, uint64_t ruid, uint32_t timestamp)
{
    for (size_t i = 0; i < box->knownCount; i++)
    {
        if (box->known[i].ruid == ruid)
        {
            box->known[i].timestamp = timestamp;
            return;
        }
    }
    if (box->knownCount == box->knownSize)
    {
        size_t size = box->knownSize ? box->knownSize * 2 : 32;
        cfw_known_t *grown = osAllocMem(size * sizeof(cfw_known_t));
        if (grown == NULL)
        {
            return;
        }
        if (box->knownCount > 0)
        {
            osMemcpy(grown, box->known, box->knownCount * sizeof(cfw_known_t));
        }
        osFreeMem(box->known);
        box->known = grown;
        box->knownSize = size;
    }
    box->known[box->knownCount].ruid = ruid;
    box->known[box->knownCount].timestamp = timestamp;
    box->knownCount++;
}

static void known_forget(cfw_box_t *box, uint64_t ruid)
{
    for (size_t i = 0; i < box->knownCount; i++)
    {
        if (box->known[i].ruid == ruid)
        {
            box->known[i] = box->known[--box->knownCount];
            return;
        }
    }
}

/* the original firmware limits the volume to step 6, 9, 12 or 15: the nearest one */
static uint32_t step_to_quarter(uint32_t step)
{
    if (step <= 7)
    {
        return 0;
    }
    if (step <= 10)
    {
        return 1;
    }
    return step <= 13 ? 2 : 3;
}

bool cfw_is_derived_setting(settings_t *settings, const char *name)
{
    if (!settings->cfw.enabled || (!get_settings()->cfw.show_box_settings && !settings->cfw.force_box_settings))
    {
        return false;
    }
    if (osStrcmp(name, "toniebox.max_vol_spk") && osStrcmp(name, "toniebox.max_vol_hdp") && osStrcmp(name, "toniebox.slap_enabled"))
    {
        return false;
    }
    if (settings->internal.overlayNumber == 0)
    {
        return true;
    }
    setting_item_t *option = settings_get_by_name_ovl(name, settings->internal.overlayUniqueId);
    return option == NULL || !option->overlayed;
}

uint32_t cfw_derived_setting(settings_t *settings, const char *name, uint32_t value)
{
    if (!cfw_is_derived_setting(settings, name))
    {
        return value;
    }
    if (!osStrcmp(name, "toniebox.max_vol_spk"))
    {
        return step_to_quarter(settings->cfw.box.speaker_limit);
    }
    if (!osStrcmp(name, "toniebox.max_vol_hdp"))
    {
        return step_to_quarter(settings->cfw.box.headphone_limit);
    }
    return !settings->cfw.box.slap_lock;
}

/* the box-wide settings as global file body */
static size_t global_body(settings_t *settings, uint8_t *body)
{
    const uint8_t values[][2] = {
        {0x04, (uint8_t)settings->cfw.box.speaker_limit},
        {0x05, (uint8_t)settings->cfw.box.headphone_limit},
        {0x06, (uint8_t)settings->toniebox.led},
        {0x07, settings->cfw.box.both_ears_off},
        {0x08, settings->cfw.box.slap_lock},
        {0x09, settings->cfw.box.tilt_lock},
        {0x0A, settings->cfw.box.volume_lock},
    };
    size_t n = 0;
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        body[n++] = values[i][0];
        body[n++] = 1;
        body[n++] = values[i][1];
    }
    return n;
}

/* the global file of the box; a change of its settings gives it a new time stamp */
static size_t global_file(cfw_box_t *box, settings_t *settings, uint8_t *file)
{
    uint8_t body[sizeof(box->globalBody)];
    size_t length = global_body(settings, body);
    if (length != box->globalLength || osMemcmp(body, box->globalBody, length) != 0)
    {
        osMemcpy(box->globalBody, body, length);
        box->globalLength = length;
        box->globalTimestamp = cfw_next_timestamp(box->globalTimestamp);
        box->globalOrigin = CFW_TBS_ORIGIN_SERVER;
        cfw_box_save(box);
    }
    return cfw_tbs_build(CFW_TBS_KIND_GLOBAL, box->globalOrigin, box->globalTimestamp, body, length, file);
}

/* the file the box should get for this ruid (0: the global file), adapted to its capabilities */
static bool due_file(cfw_box_t *box, settings_t *settings, uint64_t ruid, uint8_t *file, size_t *length)
{
    uint8_t stored[CFW_TBS_MAX];
    size_t storedLength = 0;
    if (ruid == 0)
    {
        storedLength = global_file(box, settings, stored);
    }
    else if (!cfw_store_read_tag(ruid, stored, &storedLength))
    {
        return false;
    }
    uint32_t known;
    if (known_get(box, ruid, &known) && cfw_tbs_timestamp(stored) <= known)
    {
        return false;
    }
    if (stored[4] == CFW_TBS_KIND_EVENT && !(box->capabilities & CFW_CAP_EVENT_TAG_EXT))
    {
        *length = (box->capabilities & CFW_CAP_EVENT_TAGS) ? cfw_event_for_basic_box(stored, file) : 0;
        return *length > 0;
    }
    osMemcpy(file, stored, storedLength);
    *length = storedLength;
    return true;
}

static bool box_has_pending(cfw_box_t *box, settings_t *settings)
{
    uint8_t file[CFW_TBS_MAX];
    size_t length;
    bool pending = due_file(box, settings, 0, file, &length);
    uint64_t *ruids = NULL;
    size_t count = pending ? 0 : cfw_store_list_tags(&ruids);
    for (size_t i = 0; i < count && !pending; i++)
    {
        pending = due_file(box, settings, ruids[i], file, &length);
    }
    osFreeMem(ruids);
    return pending;
}

static size_t put_varint(uint8_t *out, uint64_t value)
{
    size_t n = 0;
    do
    {
        out[n] = value & 0x7F;
        value >>= 7;
        out[n++] |= value ? 0x80 : 0;
    } while (value);
    return n;
}

/* field 100: the UID bytes B0 ... B7 and the file */
static bool append_file(uint8_t *buffer, size_t *length, size_t limit, uint64_t ruid, const uint8_t *file, size_t fileLength)
{
    uint8_t header[16];
    size_t headerLength = put_varint(header, (100 << 3) | 2);
    headerLength += put_varint(&header[headerLength], 8 + fileLength);
    if (*length + headerLength + 8 + fileLength > limit)
    {
        return false;
    }
    osMemcpy(&buffer[*length], header, headerLength);
    cfw_ruid_to_bytes(ruid, &buffer[*length + headerLength]);
    osMemcpy(&buffer[*length + headerLength + 8], file, fileLength);
    *length += headerLength + 8 + fileLength;
    return true;
}

size_t cfw_freshness_finalize(client_ctx_t *client_ctx, uint8_t *buffer, size_t length, size_t cap)
{
    settings_t *settings = client_ctx->settings;
    if (!settings->cfw.enabled)
    {
        return length;
    }
    size_t limit = cap < CFW_ANSWER_LIMIT ? cap : CFW_ANSWER_LIMIT;

    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box != NULL && box->helloValid)
    {
        length = cfw_strip_volume_fields(buffer, length);
    }

    /* the hello: field 101 = 1 */
    uint8_t hello[4];
    size_t helloLength = put_varint(hello, 101 << 3);
    helloLength += put_varint(&hello[helloLength], 1);
    if (length + helloLength <= limit)
    {
        osMemcpy(&buffer[length], hello, helloLength);
        length += helloLength;
    }

    if (box != NULL)
    {
        box->syncUnanswered = 0;
    }
    if (box != NULL && box->isCfw && settings->cfw.settings_sync)
    {
        uint8_t file[CFW_TBS_MAX];
        size_t fileLength;
        size_t due = 0;
        size_t sent = 0;
        if (due_file(box, settings, 0, file, &fileLength))
        {
            due++;
            if (append_file(buffer, &length, limit, 0, file, fileLength))
            {
                known_set(box, 0, cfw_tbs_timestamp(file));
                sent++;
            }
        }
        uint64_t *ruids = NULL;
        size_t count = cfw_store_list_tags(&ruids);
        for (size_t i = 0; i < count; i++)
        {
            if (!due_file(box, settings, ruids[i], file, &fileLength))
            {
                continue;
            }
            due++;
            /* what does not fit follows in a later answer (log-host command 6) */
            if (!append_file(buffer, &length, limit, ruids[i], file, fileLength))
            {
                break;
            }
            known_set(box, ruids[i], cfw_tbs_timestamp(file));
            sent++;
        }
        osFreeMem(ruids);
        /* a file that does not even fit beside the hello would ask for command 6 every 30 s for ever */
        box->syncStalled = due > 0 && sent == 0;
        if (box->syncStalled)
        {
            TRACE_WARNING("CFW: box %s: %" PRIuSIZE " settings file(s) due, none fits into the freshness-check answer\r\n", box->id, due);
        }
    }
    cfw_unlock();
    return length;
}

/* a profile written by the box: the newer file wins */
static void store_tag_report(cfw_box_t *box, uint64_t ruid, const uint8_t *body, size_t bodyLength, uint32_t timestamp)
{
    uint8_t current[CFW_TBS_MAX];
    size_t currentLength;
    bool haveCurrent = cfw_store_read_tag(ruid, current, &currentLength);
    char text[17];
    cfw_format_ruid(ruid, text);
    if (haveCurrent && current[4] == CFW_TBS_KIND_EVENT)
    {
        TRACE_WARNING("CFW: box %s reported a profile for event tag %s, ignored\r\n", box->id, text);
    }
    else if (!haveCurrent || cfw_tbs_timestamp(current) <= timestamp)
    {
        uint8_t file[CFW_TBS_MAX];
        size_t fileLength = cfw_tbs_build(CFW_TBS_KIND_PROFILE, CFW_TBS_ORIGIN_BOX, timestamp, body, bodyLength, file);
        if (!cfw_store_write_tag(ruid, file, fileLength))
        {
            TRACE_ERROR("CFW: could not store the settings of %s\r\n", text);
        }
    }
    known_set(box, ruid, timestamp);
}

static void reset_box_setting(const char *name, const char *overlay)
{
    setting_item_t *option = settings_get_by_name_ovl(name, overlay);
    setting_item_t *global = settings_get_by_name(name);
    if (option != NULL && global != NULL && option != global)
    {
        overlay_settings_init_opt(option, global);
    }
}

/* the box changed its box-wide settings with an event tag: they become settings of this box; a record the
   box removed (mode clear) gives the box teddyCloud's value again */
static void apply_global_report(settings_t *settings, const uint8_t *body, size_t length, uint32_t timestamp)
{
    if (length > sizeof(((cfw_box_t *)0)->globalBody))
    {
        TRACE_WARNING("CFW: box %s reported box settings of %" PRIuSIZE " bytes, ignored\r\n", settings->internal.overlayUniqueId, length);
        return;
    }
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    uint8_t file[CFW_TBS_MAX];
    bool older = box == NULL || (global_file(box, settings, file) > 0 && box->globalTimestamp > timestamp);
    if (box != NULL && older)
    {
        known_set(box, 0, timestamp);
    }
    cfw_unlock();
    if (older)
    {
        return;
    }

    static const struct
    {
        uint8_t key;
        const char *name;
        bool isBool;
    } box_settings[] = {
        {0x04, "cfw.box.speaker_limit", false},
        {0x05, "cfw.box.headphone_limit", false},
        {0x06, "toniebox.led", false},
        {0x07, "cfw.box.both_ears_off", true},
        {0x08, "cfw.box.slap_lock", true},
        {0x09, "cfw.box.tilt_lock", true},
        {0x0A, "cfw.box.volume_lock", true},
    };
    const char *overlay = settings->internal.overlayUniqueId;
    for (size_t i = 0; i < sizeof(box_settings) / sizeof(box_settings[0]); i++)
    {
        const uint8_t *value = NULL;
        for (size_t pos = 0; pos + 3 <= length; pos += 3)
        {
            if (body[pos] == box_settings[i].key)
            {
                value = &body[pos + 2];
            }
        }
        if (value == NULL)
        {
            reset_box_setting(box_settings[i].name, overlay);
        }
        else if (box_settings[i].isBool)
        {
            settings_set_bool_ovl(box_settings[i].name, *value != 0, overlay);
        }
        else
        {
            settings_set_unsigned_ovl(box_settings[i].name, *value, overlay);
        }
    }
    settings_save();

    /* the box holds the reported file; if the settings now differ, the next file gets a new time stamp */
    cfw_lock();
    box = cfw_box_get(settings);
    if (box != NULL)
    {
        osMemcpy(box->globalBody, body, length);
        box->globalLength = length;
        box->globalTimestamp = timestamp;
        box->globalOrigin = CFW_TBS_ORIGIN_BOX;
        cfw_box_save(box);
        known_set(box, 0, timestamp);
    }
    cfw_unlock();
    TRACE_INFO("CFW: box %s changed its box settings\r\n", overlay);
}

/* the CFW settings are hidden until the first box with the CFW connects; then they are shown once, and
   the old global values are taken over: 25/50/75/100 % -> step 6/9/12/15, slap to skip off -> slap lock */
static void show_settings_once(void)
{
    char *dir = cfw_dir(get_settings()->internal.configdirfull, "");
    char *marker = dir ? custom_asprintf("%sshown", dir) : NULL;
    osFreeMem(dir);
    if (marker == NULL || fsFileExists(marker))
    {
        osFreeMem(marker);
        return;
    }
    settings_t *settings = get_settings();
    if (!settings->cfw.show_box_settings)
    {
        if (settings->cfw.box.speaker_limit == 15 && settings->toniebox.max_vol_spk < 3)
        {
            settings_set_unsigned("cfw.box.speaker_limit", settings->toniebox.max_vol_spk * 3 + 6);
        }
        if (settings->cfw.box.headphone_limit == 15 && settings->toniebox.max_vol_hdp < 3)
        {
            settings_set_unsigned("cfw.box.headphone_limit", settings->toniebox.max_vol_hdp * 3 + 6);
        }
        if (!settings->cfw.box.slap_lock && !settings->toniebox.slap_enabled)
        {
            settings_set_bool("cfw.box.slap_lock", true);
        }
    }
    settings_set_bool("cfw.show_tag_settings", true);
    settings_set_bool("cfw.show_box_settings", true);
    settings_save();
    cfw_write_file(marker, "1\n", 2);
    osFreeMem(marker);
    TRACE_INFO("CFW: first box with the custom firmware, its settings are shown now\r\n");
}

/* a new start of the box ends the hello of the last one; the sequence numbers start at 1 at
   every start. After a server restart, records continuing the start of the hello revive it. */
static void track_start(cfw_box_t *box, const TonieRtnlLog2 *log2)
{
    if (log2->sequence < box->lastSequence || log2->uptime < box->lastUptime)
    {
        box->helloValid = false;
        box->queueCount = 0;
        box->statusValid = false;
    }
    else if (box->lastSequence == 0 && box->helloSequence != 0 && log2->sequence > box->helloSequence && log2->uptime >= box->helloUptime)
    {
        box->helloValid = true;
    }
    box->lastSequence = log2->sequence;
    box->lastUptime = log2->uptime;
    box->lastLogTime = time(NULL);
}

/* one line per battery report in <configdir>/cfw/battery/<box>.csv; a file over 4 MB is moved to <box>.old.csv */
#define CFW_BATTERY_LOG_MAX (4 * 1024 * 1024)

static void battery_log(const char *boxId, const uint32_t battery[5], time_t now, uint64_t uptime, uint32_t build)
{
    char *dir = cfw_dir(get_settings()->internal.configdirfull, "battery");
    char *path = dir ? custom_asprintf("%s%c%s.csv", dir, PATH_SEPARATOR, boxId) : NULL;
    if (path == NULL)
    {
        osFreeMem(dir);
        return;
    }
    uint32_t size = 0;
    bool exists = fsGetFileSize(path, &size) == NO_ERROR;
    if (exists && size > CFW_BATTERY_LOG_MAX)
    {
        char *old = custom_asprintf("%s%c%s.old.csv", dir, PATH_SEPARATOR, boxId);
        if (old != NULL)
        {
            fsDeleteFile(old);
            fsRenameFile(path, old);
            exists = false;
        }
        osFreeMem(old);
    }
    osFreeMem(dir);

    FsFile *file = fsOpenFileEx(path, "ab");
    if (file == NULL)
    {
        TRACE_ERROR("CFW: could not write the battery log %s\r\n", path);
        osFreeMem(path);
        return;
    }
    char line[192];
    if (!exists)
    {
        const char *header = "time,mv,station,low,critical,implausible,reason,state,step,headphones,adc,uptime_ms,build\n";
        fsWriteFile(file, (void *)header, osStrlen(header));
    }
    DateTime date;
    convertUnixTimeToDate(now, &date);
    char stamp[32];
    osSnprintf(stamp, sizeof(stamp), "%04u-%02u-%02uT%02u:%02u:%02uZ", date.year, date.month, date.day, date.hours,
               date.minutes, date.seconds);
    uint32_t flags = battery[1], load = battery[3];
    osSnprintf(line, sizeof(line), "%s,%" PRIu32 ",%u,%u,%u,%u,%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%u,%" PRIu32 ",%" PRIu64 ",%" PRIu32 "\n",
               stamp, battery[0], (unsigned)(flags & 1), (unsigned)((flags >> 1) & 1), (unsigned)((flags >> 2) & 1), (unsigned)((flags >> 3) & 1),
               battery[2], load & 0xFF, (load >> 8) & 0xFF, (unsigned)((load >> 16) & 1), battery[4], uptime, build);
    fsWriteFile(file, line, osStrlen(line));
    fsCloseFile(file);
    osFreeMem(path);
}

void cfw_rtnl_record(client_ctx_t *client_ctx, const TonieRtnlLog2 *log2)
{
    settings_t *settings = client_ctx->settings;
    if (!settings->cfw.enabled)
    {
        return;
    }
    const uint8_t *payload = log2->field6.data;
    size_t length = log2->field6.len;
    char event[256] = "";
    const char *eventName = NULL;
    bool eventIsText = false;
    bool hello = false;
    uint8_t globalBody[64];
    size_t globalLength = 0;
    uint32_t globalTimestamp = 0;
    bool batteryReport = false;
    bool statusReport = false;
    uint32_t status[sizeof(((cfw_box_t *)0)->status) / sizeof(uint32_t)];
    uint32_t battery[5];
    char boxId[sizeof(((cfw_box_t *)0)->id)];
    uint32_t build = 0;

    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box == NULL)
    {
        cfw_unlock();
        return;
    }
    track_start(box, log2);
    if (log2->function_group != CFW_LOG_GROUP)
    {
        cfw_unlock();
        return;
    }
    switch (log2->function)
    {
    case CFW_FUNC_HELLO:
        if (length >= 8)
        {
            box->version = cfw_le32(&payload[0]);
            box->capabilities = cfw_le32(&payload[4]);
            box->updateResult = length >= 12 ? cfw_le32(&payload[8]) : 0;
            if (length >= 16 && cfw_le32(&payload[12]) != 0)
            {
                cfw_box_rolled_back(box, cfw_le32(&payload[12]), true);
            }
            cfw_box_rolled_back(box, box->version, false);
            box->helloValid = true;
            box->helloUptime = log2->uptime;
            box->helloSequence = log2->sequence;
            box->helloTime = time(NULL);
            box->isCfw = true;
            cfw_box_save(box);
            hello = true;
            eventName = "cfw-hello";
            osSnprintf(event, sizeof(event), "{\"box\":\"%s\",\"version\":%" PRIu32 ",\"capabilities\":%" PRIu32 "}", box->id, box->version, box->capabilities);
            TRACE_INFO("CFW: box %s answered the hello: build %" PRIu32 ", capabilities 0x%04" PRIX32 ", update result %" PRIu32 "\r\n", box->id, box->version, box->capabilities, box->updateResult);
        }
        break;
    case CFW_FUNC_SETTINGS_CHANGED:
        if (length >= 20 && settings->cfw.settings_sync)
        {
            uint64_t ruid = cfw_ruid_from_bytes(payload);
            uint32_t packed = cfw_le32(&payload[8]);
            uint32_t timestamp = cfw_le32(&payload[16]);
            uint8_t kind = packed & 3;
            uint8_t body[64];
            size_t bodyLength = cfw_report_body(packed, cfw_le32(&payload[12]), body);
            if (kind == CFW_TBS_KIND_PROFILE && ruid != 0)
            {
                store_tag_report(box, ruid, body, bodyLength, timestamp);
                eventName = "cfw-settings";
                eventIsText = true;
                cfw_format_ruid(ruid, event);
            }
            else if (kind == CFW_TBS_KIND_GLOBAL && ruid == 0)
            {
                osMemcpy(globalBody, body, bodyLength);
                globalLength = bodyLength;
                globalTimestamp = timestamp;
                eventName = "cfw-settings";
                eventIsText = true;
                osStrncpy(event, box->id, sizeof(event) - 1);
            }
        }
        break;
    case CFW_FUNC_LOCKED_GESTURE:
        if (length >= 8)
        {
            box->lockedGesture = cfw_le32(&payload[0]);
            box->lockedSource = cfw_le32(&payload[4]);
            box->lockedTime = time(NULL);
            eventName = "cfw-locked";
            osSnprintf(event, sizeof(event), "{\"box\":\"%s\",\"gesture\":%" PRIu32 ",\"source\":%" PRIu32 "}", box->id, box->lockedGesture, box->lockedSource);
        }
        break;
    case CFW_FUNC_REMOTE_RESULT:
        if (length >= 12)
        {
            box->lastCommand = cfw_le32(&payload[0]);
            box->lastResult = cfw_le32(&payload[8]);
            box->lastResultTime = time(NULL);
            eventName = "cfw-result";
            osSnprintf(event, sizeof(event), "{\"box\":\"%s\",\"command\":%" PRIu32 ",\"result\":%" PRIu32 "}", box->id, box->lastCommand, box->lastResult);
        }
        break;
    case CFW_FUNC_STATUS:
        if (length >= sizeof(box->status))
        {
            for (size_t i = 0; i < sizeof(box->status) / sizeof(box->status[0]); i++)
            {
                box->status[i] = cfw_le32(&payload[4 * i]);
            }
            box->statusValid = true;
            box->statusTime = time(NULL);
            osMemcpy(status, box->status, sizeof(status));
            statusReport = true;
            eventName = "cfw-status";
            osSnprintf(event, sizeof(event), "{\"box\":\"%s\",\"state\":%" PRIu32 "}", box->id, box->status[0]);
        }
        break;
    case CFW_FUNC_BATTERY:
        if (length >= sizeof(box->battery))
        {
            for (size_t i = 0; i < sizeof(box->battery) / sizeof(box->battery[0]); i++)
            {
                box->battery[i] = cfw_le32(&payload[4 * i]);
            }
            box->batteryValid = true;
            box->batteryTime = time(NULL);
            batteryReport = settings->cfw.battery_log;
            osMemcpy(battery, box->battery, sizeof(battery));
            osStrncpy(boxId, box->id, sizeof(boxId) - 1);
            boxId[sizeof(boxId) - 1] = 0;
            build = box->version;
            eventName = "cfw-battery";
            osSnprintf(event, sizeof(event), "{\"box\":\"%s\",\"mv\":%" PRIu32 ",\"station\":%s}", box->id, box->battery[0], (box->battery[1] & 1) ? "true" : "false");
            TRACE_DEBUG("CFW: box %s battery %" PRIu32 " mV, flags 0x%" PRIX32 ", reason %" PRIu32 "\r\n", box->id, box->battery[0], box->battery[1], box->battery[2]);
        }
        break;
    default:
        break;
    }
    cfw_unlock();

    if (statusReport)
    {
        cfw_mqtt_status(client_ctx, status);
    }
    if (batteryReport)
    {
        battery_log(boxId, battery, time(NULL), log2->uptime, build);
    }
    if (globalLength > 0)
    {
        apply_global_report(settings, globalBody, globalLength, globalTimestamp);
    }
    if (eventName != NULL)
    {
        sse_sendEvent(eventName, event, eventIsText);
    }
    if (hello)
    {
        show_settings_once();
    }
}

uint_t cfw_remote_send(settings_t *settings, uint8_t command, const uint8_t *args, size_t argsLength, char *message, size_t messageSize)
{
    uint_t status = 409;
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (!get_settings()->cfw.enabled || !settings->cfw.enabled || !settings->cfw.remote_control)
    {
        osSnprintf(message, messageSize, "remote control is switched off for this box");
    }
    else if (box == NULL || !box->helloValid)
    {
        osSnprintf(message, messageSize, "the box is not connected with the custom firmware");
    }
    else if (!(box->capabilities & CFW_CAP_REMOTE))
    {
        osSnprintf(message, messageSize, "the firmware of the box has no remote control");
    }
    else if (!cfw_remote_queue(box, command, args, argsLength))
    {
        status = 429;
        osSnprintf(message, messageSize, "too many commands waiting");
    }
    else
    {
        status = 200;
        osSnprintf(message, messageSize, "OK");
    }
    cfw_unlock();
    return status;
}

bool cfw_remote_queue(cfw_box_t *box, uint8_t command, const uint8_t *args, size_t argsLength)
{
    if (box->queueCount >= CFW_REMOTE_QUEUE || argsLength > CFW_REMOTE_ARGS_MAX)
    {
        return false;
    }
    cfw_remote_t *entry = &box->queue[box->queueCount++];
    entry->command = command;
    entry->argsLength = argsLength;
    if (argsLength > 0)
    {
        osMemcpy(entry->args, args, argsLength);
    }
    return true;
}

/* command frame: a 4-byte big-endian length that counts itself, field 1 the command, field 3 the
   arguments; no sequence number */
static size_t build_frame(uint8_t *frame, uint8_t command, const uint8_t *args, size_t argsLength)
{
    size_t n = 4;
    n += put_varint(&frame[n], 1 << 3);
    n += put_varint(&frame[n], command);
    if (argsLength > 0)
    {
        n += put_varint(&frame[n], (3 << 3) | 2);
        n += put_varint(&frame[n], argsLength);
        osMemcpy(&frame[n], args, argsLength);
        n += argsLength;
    }
    frame[0] = (n >> 24) & 0xFF;
    frame[1] = (n >> 16) & 0xFF;
    frame[2] = (n >> 8) & 0xFF;
    frame[3] = n & 0xFF;
    return n;
}

/* the next frame for the box, at most one per call: a box without F12 reads one frame of up to 15 bytes
   per check. A settings file sent with command 64 counts as held by the box. */
static size_t next_frame(cfw_box_t *box, settings_t *settings, bool received, uint8_t *frame, cfw_remote_t *sent)
{
    time_t now = time(NULL);
    bool remote = (box->capabilities & CFW_CAP_REMOTE) && settings->cfw.remote_control;

    /* command 6 only in reply to log data, at most every 30 s and only with files due */
    /* not when the last answer could take none of the due files, and not again after three that the box left
       without a freshness check: until the next freshness check */
    if (received && settings->cfw.settings_sync && now - box->lastSyncCommand >= CFW_SYNC_INTERVAL && !box->syncStalled &&
        box->syncUnanswered < CFW_SYNC_UNANSWERED_MAX && box_has_pending(box, settings))
    {
        box->lastSyncCommand = now;
        box->syncUnanswered++;
        TRACE_INFO("CFW: box %s: settings files due, log-host command 6 (%" PRIu32 ")\r\n", box->id, box->syncUnanswered);
        return build_frame(frame, CFW_CMD_SYNC, NULL, 0);
    }
    if (remote && settings->cfw.settings_sync && box->queueCount == 0 && now != box->lastGlobalCheck)
    {
        box->lastGlobalCheck = now;
        uint8_t file[CFW_TBS_MAX];
        size_t fileLength;
        if (due_file(box, settings, 0, file, &fileLength))
        {
            sent->command = CFW_CMD_APPLY_SETTINGS;
            osMemset(sent->args, 0, 8);
            osMemcpy(&sent->args[8], file, fileLength);
            sent->argsLength = 8 + fileLength;
            known_set(box, 0, cfw_tbs_timestamp(file));
            return build_frame(frame, sent->command, sent->args, sent->argsLength);
        }
    }
    if (box->queueCount == 0)
    {
        return 0;
    }
    if (!remote)
    {
        box->queueCount = 0;
        return 0;
    }
    *sent = box->queue[0];
    box->queueCount--;
    osMemmove(&box->queue[0], &box->queue[1], box->queueCount * sizeof(cfw_remote_t));
    if (sent->command == CFW_CMD_APPLY_SETTINGS)
    {
        known_set(box, cfw_ruid_from_bytes(sent->args), cfw_tbs_timestamp(&sent->args[8]));
    }
    return build_frame(frame, sent->command, sent->args, sent->argsLength);
}

/* a frame that could not be sent waits for the next connection of the box */
static void resend_later(settings_t *settings, const HttpConnection *connection, const cfw_remote_t *sent)
{
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box != NULL && box->connection == connection)
    {
        box->connection = NULL;
        if (sent->command == CFW_CMD_APPLY_SETTINGS)
        {
            known_forget(box, cfw_ruid_from_bytes(sent->args));
        }
        else if (sent->command != CFW_CMD_SYNC && box->queueCount < CFW_REMOTE_QUEUE)
        {
            osMemmove(&box->queue[1], &box->queue[0], box->queueCount * sizeof(cfw_remote_t));
            box->queue[0] = *sent;
            box->queueCount++;
        }
    }
    cfw_unlock();
}

void cfw_rtnl_poll(HttpConnection *connection, bool received)
{
    settings_t *settings = connection->private.client_ctx.settings;
    if (settings == NULL || !settings->cfw.enabled)
    {
        return;
    }
    uint8_t frame[CFW_REMOTE_ARGS_MAX + 16];
    size_t frameLength = 0;
    cfw_remote_t sent = {.command = CFW_CMD_SYNC};

    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box != NULL && box->helloValid)
    {
        if (received)
        {
            box->connection = connection;
        }
        /* an older connection of the box that has not noticed its end yet sends nothing */
        if (box->connection == connection)
        {
            frameLength = next_frame(box, settings, received, frame, &sent);
        }
    }
    cfw_unlock();

    if (frameLength > 0)
    {
        /* the short receive timeout of the log connection must not cut a frame */
        socketSetTimeout(connection->socket, HTTP_SERVER_TIMEOUT);
        error_t err = httpSend(connection, frame, frameLength, 0);
        socketSetTimeout(connection->socket, HTTP_SERVER_BINARY_TIMEOUT);
        if (err != NO_ERROR)
        {
            TRACE_WARNING("CFW: sending command %u failed: %s\r\n", sent.command, error2text(err));
            resend_later(settings, connection, &sent);
        }
    }
}

/* a box with the custom firmware keeps its log connection while it is silent: it reads commands from it
   every second but sends records only on events, and closing it after a minute without data
   would strand every remote command until the box logs again */
bool_t cfw_rtnl_idle(HttpConnection *connection)
{
    cfw_rtnl_poll(connection, false);
    settings_t *settings = connection->private.client_ctx.settings;
    if (settings == NULL || !settings->cfw.enabled)
    {
        return FALSE;
    }
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    bool_t keep = box != NULL && box->helloValid && box->connection == connection;
    cfw_unlock();
    return keep;
}
