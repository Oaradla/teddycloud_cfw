#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfw_internal.h"
#include "debug.h"
#include "fs_ext.h"
#include "os_port.h"
#include "server_helpers.h"

#define CFW_BODY_MAX 8192

typedef struct
{
    uint8_t key;
    const char *name;
    uint8_t length;
    uint32_t max;
    bool isBool;
} cfw_profile_record_t;

/* profile records as JSON fields; null: the record is absent */
static const cfw_profile_record_t profile_records[] = {
    {0x01, "resume", 1, 1, true},
    {0x02, "shuffle", 1, 1, true},
    {0x03, "sleepMinutes", 2, 65535, false},
    {0x04, "speakerLimit", 1, 15, false},
    {0x05, "headphoneLimit", 1, 15, false},
    {0x06, "ledLevel", 1, 2, false},
    {0x08, "slapLock", 1, 1, true},
    {0x09, "tiltLock", 1, 1, true},
    {0x0A, "volumeLock", 1, 1, true},
};

#define PROFILE_RECORDS (sizeof(profile_records) / sizeof(profile_records[0]))

static error_t send_json(HttpConnection *connection, cJSON *json, uint_t statusCode)
{
    char *text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (text == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }
    httpInitResponseHeader(connection);
    connection->response.contentType = "text/json";
    connection->response.contentLength = osStrlen(text);
    connection->response.statusCode = statusCode;
    return httpWriteResponse(connection, text, connection->response.contentLength, true);
}

static error_t send_message(HttpConnection *connection, uint_t statusCode, const char *message)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", statusCode == 200);
    cJSON_AddStringToObject(json, "message", message);
    return send_json(connection, json, statusCode);
}

/* the API with cfw.enabled off: as without CFW support, nothing is read or written (a body left unread
   ends the connection) */
static error_t send_disabled(HttpConnection *connection)
{
    connection->request.keepAlive = FALSE;
    return send_message(connection, 404, "CFW support is off (cfw.enabled)");
}

static cJSON *read_body_json(HttpConnection *connection)
{
    if (connection->request.byteCount == 0 || connection->request.byteCount >= CFW_BODY_MAX)
    {
        return NULL;
    }
    char *data = osAllocMem(CFW_BODY_MAX);
    if (data == NULL)
    {
        return NULL;
    }
    size_t total = 0;
    size_t size = 0;
    while (total < connection->request.byteCount && httpReceive(connection, &data[total], CFW_BODY_MAX - 1 - total, &size, 0) == NO_ERROR && size > 0)
    {
        total += size;
    }
    data[total] = '\0';
    cJSON *json = cJSON_Parse(data);
    osFreeMem(data);
    return json;
}

/* a whole number from 0 to max */
static bool json_uint(const cJSON *item, uint32_t max, uint32_t *value)
{
    if (!cJSON_IsNumber(item) || item->valuedouble < 0 || item->valuedouble > max || floor(item->valuedouble) != item->valuedouble)
    {
        return false;
    }
    *value = (uint32_t)item->valuedouble;
    return true;
}

static settings_t *query_box(const char *queryString)
{
    char overlay[64];
    uint8_t id = queryGet(queryString, "overlay", overlay, sizeof(overlay)) ? get_overlay_id(overlay) : 0;
    return id > 0 ? get_settings_id(id) : NULL;
}

static bool query_ruid(const char *queryString, uint64_t *ruid)
{
    char text[32];
    return queryGet(queryString, "ruid", text, sizeof(text)) && cfw_parse_ruid(text, ruid) && *ruid != 0;
}

/* of repeated records the last valid one counts */
static void profile_to_json(const uint8_t *file, cJSON *json)
{
    bool present[PROFILE_RECORDS] = {false};
    uint32_t values[PROFILE_RECORDS] = {0};
    size_t pos = 0;
    cfw_record_t record;
    while (cfw_tbs_next_record(file, &pos, &record))
    {
        for (size_t r = 0; r < PROFILE_RECORDS; r++)
        {
            uint32_t value = record.value[0] | (record.length == 2 ? record.value[1] << 8 : 0);
            if (record.key == profile_records[r].key && record.length == profile_records[r].length && value <= profile_records[r].max)
            {
                present[r] = true;
                values[r] = value;
            }
        }
    }
    for (size_t r = 0; r < PROFILE_RECORDS; r++)
    {
        if (!present[r])
        {
            cJSON_AddNullToObject(json, profile_records[r].name);
        }
        else if (profile_records[r].isBool)
        {
            cJSON_AddBoolToObject(json, profile_records[r].name, values[r] != 0);
        }
        else
        {
            cJSON_AddNumberToObject(json, profile_records[r].name, values[r]);
        }
    }
}

static bool json_to_profile(const cJSON *json, uint8_t *body, size_t *bodyLength, char *message, size_t messageSize)
{
    size_t n = 0;
    for (size_t r = 0; r < PROFILE_RECORDS; r++)
    {
        const cfw_profile_record_t *record = &profile_records[r];
        const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, record->name);
        uint32_t value;
        if (item == NULL || cJSON_IsNull(item))
        {
            continue;
        }
        if (cJSON_IsBool(item) && record->isBool)
        {
            value = cJSON_IsTrue(item);
        }
        else if (!json_uint(item, record->max, &value))
        {
            osSnprintf(message, messageSize, "%s must be 0 to %" PRIu32, record->name, record->max);
            return false;
        }
        body[n++] = record->key;
        body[n++] = record->length;
        body[n++] = value & 0xFF;
        if (record->length == 2)
        {
            body[n++] = value >> 8;
        }
    }
    *bodyLength = n;
    return true;
}

static void event_to_json(const uint8_t *file, cJSON *json)
{
    bool tones = true;
    cJSON *actions = cJSON_AddArrayToObject(json, "actions");
    size_t pos = 0;
    cfw_record_t record;
    while (cfw_tbs_next_record(file, &pos, &record))
    {
        if (record.key == CFW_RECORD_ACTION && record.length == 3)
        {
            uint16_t parameter = record.value[1] | (record.value[2] << 8);
            cJSON *action = cJSON_CreateObject();
            cJSON_AddNumberToObject(action, "action", record.value[0]);
            cJSON_AddNumberToObject(action, "mode", parameter >> 14);
            cJSON_AddNumberToObject(action, "value", parameter & 0x3FFF);
            cJSON_AddItemToArray(actions, action);
        }
        else if (record.key == 0x11 && record.length == 1)
        {
            tones = record.value[0] != 0;
        }
    }
    cJSON_AddBoolToObject(json, "tones", tones);
}

/* an event tag: 1 to 16 actions and the feedback tones */
static bool json_to_event(const cJSON *json, uint8_t *body, size_t *bodyLength, char *message, size_t messageSize)
{
    const cJSON *actions = cJSON_GetObjectItemCaseSensitive(json, "actions");
    if (!cJSON_IsArray(actions) || cJSON_GetArraySize(actions) < 1 || cJSON_GetArraySize(actions) > 16)
    {
        osSnprintf(message, messageSize, "an event tag needs 1 to 16 actions");
        return false;
    }
    size_t n = 0;
    const cJSON *action;
    cJSON_ArrayForEach(action, actions)
    {
        uint32_t number;
        uint32_t mode;
        uint32_t value;
        if (!json_uint(cJSON_GetObjectItemCaseSensitive(action, "action"), 16, &number) || number == 0 || !json_uint(cJSON_GetObjectItemCaseSensitive(action, "mode"), 3, &mode) || !json_uint(cJSON_GetObjectItemCaseSensitive(action, "value"), 0x3FFF, &value))
        {
            osSnprintf(message, messageSize, "an action needs action 1 to 16, mode 0 to 3 and value 0 to 16383");
            return false;
        }
        uint16_t parameter = (mode << 14) | value;
        body[n++] = CFW_RECORD_ACTION;
        body[n++] = 3;
        body[n++] = number;
        body[n++] = parameter & 0xFF;
        body[n++] = parameter >> 8;
    }
    body[n++] = 0x11;
    body[n++] = 1;
    body[n++] = !cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(json, "tones"));
    *bodyLength = n;
    return true;
}

static const char *origin_name(uint8_t origin)
{
    static const char *names[] = {"box", "server", "tool"};
    return origin < 3 ? names[origin] : "unknown";
}

/* with the lock held: the file goes at once to every box that takes command 64, the others get it with
   their next freshness check */
static void push_file(uint64_t ruid, const uint8_t *file, size_t fileLength)
{
    uint8_t args[8 + CFW_TBS_MAX];
    cfw_ruid_to_bytes(ruid, args);
    osMemcpy(&args[8], file, fileLength);
    for (uint8_t i = 1; i < MAX_OVERLAYS; i++)
    {
        settings_t *settings = get_settings_id(i);
        cfw_box_t *box = settings->internal.config_used ? cfw_box_get(settings) : NULL;
        bool takesIt = box != NULL && box->helloValid && (box->capabilities & CFW_CAP_REMOTE) && (file[4] != CFW_TBS_KIND_EVENT || (box->capabilities & CFW_CAP_EVENT_TAG_EXT));
        if (!takesIt || !settings->cfw.enabled || !settings->cfw.settings_sync || !settings->cfw.remote_control)
        {
            continue;
        }
        if (!cfw_remote_queue(box, CFW_CMD_APPLY_SETTINGS, args, 8 + fileLength))
        {
            TRACE_WARNING("CFW: command queue of box %s full, it gets the settings with its next freshness check\r\n", box->id);
        }
    }
}

error_t handleApiCfwBoxes(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    cJSON *json = cJSON_CreateObject();
    cJSON *list = cJSON_AddArrayToObject(json, "boxes");
    for (uint8_t i = 1; i < MAX_OVERLAYS; i++)
    {
        settings_t *settings = get_settings_id(i);
        if (!settings->internal.config_used)
        {
            continue;
        }
        cfw_lock();
        cfw_box_t *found = cfw_box_get(settings);
        cfw_box_t box;
        if (found != NULL)
        {
            box = *found;
            box.known = NULL;
        }
        bool online = found != NULL && cfw_box_online(found);
        cfw_unlock();
        if (found == NULL)
        {
            continue;
        }

        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "id", box.id);
        cJSON_AddStringToObject(entry, "commonName", settings->commonName ? settings->commonName : "");
        cJSON_AddStringToObject(entry, "boxName", settings->boxName ? settings->boxName : "");
        cJSON_AddBoolToObject(entry, "isCfw", box.isCfw);
        cJSON_AddStringToObject(entry, "platform", cfw_box_platform(settings));
        cJSON_AddNumberToObject(entry, "esp32Delivered", box.esp32Delivered);
        cJSON_AddNumberToObject(entry, "pageVersion", box.pageVersion);
        cJSON_AddNumberToObject(entry, "version", box.version);
        cJSON_AddNumberToObject(entry, "capabilities", box.capabilities);
        cJSON_AddNumberToObject(entry, "updateResult", box.updateResult);
        cJSON_AddNumberToObject(entry, "rolledBackBuild", box.rolledBackBuild);
        cJSON_AddNumberToObject(entry, "helloTime", (double)box.helloTime);
        cJSON_AddBoolToObject(entry, "helloValid", box.helloValid);
        cJSON_AddBoolToObject(entry, "online", online);
        cJSON_AddNumberToObject(entry, "lastOfferedBuild", box.offeredBuild);
        cJSON_AddNumberToObject(entry, "lastOfferTime", (double)box.offerTime);
        cJSON_AddBoolToObject(entry, "showBattery", settings->cfw.show_battery);
        if (box.batteryValid)
        {
            cJSON *battery = cJSON_AddObjectToObject(entry, "battery");
            cJSON_AddNumberToObject(battery, "mv", box.battery[0]);
            cJSON_AddBoolToObject(battery, "station", box.battery[1] & 1);
            cJSON_AddBoolToObject(battery, "low", (box.battery[1] >> 1) & 1);
            cJSON_AddBoolToObject(battery, "critical", (box.battery[1] >> 2) & 1);
            cJSON_AddBoolToObject(battery, "implausible", (box.battery[1] >> 3) & 1);
            cJSON_AddNumberToObject(battery, "reason", box.battery[2]);
            cJSON_AddNumberToObject(battery, "time", (double)box.batteryTime);
        }
        cJSON *cfw = cJSON_AddObjectToObject(entry, "settings");
        cJSON_AddBoolToObject(cfw, "enabled", settings->cfw.enabled);
        cJSON_AddBoolToObject(cfw, "settingsSync", settings->cfw.settings_sync);
        cJSON_AddBoolToObject(cfw, "remoteControl", settings->cfw.remote_control);
        cJSON *update = cJSON_AddObjectToObject(entry, "update");
        cJSON_AddBoolToObject(update, "enabled", settings->cfw.update.enabled);
        cJSON_AddStringToObject(update, "channel", cfw_channel_name(settings->cfw.update.channel));
        cJSON_AddStringToObject(update, "mode", settings->cfw.update.mode == 1 ? "automatic" : "manual");
        cJSON_AddNumberToObject(update, "target", settings->cfw.update.target ? strtoul(settings->cfw.update.target, NULL, 10) : 0);
        cJSON_AddBoolToObject(update, "allowRolledBack", settings->cfw.update.allow_rolled_back);
        cJSON_AddNumberToObject(update, "next", box.isCfw ? cfw_firmware_choose(settings, &box, box.version) : 0);
        cJSON_AddItemToArray(list, entry);
    }
    return send_json(connection, json, 200);
}

/* the battery log of a box as CSV */
error_t handleApiCfwBattery(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    settings_t *settings = query_box(queryString);
    if (settings == NULL)
    {
        return send_message(connection, 404, "box not found");
    }
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    char id[sizeof(box->id)] = "";
    if (box != NULL)
    {
        osStrcpy(id, box->id);
    }
    cfw_unlock();
    char *dir = id[0] ? cfw_dir(get_settings()->internal.configdirfull, "battery") : NULL;
    char *path = dir ? custom_asprintf("%s%c%s.csv", dir, PATH_SEPARATOR, id) : NULL;
    osFreeMem(dir);
    size_t length = 0;
    uint8_t *data = path ? cfw_read_file(path, 8 * 1024 * 1024, &length) : NULL;
    osFreeMem(path);
    if (data == NULL)
    {
        return send_message(connection, 404, "no battery log for this box");
    }
    httpInitResponseHeader(connection);
    connection->response.contentType = "text/csv";
    connection->response.contentLength = length;
    connection->response.statusCode = 200;
    return httpWriteResponse(connection, data, length, true);
}

error_t handleApiCfwTags(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    cJSON *json = cJSON_CreateObject();
    cJSON *list = cJSON_AddArrayToObject(json, "tags");
    uint64_t *ruids = NULL;
    size_t count = cfw_store_list_tags(&ruids);
    for (size_t i = 0; i < count; i++)
    {
        uint8_t file[CFW_TBS_MAX];
        size_t length;
        /* an empty profile is how "no settings" reaches the boxes */
        if (!cfw_store_read_tag(ruids[i], file, &length) || (file[4] == CFW_TBS_KIND_PROFILE && length == CFW_TBS_MIN))
        {
            continue;
        }
        char text[17];
        cfw_format_ruid(ruids[i], text);
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "ruid", text);
        cJSON_AddStringToObject(entry, "kind", file[4] == CFW_TBS_KIND_EVENT ? "event" : "profile");
        cJSON_AddNumberToObject(entry, "timestamp", cfw_tbs_timestamp(file));
        cJSON_AddItemToArray(list, entry);
    }
    osFreeMem(ruids);
    return send_json(connection, json, 200);
}

error_t handleApiCfwTagGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    uint64_t ruid;
    if (!query_ruid(queryString, &ruid))
    {
        return send_message(connection, 400, "ruid missing or invalid");
    }
    char text[17];
    cfw_format_ruid(ruid, text);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "ruid", text);
    uint8_t file[CFW_TBS_MAX];
    size_t length;
    if (!cfw_store_read_tag(ruid, file, &length) || (file[4] == CFW_TBS_KIND_PROFILE && length == CFW_TBS_MIN))
    {
        cJSON_AddStringToObject(json, "kind", "none");
        return send_json(connection, json, 200);
    }
    bool event = file[4] == CFW_TBS_KIND_EVENT;
    cJSON_AddStringToObject(json, "kind", event ? "event" : "profile");
    cJSON_AddStringToObject(json, "origin", origin_name(file[5]));
    cJSON_AddNumberToObject(json, "timestamp", cfw_tbs_timestamp(file));
    if (event)
    {
        event_to_json(file, cJSON_AddObjectToObject(json, "event"));
    }
    else
    {
        profile_to_json(file, cJSON_AddObjectToObject(json, "profile"));
    }
    return send_json(connection, json, 200);
}

/* "none" is stored as an empty profile: it replaces the settings on the boxes, deleting the file would not */
error_t handleApiCfwTagSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    uint64_t ruid;
    if (!query_ruid(queryString, &ruid))
    {
        return send_message(connection, 400, "ruid missing or invalid");
    }
    cJSON *json = read_body_json(connection);
    const char *kind = json ? cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "kind")) : NULL;
    uint8_t body[CFW_TBS_MAX];
    size_t bodyLength = 0;
    uint8_t fileKind = CFW_TBS_KIND_PROFILE;
    char message[128] = "kind must be profile, event or none";
    bool valid = kind != NULL && !osStrcmp(kind, "none");
    if (kind != NULL && !osStrcmp(kind, "profile"))
    {
        valid = json_to_profile(cJSON_GetObjectItemCaseSensitive(json, "profile"), body, &bodyLength, message, sizeof(message));
    }
    else if (kind != NULL && !osStrcmp(kind, "event"))
    {
        fileKind = CFW_TBS_KIND_EVENT;
        valid = json_to_event(cJSON_GetObjectItemCaseSensitive(json, "event"), body, &bodyLength, message, sizeof(message));
    }
    cJSON_Delete(json);
    if (!valid)
    {
        return send_message(connection, 400, message);
    }

    uint8_t file[CFW_TBS_MAX];
    size_t fileLength;
    cfw_lock();
    uint32_t previous = cfw_store_read_tag(ruid, file, &fileLength) ? cfw_tbs_timestamp(file) : 0;
    fileLength = cfw_tbs_build(fileKind, CFW_TBS_ORIGIN_SERVER, cfw_next_timestamp(previous), body, bodyLength, file);
    bool stored = fileLength > 0 && cfw_store_write_tag(ruid, file, fileLength);
    if (stored)
    {
        push_file(ruid, file, fileLength);
    }
    cfw_unlock();
    return stored ? send_message(connection, 200, "OK") : send_message(connection, 500, "could not store the settings");
}

/* remote commands by name; their arguments are checked here */
static const struct
{
    const char *name;
    uint8_t command;
} remote_commands[] = {
    {"pause", 65},
    {"continue", 66},
    {"stop", 67},
    {"next", 68},
    {"prev", 69},
    {"volume", CFW_CMD_VOLUME},
    {"play", CFW_CMD_PLAY},
    {"status", 72},
    {"updateCheck", CFW_CMD_UPDATE_CHECK},
};

static int remote_command(const cJSON *json, uint8_t *args, size_t *argsLength, char *message, size_t messageSize)
{
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "command"));
    int command = -1;
    for (size_t i = 0; name != NULL && i < sizeof(remote_commands) / sizeof(remote_commands[0]); i++)
    {
        if (!osStrcmp(name, remote_commands[i].name))
        {
            command = remote_commands[i].command;
        }
    }
    uint32_t step;
    uint64_t ruid;
    const char *ruidText = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "ruid"));
    *argsLength = 0;
    if (command < 0)
    {
        osSnprintf(message, messageSize, "unknown command");
    }
    else if (command == CFW_CMD_VOLUME && !json_uint(cJSON_GetObjectItemCaseSensitive(json, "volume"), 15, &step))
    {
        osSnprintf(message, messageSize, "volume must be 0 to 15");
        command = -1;
    }
    else if (command == CFW_CMD_VOLUME)
    {
        args[(*argsLength)++] = step;
    }
    else if (command == CFW_CMD_PLAY && !cfw_parse_ruid(ruidText, &ruid))
    {
        osSnprintf(message, messageSize, "ruid missing or invalid");
        command = -1;
    }
    else if (command == CFW_CMD_PLAY)
    {
        cfw_ruid_to_bytes(ruid, args);
        *argsLength = 8;
    }
    return command;
}

error_t handleApiCfwRemote(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    settings_t *settings = query_box(queryString);
    if (settings == NULL)
    {
        return send_message(connection, 404, "box not found");
    }
    cJSON *json = read_body_json(connection);
    uint8_t args[8];
    size_t argsLength = 0;
    char message[128] = "invalid JSON";
    int command = json ? remote_command(json, args, &argsLength, message, sizeof(message)) : -1;
    cJSON_Delete(json);
    if (command < 0)
    {
        return send_message(connection, 400, message);
    }

    uint_t status = 409;
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (!settings->cfw.enabled || !settings->cfw.remote_control)
    {
        osSnprintf(message, sizeof(message), "remote control is switched off for this box");
    }
    else if (box == NULL || !box->helloValid)
    {
        osSnprintf(message, sizeof(message), "the box is not connected with the custom firmware");
    }
    else if (!(box->capabilities & CFW_CAP_REMOTE))
    {
        osSnprintf(message, sizeof(message), "the firmware of the box has no remote control");
    }
    else if (!cfw_remote_queue(box, (uint8_t)command, args, argsLength))
    {
        status = 429;
        osSnprintf(message, sizeof(message), "too many commands waiting");
    }
    else
    {
        status = 200;
        osSnprintf(message, sizeof(message), "OK");
    }
    cfw_unlock();
    return send_message(connection, status, message);
}

static void add_status(cJSON *json, const cfw_box_t *box)
{
    static const char *states[] = {"idle", "idleWithFigure", "playing", "paused", "preparing"};
    char text[17];
    uint64_t ruid = cfw_ruid_from_words(box->status[1], box->status[2]);
    cfw_format_ruid(ruid, text);
    cJSON *status = cJSON_AddObjectToObject(json, "status");
    cJSON_AddStringToObject(status, "state", box->status[0] < 5 ? states[box->status[0]] : "unknown");
    cJSON_AddStringToObject(status, "ruid", ruid ? text : "");
    cJSON_AddNumberToObject(status, "audioId", box->status[3]);
    cJSON_AddNumberToObject(status, "chapter", box->status[4]);
    cJSON_AddNumberToObject(status, "position", box->status[5]);
    cJSON_AddNumberToObject(status, "volume", box->status[6] & 0xFF);
    cJSON_AddNumberToObject(status, "limit", (box->status[6] >> 8) & 0xFF);
    cJSON_AddBoolToObject(status, "headphones", (box->status[6] >> 16) & 1);
    cJSON_AddNumberToObject(status, "batteryMv", box->status[7] & 0x7FFFFFFF);
    cJSON_AddBoolToObject(status, "charging", box->status[7] >> 31);
    cJSON *locks = cJSON_AddObjectToObject(status, "locks");
    cJSON_AddBoolToObject(locks, "slap", box->status[8] & 1);
    cJSON_AddBoolToObject(locks, "tilt", (box->status[8] >> 1) & 1);
    cJSON_AddBoolToObject(locks, "volume", (box->status[8] >> 2) & 1);
    cJSON_AddNumberToObject(status, "time", (double)box->statusTime);
}

error_t handleApiCfwStatus(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    settings_t *settings = query_box(queryString);
    if (settings == NULL)
    {
        return send_message(connection, 404, "box not found");
    }
    cJSON *json = cJSON_CreateObject();
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box != NULL)
    {
        cJSON_AddBoolToObject(json, "helloValid", box->helloValid);
        cJSON_AddBoolToObject(json, "online", cfw_box_online(box));
        cJSON_AddNumberToObject(json, "capabilities", box->capabilities);
        cJSON_AddBoolToObject(json, "remote", box->helloValid && (box->capabilities & CFW_CAP_REMOTE) && settings->cfw.enabled && settings->cfw.remote_control);
        cJSON_AddNumberToObject(json, "queued", box->queueCount);
        if (box->statusValid)
        {
            add_status(json, box);
        }
        if (box->lastResultTime)
        {
            cJSON *result = cJSON_AddObjectToObject(json, "lastResult");
            cJSON_AddNumberToObject(result, "command", box->lastCommand);
            cJSON_AddNumberToObject(result, "result", box->lastResult);
            cJSON_AddNumberToObject(result, "time", (double)box->lastResultTime);
        }
        if (box->lockedTime)
        {
            cJSON *locked = cJSON_AddObjectToObject(json, "lastLockedGesture");
            cJSON_AddNumberToObject(locked, "gesture", box->lockedGesture);
            cJSON_AddStringToObject(locked, "source", box->lockedSource == 1 ? "figure" : "box");
            cJSON_AddNumberToObject(locked, "time", (double)box->lockedTime);
        }
    }
    cfw_unlock();
    return send_json(connection, json, 200);
}

static cJSON *image_json(const cfw_image_t *image)
{
    cJSON *entry = cJSON_CreateObject();
    cJSON_AddNumberToObject(entry, "build", image->build);
    cJSON_AddStringToObject(entry, "version", image->version);
    cJSON_AddStringToObject(entry, "revision", image->revision);
    cJSON_AddStringToObject(entry, "buildDate", image->buildDate);
    cJSON_AddStringToObject(entry, "platform", image->platform);
    cJSON_AddBoolToObject(entry, "original", image->original);
    cJSON_AddStringToObject(entry, "patches", image->patches);
    cJSON_AddStringToObject(entry, "channel", cfw_channel_name(image->channel));
    cJSON_AddStringToObject(entry, "source", image->source);
    cJSON_AddStringToObject(entry, "githubTag", image->githubTag);
    cJSON_AddStringToObject(entry, "notes", image->notes);
    cJSON_AddNumberToObject(entry, "added", (double)image->added);
    cJSON_AddNumberToObject(entry, "size", image->size);
    cJSON_AddNumberToObject(entry, "page", image->page);
    cJSON_AddStringToObject(entry, "pageLabel", image->pageLabel);
    cJSON_AddStringToObject(entry, "pageRequires", image->pageRequires);
    return entry;
}

error_t handleApiCfwFirmwareList(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    cJSON *json = cJSON_CreateObject();
    cJSON *list = cJSON_AddArrayToObject(json, "images");
    cfw_image_t *images = NULL;
    size_t count = cfw_firmware_list(&images);
    for (size_t i = 0; i < count; i++)
    {
        /* pageNew: the image brings a setup page that differs from the one of the next older image of its
           platform */
        const cfw_image_t *older = NULL;
        for (size_t k = 0; k < count; k++)
        {
            if (!images[k].original && images[k].build < images[i].build && osStrcmp(images[k].platform, images[i].platform) == 0 &&
                (older == NULL || images[k].build > older->build))
            {
                older = &images[k];
            }
        }
        cJSON *entry = image_json(&images[i]);
        cJSON_AddBoolToObject(entry, "pageNew", images[i].page != 0 && (older == NULL || older->page != images[i].page));
        cJSON_AddItemToArray(list, entry);
    }
    osFreeMem(images);
    char label[32];
    char required[32];
    uint32_t page = cfw_firmware_default_page(label, sizeof(label), required, sizeof(required));
    cJSON *defaultPage = cJSON_AddObjectToObject(json, "defaultPage");
    cJSON_AddNumberToObject(defaultPage, "page", page);
    cJSON_AddStringToObject(defaultPage, "label", label);
    cJSON_AddStringToObject(defaultPage, "requires", required);
    settings_t *settings = get_settings();
    cJSON *github = cfw_github_releases_json();
    cJSON_AddStringToObject(github, "repo", settings->cfw.firmware.github_repo ? settings->cfw.firmware.github_repo : "");
    cJSON_AddNumberToObject(github, "autoDownload", settings->cfw.firmware.github_download);
    cJSON_AddItemToObject(json, "github", github);
    return send_json(connection, json, 200);
}

typedef struct
{
    const char *path;
    FsFile *file;
    bool received;
    bool failed;
} upload_t;

static error_t upload_start(void *ctx, const char *name, const char *filename)
{
    upload_t *upload = ctx;
    if (upload->file != NULL)
    {
        return ERROR_FAILURE;
    }
    upload->file = fsOpenFile(upload->path, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);
    return upload->file ? NO_ERROR : ERROR_FILE_OPENING_FAILED;
}

static error_t upload_add(void *ctx, void *data, size_t length)
{
    upload_t *upload = ctx;
    upload->received = true;
    upload->failed = upload->failed || upload->file == NULL || fsWriteFile(upload->file, data, length) != NO_ERROR;
    return upload->failed ? ERROR_WRITE_FAILED : NO_ERROR;
}

static error_t upload_end(void *ctx)
{
    upload_t *upload = ctx;
    if (upload->file != NULL)
    {
        fsCloseFile(upload->file);
        upload->file = NULL;
    }
    return NO_ERROR;
}

/* an image into the library; the original firmware of the ESP32 box (app image or flash dump) with teddyCloud's
   patches from ?hostname=, ?hostname_old= and ?port= */
error_t handleApiCfwFirmwareUpload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    char channel[16] = "beta";
    queryGet(queryString, "channel", channel, sizeof(channel));
    cfw_esp32_patch_t patch = {0};
    char port[8] = "";
    queryGet(queryString, "hostname", patch.host, sizeof(patch.host));
    queryGet(queryString, "hostname_old", patch.hostOld, sizeof(patch.hostOld));
    queryGet(queryString, "port", port, sizeof(port));
    unsigned long portNumber = strtoul(port, NULL, 10);
    if (portNumber > 65535)
    {
        return send_message(connection, 400, "port out of range");
    }
    patch.port = (uint16_t)portNumber;
    upload_t upload = {.path = cfw_firmware_temp_path()};
    if (upload.path == NULL)
    {
        return send_message(connection, 500, "out of memory");
    }
    multipart_cbr_t cbr = {.multipart_start = upload_start, .multipart_add = upload_add, .multipart_end = upload_end};
    error_t err = multipart_handle(connection, &cbr, &upload);
    upload_end(&upload);

    char message[256] = "no image received";
    bool received = err == NO_ERROR && upload.received && !upload.failed;
    /* a setup page alone: for the image of ?build= and ?platform=, else the default page */
    size_t pageSize = 0;
    uint8_t *page = received ? cfw_read_file(upload.path, 65537, &pageSize) : NULL;
    size_t first = 0;
    while (page != NULL && first < pageSize && (page[first] == ' ' || page[first] == '\r' || page[first] == '\n' || page[first] == 0xEF || page[first] == 0xBB || page[first] == 0xBF))
    {
        first++;
    }
    if (page != NULL && first < pageSize && page[first] == '<')
    {
        char build[16] = "";
        char platform[16] = "";
        queryGet(queryString, "build", build, sizeof(build));
        queryGet(queryString, "platform", platform, sizeof(platform));
        uint32_t value = 0;
        char label[32] = "";
        bool stored = cfw_firmware_set_page(osStrcmp(platform, CFW_PLATFORM_ESP32) == 0 ? CFW_PLATFORM_ESP32 : CFW_PLATFORM_CC3200,
                                            (uint32_t)strtoul(build, NULL, 10), page, pageSize, NULL, &value, label, sizeof(label), message, sizeof(message));
        osFreeMem(page);
        fsDeleteFile(upload.path);
        osFreeMem((char *)upload.path);
        if (!stored)
        {
            return send_message(connection, 400, message);
        }
        cJSON *json = cJSON_CreateObject();
        cJSON_AddBoolToObject(json, "ok", true);
        cJSON_AddStringToObject(json, "message", "OK");
        cJSON *info = cJSON_AddObjectToObject(json, "page");
        cJSON_AddNumberToObject(info, "page", value);
        cJSON_AddStringToObject(info, "label", label);
        return send_json(connection, json, 200);
    }
    osFreeMem(page);
    cfw_image_t images[4];
    size_t count = 4;
    bool added = received && cfw_firmware_import(upload.path, cfw_channel_parse(channel), "upload", "", "", &patch, images, &count, message, sizeof(message));
    if (!added)
    {
        fsDeleteFile(upload.path);
    }
    osFreeMem((char *)upload.path);
    if (!added)
    {
        return send_message(connection, 400, message);
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddStringToObject(json, "message", "OK");
    cJSON_AddItemToObject(json, "image", image_json(&images[0]));
    cJSON *list = cJSON_AddArrayToObject(json, "images");
    for (size_t i = 0; i < count; i++)
    {
        cJSON_AddItemToArray(list, image_json(&images[i]));
    }
    return send_json(connection, json, 200);
}

static bool body_build(const cJSON *json, uint32_t *build)
{
    return json != NULL && json_uint(cJSON_GetObjectItemCaseSensitive(json, "build"), UINT32_MAX, build);
}

/* the platform of the image a request names ("platform" of the body), NULL when it names none */
static const char *body_platform(const cJSON *json)
{
    const char *platform = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "platform"));
    if (platform != NULL && osStrcmp(platform, CFW_PLATFORM_ESP32) == 0)
    {
        return CFW_PLATFORM_ESP32;
    }
    return platform != NULL && osStrcmp(platform, CFW_PLATFORM_CC3200) == 0 ? CFW_PLATFORM_CC3200 : NULL;
}

error_t handleApiCfwFirmwareEdit(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    cJSON *json = read_body_json(connection);
    uint32_t build;
    cfw_image_t image;
    const char *platform = body_platform(json);
    cfw_library_lock();
    if (!body_build(json, &build) || platform == NULL || !cfw_firmware_get(platform, build, &image))
    {
        cfw_library_unlock();
        cJSON_Delete(json);
        return send_message(connection, 404, "image not found");
    }
    const char *channel = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "channel"));
    const char *notes = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "notes"));
    if (channel != NULL && !image.original) /* the original firmware stays out of the channels */
    {
        image.channel = cfw_channel_parse(channel);
    }
    if (notes != NULL)
    {
        osStrncpy(image.notes, notes, sizeof(image.notes) - 1);
        image.notes[sizeof(image.notes) - 1] = '\0';
    }
    cJSON_Delete(json);
    bool valid = image.channel != CFW_CHANNEL_NONE || image.original;
    bool saved = valid && cfw_firmware_save_meta(&image);
    cfw_library_unlock();
    if (!valid)
    {
        return send_message(connection, 400, "channel must be release, beta or alpha");
    }
    return saved ? send_message(connection, 200, "OK") : send_message(connection, 500, "could not save");
}

error_t handleApiCfwFirmwareDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    cJSON *json = read_body_json(connection);
    uint32_t build;
    const char *platform = body_platform(json);
    bool known = body_build(json, &build) && platform != NULL;
    cJSON_Delete(json);
    if (!known)
    {
        return send_message(connection, 404, "image not found");
    }
    return cfw_firmware_delete(platform, build) ? send_message(connection, 200, "OK") : send_message(connection, 404, "image not found");
}

error_t handleApiCfwFirmwareGithub(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    char message[256];
    error_t err = cfw_github_check(message, sizeof(message));
    return send_message(connection, err == NO_ERROR ? 200 : 502, message);
}

error_t handleApiCfwFirmwareGithubDownload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    cJSON *json = read_body_json(connection);
    const char *tag = json ? cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(json, "tag")) : NULL;
    char message[256] = "tag missing";
    error_t err = tag ? cfw_github_download(tag, message, sizeof(message)) : ERROR_INVALID_PARAMETER;
    cJSON_Delete(json);
    return send_message(connection, err == NO_ERROR ? 200 : (tag ? 502 : 400), message);
}

/* asks the box to check for an update at once (remote command); false: not possible now */
static bool update_check_now(settings_t *settings)
{
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    bool checking = box != NULL && box->helloValid && (box->capabilities & CFW_CAP_REMOTE) && settings->cfw.remote_control && cfw_remote_queue(box, CFW_CMD_UPDATE_CHECK, NULL, 0);
    cfw_unlock();
    return checking;
}

/* assigns an image to the box (manual delivery, build 0: none); with "now", the box checks at once;
   "now" without "build" keeps the assignment and only starts the check (automatic delivery) */
error_t handleApiCfwDeliver(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    if (!get_settings()->cfw.enabled)
    {
        return send_disabled(connection);
    }
    settings_t *settings = query_box(queryString);
    if (settings == NULL)
    {
        return send_message(connection, 404, "box not found");
    }
    cJSON *json = read_body_json(connection);
    uint32_t build;
    bool hasBuild = json != NULL && cJSON_GetObjectItemCaseSensitive(json, "build") != NULL;
    bool valid = body_build(json, &build);
    bool now = json && cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "now"));
    cJSON_Delete(json);
    if (!hasBuild && now)
    {
        bool checking = update_check_now(settings);
        return send_message(connection, checking ? 200 : 409, checking ? "the box checks for an update now" : "the box cannot be reached now");
    }
    cfw_image_t image;
    if (!valid || (build != 0 && !cfw_firmware_get(cfw_box_platform(settings), build, &image)))
    {
        return send_message(connection, 404, "image not found");
    }
    if (build != 0 && osStrcmp(image.platform, cfw_box_platform(settings)) != 0)
    {
        return send_message(connection, 409, "the image is for another box platform");
    }
    /* a new assignment may be delivered to the original firmware of an ESP32 box once more */
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box != NULL && box->esp32Delivered != 0)
    {
        box->esp32Delivered = 0;
        cfw_box_save(box);
    }
    cfw_unlock();
    char value[16] = "";
    if (build != 0)
    {
        osSnprintf(value, sizeof(value), "%" PRIu32, build);
    }
    settings_set_string_ovl("cfw.update.target", value, settings->internal.overlayUniqueId);
    settings_save();
    if (build == 0)
    {
        return send_message(connection, 200, "assignment removed");
    }

    bool checking = now && update_check_now(settings);
    return send_message(connection, 200, checking ? "assigned; the box checks for the update now" : "assigned; the box takes it at its next start");
}
