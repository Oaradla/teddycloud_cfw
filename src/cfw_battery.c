/* The charge of a box: the learning model of cfw_battery_model.c for each box, kept in
   <configdir>/cfw/battery/<box>.model.json and fed with every battery report. A box without a model
   file learns from its battery log (<box>.csv) first, so the reports logged so far count. */
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "cfw_internal.h"
#include "debug.h"
#include "fs_ext.h"
#include "os_port.h"
#include "server_helpers.h"
#include "settings.h"

#define MODEL_FILE_MAX (64 * 1024)
#define LOG_FILE_MAX (8 * 1024 * 1024)

static char *model_path(const char *boxId, const char *suffix)
{
    char *dir = cfw_dir(get_settings()->internal.configdirfull, "battery");
    char *path = dir ? custom_asprintf("%s%c%s%s", dir, PATH_SEPARATOR, boxId, suffix) : NULL;
    osFreeMem(dir);
    return path;
}

static void report_from_values(cfw_battery_report_t *r, uint32_t mv, uint32_t flags, uint32_t load, uint64_t uptimeMs)
{
    osMemset(r, 0, sizeof(*r));
    r->mv = (uint16_t)(mv > 0xFFFF ? 0xFFFF : mv);
    r->station = flags & 1;
    r->low = (flags >> 1) & 1;
    r->critical = (flags >> 2) & 1;
    r->implausible = (flags >> 3) & 1;
    r->state = load & 0xFF;
    r->step = (load >> 8) & 0xFF;
    r->headphones = (load >> 16) & 1;
    r->uptimeMs = (uint32_t)uptimeMs;
}

/* the reports of the battery log: time,mv,station,low,critical,implausible,reason,state,step,headphones,adc,uptime_ms,build */
static void learn_from_log(cfw_battery_model_t *model, const char *boxId)
{
    char *path = model_path(boxId, ".csv");
    size_t length = 0;
    uint8_t *data = path ? cfw_read_file(path, LOG_FILE_MAX, &length) : NULL;
    osFreeMem(path);
    if (data == NULL)
    {
        return;
    }
    size_t count = 0;
    char *line = (char *)data;
    while (line < (char *)data + length)
    {
        char *end = memchr(line, '\n', (char *)data + length - line);
        if (end == NULL)
        {
            end = (char *)data + length;
        }
        *end = '\0';
        char *fields[13];
        size_t n = 0;
        for (char *p = line; n < 13;)
        {
            fields[n++] = p;
            char *comma = strchr(p, ',');
            if (comma == NULL)
            {
                break;
            }
            *comma = '\0';
            p = comma + 1;
        }
        if (n >= 12 && fields[1][0] >= '0' && fields[1][0] <= '9')
        {
            uint32_t flags = (atoi(fields[2]) ? 1u : 0) | (atoi(fields[3]) ? 2u : 0) | (atoi(fields[4]) ? 4u : 0) | (atoi(fields[5]) ? 8u : 0);
            uint32_t load = ((uint32_t)atoi(fields[7]) & 0xFF) | (((uint32_t)atoi(fields[8]) & 0xFF) << 8) | (atoi(fields[9]) ? 1u << 16 : 0);
            cfw_battery_report_t r;
            report_from_values(&r, (uint32_t)atoi(fields[1]), flags, load, strtoull(fields[11], NULL, 10));
            cfw_battery_model_report(model, &r, NULL);
            count++;
        }
        line = end + 1;
    }
    osFreeMem(data);
    TRACE_INFO("CFW: box %s: battery model learned from %" PRIuSIZE " logged reports\r\n", boxId, count);
}

static void get_u16_array(cJSON *json, const char *name, uint16_t *out, size_t count)
{
    cJSON *array = cJSON_GetObjectItemCaseSensitive(json, name);
    for (size_t i = 0; i < count && cJSON_IsArray(array) && (int)i < cJSON_GetArraySize(array); i++)
    {
        out[i] = (uint16_t)cJSON_GetNumberValue(cJSON_GetArrayItem(array, (int)i));
    }
}

static double get_number(cJSON *json, const char *name)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, name);
    return cJSON_IsNumber(item) ? item->valuedouble : 0;
}

static bool load_model(cfw_battery_model_t *model, const char *boxId)
{
    char *path = model_path(boxId, ".model.json");
    size_t length = 0;
    uint8_t *data = path ? cfw_read_file(path, MODEL_FILE_MAX, &length) : NULL;
    osFreeMem(path);
    if (data == NULL)
    {
        return false;
    }
    cJSON *json = cJSON_ParseWithLength((const char *)data, length);
    osFreeMem(data);
    if (json == NULL || get_number(json, "version") != 1)
    {
        cJSON_Delete(json);
        return false;
    }
    get_u16_array(json, "curve", model->curve, CFW_BAT_LEVELS);
    model->cycles = (uint16_t)get_number(json, "cycles");
    model->baseDrop = (uint16_t)get_number(json, "baseDrop");
    model->baseDropSamples = (uint16_t)get_number(json, "baseDropSamples");
    get_u16_array(json, "playDrop", model->playDrop, CFW_BAT_BANDS);
    get_u16_array(json, "playDropSamples", model->playDropSamples, CFW_BAT_BANDS);
    model->capacity = (uint32_t)get_number(json, "capacity");

    cJSON *cycle = cJSON_GetObjectItemCaseSensitive(json, "cycle");
    model->cycleActive = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(cycle, "active"));
    model->cycleFromFull = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(cycle, "fromFull"));
    model->cycleUsed = (uint32_t)get_number(cycle, "used");
    model->cycleStep = (uint16_t)get_number(cycle, "step");
    model->cycleSkip = (uint16_t)get_number(cycle, "skip");
    if (model->cycleStep == 0)
    {
        model->cycleStep = 1;
    }
    cJSON *mv = cJSON_GetObjectItemCaseSensitive(cycle, "mv");
    cJSON *at = cJSON_GetObjectItemCaseSensitive(cycle, "at");
    int n = (cJSON_IsArray(mv) && cJSON_IsArray(at)) ? cJSON_GetArraySize(mv) : 0;
    if (n > CFW_BAT_SAMPLES || cJSON_GetArraySize(at) != n)
    {
        n = 0;
    }
    for (int i = 0; i < n; i++)
    {
        model->cycleMv[i] = (uint16_t)cJSON_GetNumberValue(cJSON_GetArrayItem(mv, i));
        model->cycleAt[i] = (uint32_t)cJSON_GetNumberValue(cJSON_GetArrayItem(at, i));
    }
    model->cycleCount = (uint16_t)n;

    cJSON *last = cJSON_GetObjectItemCaseSensitive(json, "last");
    model->lastValid = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(last, "valid"));
    model->lastStation = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(last, "station"));
    model->lastState = (uint8_t)get_number(last, "state");
    model->lastBand = (uint8_t)get_number(last, "band");
    model->lastMv = (uint16_t)get_number(last, "mv");
    model->lastUptimeMs = (uint32_t)get_number(last, "uptimeMs");
    cJSON *window = cJSON_GetObjectItemCaseSensitive(last, "window");
    int w = cJSON_IsArray(window) ? cJSON_GetArraySize(window) : 0;
    model->windowCount = (uint8_t)(w > CFW_BAT_WINDOW ? CFW_BAT_WINDOW : w);
    get_u16_array(last, "window", model->window, model->windowCount);
    cJSON_Delete(json);
    return true;
}

static void add_u16_array(cJSON *json, const char *name, const uint16_t *values, size_t count)
{
    cJSON *array = cJSON_AddArrayToObject(json, name);
    for (size_t i = 0; i < count; i++)
    {
        cJSON_AddItemToArray(array, cJSON_CreateNumber(values[i]));
    }
}

void cfw_battery_save(const char *boxId, cfw_battery_model_t *model)
{
    if (model == NULL)
    {
        return;
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "version", 1);
    add_u16_array(json, "curve", model->curve, CFW_BAT_LEVELS);
    cJSON_AddNumberToObject(json, "cycles", model->cycles);
    cJSON_AddNumberToObject(json, "baseDrop", model->baseDrop);
    cJSON_AddNumberToObject(json, "baseDropSamples", model->baseDropSamples);
    add_u16_array(json, "playDrop", model->playDrop, CFW_BAT_BANDS);
    add_u16_array(json, "playDropSamples", model->playDropSamples, CFW_BAT_BANDS);
    cJSON_AddNumberToObject(json, "capacity", model->capacity);

    cJSON *cycle = cJSON_AddObjectToObject(json, "cycle");
    cJSON_AddBoolToObject(cycle, "active", model->cycleActive);
    cJSON_AddBoolToObject(cycle, "fromFull", model->cycleFromFull);
    cJSON_AddNumberToObject(cycle, "used", model->cycleUsed);
    cJSON_AddNumberToObject(cycle, "step", model->cycleStep);
    cJSON_AddNumberToObject(cycle, "skip", model->cycleSkip);
    add_u16_array(cycle, "mv", model->cycleMv, model->cycleCount);
    cJSON *at = cJSON_AddArrayToObject(cycle, "at");
    for (uint16_t i = 0; i < model->cycleCount; i++)
    {
        cJSON_AddItemToArray(at, cJSON_CreateNumber(model->cycleAt[i]));
    }

    cJSON *last = cJSON_AddObjectToObject(json, "last");
    cJSON_AddBoolToObject(last, "valid", model->lastValid);
    cJSON_AddBoolToObject(last, "station", model->lastStation);
    cJSON_AddNumberToObject(last, "state", model->lastState);
    cJSON_AddNumberToObject(last, "band", model->lastBand);
    cJSON_AddNumberToObject(last, "mv", model->lastMv);
    cJSON_AddNumberToObject(last, "uptimeMs", model->lastUptimeMs);
    add_u16_array(last, "window", model->window, model->windowCount);

    char *text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    char *path = model_path(boxId, ".model.json");
    char *tmp = path ? custom_asprintf("%s.tmp", path) : NULL;
    FsFile *file = tmp ? fsOpenFile(tmp, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC) : NULL;
    if (file != NULL && text != NULL)
    {
        error_t err = fsWriteFile(file, text, osStrlen(text));
        fsCloseFile(file);
        if (err != NO_ERROR || fsMoveFile(tmp, path, true) != NO_ERROR)
        {
            TRACE_ERROR("CFW: could not write the battery model %s\r\n", path);
            fsDeleteFile(tmp);
        }
    }
    else if (file != NULL)
    {
        fsCloseFile(file);
    }
    osFreeMem(text);
    osFreeMem(tmp);
    osFreeMem(path);
    osFreeMem(model);
}

cfw_battery_model_t *cfw_battery_update(cfw_box_t *box, uint64_t uptimeMs)
{
    if (box->batteryModel == NULL)
    {
        box->batteryModel = osAllocMem(sizeof(cfw_battery_model_t));
        if (box->batteryModel == NULL)
        {
            return NULL;
        }
        cfw_battery_model_init(box->batteryModel);
        if (!load_model(box->batteryModel, box->id))
        {
            cfw_battery_model_init(box->batteryModel);
            learn_from_log(box->batteryModel, box->id);
        }
    }
    cfw_battery_report_t r;
    report_from_values(&r, box->battery[0], box->battery[1], box->battery[3], uptimeMs);
    if (cfw_battery_model_report(box->batteryModel, &r, &box->batteryResult))
    {
        TRACE_INFO("CFW: box %s: battery curve learned from a discharge (%u so far)\r\n", box->id, box->batteryModel->cycles);
    }
    box->batteryResultValid = true;

    /* a copy to write outside the lock */
    cfw_battery_model_t *copy = osAllocMem(sizeof(cfw_battery_model_t));
    if (copy != NULL)
    {
        osMemcpy(copy, box->batteryModel, sizeof(*copy));
    }
    return copy;
}

void cfw_battery_free(cfw_box_t *box)
{
    osFreeMem(box->batteryModel);
    box->batteryModel = NULL;
}
