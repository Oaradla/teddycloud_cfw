/* The charge of a box: the learning model of cfw_battery_model.c for each box, kept in
   <configdir>/cfw/battery/<box>.model.json and fed with every battery report. A box without a model
   file of this version learns from its battery log (<box>.csv) first, so the reports logged so far count. */
#include <stdlib.h>
#include <string.h>

#include "cJSON.h"
#include "cfw_internal.h"
#include "debug.h"
#include "fs_ext.h"
#include "os_port.h"
#include "server_helpers.h"
#include "settings.h"

/* a model file of another version is not read: the model learns from the battery log again */
#define MODEL_VERSION 5
#define MODEL_FILE_MAX (64 * 1024)
#define LOG_FILE_MAX (8 * 1024 * 1024)

static char *model_path(const char *boxId, const char *suffix)
{
    char *dir = cfw_dir(get_settings()->internal.configdirfull, "battery");
    char *path = dir ? custom_asprintf("%s%c%s%s", dir, PATH_SEPARATOR, boxId, suffix) : NULL;
    osFreeMem(dir);
    return path;
}

static void report_from_values(cfw_battery_report_t *r, uint32_t mv, uint32_t flags, uint64_t uptimeMs, uint64_t time)
{
    osMemset(r, 0, sizeof(*r));
    r->mv = (uint16_t)(mv > 0xFFFF ? 0xFFFF : mv);
    r->station = flags & 1;
    r->low = (flags >> 1) & 1;
    r->critical = (flags >> 2) & 1;
    r->implausible = (flags >> 3) & 1;
    r->uptimeMs = (uint32_t)uptimeMs;
    r->time = time;
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
            DateTime date = {0};
            unsigned year = 0, month = 0, day = 0, hours = 0, minutes = 0, seconds = 0;
            sscanf(fields[0], "%4u-%2u-%2uT%2u:%2u:%2uZ", &year, &month, &day, &hours, &minutes, &seconds);
            date.year = year;
            date.month = month;
            date.day = day;
            date.hours = hours;
            date.minutes = minutes;
            date.seconds = seconds;
            cfw_battery_report_t r;
            report_from_values(&r, (uint32_t)atoi(fields[1]), flags, strtoull(fields[11], NULL, 10), convertDateToUnixTime(&date));
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
    if (json == NULL || get_number(json, "version") != MODEL_VERSION)
    {
        cJSON_Delete(json);
        return false;
    }
    get_u16_array(json, "curve", model->curve, CFW_BAT_LEVELS);
    model->cycles = (uint16_t)get_number(json, "cycles");
    model->measured = (uint16_t)get_number(json, "measured");
    model->capacity = (uint32_t)get_number(json, "capacity");
    cJSON *charge = cJSON_GetObjectItemCaseSensitive(json, "charge");
    model->chargeValid = cJSON_IsNumber(charge);
    model->charge = model->chargeValid && charge->valuedouble <= CFW_BAT_FULL ? (uint32_t)charge->valuedouble : 0;
    model->spread = (uint32_t)get_number(json, "spread");
    cJSON *rest = cJSON_GetObjectItemCaseSensitive(json, "restCharge");
    model->restValid = cJSON_IsNumber(rest) && rest->valuedouble <= CFW_BAT_FULL;
    model->restCharge = model->restValid ? (uint32_t)rest->valuedouble : 0;

    cJSON *cycle = cJSON_GetObjectItemCaseSensitive(json, "cycle");
    model->cycleActive = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(cycle, "active"));
    model->cycleFrom = (uint32_t)get_number(cycle, "from");
    model->cycleUsedMs = (uint32_t)get_number(cycle, "usedMs");
    model->cycleLowMs = (uint32_t)get_number(cycle, "lowMs");
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
    model->lastMv = (uint16_t)get_number(last, "mv");
    model->lastUptimeMs = (uint32_t)get_number(last, "uptimeMs");
    model->lastTime = (uint64_t)get_number(last, "time");
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
    cJSON_AddNumberToObject(json, "version", MODEL_VERSION);
    add_u16_array(json, "curve", model->curve, CFW_BAT_LEVELS);
    cJSON_AddNumberToObject(json, "cycles", model->cycles);
    cJSON_AddNumberToObject(json, "measured", model->measured);
    cJSON_AddNumberToObject(json, "capacity", model->capacity);
    if (model->chargeValid)
    {
        cJSON_AddNumberToObject(json, "charge", model->charge);
        cJSON_AddNumberToObject(json, "spread", model->spread);
    }
    if (model->restValid)
    {
        cJSON_AddNumberToObject(json, "restCharge", model->restCharge);
    }

    cJSON *cycle = cJSON_AddObjectToObject(json, "cycle");
    cJSON_AddBoolToObject(cycle, "active", model->cycleActive);
    cJSON_AddNumberToObject(cycle, "from", model->cycleFrom);
    cJSON_AddNumberToObject(cycle, "usedMs", model->cycleUsedMs);
    cJSON_AddNumberToObject(cycle, "lowMs", model->cycleLowMs);
    add_u16_array(cycle, "mv", model->cycleMv, model->cycleCount);
    cJSON *at = cJSON_AddArrayToObject(cycle, "at");
    for (uint16_t i = 0; i < model->cycleCount; i++)
    {
        cJSON_AddItemToArray(at, cJSON_CreateNumber(model->cycleAt[i]));
    }

    cJSON *last = cJSON_AddObjectToObject(json, "last");
    cJSON_AddBoolToObject(last, "valid", model->lastValid);
    cJSON_AddBoolToObject(last, "station", model->lastStation);
    cJSON_AddNumberToObject(last, "mv", model->lastMv);
    cJSON_AddNumberToObject(last, "uptimeMs", model->lastUptimeMs);
    cJSON_AddNumberToObject(last, "time", (double)model->lastTime);

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

cfw_battery_model_t *cfw_battery_load(const char *boxId)
{
    cfw_battery_model_t *model = osAllocMem(sizeof(cfw_battery_model_t));
    if (model == NULL)
    {
        return NULL;
    }
    cfw_battery_model_init(model);
    if (!load_model(model, boxId))
    {
        cfw_battery_model_init(model);
        learn_from_log(model, boxId);
    }
    return model;
}

cfw_battery_model_t *cfw_battery_update(cfw_box_t *box, uint64_t uptimeMs, cfw_battery_model_t **loaded)
{
    if (box->batteryModel == NULL)
    {
        if (*loaded == NULL)
        {
            return NULL;
        }
        box->batteryModel = *loaded;
        *loaded = NULL;
    }
    cfw_battery_report_t r;
    report_from_values(&r, box->battery[0], box->battery[1], uptimeMs, (uint64_t)time(NULL));
    if (cfw_battery_model_report(box->batteryModel, &r, &box->batteryResult))
    {
        TRACE_INFO("CFW: box %s: battery capacity and curve learned from a discharge (%u so far)\r\n", box->id, box->batteryModel->cycles);
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
