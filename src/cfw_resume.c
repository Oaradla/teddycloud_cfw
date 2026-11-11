#include "cfw_resume.h"

#include "cfw_internal.h"
#include "cfw_resume_model.h"
#include "debug.h"
#include "os_port.h"
#include "server_helpers.h"

#define RESUME_PAYLOAD 32

static cfw_resume_t *entries;
static size_t entryCount;
static bool loaded;

static char *store_path(void)
{
    char *dir = cfw_dir(get_settings()->internal.configdirfull, "");
    char *path = dir ? custom_asprintf("%sresume.json", dir) : NULL;
    osFreeMem(dir);
    return path;
}

static cJSON *position_json(const cfw_position_t *p)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "box", p->box);
    cJSON_AddNumberToObject(json, "base", p->base);
    cJSON_AddNumberToObject(json, "listened", p->listened);
    cJSON_AddNumberToObject(json, "audioId", p->audioId);
    cJSON_AddNumberToObject(json, "position", p->position);
    cJSON_AddNumberToObject(json, "seed", p->seed);
    cJSON_AddNumberToObject(json, "index", p->index);
    cJSON_AddNumberToObject(json, "chapters", p->chapters);
    cJSON_AddNumberToObject(json, "flags", p->flags);
    cJSON_AddNumberToObject(json, "time", (double)p->time);
    return json;
}

static double number(const cJSON *json, const char *name)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(json, name);
    return cJSON_IsNumber(item) ? item->valuedouble : 0;
}

static void position_from(const cJSON *json, cfw_position_t *p)
{
    osMemset(p, 0, sizeof(*p));
    const cJSON *box = cJSON_GetObjectItemCaseSensitive(json, "box");
    if (cJSON_IsString(box))
    {
        osStrncpy(p->box, box->valuestring, sizeof(p->box) - 1);
    }
    p->base = (uint16_t)number(json, "base");
    p->listened = (uint16_t)number(json, "listened");
    p->audioId = (uint32_t)number(json, "audioId");
    p->position = (uint32_t)number(json, "position");
    p->seed = (uint32_t)number(json, "seed");
    p->index = (uint8_t)number(json, "index");
    p->chapters = (uint8_t)number(json, "chapters");
    p->flags = (uint8_t)number(json, "flags");
    p->time = (time_t)number(json, "time");
}

static cJSON *entry_json(const cfw_resume_t *r, bool full)
{
    char text[17];
    cJSON *json = cJSON_CreateObject();
    cfw_format_ruid(r->ruid, text);
    cJSON_AddStringToObject(json, "ruid", text);
    cJSON_AddBoolToObject(json, "global", r->global);
    cJSON_AddNumberToObject(json, "revision", r->revision);
    cJSON_AddItemToObject(json, "last", position_json(&r->last));
    if (r->historyCount > 0)
    {
        cJSON_AddItemToObject(json, "current", position_json(&r->current));
    }
    cJSON_AddBoolToObject(json, "conflict", r->conflict);
    cJSON *branches = cJSON_AddArrayToObject(json, "branches");
    for (size_t i = 0; i < r->branchCount; i++)
    {
        cJSON_AddItemToArray(branches, position_json(&r->branch[i]));
    }
    cJSON_AddStringToObject(json, "onBox", r->onBox);
    if (full)
    {
        cJSON *history = cJSON_AddArrayToObject(json, "history");
        for (size_t i = 0; i < r->historyCount; i++)
        {
            cJSON *h = cJSON_CreateObject();
            cJSON_AddNumberToObject(h, "revision", r->historyRevision[i]);
            cJSON_AddNumberToObject(h, "listened", r->historyListened[i]);
            cJSON_AddItemToArray(history, h);
        }
        cJSON *known = cJSON_AddArrayToObject(json, "known");
        for (size_t i = 0; i < r->knownCount; i++)
        {
            cJSON *k = cJSON_CreateObject();
            cJSON_AddStringToObject(k, "box", r->known[i].box);
            cJSON_AddNumberToObject(k, "base", r->known[i].base);
            cJSON_AddNumberToObject(k, "listened", r->known[i].listened);
            cJSON_AddNumberToObject(k, "revision", r->known[i].revision);
            cJSON_AddNumberToObject(k, "since", r->known[i].since);
            cJSON_AddItemToArray(known, k);
        }
    }
    return json;
}

static void entry_from(const cJSON *json, cfw_resume_t *r)
{
    osMemset(r, 0, sizeof(*r));
    const cJSON *ruid = cJSON_GetObjectItemCaseSensitive(json, "ruid");
    if (!cJSON_IsString(ruid) || !cfw_parse_ruid(ruid->valuestring, &r->ruid))
    {
        return;
    }
    r->global = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "global"));
    r->revision = (uint16_t)number(json, "revision");
    position_from(cJSON_GetObjectItemCaseSensitive(json, "last"), &r->last);
    position_from(cJSON_GetObjectItemCaseSensitive(json, "current"), &r->current);
    r->conflict = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "conflict"));
    const cJSON *item;
    cJSON_ArrayForEach(item, cJSON_GetObjectItemCaseSensitive(json, "branches"))
    {
        if (r->branchCount < CFW_RESUME_BRANCHES)
        {
            position_from(item, &r->branch[r->branchCount++]);
        }
    }
    cJSON_ArrayForEach(item, cJSON_GetObjectItemCaseSensitive(json, "history"))
    {
        if (r->historyCount < CFW_RESUME_HISTORY)
        {
            r->historyRevision[r->historyCount] = (uint16_t)number(item, "revision");
            r->historyListened[r->historyCount++] = (uint16_t)number(item, "listened");
        }
    }
    cJSON_ArrayForEach(item, cJSON_GetObjectItemCaseSensitive(json, "known"))
    {
        const cJSON *box = cJSON_GetObjectItemCaseSensitive(item, "box");
        if (r->knownCount < CFW_RESUME_BOXES && cJSON_IsString(box))
        {
            cfw_resume_known_t *k = &r->known[r->knownCount++];
            osStrncpy(k->box, box->valuestring, CFW_RESUME_BOX_ID - 1);
            k->base = (uint16_t)number(item, "base");
            k->listened = (uint16_t)number(item, "listened");
            k->revision = (uint16_t)number(item, "revision");
            k->since = (uint16_t)number(item, "since");
        }
    }
    r->conflict = r->conflict && r->branchCount >= 2;
}

static void load(void)
{
    loaded = true;
    char *path = store_path();
    size_t length = 0;
    uint8_t *data = path ? cfw_read_file(path, 16 * 1024 * 1024, &length) : NULL;
    osFreeMem(path);
    cJSON *json = data ? cJSON_Parse((const char *)data) : NULL;
    osFreeMem(data);
    int count = cJSON_GetArraySize(json);
    entries = count > 0 ? osAllocMem(count * sizeof(cfw_resume_t)) : NULL;
    const cJSON *item;
    cJSON_ArrayForEach(item, json)
    {
        if (entries != NULL)
        {
            entry_from(item, &entries[entryCount]);
            entryCount += entries[entryCount].ruid != 0;
        }
    }
    cJSON_Delete(json);
}

static void save(void)
{
    cJSON *json = cJSON_CreateArray();
    for (size_t i = 0; i < entryCount; i++)
    {
        cJSON_AddItemToArray(json, entry_json(&entries[i], true));
    }
    char *text = cJSON_PrintUnformatted(json);
    char *path = store_path();
    if (text == NULL || path == NULL || !cfw_write_file(path, text, osStrlen(text)))
    {
        TRACE_WARNING("CFW: resume positions not written\r\n");
    }
    osFreeMem(path);
    osFreeMem(text);
    cJSON_Delete(json);
}

static cfw_resume_t *find(uint64_t ruid, bool create)
{
    if (!loaded)
    {
        load();
    }
    for (size_t i = 0; i < entryCount; i++)
    {
        if (entries[i].ruid == ruid)
        {
            return &entries[i];
        }
    }
    if (!create)
    {
        return NULL;
    }
    cfw_resume_t *more = osAllocMem((entryCount + 1) * sizeof(cfw_resume_t));
    if (more == NULL)
    {
        return NULL;
    }
    if (entryCount > 0)
    {
        osMemcpy(more, entries, entryCount * sizeof(cfw_resume_t));
    }
    osFreeMem(entries);
    entries = more;
    cfw_resume_t *r = &entries[entryCount++];
    osMemset(r, 0, sizeof(*r));
    r->ruid = ruid;
    return r;
}

bool cfw_resume_record(const char *boxId, const uint8_t *payload, size_t length, bool query, uint64_t *ruid,
                       uint16_t *base)
{
    if (length < RESUME_PAYLOAD)
    {
        return false;
    }
    *ruid = cfw_ruid_from_bytes(payload);
    cfw_resume_t *r = find(*ruid, true);
    if (r == NULL)
    {
        return false;
    }
    cfw_position_t p;
    osMemset(&p, 0, sizeof(p));
    osStrncpy(p.box, boxId, sizeof(p.box) - 1);
    p.audioId = cfw_le32(&payload[8]);
    p.position = cfw_le32(&payload[12]);
    p.seed = cfw_le32(&payload[16]);
    uint32_t shuffle = cfw_le32(&payload[20]);
    p.index = shuffle & 0xFF;
    p.chapters = (shuffle >> 8) & 0xFF;
    p.flags = (shuffle >> 16) & 1;
    uint32_t reason = cfw_le32(&payload[24]);
    uint32_t baseTime = cfw_le32(&payload[28]);
    p.base = baseTime & 0xFFFF;
    p.listened = baseTime >> 16;
    p.time = time(NULL);
    *base = p.base;
    bool global = (shuffle >> 17) & 1;
    cfw_resume_result_t result =
        cfw_resume_apply(r, &p, global, query ? CFW_RESUME_QUERY : (cfw_resume_reason_t)reason);
    char text[17];
    cfw_format_ruid(*ruid, text);
    TRACE_INFO("CFW: box %s %s %s: block %" PRIu32 ", base %u, %u s, result %d, revision %u\r\n", boxId,
               query ? "asks for" : "reports", text, p.position, p.base, p.listened, result, r->revision);
    if (result != CFW_RESUME_NONE || reason != CFW_RESUME_PLAYING)
    {
        save();
    }
    return result == CFW_RESUME_CONFLICTS;
}

const char *cfw_resume_elsewhere(uint64_t ruid, const char *boxId)
{
    cfw_resume_t *r = find(ruid, false);
    return r != NULL && r->onBox[0] != '\0' && osStrcmp(r->onBox, boxId) != 0 ? r->onBox : NULL;
}

uint32_t cfw_resume_reports(uint64_t ruid)
{
    cfw_resume_t *r = find(ruid, false);
    return r != NULL ? r->reports : 0;
}

bool cfw_resume_reported_since(uint64_t ruid, const char *boxId, uint32_t reports)
{
    cfw_resume_t *r = find(ruid, false);
    return r != NULL && r->reports != reports && osStrcmp(r->last.box, boxId) == 0;
}

size_t cfw_resume_answer_args(uint64_t ruid, const char *boxId, uint16_t base, uint8_t *args)
{
    cfw_resume_t *r = find(ruid, false);
    cfw_resume_answer_t answer = r != NULL ? cfw_resume_answer_for(r, boxId, base) : CFW_RESUME_KEEP;
    cfw_ruid_to_bytes(ruid, args);
    args[8] = (uint8_t)answer;
    if (answer != CFW_RESUME_TAKE)
    {
        return 9;
    }
    args[9] = r->revision & 0xFF;
    args[10] = r->revision >> 8;
    cfw_put_le32(&args[11], r->current.audioId);
    cfw_put_le32(&args[15], r->current.position);
    cfw_put_le32(&args[19], r->current.seed);
    args[23] = r->current.index;
    args[24] = r->current.chapters;
    args[25] = r->current.flags;
    return 26;
}

cJSON *cfw_resume_json(void)
{
    if (!loaded)
    {
        load();
    }
    cJSON *json = cJSON_CreateArray();
    for (size_t i = 0; i < entryCount; i++)
    {
        cJSON_AddItemToArray(json, entry_json(&entries[i], false));
    }
    return json;
}

cJSON *cfw_resume_entry(uint64_t ruid)
{
    cfw_resume_t *r = find(ruid, false);
    return r != NULL ? entry_json(r, false) : NULL;
}

size_t cfw_resume_conflict_boxes(uint64_t ruid, char boxes[CFW_RESUME_BRANCHES][CFW_RESUME_BOX_ID])
{
    cfw_resume_t *r = find(ruid, false);
    size_t count = r != NULL && r->conflict ? r->branchCount : 0;
    for (size_t i = 0; i < count; i++)
    {
        osMemcpy(boxes[i], r->branch[i].box, CFW_RESUME_BOX_ID);
    }
    return count;
}

bool cfw_resume_choose_branch(uint64_t ruid, size_t branch)
{
    cfw_resume_t *r = find(ruid, false);
    if (r == NULL || !cfw_resume_choose(r, branch))
    {
        return false;
    }
    save();
    return true;
}

void cfw_resume_free(void)
{
    osFreeMem(entries);
    entries = NULL;
    entryCount = 0;
    loaded = false;
}
