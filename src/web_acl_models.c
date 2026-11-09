#include <stdio.h>
#include <string.h>

#include "web_acl.h"
#include "web_acl_core.h"
#include "cJSON.h"
#include "fs_port.h"
#include "handler.h"
#include "handler_api.h"
#include "mutex_manager.h"
#include "os_port.h"
#include "server_helpers.h"
#include "settings.h"

/* Custom tonies are used by library files and by tonie contents: with one of their audio ids or,
   for a tonie, with the model set in its content json. */

#define LIB_PATH_MAX 256

/* lib: path of a library file below the library, ruid: tonie as "HI8LO8"; one of them is set */
typedef bool (*use_fn)(void *ctx, tonie_info_t *info, const char *lib, const char *ruid);

static bool model_used(const cJSON *entry, tonie_info_t *info)
{
    const cJSON *model = cJSON_GetObjectItemCaseSensitive(entry, "model");
    if (cJSON_IsString(model) && info->json.tonie_model != NULL && !osStrcasecmp(info->json.tonie_model, model->valuestring))
    {
        return true;
    }
    if (!info->valid || info->tafHeader == NULL)
    {
        return false;
    }
    const cJSON *id = NULL;
    cJSON_ArrayForEach(id, cJSON_GetObjectItemCaseSensitive(entry, "audio_id"))
    {
        uint32_t value = cJSON_IsString(id) ? (uint32_t)strtoul(id->valuestring, NULL, 10) : (uint32_t)id->valuedouble;
        if (value == info->tafHeader->audio_id)
        {
            return true;
        }
    }
    return false;
}

static bool walk_library(const char *base, const char *rel, use_fn fn, void *ctx)
{
    char *dirPath = custom_asprintf("%s%c%s", base, PATH_SEPARATOR, rel);
    FsDir *dir = fsOpenDir(dirPath);
    bool go_on = true;
    FsDirEntry entry;
    while (go_on && dir != NULL && fsReadDir(dir, &entry) == NO_ERROR)
    {
        /* "by" holds the cache of tonie contents, those count as tonies */
        if (entry.name[0] == '.' || (rel[0] == '\0' && !osStrcmp(entry.name, "by")))
        {
            continue;
        }
        char path[LIB_PATH_MAX];
        if (osSnprintf(path, sizeof(path), "%s%s%s", rel, rel[0] ? "/" : "", entry.name) >= (int)sizeof(path))
        {
            continue;
        }
        if (entry.attributes & FS_FILE_ATTR_DIRECTORY)
        {
            go_on = walk_library(base, path, fn, ctx);
            continue;
        }
        char *abs = custom_asprintf("%s%c%s", base, PATH_SEPARATOR, path);
        tonie_info_t *info = getTonieInfo(abs, false, get_settings());
        go_on = fn(ctx, info, path, NULL);
        freeTonieInfo(info);
        osFreeMem(abs);
    }
    if (dir != NULL)
    {
        fsCloseDir(dir);
    }
    osFreeMem(dirPath);
    return go_on;
}

static bool hex8(const char *name)
{
    return osStrlen(name) == 8 && strspn(name, "0123456789abcdefABCDEF") == 8;
}

static bool walk_tonies(const char *base, use_fn fn, void *ctx)
{
    FsDir *dir = fsOpenDir(base);
    bool go_on = true;
    FsDirEntry hi;
    while (go_on && dir != NULL && fsReadDir(dir, &hi) == NO_ERROR)
    {
        if (!(hi.attributes & FS_FILE_ATTR_DIRECTORY) || !hex8(hi.name))
        {
            continue;
        }
        char *hiPath = custom_asprintf("%s%c%s", base, PATH_SEPARATOR, hi.name);
        FsDir *sub = fsOpenDir(hiPath);
        FsDirEntry lo;
        while (go_on && sub != NULL && fsReadDir(sub, &lo) == NO_ERROR)
        {
            if ((lo.attributes & FS_FILE_ATTR_DIRECTORY) || !hex8(lo.name))
            {
                continue;
            }
            char ruid[17];
            osSnprintf(ruid, sizeof(ruid), "%s%s", hi.name, lo.name);
            char *abs = custom_asprintf("%s%c%s", hiPath, PATH_SEPARATOR, lo.name);
            tonie_info_t *info = getTonieInfo(abs, false, get_settings());
            go_on = fn(ctx, info, NULL, ruid);
            freeTonieInfo(info);
            osFreeMem(abs);
        }
        if (sub != NULL)
        {
            fsCloseDir(sub);
        }
        osFreeMem(hiPath);
    }
    if (dir != NULL)
    {
        fsCloseDir(dir);
    }
    return go_on;
}

static void walk_uses(use_fn fn, void *ctx)
{
    settings_t *settings = get_settings();
    if (walk_library(settings->internal.librarydirfull, "", fn, ctx))
    {
        walk_tonies(settings->internal.contentdirfull, fn, ctx);
    }
}

/* per custom tonie of root: how often it is used, whether outside the paths, whether where the user may not write */
typedef struct
{
    HttpConnection *connection; /* NULL: rights are not asked */
    cJSON *root;
    char (*paths)[LIB_PATH_MAX];
    size_t count;
    int *uses;
    bool *outside;
    bool *blocked;
} tally_t;

static bool use_writable(HttpConnection *connection, const char *lib, const char *ruid)
{
    if (ruid != NULL)
    {
        return web_acl_tonie_allowed(connection, ruid, "tonie.edit");
    }
    char folder[LIB_PATH_MAX];
    osSnprintf(folder, sizeof(folder), "%s", lib);
    char *slash = strrchr(folder, '/');
    *(slash ? slash : folder) = '\0';
    return web_acl_folder_allowed(connection, folder, "folder.write");
}

static bool tally_use(void *ctx, tonie_info_t *info, const char *lib, const char *ruid)
{
    tally_t *t = ctx;
    bool inside = false;
    for (size_t p = 0; lib != NULL && p < t->count && !inside; p++)
    {
        inside = acl_path_within(lib, t->paths[p]);
    }
    int writable = -1;
    int i = 0;
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, t->root)
    {
        if (model_used(entry, info))
        {
            t->uses[i]++;
            t->outside[i] |= !inside;
            if (t->connection != NULL && writable < 0)
            {
                writable = use_writable(t->connection, lib, ruid);
            }
            t->blocked[i] |= writable == 0;
        }
        i++;
    }
    return true;
}

static void tally(tally_t *t)
{
    int n = cJSON_GetArraySize(t->root) + 1;
    t->uses = osAllocMem(sizeof(int) * n);
    t->outside = osAllocMem(sizeof(bool) * n);
    t->blocked = osAllocMem(sizeof(bool) * n);
    osMemset(t->uses, 0, sizeof(int) * n);
    osMemset(t->outside, 0, sizeof(bool) * n);
    osMemset(t->blocked, 0, sizeof(bool) * n);
    walk_uses(tally_use, t);
}

static void tally_free(tally_t *t)
{
    osFreeMem(t->uses);
    osFreeMem(t->outside);
    osFreeMem(t->blocked);
}

static cJSON *load_models(void)
{
    cJSON *root = NULL;
    if (loadToniesCustomJsonRoot(settings_get_string("internal.configdirfull"), &root) != NO_ERROR)
    {
        return cJSON_CreateArray();
    }
    return root;
}

static bool owned_model(HttpConnection *connection, const cJSON *entry)
{
    const cJSON *model = cJSON_GetObjectItemCaseSensitive(entry, "model");
    return cJSON_IsString(model) && web_acl_owns(connection, "models", model->valuestring);
}

bool web_acl_model_allowed(HttpConnection *connection, const cJSON *entry)
{
    if (web_acl_is_admin(connection))
    {
        return true;
    }
    if (!web_acl_system_allowed(connection, "model.create"))
    {
        return false;
    }
    if (entry == NULL || owned_model(connection, entry))
    {
        return true;
    }
    cJSON *one = cJSON_CreateArray();
    cJSON_AddItemReferenceToArray(one, (cJSON *)entry);
    tally_t t = {connection, one, NULL, 0};
    tally(&t);
    bool ok = t.uses[0] > 0 && !t.blocked[0];
    tally_free(&t);
    cJSON_Delete(one);
    return ok;
}

static const char *picture_of(const cJSON *entry)
{
    const cJSON *pic = cJSON_GetObjectItemCaseSensitive(entry, "pic");
    return cJSON_IsString(pic) && !osStrncmp(pic->valuestring, "/custom_img/", 12) ? pic->valuestring + 12 : NULL;
}

/* the custom tonies and pictures the user may change, as names in "models" and "images" */
cJSON *web_acl_models_changeable(HttpConnection *connection)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *models = cJSON_AddArrayToObject(json, "models");
    cJSON *images = cJSON_AddArrayToObject(json, "images");
    if (!web_acl_system_allowed(connection, "model.create"))
    {
        return json;
    }
    tally_t t = {connection, load_models(), NULL, 0};
    tally(&t);
    /* a picture goes when every tonie showing it may be changed: blocked by one that may not */
    cJSON *blocked = cJSON_CreateObject();
    int i = 0;
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, t.root)
    {
        const cJSON *model = cJSON_GetObjectItemCaseSensitive(entry, "model");
        const char *pic = picture_of(entry);
        bool ok = web_acl_is_admin(connection) || owned_model(connection, entry) || (t.uses[i] > 0 && !t.blocked[i]);
        if (ok && cJSON_IsString(model))
        {
            cJSON_AddItemToArray(models, cJSON_CreateString(model->valuestring));
        }
        if (pic != NULL && !cJSON_HasObjectItem(blocked, pic))
        {
            cJSON_AddBoolToObject(blocked, pic, !ok);
        }
        else if (pic != NULL && !ok)
        {
            cJSON_ReplaceItemInObjectCaseSensitive(blocked, pic, cJSON_CreateTrue());
        }
        i++;
    }
    cJSON *pic = NULL;
    cJSON_ArrayForEach(pic, blocked)
    {
        if (cJSON_IsFalse(pic) || web_acl_owns(connection, "images", pic->string))
        {
            cJSON_AddItemToArray(images, cJSON_CreateString(pic->string));
        }
    }
    cJSON_Delete(blocked);
    tally_free(&t);
    cJSON_Delete(t.root);
    return json;
}

bool web_acl_image_allowed(HttpConnection *connection, const char *name)
{
    if (web_acl_owns(connection, "images", name))
    {
        return web_acl_system_allowed(connection, "model.create");
    }
    if (!web_acl_system_allowed(connection, "model.create"))
    {
        return false;
    }
    /* every custom tonie showing it may be changed: the ones not owned are looked up in one go */
    cJSON *root = load_models();
    cJSON *others = cJSON_CreateArray();
    int shown = 0;
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, root)
    {
        const char *pic = picture_of(entry);
        if (pic != NULL && !osStrcmp(pic, name))
        {
            shown++;
            if (!owned_model(connection, entry))
            {
                cJSON_AddItemReferenceToArray(others, (cJSON *)entry);
            }
        }
    }
    bool ok = shown > 0;
    int n = cJSON_GetArraySize(others);
    if (ok && n > 0)
    {
        tally_t t = {connection, others, NULL, 0};
        tally(&t);
        for (int i = 0; i < n; i++)
        {
            ok = ok && t.uses[i] > 0 && !t.blocked[i];
        }
        tally_free(&t);
    }
    cJSON_Delete(others);
    cJSON_Delete(root);
    return ok;
}

/* per custom tonie of root: how often it is used, whether somewhere else than in the private folders of others */
typedef struct
{
    cJSON *root;
    char own[LIB_PATH_MAX]; /* the private folder of the user */
    int *uses;
    bool *seen;
} sight_t;

static bool sight_use(void *ctx, tonie_info_t *info, const char *lib, const char *ruid)
{
    sight_t *s = ctx;
    bool seen = lib == NULL || !acl_path_within(lib, "private") || acl_path_within(lib, s->own);
    int i = 0;
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, s->root)
    {
        if (model_used(entry, info))
        {
            s->uses[i]++;
            s->seen[i] |= seen;
        }
        i++;
    }
    return true;
}

/* the pictures of root whose custom tonies are all used, and only in the private folders of others */
static cJSON *pictures_hidden(HttpConnection *connection, cJSON *root)
{
    int n = cJSON_GetArraySize(root) + 1;
    sight_t s = {root, "", osAllocMem(sizeof(int) * n), osAllocMem(sizeof(bool) * n)};
    osSnprintf(s.own, sizeof(s.own), "private/%s", connection->private.web_user);
    osMemset(s.uses, 0, sizeof(int) * n);
    osMemset(s.seen, 0, sizeof(bool) * n);
    walk_uses(sight_use, &s);
    cJSON *shown = cJSON_CreateObject();
    int i = 0;
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, root)
    {
        const char *pic = picture_of(entry);
        if (pic != NULL && (s.uses[i] == 0 || s.seen[i]) && !cJSON_HasObjectItem(shown, pic))
        {
            cJSON_AddTrueToObject(shown, pic);
        }
        i++;
    }
    cJSON *hidden = cJSON_CreateObject();
    cJSON_ArrayForEach(entry, root)
    {
        const char *pic = picture_of(entry);
        if (pic != NULL && !cJSON_HasObjectItem(shown, pic) && !cJSON_HasObjectItem(hidden, pic) &&
            !web_acl_owns(connection, "images", pic))
        {
            cJSON_AddTrueToObject(hidden, pic);
        }
    }
    cJSON_Delete(shown);
    osFreeMem(s.uses);
    osFreeMem(s.seen);
    return hidden;
}

/* a tonies page asks for many pictures at once: the hidden ones of the last users are kept a few seconds */
#define HIDDEN_KEEP_MS 5000
#define HIDDEN_USERS 8

typedef struct
{
    char user[sizeof(((http_connection_private_t *)NULL)->web_user)];
    systime_t time;
    cJSON *hidden;
} hidden_cache_t;

static hidden_cache_t hidden_cache[HIDDEN_USERS];

cJSON *web_acl_images_hidden(HttpConnection *connection)
{
    if (web_acl_is_admin(connection))
    {
        return cJSON_CreateObject();
    }
    const char *user = connection->private.web_user;
    systime_t now = osGetSystemTime();
    mutex_lock(MUTEX_WEB_ACL_IMAGES);
    hidden_cache_t *slot = &hidden_cache[0];
    for (size_t i = 0; i < HIDDEN_USERS; i++)
    {
        if (!osStrcmp(hidden_cache[i].user, user))
        {
            slot = &hidden_cache[i];
            break;
        }
        if (hidden_cache[i].time < slot->time)
        {
            slot = &hidden_cache[i];
        }
    }
    if (slot->hidden == NULL || osStrcmp(slot->user, user) || now - slot->time > HIDDEN_KEEP_MS)
    {
        cJSON_Delete(slot->hidden);
        cJSON *root = load_models();
        slot->hidden = pictures_hidden(connection, root);
        cJSON_Delete(root);
        osSnprintf(slot->user, sizeof(slot->user), "%s", user);
        slot->time = now;
    }
    cJSON *hidden = cJSON_Duplicate(slot->hidden, true);
    mutex_unlock(MUTEX_WEB_ACL_IMAGES);
    return hidden;
}

bool web_acl_image_visible(HttpConnection *connection, const char *name)
{
    char norm[LIB_PATH_MAX];
    if (!acl_path_normalize(name, norm, sizeof(norm)))
    {
        return false;
    }
    cJSON *hidden = web_acl_images_hidden(connection);
    bool visible = !cJSON_HasObjectItem(hidden, norm);
    cJSON_Delete(hidden);
    return visible;
}

cJSON *web_acl_model_orphans(HttpConnection *connection, const char *const *paths, size_t count)
{
    cJSON *names = cJSON_CreateArray();
    if (!web_acl_system_allowed(connection, "model.create"))
    {
        return names;
    }
    char(*norm)[LIB_PATH_MAX] = osAllocMem(LIB_PATH_MAX * (count + 1));
    size_t k = 0;
    for (size_t p = 0; p < count; p++)
    {
        k += acl_path_normalize(paths[p], norm[k], LIB_PATH_MAX);
    }
    tally_t t = {NULL, load_models(), norm, k};
    tally(&t);
    int i = 0;
    const cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, t.root)
    {
        const cJSON *model = cJSON_GetObjectItemCaseSensitive(entry, "model");
        if (t.uses[i] > 0 && !t.outside[i] && cJSON_IsString(model))
        {
            cJSON_AddItemToArray(names, cJSON_CreateString(model->valuestring));
        }
        i++;
    }
    tally_free(&t);
    cJSON_Delete(t.root);
    osFreeMem(norm);
    return names;
}
