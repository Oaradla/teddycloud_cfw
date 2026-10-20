#include "tonie_audio_playlist.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_acl.h"
#include "web_acl_core.h"
#include "cJSON.h"
#include "debug.h"
#include "fs_ext.h"
#include "fs_port.h"
#include "handler_web_auth.h"
#include "os_port.h"
#include "server_helpers.h"
#include "settings.h"

#define BOX_ID_MAX 64
#define RUID_LEN 16
#define PATH_MAX_LEN 256
#define RIGHTS_MAX 2048
#define ACL_FILE_MAX (2 * 1024 * 1024)
#define PRIVATE_DIR "private"

static cJSON *acl = NULL;
static OsMutex acl_mutex;
static bool acl_mutex_ready = false;

/* guests: everything a share can give them, but no sharing on and no users */
static const char *const default_guest_max = "box.view, box.settings, box.cfw, tonie.view, tonie.assign, tonie.edit, folder.read, folder.write";
static const char *const default_unassigned_tonie = "tonie.view, tonie.assign, tonie.edit";

/* ---------- storage ---------- */

static void lock_acl(void)
{
    if (acl_mutex_ready)
    {
        osAcquireMutex(&acl_mutex);
    }
}

static void unlock_acl(void)
{
    if (acl_mutex_ready)
    {
        osReleaseMutex(&acl_mutex);
    }
}

static char *acl_path(void)
{
    const char *dir = settings_get_string("internal.configdirfull");
    if (dir == NULL || dir[0] == '\0')
    {
        return NULL;
    }
    return custom_asprintf("%s%c%s", dir, PATH_SEPARATOR, WEB_ACL_JSON_FILE);
}

static cJSON *obj(cJSON *parent, const char *key)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, key);
    if (!cJSON_IsObject(item))
    {
        if (item != NULL)
        {
            cJSON_DeleteItemFromObjectCaseSensitive(parent, key);
        }
        item = cJSON_AddObjectToObject(parent, key);
    }
    return item;
}

static const char *str(cJSON *parent, const char *key, const char *def)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(parent, key);
    return cJSON_IsString(item) && item->valuestring != NULL ? item->valuestring : def;
}

static cJSON *folder_entry(const char *owner, const char *everyone)
{
    cJSON *e = cJSON_CreateObject();
    cJSON *owners = cJSON_AddArrayToObject(e, "owners");
    if (owner != NULL)
    {
        cJSON_AddItemToArray(owners, cJSON_CreateString(owner));
    }
    cJSON *shares = cJSON_AddObjectToObject(e, "shares");
    if (everyone != NULL)
    {
        cJSON_AddStringToObject(shares, "*", everyone);
    }
    return e;
}

/* fills in what is missing, so an empty or old file gets the defaults */
static void apply_defaults_unlocked(void)
{
    if (acl == NULL)
    {
        acl = cJSON_CreateObject();
    }
    if (!cJSON_GetObjectItemCaseSensitive(acl, "version"))
    {
        cJSON_AddNumberToObject(acl, "version", 1);
    }
    cJSON *levels = obj(acl, "levels");
    if (!cJSON_IsString(cJSON_GetObjectItemCaseSensitive(levels, "user")))
    {
        cJSON_AddStringToObject(levels, "user", "*");
    }
    if (!cJSON_IsString(cJSON_GetObjectItemCaseSensitive(levels, "guest")))
    {
        cJSON_AddStringToObject(levels, "guest", default_guest_max);
    }
    /* the deny list per level of an earlier build: the limits of the levels and groups do this */
    cJSON_DeleteItemFromObjectCaseSensitive(acl, "levelDeny");
    obj(acl, "groups");
    cJSON *unassigned = obj(acl, "unassigned");
    if (!cJSON_IsString(cJSON_GetObjectItemCaseSensitive(unassigned, "tonie")))
    {
        cJSON_AddStringToObject(unassigned, "tonie", default_unassigned_tonie);
    }
    if (!cJSON_IsString(cJSON_GetObjectItemCaseSensitive(unassigned, "box")))
    {
        cJSON_AddStringToObject(unassigned, "box", "");
    }
    obj(acl, "boxes");
    obj(acl, "tonies");
    cJSON *folders = obj(acl, "folders");
    /* new top-level folders: read and write for everyone; by/: read for everyone; private/: nobody */
    if (!cJSON_GetObjectItemCaseSensitive(folders, ""))
    {
        cJSON_AddItemToObject(folders, "", folder_entry(NULL, "folder.read, folder.write"));
    }
    if (!cJSON_GetObjectItemCaseSensitive(folders, "by"))
    {
        cJSON_AddItemToObject(folders, "by", folder_entry(NULL, "folder.read"));
    }
    if (!cJSON_GetObjectItemCaseSensitive(folders, PRIVATE_DIR))
    {
        cJSON_AddItemToObject(folders, PRIVATE_DIR, folder_entry(NULL, NULL));
    }
}

static bool save_unlocked(void)
{
    char *path = acl_path();
    if (path == NULL)
    {
        return false;
    }
    char *body = cJSON_Print(acl);
    bool ok = body != NULL && web_auth_write_private_file(path, body);
    if (!ok)
    {
        TRACE_ERROR("Permissions: could not save %s\r\n", path);
    }
    if (body)
    {
        osFreeMem(body);
    }
    osFreeMem(path);
    return ok;
}

static void load_unlocked(void)
{
    if (acl != NULL)
    {
        cJSON_Delete(acl);
        acl = NULL;
    }
    char *path = acl_path();
    if (path != NULL)
    {
        uint32_t size = 0;
        if (fsGetFileSize(path, &size) == NO_ERROR && size > 0 && size <= ACL_FILE_MAX)
        {
            char *buf = osAllocMem(size + 1);
            FsFile *file = buf ? fsOpenFile(path, FS_FILE_MODE_READ) : NULL;
            size_t n = 0;
            if (file != NULL)
            {
                if (fsReadFile(file, buf, size, &n) == NO_ERROR)
                {
                    buf[n] = '\0';
                    acl = cJSON_Parse(buf);
                }
                fsCloseFile(file);
            }
            if (acl == NULL || !cJSON_IsObject(acl))
            {
                /* keep the broken file for the admin; start from the defaults (owners then see nothing) */
                TRACE_ERROR("Permissions: %s is invalid, using defaults\r\n", path);
                if (acl)
                {
                    cJSON_Delete(acl);
                }
                acl = NULL;
            }
            if (buf)
            {
                osFreeMem(buf);
            }
        }
        osFreeMem(path);
    }
    apply_defaults_unlocked();
}

void web_acl_init(void)
{
    if (!acl_mutex_ready && osCreateMutex(&acl_mutex))
    {
        acl_mutex_ready = true;
    }
    lock_acl();
    load_unlocked();
    unlock_acl();
}

/* ---------- decisions ---------- */

typedef struct
{
    bool known;
    acl_level_t level;
    char user[33];
    /* own group of the user, empty for the built-in one of the level */
    char group[WEB_ACL_GROUP_ID_MAX + 1];
    char deny[RIGHTS_MAX];
} acl_user_t;

static acl_user_t current_user(HttpConnection *connection)
{
    acl_user_t u;
    osMemset(&u, 0, sizeof(u));
    if (connection == NULL || !connection->private.web_user_known)
    {
        return u;
    }
    int level = ACL_LEVEL_GUEST;
    if (web_auth_user_info(connection->private.web_user, &level, u.deny, sizeof(u.deny), NULL, 0, u.group, sizeof(u.group)))
    {
        u.known = true;
        u.level = (acl_level_t)level;
        osStrncpy(u.user, connection->private.web_user, sizeof(u.user) - 1);
    }
    else
    {
        /* the user was deleted during the request */
        u.known = true;
        u.level = ACL_LEVEL_GUEST;
        osStrcpy(u.deny, "*");
    }
    return u;
}

static bool in_owners(cJSON *entry, const char *user)
{
    cJSON *owners = cJSON_GetObjectItemCaseSensitive(entry, "owners");
    cJSON *o = NULL;
    cJSON_ArrayForEach(o, owners)
    {
        if (cJSON_IsString(o) && !osStrcasecmp(o->valuestring, user))
        {
            return true;
        }
    }
    return false;
}

static bool has_owners(cJSON *entry)
{
    return cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(entry, "owners")) > 0;
}

/* granted rights of the user in the entry (the own share and the one for everyone) */
static bool shared_rights(cJSON *entry, const char *user, char *out, size_t out_size)
{
    cJSON *shares = cJSON_GetObjectItemCaseSensitive(entry, "shares");
    out[0] = '\0';
    bool found = false;
    cJSON *s = NULL;
    cJSON_ArrayForEach(s, shares)
    {
        if (!cJSON_IsString(s) || s->string == NULL)
        {
            continue;
        }
        if (!osStrcmp(s->string, "*") || !osStrcasecmp(s->string, user))
        {
            size_t len = osStrlen(out);
            osSnprintf(out + len, out_size - len, "%s%s", len ? ", " : "", s->valuestring);
            found = true;
        }
    }
    return found;
}

static const char *level_max_unlocked(acl_level_t level)
{
    cJSON *levels = cJSON_GetObjectItemCaseSensitive(acl, "levels");
    return str(levels, acl_level_name(level), level == ACL_LEVEL_GUEST ? default_guest_max : "*");
}

static cJSON *group_unlocked(const char *id)
{
    return id != NULL && id[0] != '\0' ? cJSON_GetObjectItemCaseSensitive(obj(acl, "groups"), id) : NULL;
}

static bool group_base(cJSON *group, acl_level_t *base)
{
    return cJSON_IsObject(group) && acl_level_parse(str(group, "base", ""), base) && *base != ACL_LEVEL_ADMIN;
}

/* most the user may have: the limit of the own group, otherwise that of the level */
static const char *user_limit_unlocked(const acl_user_t *u)
{
    if (u->group[0] == '\0')
    {
        return level_max_unlocked(u->level);
    }
    cJSON *group = group_unlocked(u->group);
    acl_level_t base;
    /* a group that is gone or of another kind gives nothing */
    if (!group_base(group, &base) || base != u->level)
    {
        return "";
    }
    return str(group, "rights", "");
}

/* entry == NULL: nobody owns the resource */
static bool decide_unlocked(const acl_user_t *u, cJSON *entry, const char *unassigned, const char *right)
{
    char granted[RIGHTS_MAX];
    acl_subject_t subject;
    osMemset(&subject, 0, sizeof(subject));
    subject.level = u->level;
    subject.level_max = user_limit_unlocked(u);
    subject.user_deny = u->deny[0] ? u->deny : NULL;
    subject.unassigned = unassigned;
    granted[0] = '\0';
    if (entry != NULL && in_owners(entry, u->user))
    {
        subject.relation = ACL_REL_OWNER;
    }
    else if (entry != NULL && shared_rights(entry, u->user, granted, sizeof(granted)))
    {
        subject.relation = ACL_REL_SHARED;
    }
    else if (entry == NULL || (!has_owners(entry) && unassigned != NULL))
    {
        subject.relation = unassigned != NULL ? ACL_REL_UNASSIGNED : ACL_REL_NONE;
    }
    else
    {
        subject.relation = ACL_REL_NONE;
    }
    subject.granted = granted;
    return acl_allowed(&subject, right);
}

bool web_acl_is_admin(HttpConnection *connection)
{
    acl_user_t u = current_user(connection);
    return !u.known || u.level == ACL_LEVEL_ADMIN;
}

bool web_acl_system_allowed(HttpConnection *connection, const char *right)
{
    acl_user_t u = current_user(connection);
    if (!u.known || u.level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    lock_acl();
    acl_subject_t subject = {u.level, ACL_REL_OWNER, NULL, user_limit_unlocked(&u), u.deny[0] ? u.deny : NULL, NULL};
    /* system rights are not per resource: the level and the restrictions decide */
    if (u.level == ACL_LEVEL_GUEST)
    {
        subject.relation = ACL_REL_SHARED;
        subject.granted = user_limit_unlocked(&u);
    }
    bool ok = acl_allowed(&subject, right);
    unlock_acl();
    return ok;
}

static bool box_known(const char *box_id)
{
    return box_id != NULL && box_id[0] != '\0' && get_overlay_id(box_id) != 0;
}

bool web_acl_box_allowed(HttpConnection *connection, const char *box_id, const char *right)
{
    acl_user_t u = current_user(connection);
    if (!u.known || u.level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    if (!box_known(box_id))
    {
        return false;
    }
    lock_acl();
    cJSON *entry = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(acl, "boxes"), box_id);
    const char *unassigned = str(cJSON_GetObjectItemCaseSensitive(acl, "unassigned"), "box", "");
    bool ok = decide_unlocked(&u, entry, unassigned, right);
    unlock_acl();
    return ok;
}

static bool normalize_ruid(const char *in, char out[RUID_LEN + 1])
{
    if (in == NULL || osStrlen(in) != RUID_LEN)
    {
        return false;
    }
    for (int i = 0; i < RUID_LEN; i++)
    {
        if (!isxdigit((unsigned char)in[i]))
        {
            return false;
        }
        out[i] = (char)toupper((unsigned char)in[i]);
    }
    out[RUID_LEN] = '\0';
    return true;
}

bool web_acl_tonie_allowed(HttpConnection *connection, const char *ruid, const char *right)
{
    char id[RUID_LEN + 1];
    acl_user_t u = current_user(connection);
    if (!u.known || u.level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    if (!normalize_ruid(ruid, id))
    {
        return false;
    }
    lock_acl();
    cJSON *entry = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(acl, "tonies"), id);
    const char *unassigned = str(cJSON_GetObjectItemCaseSensitive(acl, "unassigned"), "tonie", default_unassigned_tonie);
    bool ok = decide_unlocked(&u, entry, unassigned, right);
    unlock_acl();
    return ok;
}

/* the entry of the folder itself or of its nearest parent */
static cJSON *folder_lookup_unlocked(const char *path, char *found, size_t found_size)
{
    cJSON *folders = cJSON_GetObjectItemCaseSensitive(acl, "folders");
    char probe[PATH_MAX_LEN];
    osSnprintf(probe, sizeof(probe), "%s", path);
    while (1)
    {
#if defined(_WIN32) || defined(__APPLE__)
        /* the file system ignores the case, so do the entries: "PRIVATE/bob" is "private/bob" */
        cJSON *entry = cJSON_GetObjectItem(folders, probe);
#else
        cJSON *entry = cJSON_GetObjectItemCaseSensitive(folders, probe);
#endif
        if (entry != NULL)
        {
            if (found)
            {
                osSnprintf(found, found_size, "%s", probe);
            }
            return entry;
        }
        if (probe[0] == '\0')
        {
            return NULL;
        }
        char *slash = strrchr(probe, '/');
        if (slash == NULL)
        {
            probe[0] = '\0';
        }
        else
        {
            *slash = '\0';
        }
    }
}

bool web_acl_folder_allowed(HttpConnection *connection, const char *path, const char *right)
{
    char norm[PATH_MAX_LEN];
    acl_user_t u = current_user(connection);
    if (!u.known || u.level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    if (!acl_path_normalize(path ? path : "", norm, sizeof(norm)))
    {
        return false;
    }
    lock_acl();
    cJSON *entry = folder_lookup_unlocked(norm, NULL, 0);
    bool ok = entry != NULL && decide_unlocked(&u, entry, NULL, right);
    unlock_acl();
    return ok;
}

bool web_acl_folder_visible(HttpConnection *connection, const char *parent, const char *name)
{
    char joined[PATH_MAX_LEN];
    char norm[PATH_MAX_LEN];
    acl_user_t u = current_user(connection);
    if (!u.known || u.level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    osSnprintf(joined, sizeof(joined), "%s/%s", parent ? parent : "", name);
    if (!acl_path_normalize(joined, norm, sizeof(norm)))
    {
        return false;
    }
    if (web_acl_folder_allowed(connection, norm, "folder.read"))
    {
        return true;
    }
    /* e.g. "private" is shown when the user has "private/<name>" */
    bool below = false;
    lock_acl();
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, cJSON_GetObjectItemCaseSensitive(acl, "folders"))
    {
        char granted[RIGHTS_MAX];
        if (entry->string != NULL && acl_path_within(entry->string, norm) && osStrcmp(entry->string, norm) != 0 &&
            (in_owners(entry, u.user) || shared_rights(entry, u.user, granted, sizeof(granted))))
        {
            below = true;
            break;
        }
    }
    unlock_acl();
    return below;
}

bool web_acl_folder_tree_writable(HttpConnection *connection, const char *path)
{
    char norm[PATH_MAX_LEN];
    acl_user_t u = current_user(connection);
    if (!u.known || u.level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    if (!acl_path_normalize(path ? path : "", norm, sizeof(norm)) || !web_acl_folder_allowed(connection, norm, "folder.write"))
    {
        return false;
    }
    /* folders below with own entries (e.g. one shared or owned by someone else) must be writable too */
    char keys[64][PATH_MAX_LEN];
    int n = 0;
    lock_acl();
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, cJSON_GetObjectItemCaseSensitive(acl, "folders"))
    {
        if (entry->string != NULL && osStrcmp(entry->string, norm) != 0 && acl_path_within(entry->string, norm))
        {
            if (n >= 64)
            {
                unlock_acl();
                return false;
            }
            osSnprintf(keys[n++], PATH_MAX_LEN, "%s", entry->string);
        }
    }
    unlock_acl();
    for (int i = 0; i < n; i++)
    {
        if (!web_acl_folder_allowed(connection, keys[i], "folder.write"))
        {
            return false;
        }
    }
    return true;
}

/* entries of a folder tree follow a rename, or go with a delete (dst NULL) */
static void folder_entries_change(const char *src, const char *dst)
{
    char from[PATH_MAX_LEN], to[PATH_MAX_LEN];
    if (!acl_path_normalize(src, from, sizeof(from)) || from[0] == '\0' || (dst && !acl_path_normalize(dst, to, sizeof(to))))
    {
        return;
    }
    lock_acl();
    cJSON *folders = cJSON_GetObjectItemCaseSensitive(acl, "folders");
    bool changed = false;
    cJSON *entry = folders ? folders->child : NULL;
    while (entry != NULL)
    {
        cJSON *next = entry->next;
        const char *key = entry->string;
        /* the base entries stay */
        bool protected_entry = !osStrcmp(key, "by") || !osStrcmp(key, PRIVATE_DIR) ||
                               (!osStrncmp(key, PRIVATE_DIR "/", 8) && strchr(key + 8, '/') == NULL);
        if (key != NULL && acl_path_within(key, from) && !protected_entry)
        {
            cJSON *item = cJSON_DetachItemViaPointer(folders, entry);
            if (dst != NULL)
            {
                char moved[PATH_MAX_LEN * 2];
                osSnprintf(moved, sizeof(moved), "%s%s", to, key + osStrlen(from));
                if (cJSON_GetObjectItemCaseSensitive(folders, moved) == NULL)
                {
                    cJSON_AddItemToObject(folders, moved, item);
                    item = NULL;
                }
            }
            if (item)
            {
                cJSON_Delete(item);
            }
            changed = true;
        }
        entry = next;
    }
    if (changed)
    {
        save_unlocked();
    }
    unlock_acl();
}

void web_acl_folder_moved(const char *src, const char *dst)
{
    folder_entries_change(src, dst);
}

void web_acl_folder_removed(const char *path)
{
    folder_entries_change(path, NULL);
}

/* ---------- settings ---------- */

/* settings that touch the server, the files or other boxes: admins only, also per box */
static const char *const system_settings[] = {
    "internal.", "commonName", "core.server", "core.certdir", "core.client_cert", "core.contentdir", "core.librarydir",
    "core.datadir", "core.wwwdir", "core.pluginsdir", "core.firmwaredir", "core.cachedir", "core.configdir",
    "core.allowNewBox", "core.boxCertAuth", "core.host_url", "core.allowOrigin", "core.allowPrivateFetch",
    "core.http_client_timeout", "toniebox.api_access", "toniebox.certPin", "cloud.remote_", "encode.", "log.", "rtnl.",
    "pcap.", "mqtt", "hass.", "web_auth.", "frontend.web_auth", "security_mit.", "debug.", "tonie_json.",
    "cfw.firmware", "cfw.update", NULL};

/* global settings every user may read (the web UI needs them) */
static const char *const public_settings[] = {
    "frontend.", "core.settings_level", "cloud.enabled", "internal.version.", "encode.use_frontend", "encode.bitrate",
    "log.level", "core.allowNewBox", "core.server.http_port", "core.server.https_web_port",
    /* custom firmware switches the tonie dialog reads */
    "cfw.enabled", "cfw.show_", "cfw.force_box_settings", NULL};

/* never readable for users, also per box */
static const char *const secret_settings[] = {
    "internal.server", "internal.client", "internal.server_tb2", "core.server_cert", "core.client_cert",
    "mqtt.password", "mqtt_server.", "hass.", NULL};

/* system settings a user may read for a box (the box card shows them) */
static const char *const box_readable_system[] = {
    "internal.ip", "internal.online", "internal.last_ruid", "internal.toniebox_firmware.", "internal.boxCertStatus",
    "internal.version.", "core.certdir", "toniebox.api_access", NULL};

/* key, password and certificate data in any setting name */
static bool looks_secret(const char *name)
{
    return osStrstr(name, "key") != NULL || osStrstr(name, "password") != NULL || osStrstr(name, "pass") != NULL ||
           osStrstr(name, ".data.") != NULL || osStrstr(name, "token") != NULL;
}

static bool has_prefix(const char *const *list, const char *name)
{
    for (int i = 0; list[i] != NULL; i++)
    {
        if (!osStrncmp(name, list[i], osStrlen(list[i])))
        {
            return true;
        }
    }
    return false;
}

bool web_acl_setting_allowed(HttpConnection *connection, const char *box_id, const char *name, bool write)
{
    if (web_acl_is_admin(connection))
    {
        return true;
    }
    if (name == NULL || name[0] == '\0')
    {
        return false;
    }
    if (box_id == NULL || box_id[0] == '\0')
    {
        return !write && has_prefix(public_settings, name) && !looks_secret(name);
    }
    if (has_prefix(secret_settings, name) || looks_secret(name))
    {
        return false;
    }
    if (!write)
    {
        /* the system settings of a box are not the user's business, except what the box card shows */
        if (has_prefix(system_settings, name) && !has_prefix(box_readable_system, name))
        {
            return false;
        }
        return web_acl_box_allowed(connection, box_id, "box.view");
    }
    if (has_prefix(system_settings, name))
    {
        return false;
    }
    char right[160];
    osSnprintf(right, sizeof(right), "box.setting:%s", name);
    return web_acl_box_allowed(connection, box_id, right);
}

bool web_acl_source_allowed(HttpConnection *connection, const char *source)
{
    if (web_acl_is_admin(connection) || source == NULL || source[0] == '\0')
    {
        return true;
    }
    /* users may only point a tonie at the library they can read */
    if (osStrncmp(source, "lib://", 6) || !web_acl_folder_allowed(connection, source + 6, "folder.read"))
    {
        return false;
    }
    /* a playlist: also every file in it, and its TAF is written */
    size_t len = osStrlen(source);
    if (len < 4 || osStrcasecmp(&source[len - 4], ".tap"))
    {
        return true;
    }
    char *path = strdup(source);
    resolveSpecialPathPrefix(&path, get_settings());
    tonie_audio_playlist_t tap;
    osMemset(&tap, 0, sizeof(tap));
    bool ok = fsFileExists(path) && tap_load(path, &tap) == NO_ERROR && tap._valid &&
              web_acl_folder_allowed(connection, tap.filepath + 6, "folder.write");
    for (size_t i = 0; ok && i < tap.filesCount; i++)
    {
        const char *file = tap.files[i].filepath;
        size_t file_len = osStrlen(file);
        /* no playlists in playlists */
        ok = !osStrncmp(file, "lib://", 6) && (file_len < 4 || osStrcasecmp(&file[file_len - 4], ".tap")) &&
             web_acl_folder_allowed(connection, file + 6, "folder.read");
    }
    tap_free(&tap);
    osFreeMem(path);
    return ok;
}

/* ---------- route policy ---------- */

typedef enum
{
    P_ALLOW,     /* anyone logged in */
    P_ADMIN,     /* admins only */
    P_HANDLER,   /* the handler checks */
    P_BOX,       /* ?overlay= box with the right */
    P_TONIE_Q,   /* ?ruid= tonie with the right */
    P_LIB_QUERY, /* library, ?path= folder with the right */
    P_LIB_BODY,  /* library, the handler checks the paths in the body */
    P_LIB_LIST,  /* library listing: the folder or something below it is visible */
    P_CONTENT,   /* /content/...: tonie by path or library file */
    P_TONIE_PATH,/* tonie ruid in the path at offset arg */
    P_SETTINGS,
    P_TAG_INDEX, /* the tags of the content dir only, the handler filters */
} policy_t;

typedef struct
{
    const char *prefix;
    policy_t policy;
    const char *right;
    int arg;
    const char *method; /* NULL for any */
} route_policy_t;

/* first match wins: longer paths before their prefixes */
static const route_policy_t policies[] = {
    {"/api/auth/events/get", P_ADMIN, NULL, 0, NULL},
    {"/api/auth/unlock", P_ADMIN, NULL, 0, NULL},
    {"/api/auth/enabled", P_ADMIN, NULL, 0, NULL},
    {"/api/auth/", P_HANDLER, NULL, 0, NULL},
    {"/api/acl/levels/set", P_ADMIN, NULL, 0, NULL},
    {"/api/acl/groups/", P_ADMIN, NULL, 0, NULL},
    {"/api/acl/", P_HANDLER, NULL, 0, NULL},
    {"/api/plugins/get", P_ALLOW, NULL, 0, NULL},
    {"/api/fileIndexV2", P_LIB_LIST, NULL, 0, NULL},
    {"/api/fileIndex", P_LIB_LIST, NULL, 0, NULL},
    {"/api/fileSetListened", P_LIB_QUERY, "folder.write", 0, NULL},
    {"/api/fileUpload", P_LIB_QUERY, "folder.write", 0, NULL},
    {"/api/pcmUpload", P_LIB_QUERY, "folder.write", 0, NULL},
    {"/api/tafUpload", P_LIB_QUERY, "folder.write", 0, NULL},
    {"/api/fileDelete", P_LIB_BODY, NULL, 0, NULL},
    {"/api/fileMove", P_LIB_BODY, NULL, 0, NULL},
    {"/api/dirDelete", P_LIB_BODY, NULL, 0, NULL},
    {"/api/dirCreate", P_LIB_BODY, NULL, 0, NULL},
    {"/api/fileEncode", P_LIB_BODY, NULL, 0, NULL},
    {"/api/tapBuild", P_LIB_BODY, NULL, 0, NULL},
    {"/api/tafSplit", P_LIB_BODY, NULL, 0, NULL},
    {"/api/toniesJsonSearch", P_ALLOW, NULL, 0, NULL},
    {"/api/toniesJsonUpdate", P_ADMIN, NULL, 0, NULL},
    {"/api/toniesJsonReload", P_ADMIN, NULL, 0, NULL},
    {"/api/toniesCustomJsonUpsert", P_ADMIN, NULL, 0, NULL},
    {"/api/toniesCustomJsonDelete", P_ADMIN, NULL, 0, NULL},
    {"/api/toniesCustomJsonRename", P_ADMIN, NULL, 0, NULL},
    {"/api/toniesJson", P_ALLOW, NULL, 0, NULL},
    {"/api/toniesCustomJson", P_ALLOW, NULL, 0, NULL},
    {"/api/tonieboxesJson", P_ALLOW, NULL, 0, NULL},
    {"/api/tonieboxesCustomJson", P_ALLOW, NULL, 0, NULL},
    {"/api/getTagIndex", P_TAG_INDEX, NULL, 0, NULL},
    {"/api/getTagInfo", P_TONIE_Q, "tonie.view", 0, NULL},
    {"/api/getBoxes", P_HANDLER, NULL, 0, NULL},
    {"/api/settings/removeOverlay", P_ADMIN, NULL, 0, NULL},
    {"/api/settings/", P_SETTINGS, NULL, 0, NULL},
    {"/api/sse", P_HANDLER, NULL, 0, NULL},
    /* custom firmware */
    {"/api/cfw/boxes", P_HANDLER, NULL, 0, NULL},
    {"/api/cfw/tags", P_HANDLER, NULL, 0, NULL},
    {"/api/cfw/tag", P_TONIE_Q, "tonie.view", 0, "GET"},
    {"/api/cfw/tag", P_TONIE_Q, "tonie.edit", 0, "POST"},
    {"/api/cfw/remote", P_BOX, "box.cfw", 0, NULL},
    {"/api/cfw/status", P_BOX, "box.view", 0, NULL},
    {"/api/cfw/battery", P_BOX, "box.view", 0, NULL},
    {"/api/cfw/deliver", P_BOX, "box.cfw", 0, NULL},
    {"/api/", P_ADMIN, NULL, 0, NULL},
    {"/content/download/", P_TONIE_PATH, "tonie.view", 18, NULL},
    {"/content/json/get/", P_TONIE_PATH, "tonie.edit", 18, NULL},
    {"/content/json/set/", P_HANDLER, NULL, 0, NULL},
    {"/content/json/", P_ADMIN, NULL, 0, NULL},
    {"/content/", P_CONTENT, NULL, 0, NULL},
    {"/cache/stats.html", P_ADMIN, NULL, 0, NULL},
    {"/cache/", P_ALLOW, NULL, 0, NULL},
    /* the status in the header: time of teddyCloud and of the Boxine cloud */
    {"/reverse/v1/time", P_ALLOW, NULL, 0, "GET"},
    {"/reverse", P_ADMIN, NULL, 0, NULL},
    {"/v1/time", P_ALLOW, NULL, 0, "GET"},
    {"/v1/", P_ADMIN, NULL, 0, NULL},
    {"/v2/", P_ADMIN, NULL, 0, NULL},
    {"/v3/", P_ADMIN, NULL, 0, NULL},
    {"*binary", P_ADMIN, NULL, 0, NULL},
};

static bool query_value(const char *query, const char *key, char *out, size_t size)
{
    out[0] = '\0';
    return query != NULL && queryGet(query, key, out, size);
}

/* a given overlay must be a box the user can see; an unknown one would mean the global settings */
static bool overlay_ok(HttpConnection *connection, const char *query)
{
    char overlay[BOX_ID_MAX];
    if (!query_value(query, "overlay", overlay, sizeof(overlay)) || overlay[0] == '\0')
    {
        return true;
    }
    /* the handlers read 15 characters; a longer id would mean another box or the global settings there */
    if (osStrlen(overlay) >= 16)
    {
        return false;
    }
    return web_acl_box_allowed(connection, overlay, "box.view");
}

static bool library_root(const char *query)
{
    char special[32];
    query_value(query, "special", special, sizeof(special));
    return !osStrcmp(special, "library");
}

/* "HI8/LO8" or "HI8LO8..." at p as ruid */
static bool ruid_from_path(const char *p, char out[RUID_LEN + 1])
{
    char tmp[RUID_LEN + 1];
    size_t o = 0;
    for (; *p && o < RUID_LEN; p++)
    {
        if (*p == '/')
        {
            continue;
        }
        tmp[o++] = *p;
    }
    tmp[o] = '\0';
    return o == RUID_LEN && normalize_ruid(tmp, out);
}

bool web_acl_request_allowed(HttpConnection *connection, const char_t *uri, const char_t *query)
{
    if (web_acl_is_admin(connection))
    {
        return true;
    }
    const char *method = connection->request.method;
    for (size_t i = 0; i < sizeof(policies) / sizeof(policies[0]); i++)
    {
        const route_policy_t *r = &policies[i];
        if (osStrncmp(uri, r->prefix, osStrlen(r->prefix)) != 0 || (r->method != NULL && osStrcasecmp(method, r->method) != 0))
        {
            continue;
        }
        char value[PATH_MAX_LEN];
        char ruid[RUID_LEN + 1];
        switch (r->policy)
        {
        case P_ALLOW:
        case P_HANDLER:
            return overlay_ok(connection, query);
        case P_TAG_INDEX:
        {
            char special[32];
            query_value(query, "special", special, sizeof(special));
            return special[0] == '\0' && overlay_ok(connection, query);
        }
        case P_ADMIN:
            return false;
        case P_BOX:
            query_value(query, "overlay", value, sizeof(value));
            return osStrlen(value) < 16 && web_acl_box_allowed(connection, value, r->right);
        case P_TONIE_Q:
            query_value(query, "ruid", value, sizeof(value));
            return overlay_ok(connection, query) && web_acl_tonie_allowed(connection, value, r->right);
        case P_LIB_QUERY:
        {
            char name[PATH_MAX_LEN];
            /* pcmUpload/tafUpload join "name" to the path: it must stay a file name */
            if (query_value(query, "name", name, sizeof(name)) && (strchr(name, '/') || strchr(name, '\\') || !osStrcmp(name, "..")))
            {
                return false;
            }
            query_value(query, "path", value, sizeof(value));
            return library_root(query) && overlay_ok(connection, query) && web_acl_folder_allowed(connection, value, r->right);
        }
        case P_LIB_BODY:
            return library_root(query) && overlay_ok(connection, query);
        case P_LIB_LIST:
        {
            char norm[PATH_MAX_LEN];
            query_value(query, "path", value, sizeof(value));
            if (!library_root(query) || !overlay_ok(connection, query) || !acl_path_normalize(value, norm, sizeof(norm)))
            {
                return false;
            }
            if (norm[0] == '\0' || web_acl_folder_allowed(connection, norm, "folder.read"))
            {
                return true;
            }
            char *slash = strrchr(norm, '/');
            if (slash == NULL)
            {
                return web_acl_folder_visible(connection, "", norm);
            }
            *slash = '\0';
            return web_acl_folder_visible(connection, norm, slash + 1);
        }
        case P_TONIE_PATH:
            return osStrlen(uri) > (size_t)r->arg && ruid_from_path(uri + r->arg, ruid) && overlay_ok(connection, query) &&
                   web_acl_tonie_allowed(connection, ruid, r->right);
        case P_CONTENT:
        {
            const char *rest = uri + osStrlen("/content/");
            if (!overlay_ok(connection, query))
            {
                return false;
            }
            if (library_root(query))
            {
                return web_acl_folder_allowed(connection, rest, "folder.read");
            }
            char special[32];
            query_value(query, "special", special, sizeof(special));
            /* the audio of a tonie: /content/<HI8>/<LO8> */
            return special[0] == '\0' && ruid_from_path(rest, ruid) && web_acl_tonie_allowed(connection, ruid, "tonie.view");
        }
        case P_SETTINGS:
        {
            char overlay[BOX_ID_MAX];
            query_value(query, "overlay", overlay, sizeof(overlay));
            if (osStrlen(overlay) >= 16)
            {
                return false;
            }
            if (!osStrcmp(uri, "/api/settings/getIndex"))
            {
                /* the handler leaves out what the user may not see */
                return overlay[0] != '\0' && web_acl_box_allowed(connection, overlay, "box.view");
            }
            if (!osStrncmp(uri, "/api/settings/get/", 18))
            {
                return web_acl_setting_allowed(connection, overlay, uri + 18, false);
            }
            if (!osStrncmp(uri, "/api/settings/set/", 18))
            {
                return web_acl_setting_allowed(connection, overlay, uri + 18, true);
            }
            if (!osStrncmp(uri, "/api/settings/reset/", 20))
            {
                return web_acl_setting_allowed(connection, overlay, uri + 20, true);
            }
            return false;
        }
        }
    }
    /* static files of the web UI and the plugins */
    return osStrncmp(uri, "/api/", 5) != 0;
}

/* ---------- life cycle of users and tags ---------- */

void web_acl_user_created(const char *username)
{
    char rel[PATH_MAX_LEN];
    osSnprintf(rel, sizeof(rel), PRIVATE_DIR "/%s", username);
    lock_acl();
    cJSON *folders = obj(acl, "folders");
    /* also replaces what is left of an earlier user with the same name */
    cJSON_DeleteItemFromObjectCaseSensitive(folders, rel);
    cJSON_AddItemToObject(folders, rel, folder_entry(username, NULL));
    save_unlocked();
    unlock_acl();
    /* the private folder in the library */
    const char *lib = settings_get_string("internal.librarydirfull");
    if (lib != NULL && lib[0] != '\0')
    {
        char *dir = custom_asprintf("%s%c" PRIVATE_DIR, lib, PATH_SEPARATOR);
        if (dir)
        {
            if (!fsDirExists(dir))
            {
                fsCreateDir(dir);
            }
            osFreeMem(dir);
        }
        dir = custom_asprintf("%s%c" PRIVATE_DIR "%c%s", lib, PATH_SEPARATOR, PATH_SEPARATOR, username);
        if (dir)
        {
            if (!fsDirExists(dir))
            {
                fsCreateDir(dir);
            }
            osFreeMem(dir);
        }
    }
}

static void remove_user_from(cJSON *map, const char *username)
{
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, map)
    {
        cJSON *owners = cJSON_GetObjectItemCaseSensitive(entry, "owners");
        for (int i = cJSON_GetArraySize(owners) - 1; i >= 0; i--)
        {
            cJSON *o = cJSON_GetArrayItem(owners, i);
            if (cJSON_IsString(o) && !osStrcasecmp(o->valuestring, username))
            {
                cJSON_DeleteItemFromArray(owners, i);
            }
        }
        cJSON *shares = cJSON_GetObjectItemCaseSensitive(entry, "shares");
        cJSON *s = shares ? shares->child : NULL;
        while (s != NULL)
        {
            cJSON *next = s->next;
            if (s->string && !osStrcasecmp(s->string, username))
            {
                cJSON_Delete(cJSON_DetachItemViaPointer(shares, s));
            }
            s = next;
        }
    }
}

void web_acl_user_deleted(const char *username)
{
    lock_acl();
    remove_user_from(cJSON_GetObjectItemCaseSensitive(acl, "boxes"), username);
    remove_user_from(cJSON_GetObjectItemCaseSensitive(acl, "tonies"), username);
    remove_user_from(cJSON_GetObjectItemCaseSensitive(acl, "folders"), username);
    save_unlocked();
    unlock_acl();
}

void web_acl_tag_placed(const char *ruid, const char *box_id)
{
    char id[RUID_LEN + 1];
    if (!normalize_ruid(ruid, id) || box_id == NULL || box_id[0] == '\0')
    {
        return;
    }
    lock_acl();
    cJSON *tonies = obj(acl, "tonies");
    cJSON *entry = cJSON_GetObjectItemCaseSensitive(tonies, id);
    cJSON *box = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(acl, "boxes"), box_id);
    /* a tag without owners goes to the owners of the box it is first placed on */
    if ((entry == NULL || !has_owners(entry)) && box != NULL && has_owners(box))
    {
        if (entry == NULL)
        {
            entry = cJSON_AddObjectToObject(tonies, id);
        }
        cJSON_DeleteItemFromObjectCaseSensitive(entry, "owners");
        cJSON_AddItemToObject(entry, "owners", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(box, "owners"), true));
        if (!cJSON_GetObjectItemCaseSensitive(entry, "shares"))
        {
            cJSON_AddObjectToObject(entry, "shares");
        }
        cJSON_AddStringToObject(entry, "assignedFrom", box_id);
        TRACE_INFO("Permissions: tag %s placed on box %s, it now belongs to the owners of the box\r\n", id, box_id);
        save_unlocked();
    }
    unlock_acl();
}

/* ---------- API ---------- */

static error_t send_json(HttpConnection *connection, uint_t status, cJSON *json)
{
    char *body = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (body == NULL)
    {
        return ERROR_FAILURE;
    }
    httpPrepareHeader(connection, "application/json; charset=utf-8", osStrlen(body));
    connection->response.statusCode = status;
    connection->response.noCache = TRUE;
    error_t err = httpWriteResponseString(connection, body, true);
    return err;
}

static error_t send_error(HttpConnection *connection, uint_t status, const char *code, const char *message)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "error", code);
    cJSON_AddStringToObject(json, "message", message);
    return send_json(connection, status, json);
}

static cJSON *read_body(HttpConnection *connection)
{
    size_t size = connection->request.byteCount;
    if (size == 0 || size > 256 * 1024)
    {
        return NULL;
    }
    char *buf = osAllocMem(size + 1);
    if (buf == NULL)
    {
        return NULL;
    }
    size_t total = 0;
    while (total < size)
    {
        size_t n = 0;
        if (httpReadStream(connection, buf + total, size - total, &n, 0) != NO_ERROR || n == 0)
        {
            break;
        }
        total += n;
    }
    buf[total] = '\0';
    cJSON *json = cJSON_Parse(buf);
    osFreeMem(buf);
    return json;
}

static void add_allowed(HttpConnection *connection, cJSON *array, const char *scope, const char *id)
{
    for (size_t i = 0; i < acl_rights_count; i++)
    {
        const acl_right_t *r = &acl_rights[i];
        if (osStrcmp(r->scope, scope) != 0 || !osStrcmp(r->name, "box.setting"))
        {
            continue;
        }
        bool ok = !osStrcmp(scope, "box") ? web_acl_box_allowed(connection, id, r->name)
                  : !osStrcmp(scope, "tonie") ? web_acl_tonie_allowed(connection, id, r->name)
                                              : web_acl_folder_allowed(connection, id, r->name);
        if (ok)
        {
            cJSON_AddItemToArray(array, cJSON_CreateString(r->name));
        }
    }
}

static cJSON *entry_for_user(cJSON *entry, const acl_user_t *u, bool *owner)
{
    char granted[RIGHTS_MAX];
    *owner = in_owners(entry, u->user);
    cJSON *j = cJSON_CreateObject();
    cJSON_AddBoolToObject(j, "owner", *owner);
    if (!*owner && shared_rights(entry, u->user, granted, sizeof(granted)))
    {
        cJSON_AddStringToObject(j, "granted", granted);
    }
    return j;
}

/* the settings a user can ever get for a box, with the titles of their groups, for the rights tree */
static void add_box_settings(cJSON *json)
{
    cJSON *list = cJSON_AddArrayToObject(json, "boxSettings");
    cJSON *groups = cJSON_AddObjectToObject(json, "boxSettingGroups");
    for (size_t pos = 0; pos < settings_get_size(); pos++)
    {
        setting_item_t *opt = settings_get((int)pos);
        if (opt == NULL || opt->option_name == NULL)
        {
            continue;
        }
        if (opt->type == TYPE_TREE_DESC)
        {
            if (opt->description != NULL && osStrchr(opt->option_name, '.') == NULL)
            {
                cJSON_AddStringToObject(groups, opt->option_name, opt->description);
            }
            continue;
        }
        if (opt->internal || opt->level == LEVEL_SECRET || has_prefix(system_settings, opt->option_name) ||
            has_prefix(secret_settings, opt->option_name) || looks_secret(opt->option_name))
        {
            continue;
        }
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "id", opt->option_name);
        cJSON_AddStringToObject(entry, "label", opt->label != NULL ? opt->label : opt->option_name);
        cJSON_AddItemToArray(list, entry);
    }
}

error_t handleApiAclCatalog(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *json = cJSON_CreateObject();
    cJSON *rights = cJSON_AddArrayToObject(json, "rights");
    for (size_t i = 0; i < acl_rights_count; i++)
    {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "name", acl_rights[i].name);
        cJSON_AddStringToObject(r, "scope", acl_rights[i].scope);
        cJSON_AddBoolToObject(r, "adminOnly", acl_rights[i].admin_only);
        cJSON_AddItemToArray(rights, r);
    }
    cJSON *levels = cJSON_AddArrayToObject(json, "levels");
    for (int l = 0; l < ACL_LEVEL_COUNT; l++)
    {
        cJSON_AddItemToArray(levels, cJSON_CreateString(acl_level_name((acl_level_t)l)));
    }
    lock_acl();
    cJSON_AddItemToObject(json, "levelLimits", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(acl, "levels"), true));
    cJSON *groups = cJSON_AddArrayToObject(json, "groups");
    cJSON *g = NULL;
    cJSON_ArrayForEach(g, obj(acl, "groups"))
    {
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "id", g->string);
        cJSON_AddStringToObject(entry, "name", str(g, "name", g->string));
        cJSON_AddStringToObject(entry, "base", str(g, "base", "guest"));
        cJSON_AddStringToObject(entry, "rights", str(g, "rights", ""));
        cJSON_AddItemToArray(groups, entry);
    }
    cJSON_AddItemToObject(json, "unassigned", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(acl, "unassigned"), true));
    unlock_acl();
    add_box_settings(json);
    return send_json(connection, 200, json);
}

error_t handleApiAclMine(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    acl_user_t u = current_user(connection);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "loginActive", u.known);
    cJSON_AddStringToObject(json, "username", u.user);
    cJSON_AddStringToObject(json, "level", u.known ? acl_level_name(u.level) : "admin");
    cJSON_AddBoolToObject(json, "admin", !u.known || u.level == ACL_LEVEL_ADMIN);
    cJSON_AddStringToObject(json, "group", u.group);
    cJSON_AddStringToObject(json, "deny", u.deny);
    cJSON *system = cJSON_AddArrayToObject(json, "system");
    for (size_t i = 0; i < acl_rights_count; i++)
    {
        if (!osStrcmp(acl_rights[i].scope, "system") && web_acl_system_allowed(connection, acl_rights[i].name))
        {
            cJSON_AddItemToArray(system, cJSON_CreateString(acl_rights[i].name));
        }
    }
    cJSON *boxes = cJSON_AddObjectToObject(json, "boxes");
    for (uint8_t i = 1; i < MAX_OVERLAYS; i++)
    {
        settings_t *s = get_settings_id(i);
        if (s == NULL || !s->internal.config_used || s->internal.overlayUniqueId == NULL || s->internal.overlayUniqueId[0] == '\0')
        {
            continue;
        }
        const char *id = s->internal.overlayUniqueId;
        if (!web_acl_box_allowed(connection, id, "box.view"))
        {
            continue;
        }
        cJSON *b = cJSON_CreateObject();
        cJSON *rights = cJSON_AddArrayToObject(b, "rights");
        add_allowed(connection, rights, "box", id);
        lock_acl();
        cJSON *entry = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(acl, "boxes"), id);
        bool owner = false;
        if (entry != NULL && u.known)
        {
            cJSON *mine = entry_for_user(entry, &u, &owner);
            cJSON_AddBoolToObject(b, "owner", owner);
            cJSON *granted = cJSON_GetObjectItemCaseSensitive(mine, "granted");
            if (granted)
            {
                cJSON_AddStringToObject(b, "granted", granted->valuestring);
            }
            cJSON_Delete(mine);
        }
        unlock_acl();
        cJSON_AddItemToObject(boxes, id, b);
    }
    /* tonies with an entry the user is part of; tonies without owner are open as "unassigned" says */
    cJSON *tonies = cJSON_AddObjectToObject(json, "tonies");
    cJSON *folders = cJSON_AddObjectToObject(json, "folders");
    lock_acl();
    struct
    {
        const char *key;
        cJSON *out;
    } maps[] = {{"tonies", tonies}, {"folders", folders}};
    for (int m = 0; m < 2; m++)
    {
        cJSON *entry = NULL;
        cJSON_ArrayForEach(entry, cJSON_GetObjectItemCaseSensitive(acl, maps[m].key))
        {
            bool owner = false;
            char granted[RIGHTS_MAX];
            if (!u.known || u.level == ACL_LEVEL_ADMIN || in_owners(entry, u.user) || shared_rights(entry, u.user, granted, sizeof(granted)))
            {
                cJSON *mine = u.known ? entry_for_user(entry, &u, &owner) : cJSON_CreateObject();
                cJSON_AddItemToObject(maps[m].out, entry->string, mine);
            }
        }
    }
    cJSON_AddItemToObject(json, "unassigned", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(acl, "unassigned"), true));
    unlock_acl();
    return send_json(connection, 200, json);
}

/* the map and normalized key of a type/id pair */
static cJSON *map_for(const char *type, const char *id, char *key, size_t key_size, char *scope)
{
    if (!osStrcmp(type, "box"))
    {
        if (!box_known(id))
        {
            return NULL;
        }
        osSnprintf(key, key_size, "%s", id);
        osStrcpy(scope, "box");
        return obj(acl, "boxes");
    }
    if (!osStrcmp(type, "tonie"))
    {
        char ruid[RUID_LEN + 1];
        if (!normalize_ruid(id, ruid))
        {
            return NULL;
        }
        osSnprintf(key, key_size, "%s", ruid);
        osStrcpy(scope, "tonie");
        return obj(acl, "tonies");
    }
    if (!osStrcmp(type, "folder"))
    {
        if (!acl_path_normalize(id, key, key_size))
        {
            return NULL;
        }
        osStrcpy(scope, "folder");
        return obj(acl, "folders");
    }
    return NULL;
}

/* may the user change the shares (owners: admins only) of the resource */
static bool may_share(HttpConnection *connection, const char *scope, const char *key)
{
    char right[32];
    osSnprintf(right, sizeof(right), "%s.share", scope);
    acl_user_t u = current_user(connection);
    if (!u.known || u.level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    if (u.level == ACL_LEVEL_GUEST)
    {
        return false;
    }
    bool owner = false;
    lock_acl();
    if (!osStrcmp(scope, "folder"))
    {
        cJSON *entry = folder_lookup_unlocked(key, NULL, 0);
        owner = entry != NULL && in_owners(entry, u.user);
    }
    else
    {
        cJSON *entry = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(acl, !osStrcmp(scope, "box") ? "boxes" : "tonies"), key);
        owner = entry != NULL && in_owners(entry, u.user);
    }
    unlock_acl();
    if (!owner)
    {
        return false;
    }
    return !osStrcmp(scope, "box") ? web_acl_box_allowed(connection, key, right)
           : !osStrcmp(scope, "tonie") ? web_acl_tonie_allowed(connection, key, right)
                                       : web_acl_folder_allowed(connection, key, right);
}

error_t handleApiAclGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)client_ctx;
    char type[16], id[PATH_MAX_LEN], key[PATH_MAX_LEN], scope[16];
    query_value(queryString, "type", type, sizeof(type));
    query_value(queryString, "id", id, sizeof(id));
    lock_acl();
    cJSON *map = map_for(type, id, key, sizeof(key), scope);
    unlock_acl();
    if (map == NULL)
    {
        return send_error(connection, 400, "invalid_target", "Unknown type or id");
    }
    if (!may_share(connection, scope, key))
    {
        return send_error(connection, 403, "forbidden", "Only owners and admins see the shares");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "type", type);
    cJSON_AddStringToObject(json, "id", key);
    lock_acl();
    char found[PATH_MAX_LEN] = "";
    cJSON *entry = !osStrcmp(scope, "folder") ? folder_lookup_unlocked(key, found, sizeof(found)) : cJSON_GetObjectItemCaseSensitive(map, key);
    if (entry != NULL)
    {
        cJSON_AddItemToObject(json, "owners", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(entry, "owners"), true));
        cJSON_AddItemToObject(json, "shares", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(entry, "shares"), true));
    }
    else
    {
        cJSON_AddArrayToObject(json, "owners");
        cJSON_AddObjectToObject(json, "shares");
    }
    if (!osStrcmp(scope, "folder"))
    {
        /* the folder whose entry applies (itself or a parent) */
        cJSON_AddStringToObject(json, "inheritedFrom", found);
    }
    unlock_acl();
    return send_json(connection, 200, json);
}

/* share rights must belong to the scope and to what the sharing user may do */
typedef struct
{
    HttpConnection *connection;
    const char *scope;
    const char *key;
    const char *deny;
    bool bad;
} share_check_t;

static bool scope_allowed(HttpConnection *connection, const char *scope, const char *key, const char *right)
{
    return !osStrcmp(scope, "box") ? web_acl_box_allowed(connection, key, right)
           : !osStrcmp(scope, "tonie") ? web_acl_tonie_allowed(connection, key, right)
                                       : web_acl_folder_allowed(connection, key, right);
}

static bool share_token_bad(const char *tok, size_t len, void *ctx)
{
    share_check_t *c = ctx;
    char share[32];
    size_t slen = osStrlen(c->scope);
    osSnprintf(share, sizeof(share), "%s.share", c->scope);
    /* only rights of this resource type, never sharing on */
    if (len <= slen || osStrncmp(tok, c->scope, slen) != 0 || tok[slen] != '.' ||
        acl_patterns_overlap(tok, len, share, osStrlen(share)))
    {
        c->bad = true;
        return true;
    }
    /* nothing the admin took from the sharing user, also not through a wildcard */
    char pattern[160];
    if (len >= sizeof(pattern))
    {
        c->bad = true;
        return true;
    }
    osMemcpy(pattern, tok, len);
    pattern[len] = '\0';
    if (c->deny[0] != '\0' && acl_lists_overlap(pattern, c->deny))
    {
        c->bad = true;
        return true;
    }
    /* every right the pattern stands for, the sharing user must have */
    for (size_t i = 0; i < acl_rights_count; i++)
    {
        const acl_right_t *r = &acl_rights[i];
        if (osStrcmp(r->scope, c->scope) != 0 || r->admin_only || !osStrcmp(r->name, "box.setting"))
        {
            continue;
        }
        if (acl_patterns_overlap(tok, len, r->name, osStrlen(r->name)) && !scope_allowed(c->connection, c->scope, c->key, r->name))
        {
            c->bad = true;
            return true;
        }
    }
    if (!osStrncmp(pattern, "box.setting:", 12))
    {
        /* a single setting or a group: the sharing user must be allowed the group itself */
        char probe[160];
        osSnprintf(probe, sizeof(probe), "%s", pattern);
        size_t plen = osStrlen(probe);
        if (plen > 0 && probe[plen - 1] == '*')
        {
            probe[plen - 1] = '\0';
        }
        if (!scope_allowed(c->connection, c->scope, c->key, probe))
        {
            c->bad = true;
            return true;
        }
    }
    return false;
}

static bool share_rights_ok(HttpConnection *connection, const char *scope, const char *list, const char *key)
{
    char bad[64];
    if (!acl_list_valid(list, bad, sizeof(bad)))
    {
        return false;
    }
    acl_user_t u = current_user(connection);
    share_check_t c = {connection, scope, key, u.deny, false};
    acl_list_each(list, share_token_bad, &c);
    return !c.bad;
}

static bool user_exists_level(const char *name, int *level)
{
    return web_auth_user_info(name, level, NULL, 0, NULL, 0, NULL, 0);
}

error_t handleApiAclSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = read_body(connection);
    if (body == NULL)
    {
        return send_error(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char type[16], id[PATH_MAX_LEN], key[PATH_MAX_LEN], scope[16];
    osSnprintf(type, sizeof(type), "%s", str(body, "type", ""));
    osSnprintf(id, sizeof(id), "%s", str(body, "id", ""));
    cJSON *owners = cJSON_GetObjectItemCaseSensitive(body, "owners");
    cJSON *shares = cJSON_GetObjectItemCaseSensitive(body, "shares");
    lock_acl();
    cJSON *map = map_for(type, id, key, sizeof(key), scope);
    unlock_acl();
    error_t err;
    if (map == NULL)
    {
        err = send_error(connection, 400, "invalid_target", "Unknown type or id");
        cJSON_Delete(body);
        return err;
    }
    bool admin = web_acl_is_admin(connection);
    if ((owners != NULL && !admin) || !may_share(connection, scope, key))
    {
        err = send_error(connection, 403, "forbidden", owners != NULL ? "Only admins assign owners" : "Only owners and admins share");
        cJSON_Delete(body);
        return err;
    }
    /* validate before changing anything */
    cJSON *o = NULL;
    cJSON_ArrayForEach(o, owners)
    {
        int level;
        if (!cJSON_IsString(o) || !user_exists_level(o->valuestring, &level) || level == ACL_LEVEL_GUEST)
        {
            err = send_error(connection, 400, "invalid_owner", "Owners must be existing users that are no guests");
            cJSON_Delete(body);
            return err;
        }
    }
    cJSON *s = NULL;
    cJSON_ArrayForEach(s, shares)
    {
        int level;
        if (!cJSON_IsString(s) || s->string == NULL || (osStrcmp(s->string, "*") && !user_exists_level(s->string, &level)) ||
            (!admin && !share_rights_ok(connection, scope, s->valuestring, key)) || (admin && !acl_list_valid(s->valuestring, NULL, 0)))
        {
            err = send_error(connection, 400, "invalid_share", "Unknown user or right in a share");
            cJSON_Delete(body);
            return err;
        }
    }
    lock_acl();
    map = map_for(type, id, key, sizeof(key), scope);
    cJSON *entry = cJSON_GetObjectItemCaseSensitive(map, key);
    if (entry == NULL)
    {
        entry = cJSON_AddObjectToObject(map, key);
        if (!osStrcmp(scope, "folder"))
        {
            /* a new folder entry keeps the owners of the parent */
            cJSON *parent = folder_lookup_unlocked(key, NULL, 0);
            cJSON *po = parent ? cJSON_GetObjectItemCaseSensitive(parent, "owners") : NULL;
            cJSON_AddItemToObject(entry, "owners", po ? cJSON_Duplicate(po, true) : cJSON_CreateArray());
        }
        else
        {
            cJSON_AddArrayToObject(entry, "owners");
        }
        cJSON_AddObjectToObject(entry, "shares");
    }
    if (owners != NULL)
    {
        cJSON_ReplaceItemInObjectCaseSensitive(entry, "owners", cJSON_Duplicate(owners, true));
    }
    if (shares != NULL)
    {
        cJSON *clean = cJSON_CreateObject();
        cJSON_ArrayForEach(s, shares)
        {
            if (s->valuestring[0] != '\0')
            {
                cJSON_AddStringToObject(clean, s->string, s->valuestring);
            }
        }
        if (cJSON_GetObjectItemCaseSensitive(entry, "shares"))
        {
            cJSON_ReplaceItemInObjectCaseSensitive(entry, "shares", clean);
        }
        else
        {
            cJSON_AddItemToObject(entry, "shares", clean);
        }
    }
    bool ok = save_unlocked();
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", ok);
    cJSON_AddItemToObject(json, "owners", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(entry, "owners"), true));
    cJSON_AddItemToObject(json, "shares", cJSON_Duplicate(cJSON_GetObjectItemCaseSensitive(entry, "shares"), true));
    unlock_acl();
    cJSON_Delete(body);
    return send_json(connection, ok ? 200 : 500, json);
}

error_t handleApiAclLevelsSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = read_body(connection);
    if (body == NULL)
    {
        return send_error(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    const char *user = str(body, "user", NULL);
    const char *guest = str(body, "guest", NULL);
    const char *tonie = str(body, "unassignedTonie", NULL);
    const char *box = str(body, "unassignedBox", NULL);
    const char *values[] = {user, guest, tonie, box};
    for (int i = 0; i < 4; i++)
    {
        if (values[i] != NULL && (!acl_list_valid(values[i], NULL, 0) || osStrlen(values[i]) >= RIGHTS_MAX))
        {
            cJSON_Delete(body);
            return send_error(connection, 400, "invalid_rights", "Unknown right in a list");
        }
    }
    lock_acl();
    cJSON *levels = obj(acl, "levels");
    cJSON *unassigned = obj(acl, "unassigned");
    if (user)
        cJSON_ReplaceItemInObjectCaseSensitive(levels, "user", cJSON_CreateString(user));
    if (guest)
        cJSON_ReplaceItemInObjectCaseSensitive(levels, "guest", cJSON_CreateString(guest));
    if (tonie)
        cJSON_ReplaceItemInObjectCaseSensitive(unassigned, "tonie", cJSON_CreateString(tonie));
    if (box)
        cJSON_ReplaceItemInObjectCaseSensitive(unassigned, "box", cJSON_CreateString(box));
    bool ok = save_unlocked();
    unlock_acl();
    cJSON_Delete(body);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", ok);
    return send_json(connection, ok ? 200 : 500, json);
}

/* ---------- groups ---------- */

#define GROUPS_MAX 32
#define GROUP_NAME_MAX 32

/* number of users in the group; asks the user data, so never under lock_acl */
static int group_members(const char *id)
{
    char(*names)[33] = osAllocMem(128 * 33);
    if (names == NULL)
    {
        return 1;
    }
    int members = 0;
    int n = web_auth_user_names(names, 128);
    for (int i = 0; i < n; i++)
    {
        char group[WEB_ACL_GROUP_ID_MAX + 1] = "";
        web_auth_user_info(names[i], NULL, NULL, 0, NULL, 0, group, sizeof(group));
        members += !osStrcmp(group, id);
    }
    osFreeMem(names);
    return members;
}

web_acl_group_check_t web_acl_group_check(HttpConnection *connection, const char *id, int *base)
{
    acl_user_t u = current_user(connection);
    lock_acl();
    cJSON *group = group_unlocked(id);
    acl_level_t level;
    if (!group_base(group, &level))
    {
        unlock_acl();
        return WEB_ACL_GROUP_UNKNOWN;
    }
    /* users who are no admins give only groups that have no more than they have */
    bool ok = !u.known || u.level == ACL_LEVEL_ADMIN || acl_list_within(str(group, "rights", ""), user_limit_unlocked(&u));
    unlock_acl();
    if (base != NULL)
    {
        *base = (int)level;
    }
    return ok ? WEB_ACL_GROUP_OK : WEB_ACL_GROUP_FORBIDDEN;
}

static bool group_name_valid(const char *name)
{
    size_t len = osStrlen(name);
    if (len == 0 || len > GROUP_NAME_MAX)
    {
        return false;
    }
    for (size_t i = 0; i < len; i++)
    {
        if ((unsigned char)name[i] < 0x20 || name[i] == 0x7f)
        {
            return false;
        }
    }
    return true;
}

static bool group_id_valid(const char *id)
{
    size_t len = osStrlen(id);
    if (len == 0 || len > WEB_ACL_GROUP_ID_MAX)
    {
        return false;
    }
    for (size_t i = 0; i < len; i++)
    {
        if (!isalnum((unsigned char)id[i]) && id[i] != '_' && id[i] != '-')
        {
            return false;
        }
    }
    /* the built-in groups are the levels */
    acl_level_t level;
    return !acl_level_parse(id, &level);
}

/* {id?, name, base: "user"|"guest", rights}: without id a new group is made */
error_t handleApiAclGroupsSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = read_body(connection);
    if (body == NULL)
    {
        return send_error(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char id[WEB_ACL_GROUP_ID_MAX + 1] = "";
    osSnprintf(id, sizeof(id), "%s", str(body, "id", ""));
    const char *name = str(body, "name", "");
    const char *rights = str(body, "rights", "");
    acl_level_t base;
    if (!acl_level_parse(str(body, "base", ""), &base) || base == ACL_LEVEL_ADMIN)
    {
        cJSON_Delete(body);
        return send_error(connection, 400, "invalid_level", "The kind of a group is user or guest");
    }
    if (!group_name_valid(name))
    {
        cJSON_Delete(body);
        return send_error(connection, 400, "invalid_name", "Name of 1 to 32 characters");
    }
    if (osStrlen(rights) >= RIGHTS_MAX || !acl_list_valid(rights, NULL, 0))
    {
        cJSON_Delete(body);
        return send_error(connection, 400, "invalid_rights", "Unknown right in a list");
    }
    if (id[0] != '\0' && !group_id_valid(id))
    {
        cJSON_Delete(body);
        return send_error(connection, 400, "invalid_group", "Unknown group");
    }
    int members = id[0] != '\0' ? group_members(id) : 0;
    lock_acl();
    cJSON *groups = obj(acl, "groups");
    cJSON *group = id[0] != '\0' ? group_unlocked(id) : NULL;
    if (id[0] != '\0' && group == NULL)
    {
        unlock_acl();
        cJSON_Delete(body);
        return send_error(connection, 404, "invalid_group", "Unknown group");
    }
    acl_level_t old_base;
    if (group != NULL && members > 0 && group_base(group, &old_base) && old_base != base)
    {
        /* the members have the level of the kind: change it with them */
        unlock_acl();
        cJSON_Delete(body);
        return send_error(connection, 409, "group_in_use", "The group has members");
    }
    if (group == NULL)
    {
        if (cJSON_GetArraySize(groups) >= GROUPS_MAX)
        {
            unlock_acl();
            cJSON_Delete(body);
            return send_error(connection, 400, "limit", "Too many groups");
        }
        for (int n = 1; n <= GROUPS_MAX + 1; n++)
        {
            osSnprintf(id, sizeof(id), "g%d", n);
            if (cJSON_GetObjectItemCaseSensitive(groups, id) == NULL)
            {
                break;
            }
        }
        group = cJSON_AddObjectToObject(groups, id);
    }
    cJSON_DeleteItemFromObjectCaseSensitive(group, "name");
    cJSON_DeleteItemFromObjectCaseSensitive(group, "base");
    cJSON_DeleteItemFromObjectCaseSensitive(group, "rights");
    cJSON_AddStringToObject(group, "name", name);
    cJSON_AddStringToObject(group, "base", acl_level_name(base));
    cJSON_AddStringToObject(group, "rights", rights);
    bool ok = save_unlocked();
    unlock_acl();
    cJSON_Delete(body);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", ok);
    cJSON_AddStringToObject(json, "id", id);
    return send_json(connection, ok ? 200 : 500, json);
}

/* {id}: only a group without members */
error_t handleApiAclGroupsDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = read_body(connection);
    if (body == NULL)
    {
        return send_error(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char id[WEB_ACL_GROUP_ID_MAX + 1] = "";
    osSnprintf(id, sizeof(id), "%s", str(body, "id", ""));
    cJSON_Delete(body);
    if (!group_id_valid(id))
    {
        return send_error(connection, 400, "invalid_group", "Unknown group");
    }
    if (group_members(id) > 0)
    {
        return send_error(connection, 409, "group_in_use", "The group has members");
    }
    lock_acl();
    bool found = group_unlocked(id) != NULL;
    cJSON_DeleteItemFromObjectCaseSensitive(obj(acl, "groups"), id);
    bool ok = !found || save_unlocked();
    unlock_acl();
    if (!found)
    {
        return send_error(connection, 404, "invalid_group", "Unknown group");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", ok);
    return send_json(connection, ok ? 200 : 500, json);
}

error_t web_acl_forbidden(HttpConnection *connection)
{
    return send_error(connection, 403, "forbidden", "You may not do this");
}

/* names and levels of all users, to pick whom to share with */
error_t handleApiAclUsers(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    char(*names)[33] = osAllocMem(128 * 33);
    if (names == NULL)
    {
        return send_error(connection, 500, "failed", "Out of memory");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON *array = cJSON_AddArrayToObject(json, "users");
    int n = web_auth_user_names(names, 128);
    for (int i = 0; i < n; i++)
    {
        int level = ACL_LEVEL_GUEST;
        char group[WEB_ACL_GROUP_ID_MAX + 1] = "";
        web_auth_user_info(names[i], &level, NULL, 0, NULL, 0, group, sizeof(group));
        cJSON *u = cJSON_CreateObject();
        cJSON_AddStringToObject(u, "username", names[i]);
        cJSON_AddStringToObject(u, "level", acl_level_name((acl_level_t)level));
        cJSON_AddStringToObject(u, "group", group);
        cJSON_AddItemToArray(array, u);
    }
    osFreeMem(names);
    return send_json(connection, 200, json);
}
