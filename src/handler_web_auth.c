#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

#include "handler_web_auth.h"
#include "cJSON.h"
#include "debug.h"
#include "fs_ext.h"
#include "fs_port.h"
#include "handler_api.h"
#include "os_ext.h"
#include "os_port.h"
#include "rand.h"
#include "server_helpers.h"
#include "settings.h"
#include "web_auth_crypto.h"
#include "web_auth_net.h"
#include "web_acl.h"
#include "web_acl_core.h"

/*
 * Web UI login: users with PBKDF2 password hashes, optional TOTP 2FA with
 * recovery codes, persistent cookie sessions, lockout per address and per
 * account, network filters and a short event log. Login stays off until it
 * is enabled; TEDDYCLOUD_WEB_AUTH_DISABLE=1 bypasses all of it for recovery.
 */

#define MAX_WEB_USERS 128
#define MAX_WEB_SESSIONS 256
#define MAX_CHALLENGES 32
#define USERNAME_MAX 32
#define PASSWORD_MAX 128
#define TOKEN_BYTES 32
#define TOKEN_HEX ((TOKEN_BYTES * 2) + 1)
#define HASH_HEX 65
#define SESSION_ID_LEN 16
#define LOGIN_BUCKETS 1024
#define LOCK_MAX_SECONDS (24 * 60 * 60)
#define LOCK_FORGET_SECONDS (24 * 60 * 60)
/* failures from outside the local networks before an account is locked for outside logins */
#define ACCOUNT_FAIL_FACTOR 3
#define CHALLENGE_TTL_SECONDS 300
#define CHALLENGE_ATTEMPTS 5
#define TOTP_SETUP_TTL_SECONDS 600
#define TOTP_WINDOW 1
#define RECOVERY_CODES 10
#define RECOVERY_CODE_BYTES 7
#define RECOVERY_CODE_MAX 24
#define TOTP_SEALED_MAX 160
#define MAX_EVENTS 200
#define MAX_PARALLEL_HASHES 4
/* a login waits this long for a free hash slot before it gets "busy" */
#define HASH_WAIT_MS 10000
/* sensitive changes need the password (and 2FA code) again after this time */
#define CONFIRM_TTL_SECONDS 600
/* lock for new addresses from outside while every lockout entry is in use */
#define BUCKETS_FULL_LOCK_SECONDS 60
#define SESSION_SAVE_INTERVAL 600
#define USER_AGENT_MAX 96
#define USERS_FILE_MAX (1024 * 1024)

/* same cost as a real check, so unknown users are not faster to reject */
static const char dummy_hash[] = "pbkdf2-sha256$50000$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000";

#define USER_DENY_MAX 1024

typedef struct
{
    char username[USERNAME_MAX + 1];
    char hash[WEB_AUTH_HASH_MAX];
    acl_level_t level;
    /* own group (web_acl.json), empty for the built-in one of the level */
    char group[WEB_ACL_GROUP_ID_MAX + 1];
    char deny[USER_DENY_MAX];
    char created_by[USERNAME_MAX + 1];
    bool lan_only;
    bool require_2fa;
    /* set by whoever set the password; the user may do nothing but change it */
    bool must_change_pw;
    char totp_sealed[TOTP_SEALED_MAX];
    int64_t totp_last_step;
    char recovery[RECOVERY_CODES][HASH_HEX];
    time_t created;
    time_t pw_changed;
    time_t last_login;
    /* runtime only */
    int remote_failures;
    time_t remote_locked_until;
    int tfa_failures;
    time_t tfa_locked_until;
    uint8_t pending_totp[WEB_AUTH_TOTP_KEY_BYTES];
    time_t pending_until;
} web_user_t;

typedef struct
{
    bool used;
    char token_hash[HASH_HEX];
    char username[USERNAME_MAX + 1];
    time_t created;
    time_t last_seen;
    time_t expires;
    char ip[WEB_AUTH_IP_STR_MAX];
    char user_agent[USER_AGENT_MAX + 1];
    bool restricted;
    time_t confirmed;
} web_session_t;

typedef struct
{
    bool used;
    char token_hash[HASH_HEX];
    char username[USERNAME_MAX + 1];
    char ip[WEB_AUTH_IP_STR_MAX];
    time_t expires;
    int attempts;
} login_challenge_t;

typedef struct
{
    bool used;
    char ip[WEB_AUTH_IP_STR_MAX];
    int failures;
    int lock_count;
    time_t last_failure;
    time_t locked_until;
} login_limit_t;

typedef struct
{
    time_t time;
    char type[24];
    char username[USERNAME_MAX + 1];
    char ip[WEB_AUTH_IP_STR_MAX];
    char detail[64];
} auth_event_t;

typedef struct
{
    bool found;
    bool restricted;
    char username[USERNAME_MAX + 1];
    char token_hash[HASH_HEX];
    time_t confirmed;
} session_info_t;

static web_user_t users[MAX_WEB_USERS];
static int user_count = 0;
static web_session_t sessions[MAX_WEB_SESSIONS];
static login_challenge_t challenges[MAX_CHALLENGES];
static login_limit_t login_limits[LOGIN_BUCKETS];
static auth_event_t events[MAX_EVENTS];
static int event_next = 0;
static int event_count = 0;
static uint8_t seal_key[WEB_AUTH_SEAL_KEY_BYTES];
static bool seal_key_ready = false;
static time_t sessions_saved_at = 0;
static bool sessions_dirty = false;
static int hashes_running = 0;
static char hashes_ips[MAX_PARALLEL_HASHES][WEB_AUTH_IP_STR_MAX];
static time_t buckets_full_until = 0;
static bool users_load_failed = false;
static OsMutex web_auth_mutex;
static bool mutex_ready = false;
static bool initialized = false;

static const char *const common_passwords[] = {
    "password", "passwort", "1234567890", "12345678", "123456789", "qwertzuiop", "qwertyuiop", "teddycloud", "toniebox",
    "password1", "passwort1", "iloveyou", "11111111", "00000000", "abcdefgh", "abc12345", "letmein123", "admin12345",
    "administrator", "hallo12345", "sommer2024", "sommer2025", "sommer2026", "winter2025", "winter2026", "geheim123",
    "1q2w3e4r5t", "1qaz2wsx3edc", "qwerty123", "asdfghjkl", "changeme", "welcome1", "welcome123", "superman",
    NULL};

static bool sensitive_settings_uri(const char_t *uri);
static bool recently_confirmed(const session_info_t *info);

/* ---------- small helpers ---------- */

static void copy_str(char *dst, size_t dst_size, const char *src)
{
    size_t n = 0;
    if (dst == NULL || dst_size == 0)
    {
        return;
    }
    if (src != NULL)
    {
        n = osStrlen(src);
        if (n >= dst_size)
        {
            n = dst_size - 1;
        }
        osMemcpy(dst, src, n);
    }
    dst[n] = '\0';
}

static void lock_auth(void)
{
    if (mutex_ready)
    {
        osAcquireMutex(&web_auth_mutex);
    }
}

static void unlock_auth(void)
{
    if (mutex_ready)
    {
        osReleaseMutex(&web_auth_mutex);
    }
}

static const char *env_override_value(void)
{
    return getenv("TEDDYCLOUD_WEB_AUTH_DISABLE");
}

bool web_auth_env_override(void)
{
    const char *value = env_override_value();
    if (value == NULL || value[0] == '\0')
    {
        return false;
    }
    return osStrcasecmp(value, "1") == 0 || osStrcasecmp(value, "true") == 0 || osStrcasecmp(value, "yes") == 0;
}

static bool valid_username(const char *username)
{
    size_t len = osStrlen(username);
    if (len < 1 || len > USERNAME_MAX)
    {
        return false;
    }
    for (size_t i = 0; i < len; i++)
    {
        unsigned char c = (unsigned char)username[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
        {
            return false;
        }
    }
    return true;
}

/* user names from requests end up in the log, so only valid ones are printed as they are */
static const char *log_name(const char *username)
{
    return valid_username(username) ? username : "<invalid>";
}

static char *config_path(const char *file)
{
    const char *dir = settings_get_string("internal.configdirfull");
    if (dir == NULL || dir[0] == '\0')
    {
        return NULL;
    }
    return custom_asprintf("%s%c%s", dir, PATH_SEPARATOR, file);
}

static bool random_bytes(void *buf, size_t len)
{
    return rand_get_bytes(buf, len) == 0;
}

static bool random_token(char *hex, size_t hex_size)
{
    uint8_t bytes[TOKEN_BYTES];
    if (!random_bytes(bytes, sizeof(bytes)))
    {
        return false;
    }
    web_auth_hex(bytes, sizeof(bytes), hex, hex_size);
    osMemset(bytes, 0, sizeof(bytes));
    return true;
}

static void token_hash(const char *token, char *out, size_t out_size)
{
    web_auth_sha256_hex(token, osStrlen(token), out, out_size);
}

/* writes next to the target and renames, so a crash never leaves half a file; owner-only */
bool web_auth_write_private_file(const char *path, const char *body)
{
    char *tmp = custom_asprintf("%s.tmp", path);
    bool ok = false;
    if (tmp == NULL)
    {
        return false;
    }
#ifndef _WIN32
    /* created owner-only and not through a planted link, so it is never readable by others */
    unlink(tmp);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd >= 0)
    {
        size_t len = osStrlen(body);
        size_t done = 0;
        ok = true;
        while (done < len)
        {
            ssize_t n = write(fd, body + done, len - done);
            if (n <= 0)
            {
                ok = false;
                break;
            }
            done += (size_t)n;
        }
        if (ok && fsync(fd) != 0)
        {
            ok = false;
        }
        close(fd);
    }
#else
    FsFile *file = fsOpenFile(tmp, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);
    if (file != NULL)
    {
        ok = (fsWriteFile(file, (void *)body, osStrlen(body)) == NO_ERROR);
        fsCloseFile(file);
    }
#endif
    if (ok)
    {
        ok = osChmodOwnerOnly(tmp);
    }
    if (ok)
    {
        if (fsRenameFile(tmp, path) != NO_ERROR)
        {
            /* Windows does not replace an existing file */
            fsDeleteFile(path);
            ok = (fsRenameFile(tmp, path) == NO_ERROR);
        }
    }
    if (!ok)
    {
        fsDeleteFile(tmp);
    }
    osFreeMem(tmp);
    return ok;
}

static char *read_file(const char *path, uint32_t max)
{
    uint32_t length = 0;
    if (fsGetFileSize(path, &length) != NO_ERROR || length == 0 || length > max)
    {
        return NULL;
    }
    char *buf = osAllocMem(length + 1);
    if (buf == NULL)
    {
        return NULL;
    }
    FsFile *file = fsOpenFile(path, FS_FILE_MODE_READ);
    if (file == NULL)
    {
        osFreeMem(buf);
        return NULL;
    }
    size_t n = 0;
    error_t err = fsReadFile(file, buf, length, &n);
    fsCloseFile(file);
    if (err != NO_ERROR)
    {
        osFreeMem(buf);
        return NULL;
    }
    buf[n] = '\0';
    return buf;
}

static double json_number(cJSON *obj, const char *key, double def)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsNumber(item) ? item->valuedouble : def;
}

static bool json_bool(cJSON *obj, const char *key, bool def)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsBool(item) ? cJSON_IsTrue(item) : def;
}

static const char *json_str(cJSON *obj, const char *key)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsString(item) && item->valuestring != NULL ? item->valuestring : NULL;
}

/* ---------- event log ---------- */

static void add_event_unlocked(const char *type, const char *username, const char *ip, const char *detail)
{
    auth_event_t *e = &events[event_next];
    osMemset(e, 0, sizeof(*e));
    e->time = time(NULL);
    copy_str(e->type, sizeof(e->type), type);
    copy_str(e->username, sizeof(e->username), username ? log_name(username) : "");
    copy_str(e->ip, sizeof(e->ip), ip);
    copy_str(e->detail, sizeof(e->detail), detail);
    event_next = (event_next + 1) % MAX_EVENTS;
    if (event_count < MAX_EVENTS)
    {
        event_count++;
    }
}

/* ---------- key for secrets at rest ---------- */

static bool load_seal_key_unlocked(void)
{
    if (seal_key_ready)
    {
        return true;
    }
    char *path = config_path(WEB_AUTH_KEY_FILE);
    if (path == NULL)
    {
        return false;
    }
    char *content = read_file(path, 1024);
    if (content == NULL && fsFileExists(path))
    {
        /* never replace the key, the 2FA secrets would be lost */
        TRACE_ERROR("Web UI auth: %s exists but can not be read, 2FA secrets can not be used\r\n", path);
        osFreeMem(path);
        return false;
    }
    if (content != NULL)
    {
        char *end = content + osStrlen(content);
        while (end > content && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' '))
        {
            *--end = '\0';
        }
        seal_key_ready = web_auth_unhex(content, seal_key, sizeof(seal_key));
        osMemset(content, 0, osStrlen(content));
        osFreeMem(content);
        if (!seal_key_ready)
        {
            TRACE_ERROR("Web UI auth: %s is invalid, 2FA secrets can not be read\r\n", path);
        }
        osFreeMem(path);
        return seal_key_ready;
    }
    char hex[WEB_AUTH_SEAL_KEY_BYTES * 2 + 1];
    if (random_bytes(seal_key, sizeof(seal_key)))
    {
        web_auth_hex(seal_key, sizeof(seal_key), hex, sizeof(hex));
        seal_key_ready = web_auth_write_private_file(path, hex);
        osMemset(hex, 0, sizeof(hex));
    }
    if (!seal_key_ready)
    {
        TRACE_ERROR("Web UI auth: could not create %s\r\n", path);
    }
    osFreeMem(path);
    return seal_key_ready;
}

/* ---------- users ---------- */

static web_user_t *find_user_unlocked(const char *username)
{
    if (username == NULL)
    {
        return NULL;
    }
    for (int i = 0; i < user_count; i++)
    {
        if (osStrcasecmp(users[i].username, username) == 0)
        {
            return &users[i];
        }
    }
    return NULL;
}

static bool user_has_totp(const web_user_t *user)
{
    return user->totp_sealed[0] != '\0';
}

static int recovery_left(const web_user_t *user)
{
    int n = 0;
    for (int i = 0; i < RECOVERY_CODES; i++)
    {
        if (user->recovery[i][0] != '\0')
        {
            n++;
        }
    }
    return n;
}

static bool two_factor_required(const web_user_t *user)
{
    return user->require_2fa || settings_get_bool("web_auth.require_2fa");
}

static bool save_users_unlocked(void)
{
    char *path = config_path(WEB_USERS_JSON_FILE);
    if (path == NULL)
    {
        return false;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "version", 2);
    cJSON *array = cJSON_AddArrayToObject(root, "users");
    for (int i = 0; i < user_count; i++)
    {
        web_user_t *u = &users[i];
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "username", u->username);
        cJSON_AddStringToObject(entry, "password", u->hash);
        /* an older teddyCloud reads salt/hash: empty ones make it refuse the login instead of turning it off */
        cJSON_AddStringToObject(entry, "salt", "");
        cJSON_AddStringToObject(entry, "hash", "");
        cJSON_AddStringToObject(entry, "level", acl_level_name(u->level));
        if (u->group[0] != '\0')
        {
            cJSON_AddStringToObject(entry, "group", u->group);
        }
        if (u->deny[0] != '\0')
        {
            cJSON_AddStringToObject(entry, "deny", u->deny);
        }
        if (u->created_by[0] != '\0')
        {
            cJSON_AddStringToObject(entry, "createdBy", u->created_by);
        }
        cJSON_AddBoolToObject(entry, "lanOnly", u->lan_only);
        cJSON_AddBoolToObject(entry, "require2fa", u->require_2fa);
        if (u->must_change_pw)
        {
            cJSON_AddBoolToObject(entry, "mustChangePassword", true);
        }
        if (user_has_totp(u))
        {
            cJSON_AddStringToObject(entry, "totp", u->totp_sealed);
            cJSON_AddNumberToObject(entry, "totpLastStep", (double)u->totp_last_step);
            cJSON *codes = cJSON_AddArrayToObject(entry, "recoveryCodes");
            for (int c = 0; c < RECOVERY_CODES; c++)
            {
                if (u->recovery[c][0] != '\0')
                {
                    cJSON_AddItemToArray(codes, cJSON_CreateString(u->recovery[c]));
                }
            }
        }
        cJSON_AddNumberToObject(entry, "created", (double)u->created);
        cJSON_AddNumberToObject(entry, "passwordChanged", (double)u->pw_changed);
        cJSON_AddNumberToObject(entry, "lastLogin", (double)u->last_login);
        cJSON_AddItemToArray(array, entry);
    }
    char *body = cJSON_Print(root);
    cJSON_Delete(root);
    bool ok = false;
    if (body != NULL)
    {
        ok = web_auth_write_private_file(path, body);
        osFreeMem(body);
    }
    if (!ok)
    {
        TRACE_ERROR("Web UI auth: could not save %s\r\n", path);
    }
    osFreeMem(path);
    return ok;
}

static void load_users_unlocked(void)
{
    user_count = 0;
    users_load_failed = false;
    osMemset(users, 0, sizeof(users));
    char *path = config_path(WEB_USERS_JSON_FILE);
    if (path == NULL)
    {
        return;
    }
    char *buf = read_file(path, USERS_FILE_MAX);
    bool exists = fsFileExists(path);
    uint32_t size = 0;
    fsGetFileSize(path, &size);
    osFreeMem(path);
    if (buf == NULL)
    {
        if (exists && size > 0)
        {
            /* a broken file must not silently turn the login off */
            users_load_failed = true;
            TRACE_ERROR("Web UI auth: %s can not be read, nobody can log in until it is fixed\r\n", WEB_USERS_JSON_FILE);
        }
        return;
    }
    cJSON *root = cJSON_Parse(buf);
    osFreeMem(buf);
    if (root == NULL)
    {
        users_load_failed = true;
        TRACE_ERROR("Web UI auth: %s is not valid JSON, nobody can log in until it is fixed\r\n", WEB_USERS_JSON_FILE);
        return;
    }
    bool migrated = false;
    cJSON *array = cJSON_GetObjectItemCaseSensitive(root, "users");
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, array)
    {
        if (user_count >= MAX_WEB_USERS)
        {
            TRACE_WARNING("Web UI auth: more than %d users in %s, the rest is ignored\r\n", MAX_WEB_USERS, WEB_USERS_JSON_FILE);
            break;
        }
        web_user_t *u = &users[user_count];
        osMemset(u, 0, sizeof(*u));
        const char *username = json_str(entry, "username");
        const char *password = json_str(entry, "password");
        const char *salt = json_str(entry, "salt");
        const char *hash = json_str(entry, "hash");
        if (username == NULL || !valid_username(username))
        {
            continue;
        }
        copy_str(u->username, sizeof(u->username), username);
        if (password != NULL)
        {
            copy_str(u->hash, sizeof(u->hash), password);
        }
        else if (salt != NULL && hash != NULL && salt[0] != '\0')
        {
            /* first release: separate salt and SHA-256 hash, upgraded at the next login */
            osSnprintf(u->hash, sizeof(u->hash), "sha256$%s$%s", salt, hash);
            migrated = true;
        }
        if (!web_auth_pw_hash_valid(u->hash))
        {
            TRACE_WARNING("Web UI auth: user '%s' has no valid password hash and can not log in\r\n", u->username);
        }
        /* users from before the permissions had full access: they stay admins */
        if (!acl_level_parse(json_str(entry, "level"), &u->level))
        {
            u->level = ACL_LEVEL_ADMIN;
        }
        copy_str(u->group, sizeof(u->group), json_str(entry, "group"));
        copy_str(u->deny, sizeof(u->deny), json_str(entry, "deny"));
        copy_str(u->created_by, sizeof(u->created_by), json_str(entry, "createdBy"));
        u->lan_only = json_bool(entry, "lanOnly", false);
        u->require_2fa = json_bool(entry, "require2fa", false);
        u->must_change_pw = json_bool(entry, "mustChangePassword", false);
        const char *totp = json_str(entry, "totp");
        if (totp != NULL && osStrlen(totp) < sizeof(u->totp_sealed))
        {
            copy_str(u->totp_sealed, sizeof(u->totp_sealed), totp);
        }
        u->totp_last_step = (int64_t)json_number(entry, "totpLastStep", -1);
        cJSON *codes = cJSON_GetObjectItemCaseSensitive(entry, "recoveryCodes");
        cJSON *code = NULL;
        int c = 0;
        cJSON_ArrayForEach(code, codes)
        {
            if (c < RECOVERY_CODES && cJSON_IsString(code) && osStrlen(code->valuestring) == HASH_HEX - 1)
            {
                copy_str(u->recovery[c++], HASH_HEX, code->valuestring);
            }
        }
        u->created = (time_t)json_number(entry, "created", 0);
        u->pw_changed = (time_t)json_number(entry, "passwordChanged", 0);
        u->last_login = (time_t)json_number(entry, "lastLogin", 0);
        user_count++;
    }
    cJSON_Delete(root);
    if (migrated)
    {
        TRACE_INFO("Web UI auth: users from the first login release found, their passwords are upgraded at the next login\r\n");
    }
}

/* ---------- sessions ---------- */

static bool session_expired(const web_session_t *s, time_t now)
{
    uint32_t idle_hours = settings_get_unsigned("web_auth.session_idle_hours");
    if (s->expires <= now)
    {
        return true;
    }
    if (idle_hours > 0 && s->last_seen + (time_t)idle_hours * 3600 <= now)
    {
        return true;
    }
    /* a login that still has to set up 2FA is short-lived */
    if (s->restricted && s->created + TOTP_SETUP_TTL_SECONDS <= now)
    {
        return true;
    }
    return false;
}

static bool save_sessions_unlocked(void)
{
    char *path = config_path(WEB_SESSIONS_JSON_FILE);
    if (path == NULL)
    {
        return false;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *array = cJSON_AddArrayToObject(root, "sessions");
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        web_session_t *s = &sessions[i];
        if (!s->used || s->restricted)
        {
            continue;
        }
        cJSON *entry = cJSON_CreateObject();
        /* only the hash of the token is stored, a copy of the file does not allow a login */
        cJSON_AddStringToObject(entry, "tokenHash", s->token_hash);
        cJSON_AddStringToObject(entry, "username", s->username);
        cJSON_AddNumberToObject(entry, "created", (double)s->created);
        cJSON_AddNumberToObject(entry, "lastSeen", (double)s->last_seen);
        cJSON_AddNumberToObject(entry, "expires", (double)s->expires);
        cJSON_AddStringToObject(entry, "ip", s->ip);
        cJSON_AddStringToObject(entry, "userAgent", s->user_agent);
        cJSON_AddNumberToObject(entry, "confirmed", (double)s->confirmed);
        cJSON_AddItemToArray(array, entry);
    }
    char *body = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    bool ok = false;
    if (body != NULL)
    {
        ok = web_auth_write_private_file(path, body);
        osFreeMem(body);
    }
    osFreeMem(path);
    sessions_saved_at = time(NULL);
    sessions_dirty = false;
    return ok;
}

static void load_sessions_unlocked(void)
{
    osMemset(sessions, 0, sizeof(sessions));
    char *path = config_path(WEB_SESSIONS_JSON_FILE);
    if (path == NULL)
    {
        return;
    }
    char *buf = read_file(path, USERS_FILE_MAX);
    osFreeMem(path);
    if (buf == NULL)
    {
        return;
    }
    cJSON *root = cJSON_Parse(buf);
    osFreeMem(buf);
    if (root == NULL)
    {
        return;
    }
    time_t now = time(NULL);
    int n = 0;
    cJSON *entry = NULL;
    cJSON_ArrayForEach(entry, cJSON_GetObjectItemCaseSensitive(root, "sessions"))
    {
        if (n >= MAX_WEB_SESSIONS)
        {
            break;
        }
        const char *hash = json_str(entry, "tokenHash");
        const char *username = json_str(entry, "username");
        if (hash == NULL || osStrlen(hash) != HASH_HEX - 1 || username == NULL || find_user_unlocked(username) == NULL)
        {
            continue;
        }
        web_session_t *s = &sessions[n];
        copy_str(s->token_hash, sizeof(s->token_hash), hash);
        copy_str(s->username, sizeof(s->username), find_user_unlocked(username)->username);
        s->created = (time_t)json_number(entry, "created", 0);
        s->last_seen = (time_t)json_number(entry, "lastSeen", 0);
        s->expires = (time_t)json_number(entry, "expires", 0);
        copy_str(s->ip, sizeof(s->ip), json_str(entry, "ip"));
        copy_str(s->user_agent, sizeof(s->user_agent), json_str(entry, "userAgent"));
        s->confirmed = (time_t)json_number(entry, "confirmed", 0);
        s->used = true;
        if (session_expired(s, now))
        {
            osMemset(s, 0, sizeof(*s));
            continue;
        }
        n++;
    }
    cJSON_Delete(root);
}

static void purge_sessions_unlocked(void)
{
    time_t now = time(NULL);
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        if (sessions[i].used && session_expired(&sessions[i], now))
        {
            if (!sessions[i].restricted)
            {
                sessions_dirty = true;
            }
            osMemset(&sessions[i], 0, sizeof(sessions[i]));
        }
    }
    for (int i = 0; i < MAX_CHALLENGES; i++)
    {
        if (challenges[i].used && challenges[i].expires <= now)
        {
            osMemset(&challenges[i], 0, sizeof(challenges[i]));
        }
    }
}

static bool create_session_unlocked(const char *username, const char *ip, const char *user_agent, bool restricted, char *token, size_t token_size)
{
    char raw[TOKEN_HEX];
    if (!random_token(raw, sizeof(raw)))
    {
        return false;
    }
    purge_sessions_unlocked();
    int slot = -1;
    time_t oldest = 0;
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        if (!sessions[i].used)
        {
            slot = i;
            break;
        }
        if (slot < 0 || sessions[i].last_seen < oldest)
        {
            slot = i;
            oldest = sessions[i].last_seen;
        }
    }
    web_session_t *s = &sessions[slot];
    time_t now = time(NULL);
    osMemset(s, 0, sizeof(*s));
    token_hash(raw, s->token_hash, sizeof(s->token_hash));
    copy_str(s->username, sizeof(s->username), username);
    copy_str(s->ip, sizeof(s->ip), ip);
    copy_str(s->user_agent, sizeof(s->user_agent), user_agent);
    s->created = now;
    s->last_seen = now;
    s->confirmed = restricted ? 0 : now;
    s->expires = now + (time_t)settings_get_unsigned("web_auth.session_days") * 24 * 3600;
    s->restricted = restricted;
    s->used = true;
    copy_str(token, token_size, raw);
    osMemset(raw, 0, sizeof(raw));
    if (!restricted)
    {
        save_sessions_unlocked();
    }
    return true;
}

static web_session_t *find_session_unlocked(const char *hash)
{
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        if (sessions[i].used && web_auth_const_equal_str(sessions[i].token_hash, hash))
        {
            return &sessions[i];
        }
    }
    return NULL;
}

/* ends the sessions of a user, except the one with keep_hash */
static int revoke_user_sessions_unlocked(const char *username, const char *keep_hash)
{
    int n = 0;
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        web_session_t *s = &sessions[i];
        if (s->used && osStrcasecmp(s->username, username) == 0 && (keep_hash == NULL || osStrcmp(s->token_hash, keep_hash) != 0))
        {
            osMemset(s, 0, sizeof(*s));
            n++;
        }
    }
    for (int i = 0; i < MAX_CHALLENGES; i++)
    {
        if (challenges[i].used && osStrcasecmp(challenges[i].username, username) == 0)
        {
            osMemset(&challenges[i], 0, sizeof(challenges[i]));
        }
    }
    if (n > 0)
    {
        save_sessions_unlocked();
    }
    return n;
}

/* bearer token if the request has one (then the cookie is not looked at), otherwise the cookie */
static void request_token(HttpConnection *connection, char *out, size_t out_size, bool *bearer)
{
    out[0] = '\0';
    *bearer = false;
    if (connection->private.web_bearer_token[0] != '\0')
    {
        copy_str(out, out_size, connection->private.web_bearer_token);
        *bearer = true;
        return;
    }
    /* the __Host- cookie can not be set by a sibling domain, it wins over the plain one */
    if (connection->request.webSessionCookieHost[0] != '\0')
    {
        copy_str(out, out_size, connection->request.webSessionCookieHost);
        return;
    }
    copy_str(out, out_size, connection->request.webSessionCookie);
}

static session_info_t current_session(HttpConnection *connection, bool touch)
{
    session_info_t info;
    osMemset(&info, 0, sizeof(info));
    char token[WEB_BEARER_TOKEN_MAX + 1];
    bool bearer;
    request_token(connection, token, sizeof(token), &bearer);
    if (osStrlen(token) != TOKEN_HEX - 1)
    {
        return info;
    }
    char hash[HASH_HEX];
    token_hash(token, hash, sizeof(hash));
    lock_auth();
    purge_sessions_unlocked();
    web_session_t *s = find_session_unlocked(hash);
    if (s != NULL && find_user_unlocked(s->username) != NULL)
    {
        info.found = true;
        info.restricted = s->restricted;
        copy_str(info.username, sizeof(info.username), s->username);
        copy_str(info.token_hash, sizeof(info.token_hash), s->token_hash);
        info.confirmed = s->confirmed;
        if (touch)
        {
            time_t now = time(NULL);
            if (now - s->last_seen >= 60)
            {
                s->last_seen = now;
                sessions_dirty = true;
            }
        }
    }
    if (sessions_dirty && time(NULL) - sessions_saved_at >= SESSION_SAVE_INTERVAL)
    {
        save_sessions_unlocked();
    }
    unlock_auth();
    return info;
}

/* ---------- request properties ---------- */

static bool peer_is_trusted_proxy(HttpConnection *connection)
{
    char peer[WEB_AUTH_IP_STR_MAX];
    const char *trusted = settings_get_string("web_auth.trusted_proxies");
    if (connection->socket == NULL || trusted == NULL || trusted[0] == '\0')
    {
        return false;
    }
    ipAddrToString(&connection->socket->remoteIpAddr, peer);
    return web_auth_ip_in_list(trusted, peer);
}

void web_auth_client_ip(HttpConnection *connection, char *out, size_t out_size)
{
    char peer[WEB_AUTH_IP_STR_MAX];
    if (out_size == 0)
    {
        return;
    }
    out[0] = '\0';
    if (connection == NULL || connection->socket == NULL)
    {
        return;
    }
    ipAddrToString(&connection->socket->remoteIpAddr, peer);
    web_auth_ip_resolve(peer, connection->request.forwardedFor, settings_get_string("web_auth.trusted_proxies"), out, out_size);
}

bool web_auth_request_secure(HttpConnection *connection)
{
    if (connection->tlsContext != NULL)
    {
        return true;
    }
    return osStrcasecmp(connection->request.forwardedProto, "https") == 0 && peer_is_trusted_proxy(connection);
}

static bool ip_is_lan(const char *ip)
{
    const char *lan = settings_get_string("web_auth.lan_networks");
    return web_auth_ip_in_list(lan != NULL ? lan : WEB_AUTH_DEFAULT_LAN_NETWORKS, ip);
}

/* host[:port] of an Origin header such as "https://tc.example.com:8443" */
static const char *origin_host(const char *origin)
{
    const char *p = osStrstr(origin, "://");
    return p != NULL ? p + 3 : origin;
}

static bool host_equal(const char *a, const char *b)
{
    return a != NULL && b != NULL && a[0] != '\0' && osStrcasecmp(a, b) == 0;
}

/*
 * Requests that change something or read the API must come from the web UI itself.
 * Browsers send Sec-Fetch-Site; older ones only Origin, which is compared to the host.
 * Requests with a bearer token can not be forged by another site and are not checked.
 */
static bool cross_site_request(HttpConnection *connection, const char_t *uri)
{
    bool is_get = !osStrcasecmp(connection->request.method, "GET") || !osStrcasecmp(connection->request.method, "HEAD");
    if (is_get && osStrncmp(uri, "/api/", 5) != 0)
    {
        return false;
    }
    if (connection->private.web_bearer_token[0] != '\0')
    {
        return false;
    }
    const char *site = connection->request.secFetchSite;
    if (site[0] != '\0')
    {
        return osStrcasecmp(site, "same-origin") != 0 && osStrcasecmp(site, "none") != 0;
    }
    const char *origin = connection->request.origin;
    if (origin[0] == '\0' || !osStrcmp(origin, "null"))
    {
        /* no browser, or a browser that sends neither header for same-origin GET */
        return origin[0] != '\0';
    }
    const char *host = origin_host(origin);
    if (host_equal(host, connection->request.hostFull))
    {
        return false;
    }
    if (peer_is_trusted_proxy(connection) && host_equal(host, connection->request.forwardedHost))
    {
        return false;
    }
    return true;
}

/* ---------- lockout ---------- */

static login_limit_t *find_login_limit_unlocked(const char *client_ip, bool create)
{
    char ip[WEB_AUTH_IP_STR_MAX];
    if (client_ip == NULL || client_ip[0] == '\0')
    {
        return NULL;
    }
    /* one IPv6 client usually has a whole /64 */
    web_auth_ip_lockout_key(client_ip, ip, sizeof(ip));
    time_t now = time(NULL);
    int empty = -1;
    int victim = -1;
    for (int i = 0; i < LOGIN_BUCKETS; i++)
    {
        login_limit_t *b = &login_limits[i];
        if (b->used && !osStrcmp(b->ip, ip))
        {
            return b;
        }
        if (b->used && b->locked_until <= now && b->last_failure + LOCK_FORGET_SECONDS <= now)
        {
            osMemset(b, 0, sizeof(*b));
        }
        if (!b->used && empty < 0)
        {
            empty = i;
        }
        /* when full, reuse the oldest bucket that is not locked, so locked addresses stay locked */
        if (b->used && b->locked_until <= now && (victim < 0 || b->last_failure < login_limits[victim].last_failure))
        {
            victim = i;
        }
    }
    if (!create)
    {
        return NULL;
    }
    int idx = empty >= 0 ? empty : victim;
    if (idx < 0)
    {
        /* all entries locked: someone uses many addresses, new ones from outside wait a bit */
        buckets_full_until = now + BUCKETS_FULL_LOCK_SECONDS;
        return NULL;
    }
    osMemset(&login_limits[idx], 0, sizeof(login_limits[idx]));
    login_limits[idx].used = true;
    copy_str(login_limits[idx].ip, sizeof(login_limits[idx].ip), ip);
    return &login_limits[idx];
}

/* seconds until the address may try again, 0 if not locked */
static time_t login_locked_for_unlocked(const char *ip, bool lan)
{
    login_limit_t *b = find_login_limit_unlocked(ip, false);
    time_t now = time(NULL);
    if (b == NULL)
    {
        return (!lan && buckets_full_until > now) ? buckets_full_until - now : 0;
    }
    if (b->locked_until <= now)
    {
        return 0;
    }
    return b->locked_until - now;
}

static time_t lock_duration(int lock_count)
{
    time_t seconds = (time_t)settings_get_unsigned("web_auth.lockout_minutes") * 60;
    for (int i = 1; i < lock_count && seconds < LOCK_MAX_SECONDS; i++)
    {
        seconds *= 2;
    }
    return seconds > LOCK_MAX_SECONDS ? LOCK_MAX_SECONDS : seconds;
}

static void login_register_failure_unlocked(const char *ip, web_user_t *user, bool lan, const char *attempted, const char *reason)
{
    time_t now = time(NULL);
    uint32_t limit = settings_get_unsigned("web_auth.lockout_attempts");
    /* fixed format for fail2ban, see contrib/fail2ban */
    TRACE_WARNING("Web UI login failed for user '%s' from %s (%s)\r\n", log_name(attempted), ip, reason);
    add_event_unlocked("login_failed", attempted, ip, reason);

    login_limit_t *b = find_login_limit_unlocked(ip, true);
    if (b != NULL)
    {
        if (b->locked_until != 0 && b->locked_until <= now)
        {
            b->failures = 0;
            b->locked_until = 0;
        }
        b->failures++;
        b->last_failure = now;
        if ((uint32_t)b->failures >= limit)
        {
            b->lock_count++;
            b->locked_until = now + lock_duration(b->lock_count);
            b->failures = 0;
            TRACE_WARNING("Web UI login locked for %s after %u failures for %ld seconds\r\n", ip, (unsigned)limit, (long)(b->locked_until - now));
            add_event_unlocked("ip_locked", attempted, ip, "too many failed logins");
        }
    }
    /* guessing one account from many addresses; logins from the local networks keep working */
    if (user != NULL && !lan)
    {
        if (user->remote_locked_until != 0 && user->remote_locked_until <= now)
        {
            user->remote_failures = 0;
            user->remote_locked_until = 0;
        }
        user->remote_failures++;
        if ((uint32_t)user->remote_failures >= limit * ACCOUNT_FAIL_FACTOR)
        {
            user->remote_locked_until = now + lock_duration(1);
            user->remote_failures = 0;
            TRACE_WARNING("Web UI login of user '%s' locked for logins from outside the local networks\r\n", user->username);
            add_event_unlocked("account_locked", user->username, ip, "too many failed logins from outside");
        }
    }
}

static void login_register_success_unlocked(const char *ip, web_user_t *user)
{
    login_limit_t *b = find_login_limit_unlocked(ip, false);
    if (b != NULL)
    {
        /* the failures are forgiven, earlier lockouts still count for the next one */
        b->failures = 0;
    }
    if (user != NULL)
    {
        user->remote_failures = 0;
    }
}

/*
 * PBKDF2 is slow on purpose; too many at once would let anyone stall the server.
 * One hash per address at a time, others wait for a free slot.
 */
typedef enum
{
    HASH_SLOT_OK,
    HASH_SLOT_BUSY,
    HASH_SLOT_SAME_ADDRESS
} hash_slot_t;

static hash_slot_t hash_slot_acquire(const char *ip)
{
    char key[WEB_AUTH_IP_STR_MAX];
    web_auth_ip_lockout_key(ip != NULL ? ip : "", key, sizeof(key));
    for (int waited = 0; waited <= HASH_WAIT_MS; waited += 50)
    {
        lock_auth();
        int free_slot = -1;
        for (int i = 0; i < MAX_PARALLEL_HASHES; i++)
        {
            if (hashes_ips[i][0] == '\0')
            {
                if (free_slot < 0)
                {
                    free_slot = i;
                }
            }
            else if (key[0] != '\0' && !osStrcmp(hashes_ips[i], key))
            {
                unlock_auth();
                return HASH_SLOT_SAME_ADDRESS;
            }
        }
        if (free_slot >= 0)
        {
            copy_str(hashes_ips[free_slot], sizeof(hashes_ips[free_slot]), key[0] ? key : "-");
            hashes_running++;
            unlock_auth();
            return HASH_SLOT_OK;
        }
        unlock_auth();
        osDelayTask(50);
    }
    return HASH_SLOT_BUSY;
}

static void hash_slot_release(const char *ip)
{
    char key[WEB_AUTH_IP_STR_MAX];
    web_auth_ip_lockout_key(ip != NULL ? ip : "", key, sizeof(key));
    lock_auth();
    for (int i = 0; i < MAX_PARALLEL_HASHES; i++)
    {
        if (hashes_ips[i][0] != '\0' && !osStrcmp(hashes_ips[i], key[0] ? key : "-"))
        {
            hashes_ips[i][0] = '\0';
            hashes_running--;
            break;
        }
    }
    unlock_auth();
}

static bool make_password_hash(const char *password, char *out, size_t out_size)
{
    uint8_t salt[WEB_AUTH_SALT_BYTES];
    if (!random_bytes(salt, sizeof(salt)))
    {
        return false;
    }
    return web_auth_pw_hash(password, salt, WEB_AUTH_PBKDF2_ITERATIONS, out, out_size);
}

/* NULL if fine, otherwise the reason shown to the user */
static const char *password_problem(const char *username, const char *password)
{
    size_t len = osStrlen(password);
    if (len < settings_get_unsigned("web_auth.password_min_length"))
    {
        return "password_too_short";
    }
    if (len > PASSWORD_MAX)
    {
        return "password_too_long";
    }
    if (username != NULL && osStrcasecmp(username, password) == 0)
    {
        return "password_is_username";
    }
    for (int i = 0; common_passwords[i] != NULL; i++)
    {
        if (osStrcasecmp(common_passwords[i], password) == 0)
        {
            return "password_too_common";
        }
    }
    bool all_same = true;
    for (size_t i = 1; i < len; i++)
    {
        if (password[i] != password[0])
        {
            all_same = false;
            break;
        }
    }
    return all_same ? "password_too_common" : NULL;
}

/* ---------- responses ---------- */

static void set_session_cookie(HttpConnection *connection, const char *token, bool clear)
{
#if (HTTP_SERVER_COOKIE_SUPPORT == ENABLED)
    /* over HTTPS the __Host- prefix keeps other (sub)domains from setting the cookie */
    bool is_secure = web_auth_request_secure(connection);
    const char *name = is_secure ? "__Host-" WEB_SESSION_COOKIE : WEB_SESSION_COOKIE;
    const char *secure = is_secure ? "; Secure" : "";
    if (clear || token == NULL || token[0] == '\0')
    {
        osSnprintf(connection->response.setCookie, HTTP_SERVER_COOKIE_MAX_LEN,
                   "%s=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict%s", name, secure);
        return;
    }
    osSnprintf(connection->response.setCookie, HTTP_SERVER_COOKIE_MAX_LEN,
               "%s=%s; Path=/; Max-Age=%u; HttpOnly; SameSite=Strict%s",
               name, token, (unsigned)(settings_get_unsigned("web_auth.session_days") * 24 * 3600), secure);
#else
    (void)connection;
    (void)token;
    (void)clear;
#endif
}

static error_t send_json_status(HttpConnection *connection, uint_t status, cJSON *json, const char *token, bool clear_cookie)
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
    if (token != NULL || clear_cookie)
    {
        set_session_cookie(connection, token, clear_cookie);
    }
    error_t err = httpWriteResponseString(connection, body, true);
    return err;
}

static error_t send_message(HttpConnection *connection, uint_t status, const char *error, const char *message)
{
    cJSON *json = cJSON_CreateObject();
    if (error)
    {
        cJSON_AddStringToObject(json, "error", error);
    }
    if (message)
    {
        cJSON_AddStringToObject(json, "message", message);
    }
    return send_json_status(connection, status, json, NULL, false);
}

static error_t send_ok(HttpConnection *connection)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    return send_json_status(connection, 200, json, NULL, false);
}

static error_t read_json_body(HttpConnection *connection, cJSON **outJson)
{
    *outJson = NULL;
    if (connection->request.byteCount == 0 || connection->request.byteCount > (64 * 1024))
    {
        return ERROR_INVALID_LENGTH;
    }
    size_t bodySize = connection->request.byteCount;
    char *postData = osAllocMem(bodySize + 1);
    if (postData == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }
    osMemset(postData, 0, bodySize + 1);
    size_t totalRead = 0;
    while (totalRead < bodySize)
    {
        size_t chunkRead = 0;
        error_t error = httpReadStream(connection, postData + totalRead, bodySize - totalRead, &chunkRead, 0x00);
        if (error != NO_ERROR)
        {
            osMemset(postData, 0, bodySize + 1);
            osFreeMem(postData);
            return error;
        }
        if (chunkRead == 0)
        {
            break;
        }
        totalRead += chunkRead;
    }
    postData[totalRead] = '\0';
    *outJson = cJSON_Parse(postData);
    /* the body may hold a password */
    osMemset(postData, 0, bodySize + 1);
    osFreeMem(postData);
    if (*outJson == NULL)
    {
        return ERROR_INVALID_SYNTAX;
    }
    return NO_ERROR;
}

static bool json_string(cJSON *obj, const char *key, char *out, size_t out_size)
{
    const char *value = json_str(obj, key);
    if (value == NULL || osStrlen(value) >= out_size)
    {
        return false;
    }
    osStrcpy(out, value);
    return true;
}

/* cJSON keeps the parsed passwords in memory that is freed later, wipe them first */
static void delete_body(cJSON *body)
{
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, body)
    {
        if (cJSON_IsString(item) && item->valuestring != NULL)
        {
            osMemset(item->valuestring, 0, osStrlen(item->valuestring));
        }
    }
    cJSON_Delete(body);
}

static void wipe(void *p, size_t len)
{
    volatile uint8_t *v = p;
    while (len--)
    {
        *v++ = 0;
    }
}

/* ---------- public checks ---------- */

void web_auth_init(void)
{
    if (!mutex_ready && osCreateMutex(&web_auth_mutex))
    {
        mutex_ready = true;
    }
    lock_auth();
    osMemset(login_limits, 0, sizeof(login_limits));
    osMemset(challenges, 0, sizeof(challenges));
    load_users_unlocked();
    load_sessions_unlocked();
    initialized = true;
    unlock_auth();
    TRACE_INFO("Web UI auth loaded %d user(s), enabled=%s, envOverride=%s\r\n",
               user_count,
               settings_get_bool("frontend.web_auth_enabled") ? "true" : "false",
               web_auth_env_override() ? "true" : "false");
}

bool web_auth_requires_login(void)
{
    if (web_auth_env_override())
    {
        return false;
    }
    if (!settings_get_bool("frontend.web_auth_enabled"))
    {
        return false;
    }
    lock_auth();
    if (!initialized)
    {
        load_users_unlocked();
        load_sessions_unlocked();
        initialized = true;
    }
    int count = user_count;
    bool failed = users_load_failed;
    unlock_auth();
    return count > 0 || failed;
}

/* exact paths; the router matches prefixes, so a longer path would reach another handler */
static const char *const public_api[] = {
    "/api/auth/login",
    "/api/auth/login2fa",
    "/api/auth/status",
    "/api/auth/logout",
    "/api/auth/refresh-token",
    NULL};

/* what a login may do that still has to change its password */
static const char *const password_change_api[] = {
    "/api/auth/users/updatePassword",
    NULL};

/* what a login may do that still has to set up 2FA */
static const char *const restricted_api[] = {
    "/api/auth/2fa/setup",
    "/api/auth/2fa/enable",
    NULL};

static bool in_list(const char *const *list, const char_t *uri)
{
    for (int i = 0; list[i] != NULL; i++)
    {
        if (!osStrcmp(uri, list[i]))
        {
            return true;
        }
    }
    return false;
}

bool web_auth_is_public_request(const char_t *uri, const char_t *method)
{
    (void)method;
    if (uri == NULL)
    {
        return false;
    }
    if (in_list(public_api, uri))
    {
        return true;
    }
    /* Login page is part of the SPA and must load before the session exists.
     * The HTTP parser rewrites "/" to the default document "index.shtm" (without leading slash). */
    if (!osStrcmp(uri, "/") || !osStrcmp(uri, "index.shtm") || !osStrcmp(uri, "/index.shtm") || !osStrcmp(uri, "/favicon.ico"))
    {
        return true;
    }
    if (!osStrncmp(uri, "/web", 4) && (uri[4] == '\0' || uri[4] == '/'))
    {
        return true;
    }
    return false;
}

bool web_auth_is_authenticated(HttpConnection *connection, char *username, size_t username_size)
{
    session_info_t info = current_session(connection, false);
    if (username != NULL && username_size > 0)
    {
        copy_str(username, username_size, info.found && !info.restricted ? info.username : "");
    }
    return info.found && !info.restricted;
}

error_t web_auth_unauthorized(HttpConnection *connection)
{
    return send_message(connection, 401, "unauthorized", "Login required");
}

/* behind a proxy that is not trusted every client has the proxy's address, often a local one */
static bool forwarding_ignored(HttpConnection *connection)
{
    return connection->request.forwardedFor[0] != '\0' && !peer_is_trusted_proxy(connection);
}

static void warn_untrusted_forwarding(HttpConnection *connection)
{
    static bool warned = false;
    if (!warned && forwarding_ignored(connection))
    {
        char peer[WEB_AUTH_IP_STR_MAX];
        ipAddrToString(&connection->socket->remoteIpAddr, peer);
        TRACE_WARNING("Web UI: %s sends X-Forwarded-For but is no trusted proxy, all clients behind it look like %s. "
                      "Add it to web_auth.trusted_proxies if it is your reverse proxy.\r\n",
                      peer, peer);
        warned = true;
    }
}

bool web_auth_gate(HttpConnection *connection, const char_t *uri, error_t *error)
{
    char ip[WEB_AUTH_IP_STR_MAX];
    *error = NO_ERROR;
    if (connection->private.api_access_only || web_auth_env_override())
    {
        return false;
    }
    web_auth_client_ip(connection, ip, sizeof(ip));
    bool lan = ip_is_lan(ip);
    warn_untrusted_forwarding(connection);

    const char *deny = settings_get_string("web_auth.deny_networks");
    if (deny != NULL && deny[0] != '\0' && web_auth_ip_in_list(deny, ip))
    {
        TRACE_DEBUG("Web UI: %s is a blocked network\r\n", ip);
        *error = send_message(connection, 403, "forbidden", "Access denied");
        return true;
    }
    if (!lan && !settings_get_bool("web_auth.remote_access"))
    {
        const char *allow = settings_get_string("web_auth.allow_networks");
        if (allow == NULL || !web_auth_ip_in_list(allow, ip))
        {
            TRACE_DEBUG("Web UI: %s is outside the local networks\r\n", ip);
            *error = send_message(connection, 403, "forbidden", "Access denied");
            return true;
        }
    }
    if (!lan && settings_get_bool("web_auth.remote_https_only") && !web_auth_request_secure(connection))
    {
        *error = send_message(connection, 403, "https_required", "HTTPS required");
        return true;
    }
    if (!web_auth_requires_login())
    {
        return false;
    }
    if (!osStrcasecmp(connection->request.method, "OPTIONS"))
    {
        /* CORS preflight, answered without content */
        return false;
    }
    if (cross_site_request(connection, uri))
    {
        TRACE_WARNING("Web UI: cross-site request to %s from %s rejected (Origin '%s', Sec-Fetch-Site '%s')\r\n", uri, ip,
                      connection->request.origin, connection->request.secFetchSite);
        *error = send_message(connection, 403, "cross_site", "Cross-site request rejected");
        return true;
    }
    if (web_auth_is_public_request(uri, connection->request.method))
    {
        return false;
    }
    session_info_t info = current_session(connection, true);
    if (!info.found)
    {
        *error = web_auth_unauthorized(connection);
        return true;
    }
    if (info.restricted && !in_list(restricted_api, uri))
    {
        *error = send_message(connection, 403, "2fa_setup_required", "Set up two-factor authentication first");
        return true;
    }
    if (sensitive_settings_uri(uri) && !recently_confirmed(&info))
    {
        *error = send_message(connection, 403, "reauth_required", "Confirm with your password");
        return true;
    }
    lock_auth();
    web_user_t *user = find_user_unlocked(info.username);
    bool must_change_pw = user != NULL && user->must_change_pw;
    if (user != NULL)
    {
        connection->private.web_user_known = TRUE;
        connection->private.web_level = (uint8_t)user->level;
        copy_str(connection->private.web_user, sizeof(connection->private.web_user), user->username);
    }
    unlock_auth();
    if (user == NULL)
    {
        /* deleted meanwhile: without a user every check would let it through */
        *error = web_auth_unauthorized(connection);
        return true;
    }
    if (must_change_pw && !in_list(password_change_api, uri))
    {
        *error = send_message(connection, 403, "password_change_required", "Change your password first");
        return true;
    }
    if (!info.restricted && !web_acl_request_allowed(connection, uri, connection->request.queryString))
    {
        *error = send_message(connection, 403, "forbidden", "You may not do this");
        return true;
    }
    return false;
}

bool web_auth_user_info(const char *username, int *level, char *deny, size_t deny_size, char *created_by, size_t created_by_size,
                        char *group, size_t group_size)
{
    lock_auth();
    web_user_t *user = find_user_unlocked(username);
    if (user != NULL)
    {
        if (level)
        {
            *level = (int)user->level;
        }
        if (deny)
        {
            copy_str(deny, deny_size, user->deny);
        }
        if (created_by)
        {
            copy_str(created_by, created_by_size, user->created_by);
        }
        if (group)
        {
            copy_str(group, group_size, user->group);
        }
    }
    unlock_auth();
    return user != NULL;
}

int web_auth_user_names(char names[][33], int max)
{
    lock_auth();
    int n = 0;
    for (int i = 0; i < user_count && n < max; i++)
    {
        copy_str(names[n++], 33, users[i].username);
    }
    unlock_auth();
    return n;
}

/* ---------- endpoint helpers ---------- */

/* the logged-in user; with login disabled there is none */
static bool session_user(HttpConnection *connection, session_info_t *info)
{
    *info = current_session(connection, false);
    return info->found;
}

static void user_agent_of(HttpConnection *connection, char *out, size_t out_size)
{
    copy_str(out, out_size, connection->request.userAgent);
    for (char *p = out; *p; p++)
    {
        if ((unsigned char)*p < 0x20 || *p == '"' || *p == '\\')
        {
            *p = ' ';
        }
    }
}

/*
 * Checks the password of the logged-in user again with the cost of a real login.
 * A wrong one counts like a failed login, so a stolen session can not be used to guess it.
 * False also if busy or locked.
 */
static bool check_password(HttpConnection *connection, const char *username, const char *password, bool *busy)
{
    char stored[WEB_AUTH_HASH_MAX];
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    bool lan = ip_is_lan(ip);
    *busy = false;
    lock_auth();
    web_user_t *user = find_user_unlocked(username);
    copy_str(stored, sizeof(stored), user != NULL ? user->hash : dummy_hash);
    time_t locked = login_locked_for_unlocked(ip, lan);
    unlock_auth();
    if (locked > 0)
    {
        *busy = true;
        return false;
    }
    if (hash_slot_acquire(ip) != HASH_SLOT_OK)
    {
        *busy = true;
        return false;
    }
    bool ok = web_auth_pw_verify(stored, password, NULL);
    hash_slot_release(ip);
    if (!ok)
    {
        lock_auth();
        login_register_failure_unlocked(ip, find_user_unlocked(username), lan, username, "wrong password for a confirmation");
        unlock_auth();
    }
    return ok && user != NULL;
}

static bool user_totp_key_unlocked(const web_user_t *user, uint8_t key[WEB_AUTH_TOTP_KEY_BYTES])
{
    if (!user_has_totp(user) || !load_seal_key_unlocked())
    {
        return false;
    }
    return web_auth_unseal(seal_key, user->username, user->totp_sealed, key, WEB_AUTH_TOTP_KEY_BYTES) == WEB_AUTH_TOTP_KEY_BYTES;
}

/* "abcde-fghij" -> "ABCDEFGHIJ" for hashing */
static bool normalize_recovery(const char *code, char *out, size_t out_size)
{
    size_t o = 0;
    for (const char *p = code; *p; p++)
    {
        if (*p == '-' || *p == ' ')
        {
            continue;
        }
        if (!isalnum((unsigned char)*p) || o + 1 >= out_size)
        {
            return false;
        }
        out[o++] = (char)toupper((unsigned char)*p);
    }
    out[o] = '\0';
    return o > 0;
}

static void recovery_hash(const char *username, const char *normalized, char *out, size_t out_size)
{
    char buf[USERNAME_MAX + RECOVERY_CODE_MAX + 2];
    osSnprintf(buf, sizeof(buf), "%s:%s", username, normalized);
    for (char *p = buf; *p && *p != ':'; p++)
    {
        *p = (char)tolower((unsigned char)*p);
    }
    web_auth_sha256_hex(buf, osStrlen(buf), out, out_size);
    wipe(buf, sizeof(buf));
}

/* uses up a matching recovery code */
static bool use_recovery_code_unlocked(web_user_t *user, const char *code)
{
    char normalized[RECOVERY_CODE_MAX];
    char hash[HASH_HEX];
    bool found = false;
    if (!normalize_recovery(code, normalized, sizeof(normalized)))
    {
        return false;
    }
    recovery_hash(user->username, normalized, hash, sizeof(hash));
    for (int i = 0; i < RECOVERY_CODES; i++)
    {
        if (user->recovery[i][0] != '\0' && web_auth_const_equal_str(user->recovery[i], hash) && !found)
        {
            user->recovery[i][0] = '\0';
            found = true;
        }
    }
    return found;
}

/* new recovery codes, the plain codes go into the array for the one-time display */
static bool new_recovery_codes_unlocked(web_user_t *user, cJSON *out)
{
    for (int i = 0; i < RECOVERY_CODES; i++)
    {
        uint8_t raw[RECOVERY_CODE_BYTES];
        char b32[RECOVERY_CODE_MAX];
        char shown[RECOVERY_CODE_MAX];
        if (!random_bytes(raw, sizeof(raw)))
        {
            return false;
        }
        web_auth_base32_encode(raw, sizeof(raw), b32, sizeof(b32));
        b32[10] = '\0';
        osSnprintf(shown, sizeof(shown), "%.5s-%.5s", b32, b32 + 5);
        recovery_hash(user->username, b32, user->recovery[i], HASH_HEX);
        cJSON_AddItemToArray(out, cJSON_CreateString(shown));
        wipe(raw, sizeof(raw));
        wipe(b32, sizeof(b32));
    }
    return true;
}

static cJSON *user_json(const web_user_t *u)
{
    cJSON *entry = cJSON_CreateObject();
    cJSON_AddStringToObject(entry, "username", u->username);
    cJSON_AddStringToObject(entry, "level", acl_level_name(u->level));
    cJSON_AddStringToObject(entry, "group", u->group);
    cJSON_AddStringToObject(entry, "deny", u->deny);
    cJSON_AddStringToObject(entry, "createdBy", u->created_by);
    cJSON_AddBoolToObject(entry, "twoFactor", user_has_totp(u));
    cJSON_AddBoolToObject(entry, "require2fa", u->require_2fa);
    cJSON_AddBoolToObject(entry, "mustChangePassword", u->must_change_pw);
    cJSON_AddBoolToObject(entry, "lanOnly", u->lan_only);
    cJSON_AddNumberToObject(entry, "recoveryCodesLeft", recovery_left(u));
    cJSON_AddNumberToObject(entry, "created", (double)u->created);
    cJSON_AddNumberToObject(entry, "passwordChanged", (double)u->pw_changed);
    cJSON_AddNumberToObject(entry, "lastLogin", (double)u->last_login);
    cJSON_AddBoolToObject(entry, "legacyHash", !osStrncmp(u->hash, "sha256$", 7));
    return entry;
}

/* finishes a login: session, cookie, response */
static error_t complete_login(HttpConnection *connection, const char *username, const char *ip, bool restricted, bool want_token, cJSON *extra)
{
    char token[WEB_BEARER_TOKEN_MAX + 1];
    char ua[USER_AGENT_MAX + 1];
    user_agent_of(connection, ua, sizeof(ua));
    lock_auth();
    bool ok = create_session_unlocked(username, ip, ua, restricted, token, sizeof(token));
    web_user_t *user = find_user_unlocked(username);
    if (ok && user != NULL && !restricted)
    {
        user->last_login = time(NULL);
        save_users_unlocked();
    }
    add_event_unlocked(restricted ? "login_2fa_setup" : "login", username, ip, NULL);
    unlock_auth();
    if (!ok)
    {
        if (extra)
        {
            cJSON_Delete(extra);
        }
        return send_message(connection, 500, "session_failed", "Could not create a session");
    }
    TRACE_INFO("Web UI login of user '%s' from %s%s\r\n", username, ip, restricted ? " (2FA setup required)" : "");
    cJSON *json = extra ? extra : cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddStringToObject(json, "username", username);
    /* page scripts can read the body; only a client that can not use the cookie asks for the token */
    if (want_token)
    {
        cJSON_AddStringToObject(json, "token", token);
    }
    cJSON_AddBoolToObject(json, "twoFactorSetupRequired", restricted);
    error_t err = send_json_status(connection, 200, json, token, false);
    wipe(token, sizeof(token));
    return err;
}

static error_t rate_limited(HttpConnection *connection, time_t retry)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "error", "rate_limited");
    cJSON_AddStringToObject(json, "message", "Too many login attempts, try again later");
    cJSON_AddNumberToObject(json, "retryAfter", (double)retry);
    return send_json_status(connection, 429, json, NULL, false);
}

/* settings that change the protection itself */
static const char *const sensitive_settings[] = {
    "web_auth.",
    "frontend.web_auth",
    "core.server_cert.",
    "core.allowOrigin",
    "core.boxCertAuth",
    "security_mit.",
    NULL};

static bool sensitive_settings_uri(const char_t *uri)
{
    static const char *const prefixes[] = {"/api/settings/set/", "/api/settings/reset/", NULL};
    for (int p = 0; prefixes[p] != NULL; p++)
    {
        size_t len = osStrlen(prefixes[p]);
        if (osStrncmp(uri, prefixes[p], len) != 0)
        {
            continue;
        }
        for (int i = 0; sensitive_settings[i] != NULL; i++)
        {
            if (!osStrncasecmp(uri + len, sensitive_settings[i], osStrlen(sensitive_settings[i])))
            {
                return true;
            }
        }
    }
    return false;
}

static bool recently_confirmed(const session_info_t *info)
{
    return info->found && info->confirmed + CONFIRM_TTL_SECONDS > time(NULL);
}

/*
 * Sensitive changes need the password (and a 2FA code) again when the last
 * confirmation is older than CONFIRM_TTL_SECONDS, so a stolen session alone can not
 * take over accounts or switch the protection off. Without login there is nothing to confirm.
 */
static bool require_confirmation(HttpConnection *connection, error_t *err)
{
    if (!web_auth_requires_login())
    {
        return true;
    }
    session_info_t info = current_session(connection, false);
    if (recently_confirmed(&info))
    {
        return true;
    }
    *err = send_message(connection, 403, "reauth_required", "Confirm with your password");
    return false;
}

/* ---------- who may manage whom ---------- */

/* the user of the request; NULL without login (then everyone may do everything, as before) */
static web_user_t *actor_unlocked(HttpConnection *connection)
{
    if (!connection->private.web_user_known)
    {
        return NULL;
    }
    return find_user_unlocked(connection->private.web_user);
}

static int admin_count_unlocked(void)
{
    int n = 0;
    for (int i = 0; i < user_count; i++)
    {
        n += users[i].level == ACL_LEVEL_ADMIN;
    }
    return n;
}

/* admins manage everyone; others the users they created, of the same or a lower level */
static bool may_manage_unlocked(HttpConnection *connection, const web_user_t *target, bool can_manage)
{
    web_user_t *actor = actor_unlocked(connection);
    if (!connection->private.web_user_known)
    {
        return true;
    }
    if (actor == NULL)
    {
        return false;
    }
    if (actor->level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    return target != actor && osStrcasecmp(target->created_by, actor->username) == 0 &&
           acl_may_manage_level(actor->level, target->level) && can_manage;
}

static bool is_admin_unlocked(HttpConnection *connection)
{
    web_user_t *actor = actor_unlocked(connection);
    return !connection->private.web_user_known || (actor != NULL && actor->level == ACL_LEVEL_ADMIN);
}

/* ---------- login ---------- */

error_t handleApiAuthStatus(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    session_info_t info = current_session(connection, false);
    bool env = web_auth_env_override();
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    lock_auth();
    int count = user_count;
    web_user_t *user = info.found ? find_user_unlocked(info.username) : NULL;
    bool totp = user != NULL && user_has_totp(user);
    bool required = user != NULL && two_factor_required(user);
    bool must_change_pw = user != NULL && user->must_change_pw;
    int left = user != NULL ? recovery_left(user) : 0;
    unlock_auth();
    bool enabled = !env && settings_get_bool("frontend.web_auth_enabled") && count > 0;
    bool logged_in = enabled && info.found && !info.restricted;

    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "enabled", enabled);
    cJSON_AddBoolToObject(json, "loggedIn", logged_in);
    cJSON_AddStringToObject(json, "username", enabled && info.found ? info.username : "");
    cJSON_AddBoolToObject(json, "envOverride", env);
    cJSON_AddNumberToObject(json, "userCount", count);
    cJSON_AddBoolToObject(json, "twoFactorSetupRequired", enabled && info.found && info.restricted);
    cJSON_AddBoolToObject(json, "passwordChangeRequired", logged_in && must_change_pw);
    cJSON_AddBoolToObject(json, "twoFactorEnabled", totp);
    cJSON_AddBoolToObject(json, "twoFactorRequired", required);
    cJSON_AddNumberToObject(json, "recoveryCodesLeft", left);
    cJSON_AddNumberToObject(json, "passwordMinLength", settings_get_unsigned("web_auth.password_min_length"));
    /* lets the admin check a proxy setup; only shown to logged-in users or without login */
    if (!enabled || logged_in)
    {
        cJSON *client = cJSON_AddObjectToObject(json, "client");
        cJSON_AddStringToObject(client, "ip", ip);
        cJSON_AddBoolToObject(client, "lan", ip_is_lan(ip));
        cJSON_AddBoolToObject(client, "secure", web_auth_request_secure(connection));
        cJSON_AddBoolToObject(client, "viaTrustedProxy", peer_is_trusted_proxy(connection));
        cJSON_AddBoolToObject(client, "forwardedForIgnored", forwarding_ignored(connection));
    }
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthLogin(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid login payload");
    }
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];
    bool have = json_string(body, "username", username, sizeof(username)) && json_string(body, "password", password, sizeof(password));
    bool want_token = json_bool(body, "wantToken", false);
    delete_body(body);
    if (!have)
    {
        wipe(password, sizeof(password));
        return send_message(connection, 400, "invalid_body", "Username and password required");
    }

    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    bool lan = ip_is_lan(ip);
    time_t now = time(NULL);

    char stored[WEB_AUTH_HASH_MAX];
    lock_auth();
    time_t locked = login_locked_for_unlocked(ip, lan);
    web_user_t *user = find_user_unlocked(username);
    copy_str(stored, sizeof(stored), user != NULL ? user->hash : dummy_hash);
    unlock_auth();
    if (locked > 0)
    {
        wipe(password, sizeof(password));
        return rate_limited(connection, locked);
    }
    hash_slot_t slot = hash_slot_acquire(ip);
    if (slot != HASH_SLOT_OK)
    {
        wipe(password, sizeof(password));
        return slot == HASH_SLOT_SAME_ADDRESS ? rate_limited(connection, 1) : send_message(connection, 503, "busy", "Too many logins at once, try again");
    }
    bool rehash = false;
    bool ok = web_auth_pw_verify(stored, password, &rehash);
    char new_hash[WEB_AUTH_HASH_MAX];
    new_hash[0] = '\0';
    if (ok && rehash && !make_password_hash(password, new_hash, sizeof(new_hash)))
    {
        new_hash[0] = '\0';
    }
    hash_slot_release(ip);
    wipe(password, sizeof(password));

    char challenge[TOKEN_HEX];
    challenge[0] = '\0';
    bool restricted = false;
    bool needs_challenge = false;
    char canonical[USERNAME_MAX + 1];
    const char *reason = NULL;

    lock_auth();
    /* the user may have been deleted or changed while hashing */
    user = find_user_unlocked(username);
    if (user == NULL)
    {
        reason = "unknown user";
    }
    else if (!ok || osStrcmp(stored, user->hash) != 0)
    {
        reason = "wrong password";
    }
    else if (user->lan_only && !lan)
    {
        reason = "user may log in from local networks only";
    }
    else if (!lan && user->remote_locked_until > now)
    {
        reason = "account locked for logins from outside";
    }
    if (reason != NULL)
    {
        login_register_failure_unlocked(ip, user, lan, username, reason);
        unlock_auth();
        wipe(new_hash, sizeof(new_hash));
        return send_message(connection, 401, "unauthorized", "Invalid username or password");
    }
    /* with 2FA the failures are forgiven only after the second factor, so codes can not be guessed endlessly */
    if (!user_has_totp(user))
    {
        login_register_success_unlocked(ip, user);
    }
    copy_str(canonical, sizeof(canonical), user->username);
    if (new_hash[0] != '\0')
    {
        copy_str(user->hash, sizeof(user->hash), new_hash);
        save_users_unlocked();
        TRACE_INFO("Web UI auth: password hash of user '%s' upgraded\r\n", user->username);
    }
    if (user_has_totp(user))
    {
        needs_challenge = true;
        purge_sessions_unlocked();
        int slot = -1;
        for (int i = 0; i < MAX_CHALLENGES; i++)
        {
            if (!challenges[i].used)
            {
                slot = i;
                break;
            }
            if (slot < 0 || challenges[i].expires < challenges[slot].expires)
            {
                slot = i;
            }
        }
        login_challenge_t *c = &challenges[slot];
        osMemset(c, 0, sizeof(*c));
        if (random_token(challenge, sizeof(challenge)))
        {
            token_hash(challenge, c->token_hash, sizeof(c->token_hash));
            copy_str(c->username, sizeof(c->username), user->username);
            copy_str(c->ip, sizeof(c->ip), ip);
            c->expires = now + CHALLENGE_TTL_SECONDS;
            c->used = true;
        }
        else
        {
            challenge[0] = '\0';
        }
    }
    else if (two_factor_required(user))
    {
        restricted = true;
    }
    unlock_auth();
    wipe(new_hash, sizeof(new_hash));

    if (needs_challenge)
    {
        if (challenge[0] == '\0')
        {
            return send_message(connection, 500, "session_failed", "Could not create a session");
        }
        cJSON *json = cJSON_CreateObject();
        cJSON_AddBoolToObject(json, "ok", false);
        cJSON_AddBoolToObject(json, "twoFactorRequired", true);
        cJSON_AddStringToObject(json, "challenge", challenge);
        cJSON *methods = cJSON_AddArrayToObject(json, "methods");
        cJSON_AddItemToArray(methods, cJSON_CreateString("totp"));
        cJSON_AddItemToArray(methods, cJSON_CreateString("recovery"));
        wipe(challenge, sizeof(challenge));
        return send_json_status(connection, 200, json, NULL, false);
    }
    return complete_login(connection, canonical, ip, restricted, want_token, NULL);
}

error_t handleApiAuthLogin2fa(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid payload");
    }
    char challenge[TOKEN_HEX];
    char code[RECOVERY_CODE_MAX];
    char recovery[RECOVERY_CODE_MAX];
    bool have_challenge = json_string(body, "challenge", challenge, sizeof(challenge));
    bool have_code = json_string(body, "code", code, sizeof(code));
    bool have_recovery = json_string(body, "recoveryCode", recovery, sizeof(recovery));
    bool want_token = json_bool(body, "wantToken", false);
    delete_body(body);
    if (!have_challenge || (!have_code && !have_recovery))
    {
        return send_message(connection, 400, "invalid_body", "Challenge and code required");
    }
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    bool lan = ip_is_lan(ip);
    char hash[HASH_HEX];
    token_hash(challenge, hash, sizeof(hash));
    wipe(challenge, sizeof(challenge));

    lock_auth();
    time_t locked = login_locked_for_unlocked(ip, lan);
    if (locked > 0)
    {
        unlock_auth();
        return rate_limited(connection, locked);
    }
    purge_sessions_unlocked();
    login_challenge_t *c = NULL;
    for (int i = 0; i < MAX_CHALLENGES; i++)
    {
        if (challenges[i].used && web_auth_const_equal_str(challenges[i].token_hash, hash))
        {
            c = &challenges[i];
        }
    }
    web_user_t *user = c != NULL ? find_user_unlocked(c->username) : NULL;
    if (c == NULL || user == NULL || osStrcmp(c->ip, ip) != 0)
    {
        login_register_failure_unlocked(ip, NULL, lan, c != NULL ? c->username : "", "invalid or expired 2FA challenge");
        unlock_auth();
        return send_message(connection, 401, "challenge_invalid", "Login expired, please log in again");
    }
    time_t now = time(NULL);
    if (!lan && user->tfa_locked_until > now)
    {
        time_t retry = user->tfa_locked_until - now;
        unlock_auth();
        return rate_limited(connection, retry);
    }
    bool ok = false;
    bool used_recovery = false;
    if (have_code)
    {
        uint8_t key[WEB_AUTH_TOTP_KEY_BYTES];
        if (user_totp_key_unlocked(user, key))
        {
            int64_t step = web_auth_totp_match(key, sizeof(key), code, time(NULL), TOTP_WINDOW, user->totp_last_step);
            if (step >= 0)
            {
                /* a code works only once, also within its 30 seconds */
                user->totp_last_step = step;
                ok = true;
            }
        }
        wipe(key, sizeof(key));
    }
    else if (use_recovery_code_unlocked(user, recovery))
    {
        ok = true;
        used_recovery = true;
    }
    wipe(code, sizeof(code));
    wipe(recovery, sizeof(recovery));
    if (!ok)
    {
        c->attempts++;
        if (c->attempts >= CHALLENGE_ATTEMPTS)
        {
            osMemset(c, 0, sizeof(*c));
        }
        login_register_failure_unlocked(ip, user, lan, user->username, have_code ? "wrong 2FA code" : "wrong recovery code");
        /* the password is known to whoever gets here: wrong codes count per account, from any address outside */
        if (!lan)
        {
            if (user->tfa_locked_until != 0 && user->tfa_locked_until <= now)
            {
                user->tfa_failures = 0;
                user->tfa_locked_until = 0;
            }
            if ((uint32_t)++user->tfa_failures >= settings_get_unsigned("web_auth.lockout_attempts") * ACCOUNT_FAIL_FACTOR)
            {
                user->tfa_locked_until = now + lock_duration(1);
                user->tfa_failures = 0;
                TRACE_WARNING("Web UI 2FA of user '%s' locked for logins from outside after wrong codes\r\n", user->username);
                add_event_unlocked("account_locked", user->username, ip, "too many wrong 2FA codes");
            }
        }
        unlock_auth();
        return send_message(connection, 401, "invalid_code", "Invalid code");
    }
    char username[USERNAME_MAX + 1];
    copy_str(username, sizeof(username), user->username);
    osMemset(c, 0, sizeof(*c));
    login_register_success_unlocked(ip, user);
    user->tfa_failures = 0;
    int left = recovery_left(user);
    save_users_unlocked();
    if (used_recovery)
    {
        add_event_unlocked("recovery_code_used", username, ip, NULL);
        TRACE_WARNING("Web UI login of user '%s' with a recovery code, %d left\r\n", username, left);
    }
    unlock_auth();
    cJSON *extra = cJSON_CreateObject();
    cJSON_AddNumberToObject(extra, "recoveryCodesLeft", left);
    return complete_login(connection, username, ip, false, want_token, extra);
}

error_t handleApiAuthLogout(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    session_info_t info = current_session(connection, false);
    if (info.found)
    {
        lock_auth();
        web_session_t *s = find_session_unlocked(info.token_hash);
        if (s != NULL)
        {
            bool persisted = !s->restricted;
            osMemset(s, 0, sizeof(*s));
            if (persisted)
            {
                save_sessions_unlocked();
            }
        }
        unlock_auth();
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    return send_json_status(connection, 200, json, NULL, true);
}

error_t handleApiAuthRefreshToken(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    char username[USERNAME_MAX + 1];
    if (!web_auth_is_authenticated(connection, username, sizeof(username)))
    {
        return send_message(connection, 401, "unauthorized", "Login required");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddStringToObject(json, "username", username);
    return send_json_status(connection, 200, json, NULL, false);
}

/* ---------- two-factor authentication of the own account ---------- */

error_t handleApiAuth2faSetup(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    session_info_t info;
    if (!session_user(connection, &info))
    {
        return send_message(connection, 400, "login_disabled", "Two-factor authentication needs a login");
    }
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid payload");
    }
    char password[PASSWORD_MAX + 1];
    bool have = json_string(body, "password", password, sizeof(password));
    delete_body(body);
    if (!have)
    {
        return send_message(connection, 400, "invalid_body", "Password required");
    }
    bool busy;
    bool ok = check_password(connection, info.username, password, &busy);
    wipe(password, sizeof(password));
    if (busy)
    {
        return send_message(connection, 503, "busy", "Try again");
    }
    if (!ok)
    {
        return send_message(connection, 403, "wrong_password", "Wrong password");
    }
    uint8_t key[WEB_AUTH_TOTP_KEY_BYTES];
    char secret[64];
    if (!random_bytes(key, sizeof(key)))
    {
        return send_message(connection, 500, "failed", "No random numbers available");
    }
    lock_auth();
    web_user_t *user = find_user_unlocked(info.username);
    if (user == NULL || user_has_totp(user))
    {
        unlock_auth();
        wipe(key, sizeof(key));
        return send_message(connection, 409, "already_enabled", "Two-factor authentication is already set up");
    }
    if (!load_seal_key_unlocked())
    {
        unlock_auth();
        wipe(key, sizeof(key));
        return send_message(connection, 500, "failed", "Could not create the key file for 2FA secrets");
    }
    /* a setup that is still open keeps its key: it may already be in the authenticator app */
    if (user->pending_until > time(NULL))
    {
        osMemcpy(key, user->pending_totp, sizeof(key));
    }
    else
    {
        osMemcpy(user->pending_totp, key, sizeof(key));
    }
    user->pending_until = time(NULL) + TOTP_SETUP_TTL_SECONDS;
    char username[USERNAME_MAX + 1];
    copy_str(username, sizeof(username), user->username);
    unlock_auth();
    web_auth_base32_encode(key, sizeof(key), secret, sizeof(secret));
    wipe(key, sizeof(key));

    char *otpauth = custom_asprintf("otpauth://totp/TeddyCloud:%s?secret=%s&issuer=TeddyCloud&algorithm=SHA1&digits=%d&period=%d",
                                    username, secret, WEB_AUTH_TOTP_DIGITS, WEB_AUTH_TOTP_PERIOD);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddStringToObject(json, "secret", secret);
    cJSON_AddStringToObject(json, "otpauthUri", otpauth ? otpauth : "");
    cJSON_AddNumberToObject(json, "expiresIn", TOTP_SETUP_TTL_SECONDS);
    if (otpauth)
    {
        osFreeMem(otpauth);
    }
    wipe(secret, sizeof(secret));
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuth2faEnable(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    session_info_t info;
    if (!session_user(connection, &info))
    {
        return send_message(connection, 400, "login_disabled", "Two-factor authentication needs a login");
    }
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid payload");
    }
    char code[RECOVERY_CODE_MAX];
    bool have = json_string(body, "code", code, sizeof(code));
    delete_body(body);
    if (!have)
    {
        return send_message(connection, 400, "invalid_body", "Code required");
    }
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    lock_auth();
    web_user_t *user = find_user_unlocked(info.username);
    if (user == NULL || user_has_totp(user) || user->pending_until <= time(NULL))
    {
        unlock_auth();
        return send_message(connection, 409, "no_setup", "Start the setup again");
    }
    int64_t step = web_auth_totp_match(user->pending_totp, sizeof(user->pending_totp), code, time(NULL), TOTP_WINDOW, -1);
    if (step < 0)
    {
        unlock_auth();
        return send_message(connection, 400, "invalid_code", "Invalid code, check the time of the device");
    }
    uint8_t iv[WEB_AUTH_SEAL_IV_BYTES];
    cJSON *codes = cJSON_CreateArray();
    char sealed[TOTP_SEALED_MAX];
    bool ok = random_bytes(iv, sizeof(iv)) && load_seal_key_unlocked() &&
              web_auth_seal(seal_key, iv, user->username, user->pending_totp, sizeof(user->pending_totp), sealed, sizeof(sealed));
    web_user_t backup = *user;
    if (ok)
    {
        copy_str(user->totp_sealed, sizeof(user->totp_sealed), sealed);
        user->totp_last_step = step;
        ok = new_recovery_codes_unlocked(user, codes) && save_users_unlocked();
    }
    if (!ok)
    {
        *user = backup;
        unlock_auth();
        cJSON_Delete(codes);
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    wipe(user->pending_totp, sizeof(user->pending_totp));
    user->pending_until = 0;
    /* other logins of the account did not pass the second factor */
    revoke_user_sessions_unlocked(user->username, info.token_hash);
    web_session_t *s = find_session_unlocked(info.token_hash);
    if (s != NULL && s->restricted)
    {
        s->restricted = false;
        s->created = time(NULL);
        s->confirmed = s->created;
        save_sessions_unlocked();
    }
    add_event_unlocked("2fa_enabled", user->username, ip, NULL);
    unlock_auth();
    wipe(&backup, sizeof(backup));
    TRACE_INFO("Web UI auth: user '%s' set up two-factor authentication\r\n", info.username);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddItemToObject(json, "recoveryCodes", codes);
    return send_json_status(connection, 200, json, NULL, false);
}

/* password and a current code or recovery code of the logged-in user */
static bool confirm_identity(HttpConnection *connection, const session_info_t *info, cJSON *body, error_t *err)
{
    char password[PASSWORD_MAX + 1];
    char code[RECOVERY_CODE_MAX];
    if (!json_string(body, "password", password, sizeof(password)))
    {
        *err = send_message(connection, 400, "invalid_body", "Password required");
        return false;
    }
    bool busy;
    bool ok = check_password(connection, info->username, password, &busy);
    wipe(password, sizeof(password));
    if (busy)
    {
        *err = send_message(connection, 503, "busy", "Try again");
        return false;
    }
    if (!ok)
    {
        *err = send_message(connection, 403, "wrong_password", "Wrong password");
        return false;
    }
    lock_auth();
    web_user_t *user = find_user_unlocked(info->username);
    /* without 2FA the password is all there is to confirm */
    ok = user != NULL && !user_has_totp(user);
    if (user != NULL && user_has_totp(user))
    {
        if (json_string(body, "code", code, sizeof(code)))
        {
            uint8_t key[WEB_AUTH_TOTP_KEY_BYTES];
            if (user_totp_key_unlocked(user, key))
            {
                int64_t step = web_auth_totp_match(key, sizeof(key), code, time(NULL), TOTP_WINDOW, user->totp_last_step);
                if (step >= 0)
                {
                    user->totp_last_step = step;
                    ok = true;
                }
            }
            wipe(key, sizeof(key));
        }
        else if (json_string(body, "recoveryCode", code, sizeof(code)))
        {
            ok = use_recovery_code_unlocked(user, code);
        }
        wipe(code, sizeof(code));
    }
    unlock_auth();
    if (!ok)
    {
        *err = send_message(connection, 403, "invalid_code", "Invalid code");
    }
    return ok;
}

error_t handleApiAuth2faDisable(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    session_info_t info;
    if (!session_user(connection, &info) || info.restricted)
    {
        return send_message(connection, 400, "login_disabled", "Two-factor authentication needs a login");
    }
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid payload");
    }
    lock_auth();
    web_user_t *user = find_user_unlocked(info.username);
    bool required = user != NULL && two_factor_required(user);
    unlock_auth();
    if (required)
    {
        delete_body(body);
        return send_message(connection, 403, "2fa_required", "Two-factor authentication is required for this account");
    }
    error_t err = NO_ERROR;
    bool ok = confirm_identity(connection, &info, body, &err);
    delete_body(body);
    if (!ok)
    {
        return err;
    }
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    lock_auth();
    user = find_user_unlocked(info.username);
    if (user != NULL)
    {
        user->totp_sealed[0] = '\0';
        user->totp_last_step = -1;
        osMemset(user->recovery, 0, sizeof(user->recovery));
        save_users_unlocked();
        add_event_unlocked("2fa_disabled", user->username, ip, NULL);
    }
    unlock_auth();
    return send_ok(connection);
}

error_t handleApiAuth2faRecoveryCodes(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    session_info_t info;
    if (!session_user(connection, &info) || info.restricted)
    {
        return send_message(connection, 400, "login_disabled", "Two-factor authentication needs a login");
    }
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid payload");
    }
    error_t err = NO_ERROR;
    bool ok = confirm_identity(connection, &info, body, &err);
    delete_body(body);
    if (!ok)
    {
        return err;
    }
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    cJSON *codes = cJSON_CreateArray();
    lock_auth();
    web_user_t *user = find_user_unlocked(info.username);
    ok = user != NULL && new_recovery_codes_unlocked(user, codes) && save_users_unlocked();
    if (ok)
    {
        add_event_unlocked("recovery_codes_renewed", info.username, ip, NULL);
    }
    unlock_auth();
    if (!ok)
    {
        cJSON_Delete(codes);
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddItemToObject(json, "recoveryCodes", codes);
    return send_json_status(connection, 200, json, NULL, false);
}

/* ---------- user management ---------- */

error_t handleApiAuthUsersGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    /* asks the user data itself, so before lock_auth (the mutex is not recursive) */
    bool can_manage = web_acl_system_allowed(connection, "users.manage");
    (void)can_manage;
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    lock_auth();
    cJSON *json = cJSON_CreateObject();
    cJSON *names = cJSON_AddArrayToObject(json, "users");
    cJSON *details = cJSON_AddArrayToObject(json, "userDetails");
    web_user_t *actor = actor_unlocked(connection);
    for (int i = 0; i < user_count; i++)
    {
        /* others see themselves and the users they manage */
        if (connection->private.web_user_known && &users[i] != actor && !may_manage_unlocked(connection, &users[i], can_manage))
        {
            continue;
        }
        cJSON_AddItemToArray(names, cJSON_CreateString(users[i].username));
        cJSON_AddItemToArray(details, user_json(&users[i]));
    }
    cJSON_AddStringToObject(json, "level", actor != NULL ? acl_level_name(actor->level) : "admin");
    int count = user_count;
    unlock_auth();
    bool env = web_auth_env_override();
    cJSON_AddBoolToObject(json, "enabled", !env && settings_get_bool("frontend.web_auth_enabled") && count > 0);
    cJSON_AddBoolToObject(json, "envOverride", env);
    cJSON_AddBoolToObject(json, "require2faAll", settings_get_bool("web_auth.require_2fa"));
    cJSON_AddNumberToObject(json, "maxUsers", MAX_WEB_USERS);
    cJSON_AddNumberToObject(json, "passwordMinLength", settings_get_unsigned("web_auth.password_min_length"));
    return send_json_status(connection, 200, json, NULL, false);
}

static const char *password_message(const char *problem)
{
    if (!osStrcmp(problem, "password_too_short"))
        return "Password is too short";
    if (!osStrcmp(problem, "password_too_long"))
        return "Password is too long";
    if (!osStrcmp(problem, "password_is_username"))
        return "Password must not be the username";
    return "Password is too common";
}

error_t handleApiAuthUsersCreate(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    /* asks the user data itself, so before lock_auth (the mutex is not recursive) */
    bool can_manage = web_acl_system_allowed(connection, "users.manage");
    (void)can_manage;
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];
    bool have = json_string(body, "username", username, sizeof(username)) && json_string(body, "password", password, sizeof(password));
    bool lan_only = json_bool(body, "lanOnly", false);
    bool require_2fa = json_bool(body, "require2fa", false);
    bool must_change_pw = json_bool(body, "mustChangePassword", false);
    char level_name[16] = "";
    json_string(body, "level", level_name, sizeof(level_name));
    char group[WEB_ACL_GROUP_ID_MAX + 1] = "";
    json_string(body, "group", group, sizeof(group));
    delete_body(body);
    /* the group decides the level; asks the rights, so before lock_auth */
    int group_level = -1;
    if (group[0] != '\0')
    {
        web_acl_group_check_t check = web_acl_group_check(connection, group, &group_level);
        if (check != WEB_ACL_GROUP_OK)
        {
            wipe(password, sizeof(password));
            return check == WEB_ACL_GROUP_UNKNOWN ? send_message(connection, 400, "invalid_group", "Unknown group")
                                                  : send_message(connection, 403, "forbidden", "You may not give this group");
        }
    }
    error_t err = NO_ERROR;
    if (!require_confirmation(connection, &err))
    {
        wipe(password, sizeof(password));
        return err;
    }
    if (!have)
    {
        wipe(password, sizeof(password));
        return send_message(connection, 400, "invalid_body", "Username and password required");
    }
    if (!valid_username(username))
    {
        wipe(password, sizeof(password));
        return send_message(connection, 400, "invalid_user", "Invalid username (letters, digits, '.', '_' and '-')");
    }
    const char *problem = password_problem(username, password);
    if (problem != NULL)
    {
        wipe(password, sizeof(password));
        return send_message(connection, 400, problem, password_message(problem));
    }
    char hash[WEB_AUTH_HASH_MAX];
    char hash_ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, hash_ip, sizeof(hash_ip));
    if (hash_slot_acquire(hash_ip) != HASH_SLOT_OK)
    {
        wipe(password, sizeof(password));
        return send_message(connection, 503, "busy", "Try again");
    }
    bool hashed = make_password_hash(password, hash, sizeof(hash));
    hash_slot_release(hash_ip);
    wipe(password, sizeof(password));
    if (!hashed)
    {
        return send_message(connection, 500, "save_failed", "Could not hash the password");
    }
    session_info_t info = current_session(connection, false);
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    lock_auth();
    web_user_t *actor = actor_unlocked(connection);
    acl_level_t level;
    if (group_level >= 0)
    {
        level = (acl_level_t)group_level;
    }
    else if (level_name[0] != '\0')
    {
        if (!acl_level_parse(level_name, &level))
        {
            unlock_auth();
            return send_message(connection, 400, "invalid_level", "Unknown level");
        }
    }
    else
    {
        /* the first user, created without login, has to be an admin */
        level = actor == NULL ? ACL_LEVEL_ADMIN : (actor->level == ACL_LEVEL_GUEST ? ACL_LEVEL_GUEST : ACL_LEVEL_USER);
    }
    if (connection->private.web_user_known &&
        (actor == NULL || !acl_may_manage_level(actor->level, level) ||
         (actor->level != ACL_LEVEL_ADMIN && !can_manage)))
    {
        unlock_auth();
        return send_message(connection, 403, "forbidden", "You may not create users of this level");
    }
    if (find_user_unlocked(username) != NULL)
    {
        unlock_auth();
        return send_message(connection, 409, "exists", "User already exists");
    }
    if (user_count >= MAX_WEB_USERS)
    {
        unlock_auth();
        return send_message(connection, 400, "limit", "Maximum number of users reached");
    }
    web_user_t *u = &users[user_count];
    osMemset(u, 0, sizeof(*u));
    copy_str(u->username, sizeof(u->username), username);
    copy_str(u->hash, sizeof(u->hash), hash);
    u->lan_only = lan_only;
    u->require_2fa = require_2fa;
    u->must_change_pw = must_change_pw;
    u->level = level;
    copy_str(u->group, sizeof(u->group), group);
    copy_str(u->created_by, sizeof(u->created_by), actor != NULL ? actor->username : "");
    u->totp_last_step = -1;
    u->created = time(NULL);
    u->pw_changed = u->created;
    user_count++;
    bool ok = save_users_unlocked();
    if (!ok)
    {
        user_count--;
        osMemset(u, 0, sizeof(*u));
    }
    else
    {
        add_event_unlocked("user_created", username, ip, info.found ? info.username : NULL);
    }
    unlock_auth();
    if (!ok)
    {
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    web_acl_user_created(username);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddStringToObject(json, "username", username);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthUsersUpdate(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    /* asks the user data itself, so before lock_auth (the mutex is not recursive) */
    bool can_manage = web_acl_system_allowed(connection, "users.manage");
    (void)can_manage;
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char username[USERNAME_MAX + 1];
    if (!json_string(body, "username", username, sizeof(username)))
    {
        delete_body(body);
        return send_message(connection, 400, "invalid_body", "Username required");
    }
    cJSON *lan_only = cJSON_GetObjectItemCaseSensitive(body, "lanOnly");
    cJSON *require_2fa = cJSON_GetObjectItemCaseSensitive(body, "require2fa");
    cJSON *must_change_pw = cJSON_GetObjectItemCaseSensitive(body, "mustChangePassword");
    const char *new_level = json_str(body, "level");
    const char *new_group = json_str(body, "group");
    const char *new_deny = json_str(body, "deny");
    /* the group decides the level; asks the rights, so before lock_auth */
    int group_level = -1;
    if (new_group != NULL && new_group[0] != '\0')
    {
        web_acl_group_check_t check = osStrlen(new_group) > WEB_ACL_GROUP_ID_MAX ? WEB_ACL_GROUP_UNKNOWN
                                                                                 : web_acl_group_check(connection, new_group, &group_level);
        if (check != WEB_ACL_GROUP_OK)
        {
            delete_body(body);
            return check == WEB_ACL_GROUP_UNKNOWN ? send_message(connection, 400, "invalid_group", "Unknown group")
                                                  : send_message(connection, 403, "forbidden", "You may not give this group");
        }
        new_level = acl_level_name((acl_level_t)group_level);
    }
    bool reset_2fa = json_bool(body, "reset2fa", false);
    bool revoke = json_bool(body, "revokeSessions", false);
    error_t err = NO_ERROR;
    if (!require_confirmation(connection, &err))
    {
        delete_body(body);
        return err;
    }
    session_info_t info = current_session(connection, false);
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    lock_auth();
    web_user_t *user = find_user_unlocked(username);
    if (user == NULL)
    {
        unlock_auth();
        delete_body(body);
        return send_message(connection, 404, "not_found", "User not found");
    }
    if (!may_manage_unlocked(connection, user, can_manage))
    {
        unlock_auth();
        delete_body(body);
        return send_message(connection, 403, "forbidden", "You may not change this user");
    }
    if (new_level != NULL)
    {
        acl_level_t level;
        web_user_t *actor = actor_unlocked(connection);
        if (!acl_level_parse(new_level, &level) || (actor != NULL && !acl_may_manage_level(actor->level, level)))
        {
            unlock_auth();
            delete_body(body);
            return send_message(connection, 403, "forbidden", "You may not give this level");
        }
        if (user->level == ACL_LEVEL_ADMIN && level != ACL_LEVEL_ADMIN && admin_count_unlocked() <= 1)
        {
            unlock_auth();
            delete_body(body);
            return send_message(connection, 409, "last_admin", "At least one admin must remain");
        }
        user->level = level;
        /* a level without group is its built-in group */
        copy_str(user->group, sizeof(user->group), new_group != NULL ? new_group : "");
    }
    else if (new_group != NULL)
    {
        /* "": back to the built-in group of the level */
        user->group[0] = '\0';
    }
    if (new_deny != NULL)
    {
        char bad[64];
        if (!is_admin_unlocked(connection))
        {
            unlock_auth();
            delete_body(body);
            return send_message(connection, 403, "forbidden", "Only admins restrict users");
        }
        if (osStrlen(new_deny) >= sizeof(user->deny) || !acl_list_valid(new_deny, bad, sizeof(bad)))
        {
            unlock_auth();
            delete_body(body);
            return send_message(connection, 400, "invalid_rights", "Unknown right in the list");
        }
        copy_str(user->deny, sizeof(user->deny), new_deny);
    }
    if (cJSON_IsBool(lan_only))
    {
        user->lan_only = cJSON_IsTrue(lan_only);
    }
    if (cJSON_IsBool(require_2fa))
    {
        user->require_2fa = cJSON_IsTrue(require_2fa);
    }
    if (cJSON_IsBool(must_change_pw))
    {
        user->must_change_pw = cJSON_IsTrue(must_change_pw);
    }
    if (reset_2fa)
    {
        user->totp_sealed[0] = '\0';
        user->totp_last_step = -1;
        osMemset(user->recovery, 0, sizeof(user->recovery));
        add_event_unlocked("2fa_reset", user->username, ip, info.found ? info.username : NULL);
    }
    int revoked = 0;
    if (revoke || reset_2fa)
    {
        /* revoking the own sessions keeps the one in use */
        revoked = revoke_user_sessions_unlocked(user->username, info.found ? info.token_hash : NULL);
    }
    bool ok = save_users_unlocked();
    add_event_unlocked("user_updated", user->username, ip, info.found ? info.username : NULL);
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", ok);
    cJSON_AddNumberToObject(json, "sessionsRevoked", revoked);
    cJSON_AddItemToObject(json, "user", user_json(user));
    unlock_auth();
    delete_body(body);
    if (!ok)
    {
        cJSON_Delete(json);
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthUsersDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    /* asks the user data itself, so before lock_auth (the mutex is not recursive) */
    bool can_manage = web_acl_system_allowed(connection, "users.manage");
    (void)can_manage;
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char username[USERNAME_MAX + 1];
    bool have = json_string(body, "username", username, sizeof(username));
    delete_body(body);
    error_t err = NO_ERROR;
    if (!require_confirmation(connection, &err))
    {
        return err;
    }
    if (!have)
    {
        return send_message(connection, 400, "invalid_body", "Username required");
    }
    session_info_t info = current_session(connection, false);
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));

    bool auth_disabled = false;
    lock_auth();
    web_user_t *user = find_user_unlocked(username);
    if (user == NULL)
    {
        unlock_auth();
        return send_message(connection, 404, "not_found", "User not found");
    }
    if (!may_manage_unlocked(connection, user, can_manage))
    {
        unlock_auth();
        return send_message(connection, 403, "forbidden", "You may not delete this user");
    }
    if (user->level == ACL_LEVEL_ADMIN && admin_count_unlocked() <= 1 && user_count > 1)
    {
        unlock_auth();
        return send_message(connection, 409, "last_admin", "At least one admin must remain");
    }
    web_user_t removed = *user;
    int index = (int)(user - users);
    for (int i = index; i < user_count - 1; i++)
    {
        users[i] = users[i + 1];
    }
    user_count--;
    osMemset(&users[user_count], 0, sizeof(users[user_count]));
    if (!save_users_unlocked())
    {
        /* put the user back where it was */
        for (int i = user_count; i > index; i--)
        {
            users[i] = users[i - 1];
        }
        users[index] = removed;
        user_count++;
        unlock_auth();
        wipe(&removed, sizeof(removed));
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    revoke_user_sessions_unlocked(removed.username, NULL);
    add_event_unlocked("user_deleted", removed.username, ip, info.found ? info.username : NULL);
    char deleted_name[USERNAME_MAX + 1];
    copy_str(deleted_name, sizeof(deleted_name), removed.username);
    wipe(&removed, sizeof(removed));
    if (user_count == 0)
    {
        auth_disabled = true;
    }
    unlock_auth();
    web_acl_user_deleted(deleted_name);
    if (auth_disabled)
    {
        settings_set_bool("frontend.web_auth_enabled", false);
        settings_save();
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddBoolToObject(json, "authDisabled", auth_disabled);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthUsersPassword(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    /* asks the user data itself, so before lock_auth (the mutex is not recursive) */
    bool can_manage = web_acl_system_allowed(connection, "users.manage");
    (void)can_manage;
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char username[USERNAME_MAX + 1];
    char password[PASSWORD_MAX + 1];
    char current[PASSWORD_MAX + 1];
    bool have = json_string(body, "username", username, sizeof(username)) && json_string(body, "password", password, sizeof(password));
    bool have_current = json_string(body, "currentPassword", current, sizeof(current));
    bool must_change_pw = json_bool(body, "mustChangePassword", false);
    delete_body(body);
    if (!have)
    {
        wipe(password, sizeof(password));
        wipe(current, sizeof(current));
        return send_message(connection, 400, "invalid_body", "Username and password required");
    }
    session_info_t info = current_session(connection, false);
    bool own = info.found && osStrcasecmp(info.username, username) == 0;
    /* a stolen session alone must not be enough to take over the account */
    if (own)
    {
        bool busy = false;
        bool ok = have_current && check_password(connection, info.username, current, &busy);
        bool unchanged = ok && !osStrcmp(current, password);
        wipe(current, sizeof(current));
        if (busy || !ok)
        {
            wipe(password, sizeof(password));
            return busy ? send_message(connection, 503, "busy", "Try again") : send_message(connection, 403, "wrong_password", "Current password is wrong");
        }
        if (unchanged)
        {
            wipe(password, sizeof(password));
            return send_message(connection, 400, "password_unchanged", "The new password must differ from the current one");
        }
    }
    wipe(current, sizeof(current));
    error_t err = NO_ERROR;
    if (!own && !require_confirmation(connection, &err))
    {
        wipe(password, sizeof(password));
        return err;
    }
    const char *problem = password_problem(username, password);
    if (problem != NULL)
    {
        wipe(password, sizeof(password));
        return send_message(connection, 400, problem, password_message(problem));
    }
    char hash[WEB_AUTH_HASH_MAX];
    char hash_ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, hash_ip, sizeof(hash_ip));
    if (hash_slot_acquire(hash_ip) != HASH_SLOT_OK)
    {
        wipe(password, sizeof(password));
        return send_message(connection, 503, "busy", "Try again");
    }
    bool hashed = make_password_hash(password, hash, sizeof(hash));
    hash_slot_release(hash_ip);
    wipe(password, sizeof(password));
    if (!hashed)
    {
        return send_message(connection, 500, "save_failed", "Could not hash the password");
    }
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    lock_auth();
    web_user_t *user = find_user_unlocked(username);
    if (user == NULL)
    {
        unlock_auth();
        return send_message(connection, 404, "not_found", "User not found");
    }
    web_user_t *actor = actor_unlocked(connection);
    /* the gate lets a user who has to change the password through for the own one only */
    if (!own && (!may_manage_unlocked(connection, user, can_manage) || (actor != NULL && actor->must_change_pw)))
    {
        unlock_auth();
        return send_message(connection, 403, "forbidden", "You may not change this user");
    }
    char old_hash[WEB_AUTH_HASH_MAX];
    copy_str(old_hash, sizeof(old_hash), user->hash);
    time_t old_changed = user->pw_changed;
    bool old_must_change = user->must_change_pw;
    copy_str(user->hash, sizeof(user->hash), hash);
    user->pw_changed = time(NULL);
    /* the own change fulfils the demand; whoever sets another user's password decides anew */
    user->must_change_pw = !own && must_change_pw;
    bool ok = save_users_unlocked();
    int revoked = 0;
    if (!ok)
    {
        copy_str(user->hash, sizeof(user->hash), old_hash);
        user->pw_changed = old_changed;
        user->must_change_pw = old_must_change;
    }
    else
    {
        /* logins with the old password end, except the one that changed it */
        revoked = revoke_user_sessions_unlocked(user->username, own ? info.token_hash : NULL);
        add_event_unlocked("password_changed", user->username, ip, info.found ? info.username : NULL);
    }
    unlock_auth();
    wipe(old_hash, sizeof(old_hash));
    if (!ok)
    {
        return send_message(connection, 500, "save_failed", "Could not save users");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddNumberToObject(json, "sessionsRevoked", revoked);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthEnabled(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    cJSON *enabled_item = cJSON_GetObjectItemCaseSensitive(body, "enabled");
    if (!cJSON_IsBool(enabled_item))
    {
        cJSON_Delete(body);
        return send_message(connection, 400, "invalid_body", "enabled required");
    }
    bool enabled = cJSON_IsTrue(enabled_item);
    cJSON_Delete(body);
    error_t err = NO_ERROR;
    if (!enabled && !require_confirmation(connection, &err))
    {
        return err;
    }
    if (web_auth_env_override())
    {
        return send_message(connection, 400, "env_override", "Login protection is disabled by TEDDYCLOUD_WEB_AUTH_DISABLE");
    }
    lock_auth();
    int count = user_count;
    unlock_auth();
    if (enabled && count == 0)
    {
        return send_message(connection, 400, "no_users", "Create a user before enabling login protection");
    }
    if (!settings_set_bool("frontend.web_auth_enabled", enabled) || settings_save() != NO_ERROR)
    {
        return send_message(connection, 500, "save_failed", "Could not update login setting");
    }
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    lock_auth();
    add_event_unlocked(enabled ? "login_enabled" : "login_disabled", NULL, ip, NULL);
    unlock_auth();
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddBoolToObject(json, "enabled", enabled);
    return send_json_status(connection, 200, json, NULL, false);
}

/* ---------- sessions and events ---------- */

error_t handleApiAuthSessionsGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)client_ctx;
    char all_param[8] = {0};
    bool all = queryGet(queryString, "all", all_param, sizeof(all_param)) && (!osStrcmp(all_param, "1") || !osStrcmp(all_param, "true"));
    session_info_t info = current_session(connection, false);
    if (!info.found)
    {
        return send_message(connection, 400, "login_disabled", "Sessions need a login");
    }
    cJSON *json = cJSON_CreateObject();
    cJSON *array = cJSON_AddArrayToObject(json, "sessions");
    lock_auth();
    if (!is_admin_unlocked(connection))
    {
        all = false;
    }
    purge_sessions_unlocked();
    for (int i = 0; i < MAX_WEB_SESSIONS; i++)
    {
        web_session_t *s = &sessions[i];
        if (!s->used || (!all && osStrcasecmp(s->username, info.username) != 0))
        {
            continue;
        }
        char id[SESSION_ID_LEN + 1];
        copy_str(id, sizeof(id), s->token_hash);
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "id", id);
        cJSON_AddStringToObject(entry, "username", s->username);
        cJSON_AddNumberToObject(entry, "created", (double)s->created);
        cJSON_AddNumberToObject(entry, "lastSeen", (double)s->last_seen);
        cJSON_AddNumberToObject(entry, "expires", (double)s->expires);
        cJSON_AddStringToObject(entry, "ip", s->ip);
        cJSON_AddStringToObject(entry, "userAgent", s->user_agent);
        cJSON_AddBoolToObject(entry, "current", !osStrcmp(s->token_hash, info.token_hash));
        cJSON_AddBoolToObject(entry, "twoFactorSetupPending", s->restricted);
        cJSON_AddItemToArray(array, entry);
    }
    unlock_auth();
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthSessionsRevoke(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    session_info_t info = current_session(connection, false);
    if (!info.found)
    {
        return send_message(connection, 400, "login_disabled", "Sessions need a login");
    }
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char id[SESSION_ID_LEN + 1];
    bool have_id = json_string(body, "id", id, sizeof(id)) && osStrlen(id) == SESSION_ID_LEN;
    bool others = json_bool(body, "others", false);
    cJSON_Delete(body);
    char ip[WEB_AUTH_IP_STR_MAX];
    web_auth_client_ip(connection, ip, sizeof(ip));
    int revoked = 0;
    lock_auth();
    if (others)
    {
        revoked = revoke_user_sessions_unlocked(info.username, info.token_hash);
    }
    else if (have_id)
    {
        bool admin = is_admin_unlocked(connection);
        for (int i = 0; i < MAX_WEB_SESSIONS; i++)
        {
            if (sessions[i].used && !osStrncmp(sessions[i].token_hash, id, SESSION_ID_LEN) &&
                (admin || osStrcasecmp(sessions[i].username, info.username) == 0))
            {
                osMemset(&sessions[i], 0, sizeof(sessions[i]));
                revoked++;
            }
        }
        if (revoked > 0)
        {
            save_sessions_unlocked();
        }
    }
    if (revoked > 0)
    {
        add_event_unlocked("sessions_revoked", info.username, ip, NULL);
    }
    unlock_auth();
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddNumberToObject(json, "revoked", revoked);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthEventsGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *json = cJSON_CreateObject();
    cJSON *array = cJSON_AddArrayToObject(json, "events");
    lock_auth();
    for (int n = 0; n < event_count; n++)
    {
        /* newest first */
        auth_event_t *e = &events[(event_next - 1 - n + MAX_EVENTS) % MAX_EVENTS];
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddNumberToObject(entry, "time", (double)e->time);
        cJSON_AddStringToObject(entry, "type", e->type);
        cJSON_AddStringToObject(entry, "username", e->username);
        cJSON_AddStringToObject(entry, "ip", e->ip);
        cJSON_AddStringToObject(entry, "detail", e->detail);
        cJSON_AddItemToArray(array, entry);
    }
    cJSON *locked = cJSON_AddArrayToObject(json, "lockedAddresses");
    time_t now = time(NULL);
    for (int i = 0; i < LOGIN_BUCKETS; i++)
    {
        if (login_limits[i].used && login_limits[i].locked_until > now)
        {
            cJSON *entry = cJSON_CreateObject();
            cJSON_AddStringToObject(entry, "ip", login_limits[i].ip);
            cJSON_AddNumberToObject(entry, "lockedUntil", (double)login_limits[i].locked_until);
            cJSON_AddItemToArray(locked, entry);
        }
    }
    unlock_auth();
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthUnlock(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid JSON payload");
    }
    char target[WEB_AUTH_IP_STR_MAX];
    char username[USERNAME_MAX + 1];
    bool have_ip = json_string(body, "ip", target, sizeof(target));
    bool have_user = json_string(body, "username", username, sizeof(username));
    cJSON_Delete(body);
    error_t err = NO_ERROR;
    if (!require_confirmation(connection, &err))
    {
        return err;
    }
    int n = 0;
    lock_auth();
    for (int i = 0; have_ip && i < LOGIN_BUCKETS; i++)
    {
        if (login_limits[i].used && !osStrcmp(login_limits[i].ip, target))
        {
            osMemset(&login_limits[i], 0, sizeof(login_limits[i]));
            n++;
        }
    }
    web_user_t *user = have_user ? find_user_unlocked(username) : NULL;
    if (user != NULL)
    {
        user->remote_failures = 0;
        user->remote_locked_until = 0;
        user->tfa_failures = 0;
        user->tfa_locked_until = 0;
        n++;
    }
    unlock_auth();
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddNumberToObject(json, "unlocked", n);
    return send_json_status(connection, 200, json, NULL, false);
}

error_t handleApiAuthConfirm(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx)
{
    (void)uri;
    (void)queryString;
    (void)client_ctx;
    session_info_t info = current_session(connection, false);
    if (!info.found || info.restricted)
    {
        return send_message(connection, 400, "login_disabled", "Confirmation needs a login");
    }
    cJSON *body = NULL;
    if (read_json_body(connection, &body) != NO_ERROR)
    {
        return send_message(connection, 400, "invalid_body", "Invalid payload");
    }
    error_t err = NO_ERROR;
    bool ok = confirm_identity(connection, &info, body, &err);
    delete_body(body);
    if (!ok)
    {
        return err;
    }
    lock_auth();
    web_session_t *s = find_session_unlocked(info.token_hash);
    if (s != NULL)
    {
        s->confirmed = time(NULL);
        save_sessions_unlocked();
    }
    save_users_unlocked(); /* the used 2FA step */
    unlock_auth();
    cJSON *json = cJSON_CreateObject();
    cJSON_AddBoolToObject(json, "ok", true);
    cJSON_AddNumberToObject(json, "validFor", CONFIRM_TTL_SECONDS);
    return send_json_status(connection, 200, json, NULL, false);
}
