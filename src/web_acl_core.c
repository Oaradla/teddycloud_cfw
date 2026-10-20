#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "web_acl_core.h"

const acl_right_t acl_rights[] = {
    {"box.view", "box", false},
    {"box.settings", "box", false},
    {"box.setting", "box", false}, /* box.setting:<name> for single settings */
    {"box.cfw", "box", false},
    {"box.share", "box", false},
    {"tonie.view", "tonie", false},
    {"tonie.assign", "tonie", false},
    {"tonie.edit", "tonie", false},
    {"tonie.share", "tonie", false},
    {"folder.read", "folder", false},
    {"folder.write", "folder", false},
    {"folder.share", "folder", false},
    {"users.manage", "system", false},
    {"system.settings", "system", true},
    {"system.files", "system", true},
    {"system.admin", "system", true},
};
const size_t acl_rights_count = sizeof(acl_rights) / sizeof(acl_rights[0]);

static const char *const level_names[ACL_LEVEL_COUNT] = {"admin", "user", "guest"};

const char *acl_level_name(acl_level_t level)
{
    return level < ACL_LEVEL_COUNT ? level_names[level] : "guest";
}

bool acl_level_parse(const char *name, acl_level_t *level)
{
    for (int i = 0; name != NULL && i < ACL_LEVEL_COUNT; i++)
    {
        if (!strcmp(name, level_names[i]))
        {
            *level = (acl_level_t)i;
            return true;
        }
    }
    return false;
}

bool acl_pattern_match(const char *pattern, size_t len, const char *right)
{
    if (len == 0 || right == NULL)
    {
        return false;
    }
    if (len == 1 && pattern[0] == '*')
    {
        return true;
    }
    if (pattern[len - 1] == '*')
    {
        /* "box.*" covers "box.view"; "box.setting:cloud.*" covers "box.setting:cloud.enabled" */
        size_t prefix = len - 1;
        if (strncmp(right, pattern, prefix) == 0)
        {
            return true;
        }
        /* "box.setting:*" also stands for "box.settings"-like checks of the bare name "box.setting" */
        if (prefix > 1 && (pattern[prefix - 1] == '.' || pattern[prefix - 1] == ':') && strlen(right) == prefix - 1 &&
            strncmp(right, pattern, prefix - 1) == 0)
        {
            return true;
        }
        return false;
    }
    if (strlen(right) == len && strncmp(right, pattern, len) == 0)
    {
        return true;
    }
    /* "box.settings" (all settings) covers every single "box.setting:<name>" */
    if (len == strlen("box.settings") && !strncmp(pattern, "box.settings", len) && !strncmp(right, "box.setting:", 12))
    {
        return true;
    }
    return false;
}

typedef bool (*entry_fn)(const char *entry, size_t len, void *ctx);

static bool each_entry(const char *list, entry_fn fn, void *ctx)
{
    const char *p = list;
    while (p != NULL && *p)
    {
        while (*p == ',' || *p == ' ' || *p == '\t' || *p == '\n')
        {
            p++;
        }
        const char *start = p;
        while (*p && *p != ',' && *p != ' ' && *p != '\t' && *p != '\n')
        {
            p++;
        }
        if (p > start && fn(start, (size_t)(p - start), ctx))
        {
            return true;
        }
    }
    return false;
}

static bool allows_fn(const char *entry, size_t len, void *ctx)
{
    return acl_pattern_match(entry, len, (const char *)ctx);
}

bool acl_list_allows(const char *list, const char *right)
{
    return list != NULL && each_entry(list, allows_fn, (void *)right);
}

typedef struct
{
    const char *b;
} within_ctx_t;

/* stops (returns true) at the first entry of a that b does not cover */
static bool not_within_fn(const char *entry, size_t len, void *ctx)
{
    within_ctx_t *w = ctx;
    char buf[160];
    if (len >= sizeof(buf))
    {
        return true;
    }
    memcpy(buf, entry, len);
    buf[len] = '\0';
    if (acl_list_allows(w->b, buf))
    {
        return false;
    }
    /* a pattern is within b when b holds the same or a wider pattern */
    if (buf[len - 1] == '*')
    {
        char probe[170];
        snprintf(probe, sizeof(probe), "%.*s\x01", (int)(len - 1), buf);
        return !acl_list_allows(w->b, probe) && !acl_list_allows(w->b, "*");
    }
    return true;
}

bool acl_list_within(const char *a, const char *b)
{
    within_ctx_t w = {b};
    return !each_entry(a, not_within_fn, &w);
}

typedef struct
{
    char *bad;
    size_t bad_size;
} valid_ctx_t;

static bool known_right(const char *entry, size_t len)
{
    if (len == 1 && entry[0] == '*')
    {
        return true;
    }
    for (size_t i = 0; i < acl_rights_count; i++)
    {
        const char *name = acl_rights[i].name;
        size_t nlen = strlen(name);
        if (len == nlen && !strncmp(entry, name, len))
        {
            return true;
        }
        /* box.setting:<name> */
        if (!strcmp(name, "box.setting") && len > nlen + 1 && !strncmp(entry, "box.setting:", nlen + 1))
        {
            for (size_t c = nlen + 1; c < len; c++)
            {
                if (!(isalnum((unsigned char)entry[c]) || entry[c] == '.' || entry[c] == '_' || entry[c] == '-' || (entry[c] == '*' && c == len - 1)))
                {
                    return false;
                }
            }
            return true;
        }
        /* "box.*" style patterns of a known prefix */
        if (entry[len - 1] == '*' && len - 1 <= nlen && !strncmp(entry, name, len - 1))
        {
            return true;
        }
    }
    return false;
}

static bool invalid_fn(const char *entry, size_t len, void *ctx)
{
    valid_ctx_t *v = ctx;
    if (known_right(entry, len))
    {
        return false;
    }
    if (v->bad != NULL && v->bad_size > 0)
    {
        snprintf(v->bad, v->bad_size, "%.*s", (int)len, entry);
    }
    return true;
}

bool acl_list_valid(const char *list, char *bad, size_t bad_size)
{
    valid_ctx_t v = {bad, bad_size};
    if (bad != NULL && bad_size > 0)
    {
        bad[0] = '\0';
    }
    return !each_entry(list, invalid_fn, &v);
}

static bool admin_only(const char *right)
{
    for (size_t i = 0; i < acl_rights_count; i++)
    {
        if (acl_rights[i].admin_only && !strcmp(acl_rights[i].name, right))
        {
            return true;
        }
    }
    return false;
}

bool acl_allowed(const acl_subject_t *s, const char *right)
{
    if (s == NULL || right == NULL)
    {
        return false;
    }
    if (s->level == ACL_LEVEL_ADMIN)
    {
        return true;
    }
    if (admin_only(right))
    {
        return false;
    }
    if (s->user_deny != NULL && acl_list_allows(s->user_deny, right))
    {
        return false;
    }
    if (s->level_max != NULL && !acl_list_allows(s->level_max, right))
    {
        return false;
    }
    switch (s->relation)
    {
    case ACL_REL_OWNER:
        /* guests never own anything; an entry that says so gives them nothing more than a share */
        return s->level != ACL_LEVEL_GUEST || acl_list_allows(s->granted, right);
    case ACL_REL_SHARED:
        return acl_list_allows(s->granted, right);
    case ACL_REL_UNASSIGNED:
        return acl_list_allows(s->unassigned, right);
    default:
        return false;
    }
}

bool acl_may_manage_level(acl_level_t actor, acl_level_t target)
{
    return actor <= target;
}

bool acl_path_normalize(const char *in, char *out, size_t out_size)
{
    size_t o = 0;
    if (in == NULL || out_size == 0)
    {
        return false;
    }
    const char *p = in;
    while (*p)
    {
        while (*p == '/' || *p == '\\')
        {
            p++;
        }
        const char *start = p;
        while (*p && *p != '/' && *p != '\\')
        {
            p++;
        }
        size_t len = (size_t)(p - start);
        if (len == 0)
        {
            break;
        }
        if ((len == 1 && start[0] == '.'))
        {
            continue;
        }
        if (len == 2 && start[0] == '.' && start[1] == '.')
        {
            return false;
        }
        if (o + (o > 0 ? 1 : 0) + len + 1 > out_size)
        {
            return false;
        }
        if (o > 0)
        {
            out[o++] = '/';
        }
        memcpy(out + o, start, len);
        o += len;
    }
    out[o] = '\0';
    return true;
}

bool acl_path_within(const char *path, const char *folder)
{
    size_t flen = strlen(folder);
    if (flen == 0)
    {
        return true;
    }
    return strncmp(path, folder, flen) == 0 && (path[flen] == '\0' || path[flen] == '/');
}

bool acl_list_each(const char *list, bool (*fn)(const char *entry, size_t len, void *ctx), void *ctx)
{
    return list != NULL && each_entry(list, fn, ctx);
}

/* "box.settings" stands for "box.setting:*" */
static void expand_alias(const char **p, size_t *len)
{
    if (*len == 12 && !strncmp(*p, "box.settings", 12))
    {
        *p = "box.setting:*";
        *len = 13;
    }
}

bool acl_patterns_overlap(const char *a, size_t alen, const char *b, size_t blen)
{
    expand_alias(&a, &alen);
    expand_alias(&b, &blen);
    if (alen == 0 || blen == 0)
    {
        return false;
    }
    bool awild = a[alen - 1] == '*';
    bool bwild = b[blen - 1] == '*';
    size_t ap = awild ? alen - 1 : alen;
    size_t bp = bwild ? blen - 1 : blen;
    if (awild && bwild)
    {
        /* two prefixes overlap when one starts with the other */
        size_t n = ap < bp ? ap : bp;
        return strncmp(a, b, n) == 0;
    }
    if (awild)
    {
        return bp >= ap && strncmp(b, a, ap) == 0;
    }
    if (bwild)
    {
        return ap >= bp && strncmp(a, b, bp) == 0;
    }
    return ap == bp && strncmp(a, b, ap) == 0;
}

typedef struct
{
    const char *entry;
    size_t len;
} overlap_ctx_t;

static bool overlap_inner(const char *e, size_t len, void *ctx)
{
    overlap_ctx_t *o = ctx;
    return acl_patterns_overlap(o->entry, o->len, e, len);
}

typedef struct
{
    const char *other;
} overlap_outer_ctx_t;

static bool overlap_outer(const char *e, size_t len, void *ctx)
{
    overlap_outer_ctx_t *o = ctx;
    overlap_ctx_t inner = {e, len};
    return each_entry(o->other, overlap_inner, &inner);
}

bool acl_lists_overlap(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
    {
        return false;
    }
    overlap_outer_ctx_t o = {b};
    return each_entry(a, overlap_outer, &o);
}
