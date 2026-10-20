#ifndef _WEB_ACL_CORE_H
#define _WEB_ACL_CORE_H

#include <stdbool.h>
#include <stddef.h>

/*
 * Decisions of the permission system without server state, covered by tests/c.
 *
 * A right is a name like "box.view", "tonie.assign", "folder.write" or
 * "box.setting:cloud.enabled". Lists of rights are comma separated patterns;
 * "*" matches everything, "box.*" every right starting with "box.",
 * "box.setting:cloud.*" every setting below "cloud.".
 */

typedef enum
{
    ACL_LEVEL_ADMIN = 0, /* everything, all boxes, tonies and folders */
    ACL_LEVEL_USER = 1,  /* owns boxes, tonies and folders, shares them */
    ACL_LEVEL_GUEST = 2, /* only what is shared with them */
    ACL_LEVEL_COUNT
} acl_level_t;

typedef enum
{
    ACL_REL_NONE,       /* not owner, nothing shared */
    ACL_REL_SHARED,     /* shared with the user: the granted rights */
    ACL_REL_OWNER,      /* one of the owners: all rights */
    ACL_REL_UNASSIGNED, /* nobody owns it yet: the rights for unassigned resources */
} acl_relation_t;

typedef struct
{
    acl_level_t level;
    acl_relation_t relation;
    const char *granted;    /* rights of the share (ACL_REL_SHARED) */
    const char *level_max;  /* most a user of this level may have, NULL for no limit */
    const char *user_deny;  /* rights the admin took from this user, NULL for none */
    const char *unassigned; /* rights on resources nobody owns (ACL_REL_UNASSIGNED) */
} acl_subject_t;

const char *acl_level_name(acl_level_t level);
/* "admin", "user", "guest"; false for anything else */
bool acl_level_parse(const char *name, acl_level_t *level);

/* true if the pattern covers the right */
bool acl_pattern_match(const char *pattern, size_t pattern_len, const char *right);
/* true if any pattern of the comma separated list covers the right */
bool acl_list_allows(const char *list, const char *right);
/* true if every pattern of a is covered by b (a share may only hand on what the owner has) */
bool acl_list_within(const char *a, const char *b);
/* true if a right exists that both patterns cover ("box.setting:*" and "box.setting:core.*" do) */
bool acl_patterns_overlap(const char *a, size_t alen, const char *b, size_t blen);
/* true if any pattern of list a overlaps any pattern of list b */
bool acl_lists_overlap(const char *a, const char *b);
/* calls fn for every pattern of a comma separated list until it returns true */
bool acl_list_each(const char *list, bool (*fn)(const char *entry, size_t len, void *ctx), void *ctx);

/* true if every entry is a known right or a pattern of known rights */
bool acl_list_valid(const char *list, char *bad, size_t bad_size);

bool acl_allowed(const acl_subject_t *subject, const char *right);

/* a user may create and manage users of the same or a lower level */
bool acl_may_manage_level(acl_level_t actor, acl_level_t target);

/*
 * Library paths: "a/b/c" relative to the library, without leading or trailing
 * slashes, no "." or ".." parts. Returns false for paths that leave the library.
 */
bool acl_path_normalize(const char *in, char *out, size_t out_size);
/* true if path is folder or below it ("" is the library root) */
bool acl_path_within(const char *path, const char *folder);

/* catalog of the rights (for the API and the UI) */
typedef struct
{
    const char *name;
    const char *scope; /* "box", "tonie", "folder", "system" */
    bool admin_only;   /* can not be shared or given to a level */
} acl_right_t;

extern const acl_right_t acl_rights[];
extern const size_t acl_rights_count;

#endif
