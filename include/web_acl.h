#ifndef _WEB_ACL_H
#define _WEB_ACL_H

#include "handler.h"

/*
 * Permissions of the web UI users (only with the login on; without it everyone may
 * do everything, as before). Admins may do everything. Users of the level "user"
 * own boxes, tonies and library folders and share them with chosen rights; "guest"
 * users only get what is shared with them. Stored in config/web_acl.json.
 */

#define WEB_ACL_JSON_FILE "web_acl.json"
#define WEB_ACL_GROUP_ID_MAX 32

void web_acl_init(void);

/* true for admins and when the login is off */
bool web_acl_is_admin(HttpConnection *connection);
/* route policy, checked by web_auth_gate before a request is routed */
bool web_acl_request_allowed(HttpConnection *connection, const char_t *uri, const char_t *queryString);

bool web_acl_system_allowed(HttpConnection *connection, const char *right);
/* box_id is the overlay id (as in ?overlay=) */
bool web_acl_box_allowed(HttpConnection *connection, const char *box_id, const char *right);
/* ruid: 16 hex digits */
bool web_acl_tonie_allowed(HttpConnection *connection, const char *ruid, const char *right);
/* path relative to the library */
bool web_acl_folder_allowed(HttpConnection *connection, const char *path, const char *right);
/* a sub folder "name" of "parent" is listed: the user may read it or something below it */
bool web_acl_folder_visible(HttpConnection *connection, const char *parent, const char *name);
/* write right on the folder and on every folder with an own entry below it */
bool web_acl_folder_tree_writable(HttpConnection *connection, const char *path);
/* keep the entries of folder trees in step with renames and deletes */
void web_acl_folder_moved(const char *src, const char *dst);
void web_acl_folder_removed(const char *path);
/* settings name readable / changeable for a box by the user */
bool web_acl_setting_allowed(HttpConnection *connection, const char *box_id, const char *name, bool write);

/* "lib://<path>" and the like: true if the user may use it as a tonie source */
bool web_acl_source_allowed(HttpConnection *connection, const char *source);

typedef enum
{
    WEB_ACL_GROUP_OK,
    WEB_ACL_GROUP_UNKNOWN,
    /* the group has rights the user of the connection does not have */
    WEB_ACL_GROUP_FORBIDDEN,
} web_acl_group_check_t;

/* may the user of the connection put users into the group; base: its level (user or guest).
   Takes lock_acl, so never under lock_auth. */
web_acl_group_check_t web_acl_group_check(HttpConnection *connection, const char *id, int *base);

/* 403 response for a request the user may not do */
error_t web_acl_forbidden(HttpConnection *connection);

void web_acl_user_created(const char *username);
void web_acl_user_deleted(const char *username);
/* a box asked for a tag: unassigned tags go to the owners of the box */
void web_acl_tag_placed(const char *ruid, const char *box_id);

error_t handleApiAclCatalog(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiAclMine(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiAclGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiAclSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiAclUsers(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiAclGroupsSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiAclGroupsDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiAclLevelsSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);

#endif
