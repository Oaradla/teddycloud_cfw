#ifndef _HANDLER_WEB_AUTH_H
#define _HANDLER_WEB_AUTH_H

#include "handler.h"

#define WEB_USERS_JSON_FILE "web_users.json"
#define WEB_SESSIONS_JSON_FILE "web_sessions.json"
#define WEB_AUTH_KEY_FILE "web_auth.key"
#define WEB_SESSION_COOKIE "tc_web_session"
#define WEB_BEARER_TOKEN_MAX 64

void web_auth_init(void);
bool web_auth_env_override(void);
bool web_auth_requires_login(void);
bool web_auth_is_public_request(const char_t *uri, const char_t *method);
/* true for a complete login; a login that still has to set up 2FA does not count */
bool web_auth_is_authenticated(HttpConnection *connection, char *username, size_t username_size);
error_t web_auth_unauthorized(HttpConnection *connection);

/*
 * Checks a request on the web port before it is routed: blocked networks,
 * access from outside, HTTPS from outside, cross-site requests and the login.
 * Returns true when a response was sent and the request must not be routed.
 */
bool web_auth_gate(HttpConnection *connection, const char_t *uri, error_t *error);

/* level (acl_level_t), restrictions by the admin and creator of a user; false if unknown */
/* any out pointer may be NULL; group: the own group, empty for the built-in one of the level */
bool web_auth_user_info(const char *username, int *level, char *deny, size_t deny_size, char *created_by, size_t created_by_size,
                        char *group, size_t group_size);
/* names of all users, returns the count */
int web_auth_user_names(char names[][33], int max);

/* writes a file atomically and owner-only (0600) */
bool web_auth_write_private_file(const char *path, const char *body);

/* address of the client, behind trusted reverse proxies the forwarded one */
void web_auth_client_ip(HttpConnection *connection, char *out, size_t out_size);
/* true for direct TLS and for a trusted proxy that reports https */
bool web_auth_request_secure(HttpConnection *connection);

#endif
