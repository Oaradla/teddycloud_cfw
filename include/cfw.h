#pragma once

/* Support for boxes running the CC3200 custom firmware (CFW): its extension protocol
   and its firmware update. With cfw.enabled off, teddyCloud behaves as without it. */

#include <stdbool.h>
#include <stdint.h>

#include "handler.h"
#include "proto/toniebox.pb.rtnl.pb-c.h"

void cfw_init(void);
void cfw_deinit(void);
void cfw_loop(void);

size_t cfw_freshness_finalize(client_ctx_t *client_ctx, uint8_t *buffer, size_t length, size_t cap);
void cfw_rtnl_record(client_ctx_t *client_ctx, const TonieRtnlLog2 *log2);
void cfw_rtnl_poll(HttpConnection *connection, bool received);
bool_t cfw_rtnl_idle(HttpConnection *connection);
/* event tags: no box gets the content of an event tag; the source stays stored
   for switching back. A box without the CFW gets a notice in cfw.event_notice_language instead */
bool cfw_tag_is_event(settings_t *settings, uint64_t ruid);
bool cfw_tag_is_event_ruid(settings_t *settings, const char *ruid);
bool cfw_event_content(HttpConnection *connection, const char_t *uri, client_ctx_t *client_ctx, const char *ruid, error_t *result);
/* an accepted request of the box: the header X-CFW-Build (cfwBuild, 0: none) tells that it comes from the CFW
   and its build; a request without it comes from the original firmware, whose build is
   that of its User-Agent (build, TB/, 0: none) */
void cfw_box_seen_request(settings_t *settings, uint32_t build, uint32_t cfwBuild);
/* records the platform of the box IC taken from the User-Agent of a request, which a reload of the settings
   resets (cfw_box_platform) */
void cfw_box_seen_platform(settings_t *settings);
void cfw_box_host_seen(const char *host);
void cfw_box_host_get(char *host, size_t size);
/* queues a remote command for the box (CFW_CMD_*), from the API or MQTT; the HTTP status of the
   outcome (200 queued, 409 switched off or not connected, 429 queue full) with its text in message */
uint_t cfw_remote_send(settings_t *settings, uint8_t command, const uint8_t *args, size_t argsLength, char *message, size_t messageSize);
bool cfw_ota_request(HttpConnection *connection, const char_t *uri, client_ctx_t *client_ctx, uint32_t fileId, uint32_t currentVersion, error_t *result);

/* toniebox.max_vol_spk, max_vol_hdp and slap_enabled of a box without the CFW, derived from cfw.box.*
   while the CFW box settings are shown for it (unless the box has its own value of the old setting) */
bool cfw_is_derived_setting(settings_t *settings, const char *name);
uint32_t cfw_derived_setting(settings_t *settings, const char *name, uint32_t value);

error_t handleApiCfwBoxes(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwBoxHost(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwTags(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwTagGet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwTagSet(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwRemote(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwStatus(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwBattery(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwFirmwarePackage(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwFirmwareList(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwFirmwareUpload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwFirmwareEdit(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwFirmwareDelete(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwFirmwareGithub(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwFirmwareGithubDownload(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
error_t handleApiCfwDeliver(HttpConnection *connection, const char_t *uri, const char_t *queryString, client_ctx_t *client_ctx);
