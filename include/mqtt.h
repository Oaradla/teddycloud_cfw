#pragma once

#include "error.h"
#include "handler.h"
#include "home_assistant.h"

void mqtt_init();
error_t mqtt_sendEvent(const char *eventname, const char *content, client_ctx_t *client_ctx);
error_t mqtt_sendBoxEvent(const char *eventname, const char *content, client_ctx_t *client_ctx);
/* the Home Assistant device of a box, created at its first use */
t_ha_info *mqtt_get_box(client_ctx_t *client_ctx);
bool mqtt_publish(const char *item_topic, const char *content);
bool mqtt_subscribe(const char *item_topic);
