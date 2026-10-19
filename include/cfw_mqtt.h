#pragma once

/* remote control of a box with the custom firmware through MQTT (Home Assistant) */

#include <stdint.h>

#include "handler.h"
#include "home_assistant.h"

/* adds the remote control to the Home Assistant device of a box while cfw.enabled is on */
void cfw_mqtt_add_entities(t_ha_info *ha_info, uint8_t overlay);
/* publishes the playback state of a status record (CFW_FUNC_STATUS) */
void cfw_mqtt_status(client_ctx_t *client_ctx, const uint32_t *status);
