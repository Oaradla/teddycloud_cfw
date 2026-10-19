#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfw.h"
#include "cfw_format.h"
#include "cfw_internal.h"
#include "cfw_mqtt.h"
#include "debug.h"
#include "home_assistant.h"
#include "mqtt.h"
#include "os_port.h"
#include "settings.h"

/*
 * Remote control of a box with the custom firmware through MQTT: buttons, a volume number and a
 * text that plays a tag, added to the Home Assistant device of the box, and its playback state.
 * The commands take the same way as /api/cfw/remote (cfw_remote_send).
 */

static const struct
{
    const char *id;
    const char *name;
    const char *cmd_t;
    const char *ic;
    uint8_t command;
} buttons[] = {
    {"CfwPause", "Pause", "%s/CfwPause/set", "mdi:pause", CFW_CMD_PAUSE},
    {"CfwContinue", "Continue", "%s/CfwContinue/set", "mdi:play", CFW_CMD_CONTINUE},
    {"CfwStop", "Stop", "%s/CfwStop/set", "mdi:stop", CFW_CMD_STOP},
    {"CfwNext", "Next Chapter", "%s/CfwNext/set", "mdi:skip-next", CFW_CMD_NEXT},
    {"CfwPrev", "Previous Chapter", "%s/CfwPrev/set", "mdi:skip-previous", CFW_CMD_PREV},
};

static const char *const states[] = {"idle", "idle with figure", "playing", "paused", "preparing"};

/* the overlay number of the box travels as the context pointer */
static settings_t *ctx_settings(void *ctx)
{
    uint8_t overlay = (uint8_t)(uintptr_t)ctx;
    return overlay == 0 ? NULL : get_settings_id(overlay);
}

static void send(void *ctx, uint8_t command, const uint8_t *args, size_t argsLength)
{
    settings_t *settings = ctx_settings(ctx);
    char message[96];
    if (settings == NULL)
    {
        return;
    }
    uint_t status = cfw_remote_send(settings, command, args, argsLength, message, sizeof(message));
    if (status != 200)
    {
        TRACE_WARNING("CFW: MQTT command %u for box %s not sent: %s\r\n", command, settings->internal.overlayUniqueId, message);
    }
}

static void button_rx(t_ha_info *ha_info, const t_ha_entity *entity, void *ctx, const char *payload)
{
    (void)ha_info;
    (void)payload;
    for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); i++)
    {
        if (!osStrcmp(entity->id, buttons[i].id))
        {
            send(ctx, buttons[i].command, NULL, 0);
        }
    }
}

static void volume_rx(t_ha_info *ha_info, const t_ha_entity *entity, void *ctx, const char *payload)
{
    (void)ha_info;
    (void)entity;
    char *end = NULL;
    long step = payload ? strtol(payload, &end, 10) : -1;
    if (end == payload || step < 0 || step > 15)
    {
        TRACE_WARNING("CFW: MQTT volume '%s' is not 0 to 15\r\n", payload ? payload : "");
        return;
    }
    uint8_t arg = (uint8_t)step;
    send(ctx, CFW_CMD_VOLUME, &arg, 1);
}

static void play_rx(t_ha_info *ha_info, const t_ha_entity *entity, void *ctx, const char *payload)
{
    (void)ha_info;
    (void)entity;
    uint64_t ruid;
    uint8_t args[8];
    if (payload == NULL || !cfw_parse_ruid(payload, &ruid))
    {
        TRACE_WARNING("CFW: MQTT play needs a tag UID, not '%s'\r\n", payload ? payload : "");
        return;
    }
    cfw_ruid_to_bytes(ruid, args);
    send(ctx, CFW_CMD_PLAY, args, sizeof(args));
}

void cfw_mqtt_add_entities(t_ha_info *ha_info, uint8_t overlay)
{
    t_ha_entity entity;
    if (!get_settings()->cfw.enabled)
    {
        return;
    }
    void *ctx = (void *)(uintptr_t)overlay;

    for (size_t i = 0; i < sizeof(buttons) / sizeof(buttons[0]); i++)
    {
        osMemset(&entity, 0, sizeof(entity));
        entity.id = buttons[i].id;
        entity.name = buttons[i].name;
        entity.type = ha_button;
        entity.cmd_t = buttons[i].cmd_t;
        entity.ic = buttons[i].ic;
        entity.received = button_rx;
        entity.received_ctx = ctx;
        ha_add(ha_info, &entity);
    }

    osMemset(&entity, 0, sizeof(entity));
    entity.id = "CfwVolume";
    entity.name = "Volume";
    entity.type = ha_number;
    entity.cmd_t = "%s/CfwVolume/set";
    entity.stat_t = "%s/CfwVolume";
    entity.min = 0;
    entity.max = 15;
    entity.mode = "slider";
    entity.ic = "mdi:volume-high";
    entity.received = volume_rx;
    entity.received_ctx = ctx;
    ha_add(ha_info, &entity);

    osMemset(&entity, 0, sizeof(entity));
    entity.id = "CfwPlay";
    entity.name = "Play Tag";
    entity.type = ha_text;
    entity.cmd_t = "%s/CfwPlay/set";
    entity.ic = "mdi:play-box";
    entity.received = play_rx;
    entity.received_ctx = ctx;
    ha_add(ha_info, &entity);

    osMemset(&entity, 0, sizeof(entity));
    entity.id = "CfwState";
    entity.name = "Player State";
    entity.type = ha_sensor;
    entity.stat_t = "%s/CfwState";
    entity.ic = "mdi:play-pause";
    ha_add(ha_info, &entity);

    osMemset(&entity, 0, sizeof(entity));
    entity.id = "CfwChapter";
    entity.name = "Chapter";
    entity.type = ha_sensor;
    entity.stat_t = "%s/CfwChapter";
    entity.ic = "mdi:book-open-page-variant";
    ha_add(ha_info, &entity);
}

void cfw_mqtt_status(client_ctx_t *client_ctx, const uint32_t *status)
{
    char text[16];
    if (!settings_get_bool("mqtt.enabled"))
    {
        return;
    }
    t_ha_info *ha_info = mqtt_get_box(client_ctx);
    if (ha_info == NULL)
    {
        return;
    }
    ha_transmit_topic(ha_info, "%s/CfwState", status[0] < sizeof(states) / sizeof(states[0]) ? states[status[0]] : "unknown");
    osSnprintf(text, sizeof(text), "%" PRIu32, status[4]);
    ha_transmit_topic(ha_info, "%s/CfwChapter", text);
    osSnprintf(text, sizeof(text), "%" PRIu32, status[6] & 0xFF);
    ha_transmit_topic(ha_info, "%s/CfwVolume", text);
}
