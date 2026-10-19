#pragma once

/* shared by cfw.c (protocol), cfw_firmware.c (images, update) and cfw_api.c (web API) */

#include <time.h>

#include "cJSON.h"
#include "cfw.h"
#include "cfw_format.h"
#include "settings.h"

#define CFW_CAP_EVENT_TAGS (1 << 3)
#define CFW_CAP_EVENT_TAG_EXT (1 << 9)
#define CFW_CAP_REMOTE (1 << 10)

#define CFW_CMD_SYNC 6
#define CFW_CMD_APPLY_SETTINGS 64
#define CFW_CMD_PAUSE 65
#define CFW_CMD_CONTINUE 66
#define CFW_CMD_STOP 67
#define CFW_CMD_NEXT 68
#define CFW_CMD_PREV 69
#define CFW_CMD_VOLUME 70
#define CFW_CMD_PLAY 71
#define CFW_CMD_UPDATE_CHECK 73

#define CFW_REMOTE_QUEUE 8
#define CFW_REMOTE_ARGS_MAX 300
#define CFW_ROLLED_BACK_MAX 8

/* build number of the original firmware; builds of the CFW are newer. Only a plausibility check
   of uploaded images: which firmware a box runs is told by X-CFW-Build */
#define CFW_REFERENCE_BUILD 1620325289u

typedef enum
{
    CFW_CHANNEL_NONE = 0,
    CFW_CHANNEL_RELEASE = 1,
    CFW_CHANNEL_BETA = 2,
    CFW_CHANNEL_ALPHA = 3,
} cfw_channel_t;

typedef struct
{
    uint64_t ruid;
    uint32_t timestamp;
} cfw_known_t;

typedef struct
{
    uint8_t command;
    uint8_t args[CFW_REMOTE_ARGS_MAX];
    size_t argsLength;
} cfw_remote_t;

typedef struct
{
    bool loaded;
    char id[64];

    /* persisted */
    bool isCfw;       /* the last request came from the CFW (cfw_box_seen_request) */
    uint32_t version; /* build the box runs: of its last request or its hello */
    uint32_t capabilities;
    uint32_t updateResult;
    uint32_t rolledBackBuild;
    uint32_t rolledBack[CFW_ROLLED_BACK_MAX];
    size_t rolledBackCount;
    time_t helloTime;
    uint64_t helloUptime;
    uint32_t helloSequence;
    uint32_t offeredBuild;
    uint32_t esp32Delivered; /* build delivered to the original firmware of an ESP32 box */
    uint32_t pageVersion;    /* the value of its setup page the box reported last for item 7, 0: none yet */
    bool esp32;              /* last seen with an ESP32 User-Agent (the box IC from it is lost when the settings are
                                reloaded) */
    time_t offerTime;
    uint32_t offerAttempts;
    bool offerStarted;
    uint8_t globalBody[32];
    size_t globalLength;
    uint32_t globalTimestamp;
    uint8_t globalOrigin;

    /* the current start of the box */
    bool helloValid;
    uint64_t lastUptime;
    uint32_t lastSequence;
    time_t lastLogTime;
    cfw_known_t *known;
    size_t knownCount;
    size_t knownSize;
    time_t lastSyncCommand;
    uint32_t syncUnanswered; /* command 6 sent without a freshness check since */
    bool syncStalled;        /* files are due but none fitted into the last answer */
    time_t lastGlobalCheck;
    const HttpConnection *connection;
    cfw_remote_t queue[CFW_REMOTE_QUEUE];
    size_t queueCount;
    bool statusValid;
    uint32_t status[9];
    time_t statusTime;
    uint32_t lastCommand;
    uint32_t lastResult;
    time_t lastResultTime;
    uint32_t lockedGesture;
    uint32_t lockedSource;
    time_t lockedTime;
    /* the last battery report */
    bool batteryValid;
    uint32_t battery[5]; /* voltage, flags, reason, load, ADC value */
    time_t batteryTime;
} cfw_box_t;

typedef struct
{
    uint32_t build;
    char version[32];
    char revision[9];
    char buildDate[62];
    uint32_t channel;
    char source[16];
    char githubTag[64];
    char notes[256];
    time_t added;
    uint32_t size;
    char platform[8];      /* "cc3200" or "esp32" */
    bool original;         /* the original firmware of the ESP32 box, for the return */
    char patches[128];     /* what teddyCloud changed in an original image */
    uint32_t page;         /* the setup page that came with the image (the value of item 7), 0: none */
    char pageLabel[32];    /* its version: its cfw-page-version meta, else the image's version */
    char pageRequires[32]; /* the firmware it needs at least: its cfw-page-requires meta, "" when it names none */
} cfw_image_t;

/* teddyCloud's patches of an original ESP32 image: hosts replaced by host, the port; empty or 0: none */
typedef struct
{
    char host[65];
    char hostOld[65]; /* the host the image holds now; empty: the vendor's hosts */
    uint16_t port;
} cfw_esp32_patch_t;

#define CFW_PLATFORM_CC3200 "cc3200"
#define CFW_PLATFORM_ESP32 "esp32"

void cfw_lock(void);
void cfw_unlock(void);

/* with the lock held */
cfw_box_t *cfw_box_get(settings_t *settings);
void cfw_box_save(cfw_box_t *box);
bool cfw_box_online(const cfw_box_t *box);
bool cfw_remote_queue(cfw_box_t *box, uint8_t command, const uint8_t *args, size_t argsLength);
void cfw_box_rolled_back(cfw_box_t *box, uint32_t build, bool rolledBack);
bool cfw_box_is_rolled_back(const cfw_box_t *box, uint32_t build);

/* the library under <firmwaredir>/cfw/: changes of it (import, page, metadata, delete) under this lock; the
   functions below take it themselves, a caller holds it only around its own cfw_firmware_get and
   cfw_firmware_save_meta. Not to be taken with the CFW lock held. */
void cfw_library_lock(void);
void cfw_library_unlock(void);

uint32_t cfw_temp_number(void);
uint8_t *cfw_read_file(const char *path, size_t maxLength, size_t *length);
bool cfw_write_file(const char *path, const void *data, size_t length);
char *cfw_dir(const char *base, const char *sub);

uint32_t cfw_next_timestamp(uint32_t previous);
bool cfw_parse_ruid(const char *text, uint64_t *ruid);
void cfw_format_ruid(uint64_t ruid, char text[17]);
bool cfw_store_read_tag(uint64_t ruid, uint8_t *file, size_t *length);
bool cfw_store_write_tag(uint64_t ruid, const uint8_t *file, size_t length);
size_t cfw_store_list_tags(uint64_t **ruids);

uint32_t cfw_firmware_choose(settings_t *settings, const cfw_box_t *box, uint32_t currentVersion);
/* the platform of the images a box takes: "esp32" for a box with the ESP32-S3, else "cc3200" */
const char *cfw_box_platform(settings_t *settings);
size_t cfw_firmware_list(cfw_image_t **images);
bool cfw_firmware_get(const char *platform, uint32_t build, cfw_image_t *image);
/* the release package kept beside a CC3200 image, with the card tree; NULL when there is none */
char *cfw_firmware_package(uint32_t build);
/* an image (CC3200 slot image, ESP32 app image or body, or the original ESP32 firmware as app image or in a
   flash dump, with patch applied; patch may be NULL) into the library, or for a release package (zip) each of its
   images with its setup page; images holds *count entries, *count is set to the number added */
bool cfw_firmware_import(const char *tmpPath, uint32_t channel, const char *source, const char *githubTag, const char *notes,
                         const cfw_esp32_patch_t *patch, cfw_image_t *images, size_t *count, char *message, size_t messageSize);
bool cfw_firmware_save_meta(const cfw_image_t *image);
/* a setup page for the image of platform and build, or with build 0 as the default page of the
   images without one; its value and version (the cfw-page-version meta, else fallbackLabel, else the value in
   hex) into page and label; false with message when it is no page or cannot be stored */
bool cfw_firmware_set_page(const char *platform, uint32_t build, const uint8_t *data, size_t size, const char *fallbackLabel, uint32_t *page,
                           char *label, size_t labelSize, char *message, size_t messageSize);
/* the default page: its value (0: none), version and the firmware it needs at least ("" when it names none) */
uint32_t cfw_firmware_default_page(char *label, size_t labelSize, char *required, size_t requiredSize);
bool cfw_firmware_delete(const char *platform, uint32_t build);
char *cfw_firmware_temp_path(void);
const char *cfw_channel_name(uint32_t channel);
uint32_t cfw_channel_parse(const char *name);
void cfw_firmware_deinit(void);

cJSON *cfw_github_releases_json(void);
error_t cfw_github_check(char *message, size_t messageSize);
error_t cfw_github_download(const char *tag, char *message, size_t messageSize);
