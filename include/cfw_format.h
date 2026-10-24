#pragma once

/* Data formats of the CC3200 custom firmware: settings files (TBS),
   the settings change report of the box and the freshness-check answer. No server state. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CFW_TBS_MIN 16
#define CFW_TBS_MAX 256

#define CFW_TBS_KIND_PROFILE 1
#define CFW_TBS_KIND_EVENT 2
#define CFW_TBS_KIND_GLOBAL 3

#define CFW_TBS_ORIGIN_BOX 0
#define CFW_TBS_ORIGIN_SERVER 1

#define CFW_RECORD_ACTION 0x10

typedef struct
{
    uint8_t key;
    uint8_t length;
    const uint8_t *value;
} cfw_record_t;

uint32_t cfw_le32(const uint8_t *data);
void cfw_put_le32(uint8_t *data, uint32_t value);

/* UID bytes B0 ... B7; the ruid holds B0 in its most significant byte (content path order) */
void cfw_ruid_to_bytes(uint64_t ruid, uint8_t bytes[8]);
uint64_t cfw_ruid_from_bytes(const uint8_t bytes[8]);
uint64_t cfw_ruid_from_words(uint32_t low, uint32_t high);

uint32_t cfw_crc32(const uint8_t *data, size_t length);
/* the version of the setup page as the box reports it for item 7 */
uint32_t cfw_page_version(const uint8_t *data, size_t length);
bool cfw_tbs_valid(const uint8_t *file, size_t length);
size_t cfw_tbs_build(uint8_t kind, uint8_t origin, uint32_t timestamp, const uint8_t *body, size_t bodyLength, uint8_t *file);
uint32_t cfw_tbs_timestamp(const uint8_t *file);
bool cfw_tbs_next_record(const uint8_t *file, size_t *pos, cfw_record_t *record);

size_t cfw_event_for_basic_box(const uint8_t *file, uint8_t *out);
size_t cfw_report_body(uint32_t packed, uint32_t values, uint32_t idle, uint8_t *body);
size_t cfw_strip_volume_fields(uint8_t *message, size_t length);

/* App images of the ESP32 box (ESP-IDF "App Image Format") */
#define CFW_ESP32_SLOT_SIZE 0x220000
#define CFW_ESP32_PROJECT "toniebox-cfw-esp32"
#define CFW_ESP32_PROJECT_ORIGINAL "toniebox-esp32-eu"

typedef struct
{
    size_t length;         /* image bytes, appended SHA-256 included */
    size_t checksumOffset; /* the checksum byte after the segments */
    bool hashAppended;
    uint16_t chipId;
    uint8_t flashMode;
    uint8_t flashSizeFreq;
    char project[33];
    char version[33];
    size_t serverBlock; /* offset of the server block */
    size_t serverBlocks;
    size_t buildBlock; /* offset of the build block (slot image layout, family CFW1) */
    size_t buildBlocks;
} cfw_esp32_image_t;

/* the structure of an app image at data (size bytes, more may follow); false when it is none */
bool cfw_esp32_parse(const uint8_t *data, size_t size, cfw_esp32_image_t *image);
/* the checksum over the segments' data */
uint8_t cfw_esp32_checksum(const uint8_t *data, size_t size);
/* writes host (at most 64 characters) and port into the server block; checksum and hash are the caller's */
bool cfw_esp32_set_server(uint8_t *data, const cfw_esp32_image_t *image, const char *host, uint16_t port);
/* "v5.226.0" or "CFW_0.1.0" as one number for comparing versions (three parts of up to 999) */
uint32_t cfw_esp32_version_number(const char *version);
/* the build number of an ESP32 image: build date ("Mmm dd yyyy") and time ("hh:mm:ss") of the app description, read
   as UTC, in Unix seconds; 0: empty or not in that form */
uint32_t cfw_esp32_build_time(const uint8_t *data);
/* the app slot of a flash dump (partition table at 0x9000) holding the image of the project with the highest
   version: its offset; false when there is none */
bool cfw_esp32_dump_app(const uint8_t *data, size_t size, const char *project, size_t *offset);
/* replaces from with to (not longer than from) wherever from ends a zero-terminated string, the rest of it
   zero-filled; the number of replacements */
size_t cfw_esp32_replace_string(uint8_t *data, size_t size, const char *from, const char *to);

/* one file of a zip archive (release package of the custom firmware) */
typedef struct
{
    const char *name; /* not terminated */
    size_t nameLength;
    uint16_t method; /* 0: stored; the data can be used only then */
    const uint8_t *data;
    size_t size;
} cfw_zip_entry_t;

/* true when data starts like a zip archive */
bool cfw_zip_is(const uint8_t *data, size_t length);
/* the local file at *pos of a zip archive, *pos moved past it; false at the end of the files or at a broken or
   unsupported entry (sizes only in a data descriptor, data beyond the archive) */
bool cfw_zip_next(const uint8_t *zip, size_t length, size_t *pos, cfw_zip_entry_t *entry);

/* the content of <meta name="cfw-page-version" content="..."> of a setup page, at most labelSize - 1
   printable characters; false when the page has none */
bool cfw_page_label(const uint8_t *page, size_t size, char *label, size_t labelSize);
/* the content of <meta name="<name>" content="..."> of a setup page, as cfw_page_label */
bool cfw_page_meta(const uint8_t *page, size_t size, const char *name, char *label, size_t labelSize);
/* version (CFW_x.y.z) is older than than; false when either is no such version */
bool cfw_version_older(const char *version, const char *than);
