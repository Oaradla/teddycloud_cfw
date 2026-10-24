#include <assert.h>
#include <string.h>

#include "cfw_format.h"
#include "tests.h"

/* examples: a profile (resume on, sleep timer 30 min) and a global file (LED level 2) */
static const uint8_t PROFILE[] = {0x54, 0x42, 0x53, 0x31, 0x01, 0x01, 0x07, 0x00, 0x80, 0x3B, 0xB1, 0x6A, 0x01, 0x01, 0x01, 0x03, 0x02, 0x1E, 0x00, 0xF7, 0xB8, 0x55, 0x2C};
static const uint8_t GLOBAL[] = {0x54, 0x42, 0x53, 0x31, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x02, 0x88, 0x71, 0xBD, 0x37};

void test_cfw_crc(void)
{
    assert(cfw_crc32((const uint8_t *)"123456789", 9) == 0x89A1897F);
    assert(cfw_crc32(PROFILE, sizeof(PROFILE) - 4) == 0x2C55B8F7);
    assert(cfw_crc32(GLOBAL, sizeof(GLOBAL) - 4) == 0x37BD7188);
    /* the value the firmware's host test computes for this page */
    assert(cfw_page_version((const uint8_t *)"<html>x</html", 13) == 913657113u);
}

void test_cfw_tbs(void)
{
    assert(cfw_tbs_valid(PROFILE, sizeof(PROFILE)));
    assert(cfw_tbs_valid(GLOBAL, sizeof(GLOBAL)));
    assert(cfw_tbs_timestamp(PROFILE) == 1790000000);

    uint8_t file[CFW_TBS_MAX];
    assert(cfw_tbs_build(1, 1, 1790000000, &PROFILE[12], 7, file) == sizeof(PROFILE));
    assert(memcmp(file, PROFILE, sizeof(PROFILE)) == 0);

    /* one broken rule each */
    memcpy(file, PROFILE, sizeof(PROFILE));
    file[sizeof(PROFILE) - 1] ^= 1;
    assert(!cfw_tbs_valid(file, sizeof(PROFILE)));
    memcpy(file, PROFILE, sizeof(PROFILE));
    file[4] = 4;
    assert(!cfw_tbs_valid(file, sizeof(PROFILE)));
    assert(!cfw_tbs_valid(PROFILE, sizeof(PROFILE) - 1));
    const uint8_t overlong[] = {0x01, 0x05, 0x01};
    size_t length = cfw_tbs_build(1, 1, 0, overlong, sizeof(overlong), file);
    assert(!cfw_tbs_valid(file, length));

    size_t pos = 0;
    cfw_record_t record;
    assert(cfw_tbs_next_record(PROFILE, &pos, &record) && record.key == 0x01 && record.length == 1 && record.value[0] == 1);
    assert(cfw_tbs_next_record(PROFILE, &pos, &record) && record.key == 0x03 && record.length == 2 && record.value[0] == 30);
    assert(!cfw_tbs_next_record(PROFILE, &pos, &record));
}

void test_cfw_ruid(void)
{
    /* UID E0040350DEADBEEF is stored at /ext/EFBEADDE/500304E0.TBS */
    const uint8_t bytes[8] = {0xEF, 0xBE, 0xAD, 0xDE, 0x50, 0x03, 0x04, 0xE0};
    uint8_t out[8];
    assert(cfw_ruid_from_bytes(bytes) == 0xEFBEADDE500304E0ull);
    cfw_ruid_to_bytes(0xEFBEADDE500304E0ull, out);
    assert(memcmp(out, bytes, 8) == 0);
    assert(cfw_ruid_from_words(0xDEADBEEF, 0xE0040350) == 0xEFBEADDE500304E0ull);
}

void test_cfw_event_for_basic_box(void)
{
    /* resume toggle, shuffle off, action 13 toggle, tones off */
    const uint8_t body[] = {0x10, 3, 1, 0, 0, 0x10, 3, 2, 0, 0x80, 0x10, 3, 13, 0, 0, 0x11, 1, 0};
    uint8_t file[CFW_TBS_MAX];
    uint8_t out[CFW_TBS_MAX];
    size_t length = cfw_tbs_build(CFW_TBS_KIND_EVENT, 1, 5, body, sizeof(body), file);
    length = cfw_event_for_basic_box(file, out);
    assert(cfw_tbs_valid(out, length) && cfw_tbs_timestamp(out) == 5);
    const uint8_t expected[] = {0x10, 3, 1, 0, 0};
    assert(length == CFW_TBS_MIN + sizeof(expected) && memcmp(&out[12], expected, sizeof(expected)) == 0);

    const uint8_t nothing[] = {0x10, 3, 13, 0, 0};
    length = cfw_tbs_build(CFW_TBS_KIND_EVENT, 1, 5, nothing, sizeof(nothing), file);
    assert(cfw_event_for_basic_box(file, out) == 0);
}

void test_cfw_report_body(void)
{
    uint8_t body[64];
    /* "toggle shuffle" on a figure without a profile */
    const uint8_t shuffle[] = {0x02, 1, 1};
    assert(cfw_report_body(1 | (1 << 5) | (1 << 13), 0, 0, body) == sizeof(shuffle) && memcmp(body, shuffle, sizeof(shuffle)) == 0);

    /* global file: speaker limit 5, LED dimmed, both-ears switch-off off, volume lock on; profile keys skipped */
    uint32_t packed = 3 | (1 << 4) | (1 << 7) | (1 << 9) | (1 << 10) | (2 << 14);
    uint32_t values = (5 << 16) | (1 << 26) | (1 << 29);
    const uint8_t global[] = {0x04, 1, 5, 0x06, 1, 2, 0x07, 1, 0, 0x0A, 1, 1};
    assert(cfw_report_body(packed, values, 0, body) == sizeof(global) && memcmp(body, global, sizeof(global)) == 0);

    /* global file with the idle power-off times: 2 minutes on battery, 1440 on the station */
    const uint8_t idle[] = {0x0B, 2, 2, 0, 0x0C, 2, 0xA0, 0x05};
    assert(cfw_report_body(3 | (1 << 17) | (1 << 18), 0, 2 | (1440 << 16), body) == sizeof(idle) && memcmp(body, idle, sizeof(idle)) == 0);
    assert(cfw_report_body(1 | (1 << 17), 0, 2, body) == 0);
}

void test_cfw_strip_volume_fields(void)
{
    /* fields 1 (fixed64), 2, 3, 4, 7 and 101 */
    uint8_t message[] = {0x09, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 7, 0x18, 3, 0x20, 1, 0x38, 2, 0xA8, 0x06, 0x01};
    const uint8_t expected[] = {0x09, 1, 2, 3, 4, 5, 6, 7, 8, 0x10, 7, 0x20, 1, 0xA8, 0x06, 0x01};
    assert(cfw_strip_volume_fields(message, sizeof(message)) == sizeof(expected));
    assert(memcmp(message, expected, sizeof(expected)) == 0);

    uint8_t broken[] = {0x18};
    assert(cfw_strip_volume_fields(broken, sizeof(broken)) == sizeof(broken));
}

/* a synthetic app image: header, one segment with the app description, a server block and a build block */
static size_t esp32_image(uint8_t *d)
{
    memset(d, 0, 1024);
    d[0] = 0xE9;
    d[1] = 1;    /* one segment */
    d[2] = 2;    /* DIO */
    d[3] = 0x3F; /* 8 MB, 80 MHz */
    d[12] = 9;   /* ESP32-S3 */
    d[23] = 1;   /* hash appended */
    cfw_put_le32(&d[24], 0x3C000020u);
    cfw_put_le32(&d[28], 600);
    cfw_put_le32(&d[32], 0xABCD5432u);
    memcpy(&d[32 + 16], "CFW_0.1.0", 9);
    memcpy(&d[32 + 48], CFW_ESP32_PROJECT, sizeof(CFW_ESP32_PROJECT) - 1);
    memcpy(&d[300], "CFWSRV01", 8);
    uint8_t *b = &d[400];
    cfw_put_le32(&b[0], 0xBEAC0005u);
    cfw_put_le32(&b[8], 1791920934u);
    memcpy(&b[93], "CFW1", 4);
    cfw_put_le32(&b[108], 0xBEAC0005u);
    /* segment ends at 32 + 600 = 632, checksum at 639, hash 640..671 */
    d[639] = cfw_esp32_checksum(d, 1024);
    return 672;
}

void test_cfw_esp32_image(void)
{
    uint8_t d[1024];
    size_t length = esp32_image(d);
    cfw_esp32_image_t image;
    assert(cfw_esp32_parse(d, length, &image));
    assert(image.length == length && image.checksumOffset == 639 && image.hashAppended);
    assert(image.chipId == 9 && strcmp(image.project, CFW_ESP32_PROJECT) == 0 && strcmp(image.version, "CFW_0.1.0") == 0);
    assert(image.serverBlocks == 1 && image.serverBlock == 300);
    assert(image.buildBlocks == 1 && image.buildBlock == 400 && cfw_le32(&d[408]) == 1791920934u);
    assert(cfw_esp32_checksum(d, length) == d[639]);

    /* the server block filled in changes the checksum */
    assert(cfw_esp32_set_server(d, &image, "203.0.113.123", 8443));
    assert(memcmp(&d[308], "203.0.113.123", 14) == 0 && d[372] == (8443 & 0xFF) && d[373] == (8443 >> 8));
    assert(cfw_esp32_checksum(d, length) != d[639]);
    char longHost[70];
    memset(longHost, 'a', 65);
    longHost[65] = '\0';
    assert(!cfw_esp32_set_server(d, &image, longHost, 443));

    /* cut short, or no app image */
    assert(!cfw_esp32_parse(d, 600, &image));
    d[0] = 0;
    assert(!cfw_esp32_parse(d, length, &image));
}

/* the original firmware in a flash dump: the slot with the highest version, its build time, the
   host patch */
void test_cfw_esp32_original(void)
{
    static uint8_t dump[0x4000 + 3 * 1024];
    memset(dump, 0xFF, sizeof(dump));
    /* three app slots at 0x4000 (a short dump: the table only needs to point into it) */
    const char *versions[3] = {"v5.226.0", "v5.233.1", "v5.99.9"};
    for (int n = 0; n < 3; n++)
    {
        uint8_t *slot = &dump[0x4000 + n * 1024];
        esp32_image(slot);
        memset(&slot[32 + 16], 0, 64);
        memcpy(&slot[32 + 16], versions[n], strlen(versions[n]));
        memcpy(&slot[32 + 48], CFW_ESP32_PROJECT_ORIGINAL, sizeof(CFW_ESP32_PROJECT_ORIGINAL) - 1);
    }
    static uint8_t big[0xA000 + 3 * 1024];
    memset(big, 0xFF, sizeof(big));
    memcpy(&big[0xA000], &dump[0x4000], 3 * 1024);
    for (int n = 0; n < 4; n++)
    {
        uint8_t *e = &big[0x9000 + n * 32];
        e[0] = 0xAA;
        e[1] = 0x50;
        e[2] = n < 3 ? 0 : 1; /* three app slots, then a data partition */
        e[3] = (uint8_t)(0x10 + n);
        cfw_put_le32(&e[4], n < 3 ? 0xA000u + n * 1024u : 0x9000u);
        cfw_put_le32(&e[8], 1024);
    }
    size_t offset = 0;
    assert(cfw_esp32_dump_app(big, sizeof(big), CFW_ESP32_PROJECT_ORIGINAL, &offset) && offset == 0xA000 + 1024);
    assert(!cfw_esp32_dump_app(big, sizeof(big), CFW_ESP32_PROJECT, &offset));
    assert(!cfw_esp32_dump_app(big, 0x9000, CFW_ESP32_PROJECT_ORIGINAL, &offset));

    assert(cfw_esp32_version_number("v5.226.0") == 5226000u && cfw_esp32_version_number("CFW_0.1.10") == 1010u);
    assert(cfw_esp32_version_number("v5.233.1") > cfw_esp32_version_number("v5.99.9"));

    uint8_t *app = &big[0xA000];
    memcpy(&app[32 + 80], "12:34:56", 9);
    memcpy(&app[32 + 96], "Oct  9 2025", 12);
    assert(cfw_esp32_build_time(app) == 1760013296u); /* 2025-10-09 12:34:56 UTC */
    memcpy(&app[32 + 96], "Foo  9 2025", 12);
    assert(cfw_esp32_build_time(app) == 0);
    memcpy(&app[32 + 96], "Oct  9 2025", 12);
    memcpy(&app[32 + 80], "1:34:56", 8); /* not hh:mm:ss */
    assert(cfw_esp32_build_time(app) == 0);
    memset(&app[32 + 80], 0, 32); /* empty, as in the original firmware */
    assert(cfw_esp32_build_time(app) == 0);

    uint8_t text[] = "\0https://prod.de.tbs.toys\0rtnl.bxcl.de\0xrtnl.bxcl.de.evil\0";
    assert(cfw_esp32_replace_string(text, sizeof(text), "prod.de.tbs.toys", "tc.example") == 1);
    assert(memcmp(&text[1], "https://tc.example\0\0\0\0\0\0\0", 25) == 0);
    assert(cfw_esp32_replace_string(text, sizeof(text), "rtnl.bxcl.de", "tc.example") == 1);
    assert(memcmp(&text[26], "tc.example\0\0\0x", 14) == 0);
    /* a longer host would overwrite what follows */
    assert(cfw_esp32_replace_string(text, sizeof(text), "tc.example", "203.0.113.123") == 0);
}

/* release package: a zip with stored files, the way tools/release.sh writes it */
static const uint8_t ZIP_STORED[] = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x90, 0x4F, 0x5D, 0xA5, 0x20, 0x17, 0xDB, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x63, 0x63, 0x33, 0x32, 0x30, 0x30, 0x2F, 0x6E, 0x67, 0x2D, 0x63, 0x66, 0x77, 0x2E, 0x62, 0x69, 0x6E, 0x41, 0x42, 0x43, 0x44, 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x90, 0x4F, 0x5D, 0x58, 0x53, 0x88, 0x2A, 0x0D, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x68, 0x74, 0x6D, 0x3C, 0x68, 0x74, 0x6D, 0x6C, 0x3E, 0x78, 0x3C, 0x2F, 0x68, 0x74, 0x6D, 0x6C, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x90, 0x4F, 0x5D, 0xA5, 0x20, 0x17, 0xDB, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x63, 0x63, 0x33, 0x32, 0x30, 0x30, 0x2F, 0x6E, 0x67, 0x2D, 0x63, 0x66, 0x77, 0x2E, 0x62, 0x69, 0x6E, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x90, 0x4F, 0x5D, 0x58, 0x53, 0x88, 0x2A, 0x0D, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x33, 0x00, 0x00, 0x00, 0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x68, 0x74, 0x6D, 0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x76, 0x00, 0x00, 0x00, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00};
static const uint8_t ZIP_DEFLATED[] = {0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0xBA, 0x90, 0x4F, 0x5D, 0xA5, 0x20, 0x17, 0xDB, 0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x63, 0x63, 0x33, 0x32, 0x30, 0x30, 0x2F, 0x6E, 0x67, 0x2D, 0x63, 0x66, 0x77, 0x2E, 0x62, 0x69, 0x6E, 0x73, 0x74, 0x72, 0x76, 0x01, 0x00, 0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0xBA, 0x90, 0x4F, 0x5D, 0x58, 0x53, 0x88, 0x2A, 0x0C, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x68, 0x74, 0x6D, 0xB3, 0xC9, 0x28, 0xC9, 0xCD, 0xB1, 0xAB, 0xB0, 0xD1, 0x07, 0xD1, 0x00, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0xBA, 0x90, 0x4F, 0x5D, 0xA5, 0x20, 0x17, 0xDB, 0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x63, 0x63, 0x33, 0x32, 0x30, 0x30, 0x2F, 0x6E, 0x67, 0x2D, 0x63, 0x66, 0x77, 0x2E, 0x62, 0x69, 0x6E, 0x50, 0x4B, 0x01, 0x02, 0x14, 0x03, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0xBA, 0x90, 0x4F, 0x5D, 0x58, 0x53, 0x88, 0x2A, 0x0C, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x35, 0x00, 0x00, 0x00, 0x73, 0x65, 0x74, 0x75, 0x70, 0x2E, 0x68, 0x74, 0x6D, 0x50, 0x4B, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00, 0x76, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00};

void test_cfw_zip(void)
{
    size_t pos = 0;
    cfw_zip_entry_t e;
    assert(cfw_zip_is(ZIP_STORED, sizeof(ZIP_STORED)));
    assert(!cfw_zip_is((const uint8_t *)"\xE9\x06", 2));
    assert(cfw_zip_next(ZIP_STORED, sizeof(ZIP_STORED), &pos, &e));
    assert(e.method == 0 && e.nameLength == 17 && !memcmp(e.name, "cc3200/ng-cfw.bin", 17) && e.size == 4 && !memcmp(e.data, "ABCD", 4));
    assert(cfw_zip_next(ZIP_STORED, sizeof(ZIP_STORED), &pos, &e));
    assert(e.nameLength == 9 && !memcmp(e.name, "setup.htm", 9) && e.size == 13 && !memcmp(e.data, "<html>x</html", 13));
    assert(!cfw_zip_next(ZIP_STORED, sizeof(ZIP_STORED), &pos, &e)); /* the central directory follows */

    /* a compressed file is reported with its method, not as data */
    pos = 0;
    assert(cfw_zip_next(ZIP_DEFLATED, sizeof(ZIP_DEFLATED), &pos, &e) && e.method == 8);

    /* cut short inside the first file's data */
    pos = 0;
    assert(!cfw_zip_next(ZIP_STORED, 50, &pos, &e));
}

void test_cfw_page_label(void)
{
    char label[32];
    const char *page = "<html><head><meta charset=\"utf-8\">\n<meta name=\"cfw-page-version\" content=\"CFW_0.1.15\">";
    assert(cfw_page_label((const uint8_t *)page, strlen(page), label, sizeof(label)) && !strcmp(label, "CFW_0.1.15"));
    const char *none = "<html><head><title>x</title>";
    assert(!cfw_page_label((const uint8_t *)none, strlen(none), label, sizeof(label)));
    /* cut off, too long or with a quote missing: none */
    assert(!cfw_page_label((const uint8_t *)page, strlen(page) - 3, label, sizeof(label)));
    assert(!cfw_page_label((const uint8_t *)page, strlen(page), label, 5));
    const char *needs = "<meta name=\"cfw-page-version\" content=\"1.0\">\n<meta name=\"cfw-page-requires\" content=\"CFW_0.1.6\">";
    assert(cfw_page_meta((const uint8_t *)needs, strlen(needs), "cfw-page-requires", label, sizeof(label)) && !strcmp(label, "CFW_0.1.6"));
    assert(cfw_page_label((const uint8_t *)needs, strlen(needs), label, sizeof(label)) && !strcmp(label, "1.0"));
}

void test_cfw_version_older(void)
{
    assert(cfw_version_older("CFW_0.1.5", "CFW_0.1.6"));
    assert(cfw_version_older("CFW_0.1.9", "CFW_0.1.10")); /* numbers, not text */
    assert(cfw_version_older("CFW_0.9.99", "CFW_1.0.0"));
    assert(!cfw_version_older("CFW_0.1.17", "CFW_0.1.6"));
    assert(!cfw_version_older("CFW_0.1.6", "CFW_0.1.6"));
    /* not a version: never older */
    assert(!cfw_version_older("", "CFW_0.1.6"));
    assert(!cfw_version_older("v5.233.0", "CFW_0.1.6"));
    assert(!cfw_version_older("CFW_0.1.5", ""));
}
