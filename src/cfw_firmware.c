#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cfw_internal.h"
#include "cloud_request.h"
#include "debug.h"
#include "esp32_port.h"
#include "fs_ext.h"
#include "hash/sha256.h"
#include "mutex_manager.h"
#include "os_port.h"
#include "server_helpers.h"

/* an image, trailer included, larger than this is refused by the box */
#define CFW_IMAGE_MAX 212992
/* an ESP32 image with its digest text */
#define CFW_ESP32_BODY_MAX (CFW_ESP32_SLOT_SIZE + 64)
/* a flash dump of the ESP32 box, which may hold the original firmware */
#define CFW_ESP32_DUMP_MAX 0x1000000
#define CFW_BUILD_BLOCK_MAGIC 0xBEAC0005u
/* a CA bundle of the system is some 200 KB */
#define CFW_CA_BUNDLE_MAX (4 * 1024 * 1024)
/* starts without the offered image running, after which it counts as rolled back */
#define CFW_OFFER_ATTEMPTS 3

static const char *channel_names[] = {"none", "release", "beta", "alpha"};

static cJSON *github_releases = NULL;
static time_t github_last_check = 0;
static char github_message[256] = "";
static bool github_running = false;

const char *cfw_channel_name(uint32_t channel)
{
    return channel < 4 ? channel_names[channel] : channel_names[CFW_CHANNEL_NONE];
}

uint32_t cfw_channel_parse(const char *name)
{
    for (uint32_t i = 0; name != NULL && i < 4; i++)
    {
        if (!osStrcasecmp(name, channel_names[i]))
        {
            return i;
        }
    }
    return CFW_CHANNEL_NONE;
}

void cfw_library_lock(void)
{
    mutex_lock(MUTEX_CFW_LIBRARY);
}

void cfw_library_unlock(void)
{
    mutex_unlock(MUTEX_CFW_LIBRARY);
}

static bool is_esp32(const char *platform)
{
    return platform != NULL && osStrcmp(platform, CFW_PLATFORM_ESP32) == 0;
}

/* <build>.<extension> for the CC3200, esp32-<build>.<extension> for the ESP32: images of both platforms built
   from the same commit carry the same build number */
static char *firmware_path(const char *platform, uint32_t build, const char *extension)
{
    char *dir = cfw_dir(get_settings()->internal.firmwaredirfull, "");
    char *path = dir ? custom_asprintf("%s%s%" PRIu32 ".%s", dir, is_esp32(platform) ? "esp32-" : "", build, extension) : NULL;
    osFreeMem(dir);
    return path;
}

/* a file name of its own for each download or upload running at the same time */
char *cfw_firmware_temp_path(void)
{
    uint32_t number = cfw_temp_number();
    char *dir = cfw_dir(get_settings()->internal.firmwaredirfull, "");
    char *path = dir ? custom_asprintf("%sincoming-%" PRIu32 ".tmp", dir, number) : NULL;
    osFreeMem(dir);
    return path;
}

static void copy_text(char *out, size_t outSize, const uint8_t *in, size_t inSize)
{
    size_t n = 0;
    for (; n < inSize && n + 1 < outSize && in[n] != '\0'; n++)
    {
        out[n] = isprint(in[n]) ? in[n] : '?';
    }
    out[n] = '\0';
}

/* the version text "CFW_x.y.z" of the image */
static void find_version(const uint8_t *data, size_t length, char *version, size_t versionSize)
{
    version[0] = '\0';
    for (size_t i = 0; i + 5 < length; i++)
    {
        if (osMemcmp(&data[i], "CFW_", 4) == 0 && isdigit(data[i + 4]))
        {
            size_t n = 4;
            while (i + n < length && n < 15 && (isdigit(data[i + n]) || data[i + n] == '.'))
            {
                n++;
            }
            copy_text(version, versionSize, &data[i], n);
            return;
        }
    }
}

static void hex_text(const uint8_t digest[32], char hex[65])
{
    for (int i = 0; i < 32; i++)
    {
        osSprintf(&hex[2 * i], "%02x", digest[i]);
    }
}

static void hex_digest(const uint8_t *data, size_t length, char hex[65])
{
    uint8_t digest[32];
    sha256Compute(data, length, digest);
    hex_text(digest, hex);
}

/* an app image of the ESP32 box, with or without its digest text: the custom firmware, or the original firmware
   for the return; exact: nothing but the image and its digest text may follow; *imageLength: its length without
   the text */
static bool check_esp32(const uint8_t *data, size_t size, bool exact, cfw_image_t *image, size_t *imageLength, char *message, size_t messageSize)
{
    cfw_esp32_image_t esp;
    if (!cfw_esp32_parse(data, size, &esp))
    {
        osSnprintf(message, messageSize, "no complete ESP32 app image");
        return false;
    }
    bool original = osStrcmp(esp.project, CFW_ESP32_PROJECT_ORIGINAL) == 0;
    uint8_t hash[32];
    sha256Compute(data, esp.checksumOffset + 1, hash);
    char hex[65];
    if (exact && size != esp.length && size != esp.length + 64)
    {
        osSnprintf(message, messageSize, "%" PRIuSIZE " bytes after the image, neither none nor a digest text", size - esp.length);
    }
    else if (exact && size == esp.length + 64 && (hex_digest(data, esp.length, hex), osMemcmp(hex, &data[esp.length], 64) != 0))
    {
        osSnprintf(message, messageSize, "the SHA-256 digest at the end of the image does not match");
    }
    else if (esp.chipId != 9)
    {
        osSnprintf(message, messageSize, "not an image for the ESP32-S3 (chip ID %u)", esp.chipId);
    }
    else if (!original && (esp.flashMode != 2 || esp.flashSizeFreq != 0x3F))
    {
        osSnprintf(message, messageSize, "flash mode or size not DIO, 80 MHz, 8 MB");
    }
    else if (esp.length > CFW_ESP32_SLOT_SIZE)
    {
        osSnprintf(message, messageSize, "image larger than an app slot");
    }
    else if (!esp.hashAppended || osMemcmp(hash, &data[esp.checksumOffset + 1], 32) != 0 ||
             cfw_esp32_checksum(data, esp.length) != data[esp.checksumOffset])
    {
        osSnprintf(message, messageSize, "checksum or appended SHA-256 of the image wrong");
    }
    else if (original)
    {
        /* the original firmware has no build number and leaves the date and time of its app description empty:
           a number from its digest stands in, below every build number of the custom firmware */
        osMemset(image, 0, sizeof(*image));
        image->build = 1 + cfw_le32(hash) % 1000000000u;
        image->original = true;
        copy_text(image->version, sizeof(image->version), (const uint8_t *)esp.version, sizeof(esp.version));
        copy_text(image->buildDate, sizeof(image->buildDate), &data[32 + 96], 16);
        size_t dateLength = osStrlen(image->buildDate);
        if (dateLength + 1 < sizeof(image->buildDate))
        {
            image->buildDate[dateLength] = ' ';
            copy_text(&image->buildDate[dateLength + 1], sizeof(image->buildDate) - dateLength - 1, &data[32 + 80], 16);
        }
        image->size = esp.length + 64;
        osStrcpy(image->platform, CFW_PLATFORM_ESP32);
        *imageLength = esp.length;
        return true;
    }
    else if (osStrcmp(esp.project, CFW_ESP32_PROJECT) != 0)
    {
        osSnprintf(message, messageSize, "project \"%s\" is neither the custom firmware (%s) nor the original firmware (%s)", esp.project,
                   CFW_ESP32_PROJECT, CFW_ESP32_PROJECT_ORIGINAL);
    }
    else if (esp.serverBlocks != 1)
    {
        osSnprintf(message, messageSize, "server block missing or not once");
    }
    else if (esp.buildBlocks != 0)
    {
        osSnprintf(message, messageSize, "the image carries a build block: an ESP32 build from before 2026-10-14");
    }
    else if (cfw_esp32_build_time(data) == 0)
    {
        osSnprintf(message, messageSize, "build date and time of the app description empty or unreadable");
    }
    else
    {
        /* the build number is the build date and time of the app description, read as UTC */
        osMemset(image, 0, sizeof(*image));
        image->build = cfw_esp32_build_time(data);
        copy_text(image->buildDate, sizeof(image->buildDate), &data[32 + 96], 16);
        size_t dateLength = osStrlen(image->buildDate);
        if (dateLength + 1 < sizeof(image->buildDate))
        {
            image->buildDate[dateLength] = ' ';
            copy_text(&image->buildDate[dateLength + 1], sizeof(image->buildDate) - dateLength - 1, &data[32 + 80], 16);
        }
        copy_text(image->version, sizeof(image->version), (const uint8_t *)esp.version, sizeof(esp.version));
        image->size = esp.length + 64;
        osStrcpy(image->platform, CFW_PLATFORM_ESP32);
        *imageLength = esp.length;
        if (image->build <= CFW_REFERENCE_BUILD)
        {
            osSnprintf(message, messageSize, "build number %" PRIu32 " is not a build of the custom firmware", image->build);
            return false;
        }
        return true;
    }
    return false;
}

/* checksum and appended SHA-256 of an app image after a change */
static void esp32_fix(uint8_t *data, const cfw_esp32_image_t *esp)
{
    data[esp->checksumOffset] = cfw_esp32_checksum(data, esp->length);
    sha256Compute(data, esp->checksumOffset + 1, &data[esp->checksumOffset + 1]);
}

static bool host_valid(const char *host)
{
    size_t length = osStrlen(host);
    for (size_t i = 0; i < length; i++)
    {
        if (!isalnum((unsigned char)host[i]) && host[i] != '.' && host[i] != '-')
        {
            return false;
        }
    }
    return length > 0 && length <= 64;
}

/* teddyCloud's patches of an original image (length bytes, without digest text), as its ESP32 flash tool makes
   them: the server hosts and the port; checksum and hash fixed; a description into image->patches */
static bool esp32_patch(uint8_t *data, size_t length, const cfw_esp32_patch_t *patch, cfw_image_t *image, char *message, size_t messageSize)
{
    static const char *vendorHosts[] = {"prod.de.tbs.toys", "rtnl.bxcl.de"};
    char done[sizeof(image->patches)] = "";
    if (patch->host[0] != '\0')
    {
        const char *from[2] = {vendorHosts[0], vendorHosts[1]};
        size_t count = 2;
        if (patch->hostOld[0] != '\0')
        {
            from[0] = patch->hostOld;
            count = 1;
        }
        if (!host_valid(patch->host) || (patch->hostOld[0] != '\0' && !host_valid(patch->hostOld)))
        {
            osSnprintf(message, messageSize, "a host may hold letters, digits, dots and dashes only");
            return false;
        }
        size_t replaced = 0;
        for (size_t i = 0; i < count; i++)
        {
            if (osStrlen(patch->host) > osStrlen(from[i]))
            {
                osSnprintf(message, messageSize, "the host may have at most %" PRIuSIZE " characters, the length of %s", osStrlen(from[i]), from[i]);
                return false;
            }
            replaced += cfw_esp32_replace_string(data, length, from[i], patch->host);
        }
        if (replaced == 0)
        {
            osSnprintf(message, messageSize, "%s not found in the image; give the host it holds now as the old host", count == 2 ? "the vendor's hosts are" : "the old host is");
            return false;
        }
        osSnprintf(done, sizeof(done), "host %s (%" PRIuSIZE " times)", patch->host, replaced);
    }
    if (patch->port != 0)
    {
        if (!esp32_port_supported(patch->port))
        {
            osSnprintf(message, messageSize, "port %u not supported, must be 1..32767", patch->port);
            return false;
        }
        if (esp32_port_patch(data, length, patch->port) == 0)
        {
            osSnprintf(message, messageSize, "the port cannot be patched in this version of the original firmware");
            return false;
        }
        size_t used = osStrlen(done);
        osSnprintf(&done[used], sizeof(done) - used, "%sport %u", used ? ", " : "", patch->port);
    }
    cfw_esp32_image_t esp;
    if (!cfw_esp32_parse(data, length, &esp))
    {
        osSnprintf(message, messageSize, "the patched image is no app image");
        return false;
    }
    esp32_fix(data, &esp);
    osStrcpy(image->patches, done);
    return true;
}

/* digest text, build block and family marker of a slot image */
static bool check_image(const uint8_t *data, size_t size, cfw_image_t *image, char *message, size_t messageSize)
{
    if (size < 177 || size > CFW_IMAGE_MAX)
    {
        osSnprintf(message, messageSize, "size %" PRIuSIZE " is not that of a slot image (177 to %d bytes)", size, CFW_IMAGE_MAX);
        return false;
    }
    char hex[65];
    hex_digest(data, size - 64, hex);
    const uint8_t *block = &data[size - 176];
    if (osMemcmp(hex, &data[size - 64], 64) != 0)
    {
        osSnprintf(message, messageSize, "the SHA-256 digest at the end of the image does not match");
    }
    else if (cfw_le32(&block[0]) != CFW_BUILD_BLOCK_MAGIC || cfw_le32(&block[108]) != CFW_BUILD_BLOCK_MAGIC || (block[92] & 7) > 3)
    {
        osSnprintf(message, messageSize, "no valid build block");
    }
    else if (osMemcmp(&block[93], "CFW1", 4) != 0)
    {
        osSnprintf(message, messageSize, "not an image of the custom firmware (family marker CFW1 missing)");
    }
    else if (cfw_le32(&block[12]) != 0)
    {
        osSnprintf(message, messageSize, "debug build, the box would refuse it");
    }
    else if (cfw_le32(&block[100]) != 2)
    {
        osSnprintf(message, messageSize, "not an application image");
    }
    else if (cfw_le32(&block[8]) <= CFW_REFERENCE_BUILD)
    {
        osSnprintf(message, messageSize, "build number %" PRIu32 " is not a build of the custom firmware", cfw_le32(&block[8]));
    }
    else
    {
        osMemset(image, 0, sizeof(*image));
        image->build = cfw_le32(&block[8]);
        copy_text(image->revision, sizeof(image->revision), &block[16], 8);
        copy_text(image->buildDate, sizeof(image->buildDate), &block[24], 61);
        find_version(data, size - 176, image->version, sizeof(image->version));
        image->size = size;
        osStrcpy(image->platform, CFW_PLATFORM_CC3200);
        return true;
    }
    return false;
}

bool cfw_firmware_save_meta(const cfw_image_t *image)
{
    cJSON *json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "build", image->build);
    cJSON_AddStringToObject(json, "version", image->version);
    cJSON_AddStringToObject(json, "revision", image->revision);
    cJSON_AddStringToObject(json, "buildDate", image->buildDate);
    cJSON_AddStringToObject(json, "channel", cfw_channel_name(image->channel));
    cJSON_AddStringToObject(json, "source", image->source);
    cJSON_AddStringToObject(json, "githubTag", image->githubTag);
    cJSON_AddStringToObject(json, "notes", image->notes);
    cJSON_AddNumberToObject(json, "added", (double)image->added);
    cJSON_AddNumberToObject(json, "size", image->size);
    cJSON_AddStringToObject(json, "platform", image->platform);
    cJSON_AddBoolToObject(json, "original", image->original);
    cJSON_AddStringToObject(json, "patches", image->patches);
    cJSON_AddNumberToObject(json, "page", image->page);
    cJSON_AddStringToObject(json, "pageLabel", image->pageLabel);
    cJSON_AddStringToObject(json, "pageRequires", image->pageRequires);
    char *text = cJSON_Print(json);
    cJSON_Delete(json);
    char *path = firmware_path(image->platform, image->build, "json");
    bool saved = text != NULL && path != NULL && cfw_write_file(path, text, osStrlen(text));
    osFreeMem(path);
    osFreeMem(text);
    return saved;
}

static void json_text(cJSON *json, const char *name, char *out, size_t outSize)
{
    cJSON *item = cJSON_GetObjectItemCaseSensitive(json, name);
    osStrncpy(out, cJSON_IsString(item) && item->valuestring ? item->valuestring : "", outSize - 1);
    out[outSize - 1] = '\0';
}

static bool load_meta(const char *platform, uint32_t build, cfw_image_t *image)
{
    char *path = firmware_path(platform, build, "json");
    size_t length = 0;
    char *text = path ? (char *)cfw_read_file(path, 16384, &length) : NULL;
    cJSON *json = text ? cJSON_Parse(text) : NULL;
    osFreeMem(text);
    osFreeMem(path);
    if (json == NULL)
    {
        return false;
    }
    char channel[16];
    osMemset(image, 0, sizeof(*image));
    image->build = build;
    json_text(json, "version", image->version, sizeof(image->version));
    json_text(json, "revision", image->revision, sizeof(image->revision));
    json_text(json, "buildDate", image->buildDate, sizeof(image->buildDate));
    json_text(json, "channel", channel, sizeof(channel));
    image->channel = cfw_channel_parse(channel);
    json_text(json, "source", image->source, sizeof(image->source));
    json_text(json, "githubTag", image->githubTag, sizeof(image->githubTag));
    json_text(json, "notes", image->notes, sizeof(image->notes));
    json_text(json, "platform", image->platform, sizeof(image->platform));
    image->original = cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(json, "original"));
    json_text(json, "patches", image->patches, sizeof(image->patches));
    cJSON *added = cJSON_GetObjectItemCaseSensitive(json, "added");
    cJSON *size = cJSON_GetObjectItemCaseSensitive(json, "size");
    cJSON *page = cJSON_GetObjectItemCaseSensitive(json, "page");
    image->page = cJSON_IsNumber(page) ? (uint32_t)page->valuedouble : 0;
    json_text(json, "pageLabel", image->pageLabel, sizeof(image->pageLabel));
    json_text(json, "pageRequires", image->pageRequires, sizeof(image->pageRequires));
    image->added = cJSON_IsNumber(added) ? (time_t)added->valuedouble : 0;
    image->size = cJSON_IsNumber(size) ? (uint32_t)size->valuedouble : 0;
    cJSON_Delete(json);
    return true;
}

bool cfw_firmware_get(const char *platform, uint32_t build, cfw_image_t *image)
{
    char *path = firmware_path(platform, build, "bin");
    bool exists = path != NULL && fsFileExists(path);
    osFreeMem(path);
    return exists && load_meta(platform, build, image);
}

/* newest build first */
static int compare_builds(const void *a, const void *b)
{
    uint32_t x = ((const cfw_image_t *)a)->build;
    uint32_t y = ((const cfw_image_t *)b)->build;
    return (x < y) - (x > y);
}

size_t cfw_firmware_list(cfw_image_t **images)
{
    size_t count = 0;
    size_t size = 0;
    *images = NULL;

    char *dir = cfw_dir(get_settings()->internal.firmwaredirfull, "");
    FsDir *fsDir = dir ? fsOpenDir(dir) : NULL;
    osFreeMem(dir);
    if (fsDir == NULL)
    {
        return 0;
    }
    FsDirEntry entry;
    while (fsReadDir(fsDir, &entry) == NO_ERROR)
    {
        char *end = NULL;
        bool esp32 = osStrncmp(entry.name, "esp32-", 6) == 0;
        unsigned long build = strtoul(esp32 ? &entry.name[6] : entry.name, &end, 10);
        if ((entry.attributes & FS_FILE_ATTR_DIRECTORY) || build == 0 || osStrcmp(end, ".bin") != 0)
        {
            continue;
        }
        if (count == size)
        {
            size = size ? size * 2 : 8;
            cfw_image_t *grown = osAllocMem(size * sizeof(cfw_image_t));
            if (grown == NULL)
            {
                break;
            }
            if (count > 0)
            {
                osMemcpy(grown, *images, count * sizeof(cfw_image_t));
            }
            osFreeMem(*images);
            *images = grown;
        }
        if (load_meta(esp32 ? CFW_PLATFORM_ESP32 : CFW_PLATFORM_CC3200, (uint32_t)build, &(*images)[count]))
        {
            count++;
        }
    }
    fsCloseDir(fsDir);
    if (count > 1)
    {
        qsort(*images, count, sizeof(cfw_image_t), compare_builds);
    }
    return count;
}

static bool firmware_add(const char *tmpPath, uint32_t channel, const char *source, const char *githubTag, const char *notes,
                         const cfw_esp32_patch_t *patch, cfw_image_t *image, char *message, size_t messageSize)
{
    size_t size = 0;
    uint8_t *data = cfw_read_file(tmpPath, CFW_ESP32_DUMP_MAX, &size);
    bool valid = false;
    bool patching = patch != NULL && (patch->host[0] != '\0' || patch->port != 0);
    if (data != NULL && size > 0 && data[0] == 0xE9)
    {
        /* an ESP32 image is kept as the body of its delivery: the image and its digest text; from a
           flash dump, the original firmware of its slots */
        size_t start = 0;
        size_t imageLength = 0;
        bool dump = size > CFW_ESP32_BODY_MAX;
        if (dump && !cfw_esp32_dump_app(data, size, CFW_ESP32_PROJECT_ORIGINAL, &start))
        {
            osSnprintf(message, messageSize, "neither an app image nor a flash dump with the original firmware in an app slot");
        }
        else
        {
            valid = check_esp32(&data[start], size - start, !dump, image, &imageLength, message, messageSize);
        }
        if (valid && patching && !image->original)
        {
            osSnprintf(message, messageSize, "patches apply to the original firmware only");
            valid = false;
        }
        if (valid && patching)
        {
            valid = esp32_patch(&data[start], imageLength, patch, image, message, messageSize);
        }
        if (valid && (dump || patching || size == imageLength))
        {
            char hex[65];
            hex_digest(&data[start], imageLength, hex);
            FsFile *file = fsOpenFile(tmpPath, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC);
            valid = file != NULL && fsWriteFile(file, &data[start], imageLength) == NO_ERROR && fsWriteFile(file, hex, 64) == NO_ERROR;
            if (file != NULL)
            {
                fsCloseFile(file);
            }
            if (!valid)
            {
                osSnprintf(message, messageSize, "could not store the image");
            }
        }
        cfw_image_t old;
        if (valid && image->original && load_meta(image->platform, image->build, &old) && !old.original)
        {
            osSnprintf(message, messageSize, "build number %" PRIu32 " is taken by an image of the custom firmware", image->build);
            valid = false;
        }
    }
    else if (patching)
    {
        osSnprintf(message, messageSize, "patches apply to the original firmware of the ESP32 box only");
    }
    else if (data != NULL)
    {
        /* not an ESP32 image: a CC3200 slot image, which has its own limit */
        valid = check_image(data, size, image, message, messageSize);
    }
    osFreeMem(data);
    if (data == NULL || (!valid && message[0] == '\0'))
    {
        osSnprintf(message, messageSize, "no image or larger than %d bytes", CFW_ESP32_DUMP_MAX);
    }
    char *path = valid ? firmware_path(image->platform, image->build, "bin") : NULL;
    if (valid && (path == NULL || fsMoveFile(tmpPath, path, true) != NO_ERROR))
    {
        osSnprintf(message, messageSize, "could not store the image");
        valid = false;
    }
    osFreeMem(path);
    if (!valid)
    {
        fsDeleteFile(tmpPath);
        return false;
    }

    cfw_image_t old;
    bool hadMeta = load_meta(image->platform, image->build, &old);
    image->channel = (channel == CFW_CHANNEL_NONE) ? (hadMeta ? old.channel : CFW_CHANNEL_BETA) : channel;
    osStrncpy(image->source, source, sizeof(image->source) - 1);
    osStrncpy(image->githubTag, githubTag, sizeof(image->githubTag) - 1);
    osStrncpy(image->notes, hadMeta && notes[0] == '\0' ? old.notes : notes, sizeof(image->notes) - 1);
    image->added = time(NULL);
    if (image->original)
    {
        image->channel = CFW_CHANNEL_NONE; /* delivered only when assigned */
    }
    cfw_firmware_save_meta(image);
    TRACE_INFO("CFW: %s image build %" PRIu32 " (%s%s) added to channel %s%s%s\r\n", image->platform, image->build, image->version,
               image->original ? ", original firmware" : "", cfw_channel_name(image->channel), image->patches[0] ? ", patches: " : "", image->patches);
    return true;
}

static bool ends_with(const char *name, size_t length, const char *suffix)
{
    size_t n = osStrlen(suffix);
    return length >= n && osStrncasecmp(&name[length - n], suffix, n) == 0;
}

static bool set_page(const char *platform, uint32_t build, const uint8_t *data, size_t size, const char *fallbackLabel, uint32_t *page, char *label,
                     size_t labelSize, char *message, size_t messageSize);

/* files of a release package that install a CC3200 box by hand or in the browser, no images: the SD
   bootloader, its preloader for the flash and the SD card tree */
static bool package_extra(const char *name, size_t length)
{
    return ends_with(name, length, "ngbootloader.bin") || (length >= 13 && osStrncmp(name, "cc3200/flash/", 13) == 0) ||
           (length >= 12 && osStrncmp(name, "cc3200/card/", 12) == 0);
}

/* the images of a release package: every .bin of the zip into the library, its setup.htm as the page
   of each of them; with a card tree the package is kept beside the CC3200 image (<build>.zip), from
   which the web UI installs a box */
static bool import_zip(const uint8_t *zip, size_t length, uint32_t channel, const char *source, const char *githubTag, const char *notes,
                       cfw_image_t *images, size_t *count, char *message, size_t messageSize)
{
    size_t pos = 0;
    size_t max = *count;
    cfw_zip_entry_t entry;
    const uint8_t *page = NULL;
    size_t pageSize = 0;
    bool failed = false;
    bool card = false;
    *count = 0;
    while (cfw_zip_next(zip, length, &pos, &entry))
    {
        bool extra = package_extra(entry.name, entry.nameLength);
        card |= extra && osStrncmp(entry.name, "cc3200/card/", 12) == 0;
        bool bin = !extra && ends_with(entry.name, entry.nameLength, ".bin");
        bool htm = !extra && ends_with(entry.name, entry.nameLength, "setup.htm");
        if (!bin && !htm)
        {
            continue;
        }
        if (entry.method != 0)
        {
            osSnprintf(message, messageSize, "%.*s is compressed: use the release package as published (stored, without compression)", (int)entry.nameLength, entry.name);
            return false;
        }
        if (htm)
        {
            page = entry.data;
            pageSize = entry.size;
            continue;
        }
        char *tmp = cfw_firmware_temp_path();
        bool written = tmp != NULL && cfw_write_file(tmp, entry.data, entry.size);
        char one[160] = "";
        if (written && *count < max && firmware_add(tmp, channel, source, githubTag, notes, NULL, &images[*count], one, sizeof(one)))
        {
            (*count)++;
        }
        else
        {
            if (tmp != NULL)
            {
                fsDeleteFile(tmp);
            }
            osSnprintf(message, messageSize, "%.*s: %s", (int)entry.nameLength, entry.name, one[0] ? one : "not stored");
            failed = true;
        }
        osFreeMem(tmp);
    }
    if (*count == 0)
    {
        if (!failed)
        {
            osSnprintf(message, messageSize, "no image in the package");
        }
        return false;
    }
    for (size_t i = 0; card && i < *count; i++)
    {
        char *path = is_esp32(images[i].platform) ? NULL : firmware_path(images[i].platform, images[i].build, "zip");
        if (path != NULL && !cfw_write_file(path, zip, length))
        {
            osSnprintf(message, messageSize, "the package could not be kept for the installation in the browser");
        }
        osFreeMem(path);
    }
    for (size_t i = 0; page != NULL && i < *count; i++)
    {
        char note[128];
        if (set_page(images[i].platform, images[i].build, page, pageSize, images[i].version, &images[i].page, images[i].pageLabel,
                     sizeof(images[i].pageLabel), note, sizeof(note)))
        {
            /* the metadata with the page, as set_page stored it */
            cfw_firmware_get(images[i].platform, images[i].build, &images[i]);
        }
    }
    return true;
}

static bool looks_like_page(const uint8_t *data, size_t size)
{
    size_t i = 0;
    while (i < size && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n' || data[i] == 0xEF || data[i] == 0xBB || data[i] == 0xBF))
    {
        i++;
    }
    return i + 5 <= size && data[i] == '<' && (osStrncasecmp((const char *)&data[i], "<!doc", 5) == 0 || osStrncasecmp((const char *)&data[i], "<html", 5) == 0);
}

/* the default page: <firmwaredir>/cfw/default.htm, beside the pages of the images (<build>.htm); the firmware
   directory is kept across updates and not served as static files */
static char *default_page_path(void)
{
    char *dir = cfw_dir(get_settings()->internal.firmwaredirfull, "");
    char *path = dir ? custom_asprintf("%sdefault.htm", dir) : NULL;
    osFreeMem(dir);
    return path;
}

static void page_label(const uint8_t *data, size_t size, const char *fallbackLabel, uint32_t page, char *label, size_t labelSize)
{
    if (!cfw_page_label(data, size, label, labelSize))
    {
        if (fallbackLabel != NULL && fallbackLabel[0] != '\0')
        {
            osSnprintf(label, labelSize, "%s", fallbackLabel);
        }
        else
        {
            osSnprintf(label, labelSize, "#%08" PRIX32, page);
        }
    }
}

static bool set_page(const char *platform, uint32_t build, const uint8_t *data, size_t size, const char *fallbackLabel, uint32_t *page, char *label,
                     size_t labelSize, char *message, size_t messageSize)
{
    if (size == 0 || size > 65536 || !looks_like_page(data, size))
    {
        osSnprintf(message, messageSize, "no setup page (an HTML file of at most 65536 bytes)");
        return false;
    }
    cfw_image_t image;
    if (build != 0 && !cfw_firmware_get(platform, build, &image))
    {
        osSnprintf(message, messageSize, "image not found");
        return false;
    }
    char *path = build != 0 ? firmware_path(platform, build, "htm") : default_page_path();
    bool written = path != NULL && cfw_write_file(path, data, size);
    osFreeMem(path);
    if (!written)
    {
        osSnprintf(message, messageSize, "could not store the page");
        return false;
    }
    *page = cfw_page_version(data, size);
    page_label(data, size, fallbackLabel, *page, label, labelSize);
    if (build != 0)
    {
        image.page = *page;
        osSnprintf(image.pageLabel, sizeof(image.pageLabel), "%s", label);
        if (!cfw_page_meta(data, size, "cfw-page-requires", image.pageRequires, sizeof(image.pageRequires)))
        {
            image.pageRequires[0] = '\0';
        }
        cfw_firmware_save_meta(&image);
    }
    TRACE_INFO("CFW: setup page %s (%08" PRIX32 ") for %s\r\n", label, *page, build != 0 ? image.version : "images without one");
    return true;
}

bool cfw_firmware_set_page(const char *platform, uint32_t build, const uint8_t *data, size_t size, const char *fallbackLabel, uint32_t *page,
                           char *label, size_t labelSize, char *message, size_t messageSize)
{
    cfw_library_lock();
    bool stored = set_page(platform, build, data, size, fallbackLabel, page, label, labelSize, message, messageSize);
    cfw_library_unlock();
    return stored;
}

uint32_t cfw_firmware_default_page(char *label, size_t labelSize, char *required, size_t requiredSize)
{
    char *path = default_page_path();
    size_t size = 0;
    uint8_t *data = path ? cfw_read_file(path, 65536, &size) : NULL;
    osFreeMem(path);
    uint32_t page = data != NULL && size > 0 ? cfw_page_version(data, size) : 0;
    label[0] = '\0';
    required[0] = '\0';
    if (page != 0)
    {
        page_label(data, size, NULL, page, label, labelSize);
        if (!cfw_page_meta(data, size, "cfw-page-requires", required, requiredSize))
        {
            required[0] = '\0';
        }
    }
    osFreeMem(data);
    return page;
}

static bool firmware_import(const char *tmpPath, uint32_t channel, const char *source, const char *githubTag, const char *notes,
                            const cfw_esp32_patch_t *patch, cfw_image_t *images, size_t *count, char *message, size_t messageSize)
{
    size_t size = 0;
    uint8_t *data = cfw_read_file(tmpPath, CFW_ESP32_DUMP_MAX, &size);
    if (data == NULL || !cfw_zip_is(data, size))
    {
        osFreeMem(data);
        *count = firmware_add(tmpPath, channel, source, githubTag, notes, patch, &images[0], message, messageSize) ? 1 : 0;
        return *count > 0;
    }
    fsDeleteFile(tmpPath);
    bool ok = (patch == NULL || (patch->host[0] == '\0' && patch->port == 0)) &&
              import_zip(data, size, channel, source, githubTag, notes, images, count, message, messageSize);
    if (patch != NULL && (patch->host[0] != '\0' || patch->port != 0))
    {
        osSnprintf(message, messageSize, "patches apply to a single original image, not to a release package");
    }
    osFreeMem(data);
    return ok;
}

bool cfw_firmware_import(const char *tmpPath, uint32_t channel, const char *source, const char *githubTag, const char *notes,
                         const cfw_esp32_patch_t *patch, cfw_image_t *images, size_t *count, char *message, size_t messageSize)
{
    message[0] = '\0';
    cfw_library_lock();
    bool imported = firmware_import(tmpPath, channel, source, githubTag, notes, patch, images, count, message, messageSize);
    cfw_library_unlock();
    return imported;
}

bool cfw_firmware_delete(const char *platform, uint32_t build)
{
    cfw_library_lock();
    char *image = firmware_path(platform, build, "bin");
    char *meta = firmware_path(platform, build, "json");
    char *page = firmware_path(platform, build, "htm");
    char *package = firmware_path(platform, build, "zip");
    bool deleted = image != NULL && meta != NULL && fsDeleteFile(image) == NO_ERROR;
    if (deleted)
    {
        fsDeleteFile(meta);
        if (package != NULL)
        {
            fsDeleteFile(package);
        }
        if (page != NULL)
        {
            fsDeleteFile(page);
        }
    }
    cfw_library_unlock();
    osFreeMem(image);
    osFreeMem(meta);
    osFreeMem(page);
    osFreeMem(package);
    return deleted;
}

char *cfw_firmware_package(uint32_t build)
{
    char *path = firmware_path(CFW_PLATFORM_CC3200, build, "zip");
    if (path != NULL && !fsFileExists(path))
    {
        osFreeMem(path);
        path = NULL;
    }
    return path;
}

/* from the User-Agent of the current start; without one (the settings were reloaded since) the platform the box
   was last seen with. Not to be called with the CFW lock held. */
const char *cfw_box_platform(settings_t *settings)
{
    settings_box_type ic = settings->internal.toniebox_firmware.boxIC;
    bool esp32 = ic == BOX_ESP32;
    if (ic == BOX_UNKNOWN)
    {
        cfw_lock();
        cfw_box_t *box = cfw_box_get(settings);
        esp32 = box != NULL && box->esp32;
        cfw_unlock();
    }
    return esp32 ? CFW_PLATFORM_ESP32 : CFW_PLATFORM_CC3200;
}

/* the image for item 3, of the box's platform; 0: none */
uint32_t cfw_firmware_choose(settings_t *settings, const cfw_box_t *box, uint32_t currentVersion)
{
    if (!settings->cfw.update.enabled)
    {
        return 0;
    }
    bool allowRolledBack = settings->cfw.update.allow_rolled_back;
    const char *platform = cfw_box_platform(settings);

    /* manual delivery: the image assigned to the box, an older one included */
    const char *target = settings->cfw.update.target;
    if (target != NULL && target[0] != '\0')
    {
        uint32_t build = (uint32_t)strtoul(target, NULL, 10);
        cfw_image_t image;
        bool offer = build != 0 && build != currentVersion && (allowRolledBack || !cfw_box_is_rolled_back(box, build)) && cfw_firmware_get(platform, build, &image) &&
                     osStrcmp(image.platform, platform) == 0;
        return offer ? build : 0;
    }

    /* automatic delivery: the newest newer image of the box's channel or of a more stable one */
    if (settings->cfw.update.mode != 1 || settings->cfw.update.channel == CFW_CHANNEL_NONE)
    {
        return 0;
    }
    cfw_image_t *images = NULL;
    size_t count = cfw_firmware_list(&images);
    uint32_t chosen = 0;
    for (size_t i = 0; i < count && chosen == 0; i++)
    {
        bool inChannel = images[i].channel != CFW_CHANNEL_NONE && images[i].channel <= settings->cfw.update.channel &&
                         osStrcmp(images[i].platform, platform) == 0 && !images[i].original;
        if (inChannel && images[i].build > currentVersion && (allowRolledBack || !cfw_box_is_rolled_back(box, images[i].build)))
        {
            chosen = images[i].build;
        }
    }
    osFreeMem(images);
    return chosen;
}

/* the update check of a start comes before the hello, so a rollback is seen here first: an
   offered image that ran and is no longer running, or that never ran after some starts, counts as rolled
   back, so that it is not installed again and again; a newer build than the offered one (written to the
   card, for example) settles the offer without a rollback */
static void track_offer(cfw_box_t *box, uint32_t currentVersion)
{
    if (box->offeredBuild == 0)
    {
        return;
    }
    if (currentVersion == box->offeredBuild)
    {
        box->offerStarted = true;
        cfw_box_rolled_back(box, currentVersion, false);
        return;
    }
    if (currentVersion > box->offeredBuild)
    {
        TRACE_INFO("CFW: box %s runs build %" PRIu32 ", newer than the offered build %" PRIu32 "\r\n", box->id, currentVersion, box->offeredBuild);
        box->offeredBuild = 0;
        cfw_box_rolled_back(box, currentVersion, false);
        return;
    }
    if (box->offerStarted || ++box->offerAttempts >= CFW_OFFER_ATTEMPTS)
    {
        TRACE_WARNING("CFW: box %s is back on build %" PRIu32 ", build %" PRIu32 " counts as rolled back\r\n", box->id, currentVersion, box->offeredBuild);
        cfw_box_rolled_back(box, box->offeredBuild, true);
        box->offeredBuild = 0;
    }
}

/* item 7, the setup page: the page that came with the firmware the box runs, else
   the default page, when its version differs from the box's and the firmware the box runs is not older
   than the one the page needs (its cfw-page-requires; a firmware not in the library counts as new enough) */
static bool page_request(HttpConnection *connection, const char_t *uri, settings_t *settings, uint32_t build, uint32_t currentVersion, error_t *result)
{
    const char *platform = cfw_box_platform(settings);
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box != NULL && box->pageVersion != currentVersion)
    {
        box->pageVersion = currentVersion;
        cfw_box_save(box);
    }
    cfw_unlock();
    char *path = firmware_path(platform, build, "htm");
    if (path == NULL || !fsFileExists(path))
    {
        osFreeMem(path);
        path = default_page_path();
    }
    size_t size = 0;
    uint8_t *data = (path != NULL && settings->cfw.setup_page_update) ? cfw_read_file(path, 65536, &size) : NULL;
    bool offer = data != NULL && size > 0 && cfw_page_version(data, size) != currentVersion;
    char required[32];
    cfw_image_t running;
    bool tooOld = offer && cfw_page_meta(data, size, "cfw-page-requires", required, sizeof(required)) &&
                  cfw_firmware_get(platform, build, &running) && cfw_version_older(running.version, required);
    offer = offer && !tooOld;
    uint32_t offered = offer ? cfw_page_version(data, size) : 0;
    osFreeMem(data);
    if (tooOld)
    {
        TRACE_INFO("CFW: setup page not offered, it needs %s and the box runs %s\r\n", required, running.version);
    }
    else
    {
        TRACE_INFO("CFW: setup page %s (box %" PRIu32 ")\r\n", offer ? "offered" : "not offered", currentVersion);
    }
    if (offer)
    {
        *result = httpSendResponseStreamUnsafe(connection, uri, path, false);
        if (*result == NO_ERROR)
        {
            /* the box installs it without a restart: it has that page from now on, and reports the
               truth at its next start */
            cfw_lock();
            box = cfw_box_get(settings);
            if (box != NULL)
            {
                box->pageVersion = offered;
                cfw_box_save(box);
            }
            cfw_unlock();
        }
    }
    else
    {
        httpPrepareHeader(connection, NULL, 0);
        connection->response.statusCode = 304;
        *result = httpWriteResponse(connection, NULL, 0, false);
    }
    osFreeMem(path);
    return true;
}

/* the server for the server block: the host the box asked for, without a vendor domain
   and with the port of the request or the API port; false: none to give */
static bool esp32_server(HttpConnection *connection, settings_t *settings, char *host, size_t hostSize, uint16_t *port)
{
    static const char *vendor[] = {"tbs.toys", "bxcl.de", "boxine.de", "tonies.com", "tonies.de", "tonies.cloud"};
    osStrncpy(host, connection->request.host, hostSize - 1);
    host[hostSize - 1] = '\0';
    *port = (uint16_t)settings->core.https_api_port;
    char *colon = osStrchr(host, ':');
    if (colon != NULL)
    {
        *port = (uint16_t)strtoul(colon + 1, NULL, 10);
        *colon = '\0';
    }
    size_t length = osStrlen(host);
    if (length == 0 || length > 64 || *port == 0)
    {
        return false;
    }
    for (size_t i = 0; i < length; i++)
    {
        if (!isalnum((unsigned char)host[i]) && host[i] != '.' && host[i] != '-')
        {
            return false;
        }
    }
    for (size_t i = 0; i < sizeof(vendor) / sizeof(vendor[0]); i++)
    {
        size_t v = osStrlen(vendor[i]);
        if (length >= v && osStrcasecmp(&host[length - v], vendor[i]) == 0 && (length == v || host[length - v - 1] == '.'))
        {
            return false;
        }
    }
    return true;
}

/* the delivery body of an ESP32 image with the server block filled in, in a file of its own */
static char *esp32_body(uint32_t build, const char *host, uint16_t port)
{
    char *source = firmware_path(CFW_PLATFORM_ESP32, build, "bin");
    size_t size = 0;
    uint8_t *data = source ? cfw_read_file(source, CFW_ESP32_BODY_MAX, &size) : NULL;
    osFreeMem(source);
    cfw_esp32_image_t esp;
    char *path = NULL;
    if (data != NULL && cfw_esp32_parse(data, size, &esp) && cfw_esp32_set_server(data, &esp, host, port))
    {
        esp32_fix(data, &esp);
        char hex[65];
        hex_digest(data, esp.length, hex);
        path = cfw_firmware_temp_path();
        FsFile *file = path ? fsOpenFile(path, FS_FILE_MODE_WRITE | FS_FILE_MODE_TRUNC) : NULL;
        bool written = file != NULL && fsWriteFile(file, data, esp.length) == NO_ERROR && fsWriteFile(file, hex, 64) == NO_ERROR;
        if (file != NULL)
        {
            fsCloseFile(file);
        }
        if (!written)
        {
            if (path != NULL)
            {
                fsDeleteFile(path);
            }
            osFreeMem(path);
            path = NULL;
        }
    }
    osFreeMem(data);
    return path;
}

/* the original firmware asks after its image was delivered to the custom firmware: the return is done,
   the assignment goes, so that a later installation of the custom firmware is not undone */
static void esp32_returned(settings_t *settings, uint32_t build)
{
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    bool returned = box != NULL && box->offeredBuild == build;
    if (returned)
    {
        box->offeredBuild = 0;
        box->esp32Delivered = 0;
        cfw_box_save(box);
        TRACE_INFO("CFW: ESP32 box %s returned to the original firmware (image %" PRIu32 "), assignment removed\r\n", box->id, build);
    }
    cfw_unlock();
    if (returned)
    {
        settings_set_string_ovl("cfw.update.target", "", settings->internal.overlayUniqueId);
        settings_save();
    }
}

/* item 3 asked by the original firmware of an ESP32 box: the image assigned to the box, once,
   with the server block holding the server the box asked; false: not handled here */
static bool esp32_install_request(HttpConnection *connection, const char_t *uri, settings_t *settings, error_t *result)
{
    const char *target = settings->cfw.update.target;
    uint32_t build = target != NULL ? (uint32_t)strtoul(target, NULL, 10) : 0;
    cfw_image_t image;
    if (!settings->cfw.update.enabled || build == 0 || !cfw_firmware_get(CFW_PLATFORM_ESP32, build, &image))
    {
        return false;
    }
    if (image.original)
    {
        esp32_returned(settings, build);
        return false; /* the original firmware's own update check */
    }
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    bool delivered = box != NULL && box->esp32Delivered == build;
    if (box != NULL && delivered && box->offeredBuild == build)
    {
        /* the original firmware asks again: the image did not stay */
        TRACE_WARNING("CFW: ESP32 box %s runs the original firmware again, build %" PRIu32 " counts as rolled back\r\n", box->id, build);
        cfw_box_rolled_back(box, build, true);
        box->offeredBuild = 0;
        cfw_box_save(box);
    }
    cfw_unlock();
    if (box == NULL || delivered)
    {
        httpPrepareHeader(connection, NULL, 0);
        connection->response.statusCode = 304;
        *result = httpWriteResponse(connection, NULL, 0, false);
        return true;
    }

    char host[65] = "";
    uint16_t port = 0;
    if (!esp32_server(connection, settings, host, sizeof(host), &port))
    {
        host[0] = '\0';
        port = 0;
    }
    char *path = esp32_body(build, host, port);
    if (path == NULL)
    {
        TRACE_ERROR("CFW: ESP32 image %" PRIu32 " could not be prepared\r\n", build);
        return false;
    }
    cfw_lock();
    box = cfw_box_get(settings);
    if (box != NULL)
    {
        box->esp32Delivered = build;
        box->offeredBuild = build;
        box->offerAttempts = 0;
        box->offerStarted = false;
        box->offerTime = time(NULL);
        cfw_box_save(box);
    }
    cfw_unlock();
    TRACE_INFO("CFW: installing build %" PRIu32 " on the ESP32 box %s, server %s port %u\r\n", build, box ? box->id : "?", host[0] ? host : "(none)", port);
    *result = httpSendResponseStreamUnsafe(connection, uri, path, false);
    fsDeleteFile(path);
    osFreeMem(path);
    return true;
}

/* answers an item locally with 304 (nothing new) */
static bool not_modified(HttpConnection *connection, error_t *result)
{
    httpPrepareHeader(connection, NULL, 0);
    connection->response.statusCode = 304;
    *result = httpWriteResponse(connection, NULL, 0, false);
    return true;
}

bool cfw_ota_request(HttpConnection *connection, const char_t *uri, client_ctx_t *client_ctx, uint32_t fileId, uint32_t currentVersion, error_t *result)
{
    settings_t *settings = client_ctx->settings;
    /* item 7 is asked by the CFW only; without X-CFW-Build it is the original firmware's request */
    if (fileId == 7 && settings->cfw.enabled && connection->request.cfwBuild != 0)
    {
        return page_request(connection, uri, settings, connection->request.cfwBuild, currentVersion, result);
    }
    const char *ua = connection->request.userAgent;
    bool esp32Ua = ua != NULL && osStrncmp(ua, CFW_ESP32_PROJECT_ORIGINAL "/", sizeof(CFW_ESP32_PROJECT_ORIGINAL)) == 0;
    /* the CFW sends its build in X-CFW-Build and the original firmware's version as cv */
    uint32_t cfwBuild = connection->request.cfwBuild;
    /* item 7, and the update check of the ESP32 CFW with its own build as cv, are no requests of
       an original box; they are answered here and never passed on to the vendor's cloud */
    bool ownRequest = cfwBuild != 0 && (fileId == 7 || esp32Ua);
    if (fileId == 3 && settings->cfw.enabled && cfwBuild == 0 && esp32Ua)
    {
        return esp32_install_request(connection, uri, settings, result);
    }
    /* only the CFW gets a CFW image: a request without X-CFW-Build is the original firmware's, which must not
       install one (a box fallen back to it from the card would write the CFW into its flash) */
    if (fileId != 3 || !settings->cfw.enabled || cfwBuild == 0)
    {
        return ownRequest ? not_modified(connection, result) : false;
    }
    currentVersion = cfwBuild;

    const char *platform = cfw_box_platform(settings);
    cfw_lock();
    cfw_box_t *box = cfw_box_get(settings);
    if (box == NULL)
    {
        cfw_unlock();
        return ownRequest ? not_modified(connection, result) : false;
    }
    track_offer(box, currentVersion);
    cfw_box_t state = *box;
    cfw_unlock();

    uint32_t build = cfw_firmware_choose(settings, &state, currentVersion);

    cfw_lock();
    box = cfw_box_get(settings);
    if (box != NULL && build != 0 && build != box->offeredBuild)
    {
        box->offeredBuild = build;
        box->offerAttempts = 0;
        box->offerStarted = false;
    }
    if (box != NULL && build != 0)
    {
        box->offerTime = time(NULL);
    }
    if (box != NULL)
    {
        cfw_box_save(box);
    }
    cfw_unlock();

    if (build == 0)
    {
        TRACE_INFO("CFW: box %s runs build %" PRIu32 ", no image to offer\r\n", state.id, currentVersion);
        return not_modified(connection, result);
    }
    char *path = firmware_path(platform, build, "bin");
    TRACE_INFO("CFW: offering build %" PRIu32 " to box %s (running %" PRIu32 ")\r\n", build, state.id, currentVersion);
    *result = path ? httpSendResponseStreamUnsafe(connection, uri, path, false) : ERROR_OUT_OF_MEMORY;
    osFreeMem(path);
    return true;
}

typedef struct
{
    char *data;
    size_t length;
    bool failed;
} cfw_buffer_t;

typedef struct
{
    const char *path;
    FsFile *file;
    bool failed;
    size_t length;
    bool tooLarge;
    Sha256Context sha;
} cfw_download_t;

static void github_body(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cfw_buffer_t *buffer = ((cbr_ctx_t *)src_ctx)->customData;
    if (cloud_ctx->statusCode != 200 || length == 0 || buffer->failed)
    {
        return;
    }
    char *grown = buffer->length + length < 4 * 1024 * 1024 ? osAllocMem(buffer->length + length + 1) : NULL;
    if (grown == NULL)
    {
        buffer->failed = true;
        return;
    }
    if (buffer->length > 0)
    {
        osMemcpy(grown, buffer->data, buffer->length);
    }
    osMemcpy(&grown[buffer->length], payload, length);
    buffer->length += length;
    grown[buffer->length] = '\0';
    osFreeMem(buffer->data);
    buffer->data = grown;
}

static void github_file_body(void *src_ctx, HttpClientContext *cloud_ctx, const char *payload, size_t length, error_t error)
{
    cfw_download_t *download = ((cbr_ctx_t *)src_ctx)->customData;
    if (cloud_ctx->statusCode != 200 || length == 0 || download->failed)
    {
        return;
    }
    /* nothing larger than an import takes (cfw_firmware_import); the rest of the body is dropped */
    if (length > CFW_ESP32_DUMP_MAX - download->length)
    {
        download->tooLarge = true;
        download->failed = true;
        return;
    }
    download->length += length;
    if (download->file == NULL)
    {
        download->file = fsOpenFile(download->path, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);
    }
    download->failed = download->file == NULL || fsWriteFile(download->file, (void *)payload, length) != NO_ERROR;
    if (!download->failed)
    {
        sha256Update(&download->sha, payload, length);
    }
}

/* the CA bundle of the system (SSL_CERT_FILE, else where Debian, Ubuntu, Alpine and the Docker images, Fedora or
   BSD and macOS keep it); NULL: none found */
static char *ca_bundle(void)
{
    const char *paths[] = {getenv("SSL_CERT_FILE"), "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); i++)
    {
        size_t length = 0;
        char *pem = paths[i] != NULL && paths[i][0] != '\0' ? (char *)cfw_read_file(paths[i], CFW_CA_BUNDLE_MAX, &length) : NULL;
        if (pem != NULL)
        {
            return pem;
        }
    }
    return NULL;
}

static error_t github_get(const char *host, const char *uri, void (*body)(void *, HttpClientContext *, const char *, size_t, error_t), void *data, uint32_t *status)
{
    /* the server certificate must chain to a CA of the system; without a CA bundle nothing is fetched */
    char *ca = ca_bundle();
    if (ca == NULL)
    {
        TRACE_ERROR("CFW: no CA bundle found (SSL_CERT_FILE, /etc/ssl/certs/ca-certificates.crt), GitHub is not asked\r\n");
        return ERROR_UNKNOWN_CA;
    }
    cbr_ctx_t ctx = {0};
    ctx.user_agent = "teddyCloud";
    ctx.customData = data;
    ctx.trusted_ca = ca;
    req_cbr_t cbr = {.ctx = &ctx, .body = body};
    error_t err = web_request(host, 443, true, uri, NULL, "GET", NULL, 0, NULL, &cbr, false, false, status);
    osFreeMem(ca);
    return err;
}

/* release: release; prerelease with "alpha" in tag or name: alpha; other prereleases: beta */
static uint32_t release_channel(cJSON *release)
{
    if (!cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(release, "prerelease")))
    {
        return CFW_CHANNEL_RELEASE;
    }
    const char *tag = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(release, "tag_name"));
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(release, "name"));
    bool alpha = (tag && osStrstr(tag, "alpha")) || (name && osStrstr(name, "alpha"));
    return alpha ? CFW_CHANNEL_ALPHA : CFW_CHANNEL_BETA;
}

/* the release package (a .zip with "cfw" in its name), else a single image (.bin, one with "cfw" in
   its name first) */
static cJSON *release_asset(cJSON *release)
{
    cJSON *asset;
    cJSON *image = NULL;
    cJSON *fallback = NULL;
    cJSON_ArrayForEach(asset, cJSON_GetObjectItemCaseSensitive(release, "assets"))
    {
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(asset, "name"));
        size_t length = name ? osStrlen(name) : 0;
        bool cfw = name != NULL && osStrstr(name, "cfw") != NULL;
        if (cfw && ends_with(name, length, ".zip"))
        {
            return asset;
        }
        if (!ends_with(name ? name : "", length, ".bin"))
        {
            continue;
        }
        if (cfw && image == NULL)
        {
            image = asset;
        }
        fallback = fallback ? fallback : asset;
    }
    return image ? image : fallback;
}

/* tags that fit cfw_image_t.githubTag, so that a downloaded release is recognised */
static const char *release_tag(cJSON *release)
{
    const char *tag = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(release, "tag_name"));
    return tag && osStrlen(tag) < sizeof(((cfw_image_t *)0)->githubTag) ? tag : NULL;
}

static bool tag_in(const cfw_image_t *images, size_t count, const char *tag)
{
    for (size_t i = 0; tag != NULL && i < count; i++)
    {
        if (!osStrcmp(images[i].githubTag, tag))
        {
            return true;
        }
    }
    return false;
}

static error_t download_release(cJSON *release, char *message, size_t messageSize)
{
    const char *tag = release_tag(release);
    cJSON *asset = release_asset(release);
    const char *url = asset ? cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(asset, "browser_download_url")) : NULL;
    const char *path = url && !osStrncmp(url, "https://", 8) ? osStrchr(url + 8, '/') : NULL;
    if (tag == NULL || path == NULL || (size_t)(path - url - 8) >= 256)
    {
        osSnprintf(message, messageSize, "release without a usable image");
        return ERROR_NOT_FOUND;
    }
    cJSON *size = cJSON_GetObjectItemCaseSensitive(asset, "size");
    if (cJSON_IsNumber(size) && size->valuedouble > CFW_ESP32_DUMP_MAX)
    {
        osSnprintf(message, messageSize, "the image of %s is larger than %d bytes", tag, CFW_ESP32_DUMP_MAX);
        return ERROR_FAILURE;
    }
    char host[256];
    osStrncpy(host, url + 8, path - url - 8);
    host[path - url - 8] = '\0';

    cfw_download_t download = {.path = cfw_firmware_temp_path()};
    if (download.path == NULL)
    {
        return ERROR_OUT_OF_MEMORY;
    }
    sha256Init(&download.sha);
    uint32_t status = 0;
    error_t err = github_get(host, path, github_file_body, &download, &status);
    if (download.file != NULL)
    {
        fsCloseFile(download.file);
    }
    cfw_image_t images[4];
    size_t count = 4;
    const char *name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(release, "name"));
    /* the digest GitHub publishes for the asset ("sha256:<hex>"), on top of the checked certificate */
    const char *digest = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(asset, "digest"));
    char hex[65] = "";
    if (err == NO_ERROR && status == 200 && !download.failed && download.file != NULL)
    {
        uint8_t sum[32];
        sha256Final(&download.sha, sum);
        hex_text(sum, hex);
    }
    if (download.tooLarge)
    {
        osSnprintf(message, messageSize, "download of %s stopped, larger than %d bytes", tag, CFW_ESP32_DUMP_MAX);
        fsDeleteFile(download.path);
        err = ERROR_FAILURE;
    }
    else if (err != NO_ERROR || status != 200 || download.failed || download.file == NULL)
    {
        osSnprintf(message, messageSize, "download of %s failed (%s, HTTP %" PRIu32 ")", tag, error2text(err), status);
        fsDeleteFile(download.path);
        err = ERROR_FAILURE;
    }
    else if (digest != NULL && (osStrncmp(digest, "sha256:", 7) != 0 || osStrcasecmp(&digest[7], hex) != 0))
    {
        osSnprintf(message, messageSize, "download of %s does not match the digest GitHub publishes for it", tag);
        fsDeleteFile(download.path);
        err = ERROR_FAILURE;
    }
    else if (!cfw_firmware_import(download.path, release_channel(release), "github", tag, name ? name : "", NULL, images, &count, message, messageSize))
    {
        err = ERROR_FAILURE;
    }
    if (err == NO_ERROR && digest == NULL)
    {
        TRACE_WARNING("CFW: GitHub publishes no digest for %s, only its certificate was checked\r\n", tag);
    }
    osFreeMem((char *)download.path);
    return err;
}

static bool valid_repo(const char *repo)
{
    size_t slashes = 0;
    for (size_t i = 0; repo[i] != '\0'; i++)
    {
        if (repo[i] == '/')
        {
            slashes++;
        }
        else if (!isalnum((unsigned char)repo[i]) && repo[i] != '-' && repo[i] != '_' && repo[i] != '.')
        {
            return false;
        }
    }
    return slashes == 1 && repo[0] != '/' && repo[osStrlen(repo) - 1] != '/';
}

/* reads the releases of the repository; with autoDownload, downloads the new ones of the channels set */
static error_t github_update(bool autoDownload, char *message, size_t messageSize)
{
    settings_t *settings = get_settings();
    const char *repo = settings->cfw.firmware.github_repo;
    if (repo == NULL || !valid_repo(repo))
    {
        osSnprintf(message, messageSize, "no GitHub repository set (cfw.firmware.github_repo, owner/name)");
        return ERROR_INVALID_PARAMETER;
    }
    char *uri = custom_asprintf("/repos/%s/releases?per_page=30", repo);
    cfw_buffer_t buffer = {0};
    uint32_t status = 0;
    error_t err = uri ? github_get("api.github.com", uri, github_body, &buffer, &status) : ERROR_OUT_OF_MEMORY;
    osFreeMem(uri);
    cJSON *releases = (err == NO_ERROR && status == 200 && buffer.data) ? cJSON_Parse(buffer.data) : NULL;
    osFreeMem(buffer.data);
    if (!cJSON_IsArray(releases))
    {
        cJSON_Delete(releases);
        osSnprintf(message, messageSize, "GitHub request failed (%s, HTTP %" PRIu32 ")", error2text(err), status);
        return ERROR_FAILURE;
    }

    int downloaded = 0;
    int failed = 0;
    cfw_image_t *images = NULL;
    size_t count = autoDownload ? cfw_firmware_list(&images) : 0;
    cJSON *release;
    cJSON_ArrayForEach(release, releases)
    {
        const char *tag = release_tag(release);
        bool wanted = autoDownload && tag && release_channel(release) <= settings->cfw.firmware.github_download;
        if (!wanted || cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(release, "draft")) || release_asset(release) == NULL || tag_in(images, count, tag))
        {
            continue;
        }
        char result[256];
        if (download_release(release, result, sizeof(result)) == NO_ERROR)
        {
            downloaded++;
        }
        else
        {
            failed++;
            TRACE_WARNING("CFW: %s\r\n", result);
        }
    }
    osFreeMem(images);

    cfw_lock();
    cJSON_Delete(github_releases);
    github_releases = releases;
    github_last_check = time(NULL);
    osSnprintf(github_message, sizeof(github_message), "%d release(s), %d downloaded%s", cJSON_GetArraySize(releases), downloaded, failed ? ", some downloads failed" : "");
    osSnprintf(message, messageSize, "%s", github_message);
    cfw_unlock();
    return NO_ERROR;
}

error_t cfw_github_check(char *message, size_t messageSize)
{
    return github_update(false, message, messageSize);
}

error_t cfw_github_download(const char *tag, char *message, size_t messageSize)
{
    cJSON *release = NULL;
    cJSON *item;
    cfw_lock();
    cJSON_ArrayForEach(item, github_releases)
    {
        const char *itemTag = release_tag(item);
        if (release == NULL && itemTag && !osStrcmp(itemTag, tag))
        {
            release = cJSON_Duplicate(item, true);
        }
    }
    cfw_unlock();
    if (release == NULL)
    {
        osSnprintf(message, messageSize, "release %s not known, check GitHub first", tag);
        return ERROR_NOT_FOUND;
    }
    error_t err = download_release(release, message, messageSize);
    cJSON_Delete(release);
    return err;
}

cJSON *cfw_github_releases_json(void)
{
    cJSON *json = cJSON_CreateObject();
    cJSON *list = cJSON_AddArrayToObject(json, "releases");
    cJSON *release;
    cfw_lock();
    cJSON_AddNumberToObject(json, "lastCheck", (double)github_last_check);
    cJSON_AddStringToObject(json, "message", github_message);
    cJSON_ArrayForEach(release, github_releases)
    {
        const char *tag = release_tag(release);
        if (tag == NULL || cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(release, "draft")))
        {
            continue;
        }
        const char *name = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(release, "name"));
        const char *published = cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(release, "published_at"));
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "tag", tag);
        cJSON_AddStringToObject(entry, "name", name ? name : "");
        cJSON_AddStringToObject(entry, "published", published ? published : "");
        cJSON_AddStringToObject(entry, "channel", cfw_channel_name(release_channel(release)));
        cJSON_AddBoolToObject(entry, "hasImage", release_asset(release) != NULL);
        cJSON_AddItemToArray(list, entry);
    }
    cfw_unlock();
    cfw_image_t *images = NULL;
    size_t count = cfw_firmware_list(&images);
    cJSON_ArrayForEach(release, list)
    {
        cJSON_AddBoolToObject(release, "downloaded", tag_in(images, count, cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(release, "tag"))));
    }
    osFreeMem(images);
    return json;
}

static void github_task(void *param)
{
    char message[256];
    github_update(true, message, sizeof(message));
    TRACE_INFO("CFW: GitHub: %s\r\n", message);
    cfw_lock();
    github_running = false;
    cfw_unlock();
    osDeleteTask(OS_SELF_TASK_ID);
}

/* the automatic download from GitHub, every cfw.firmware.github_interval hours */
void cfw_loop(void)
{
    settings_t *settings = get_settings();
    if (!settings->cfw.enabled || settings->cfw.firmware.github_download == 0 || settings->cfw.firmware.github_repo == NULL || settings->cfw.firmware.github_repo[0] == '\0')
    {
        return;
    }
    time_t now = time(NULL);
    cfw_lock();
    bool due = !github_running && now - github_last_check >= (time_t)settings->cfw.firmware.github_interval * 3600;
    if (due)
    {
        github_running = true;
        github_last_check = now;
    }
    cfw_unlock();
    if (!due)
    {
        return;
    }
    OsTaskParameters taskParams = OS_TASK_DEFAULT_PARAMS;
    taskParams.stackSize = 64 * 1024;
    if (osCreateTask("CFW GitHub", &github_task, NULL, &taskParams) == OS_INVALID_TASK_ID)
    {
        cfw_lock();
        github_running = false;
        cfw_unlock();
    }
}

void cfw_firmware_deinit(void)
{
    cfw_lock();
    cJSON_Delete(github_releases);
    github_releases = NULL;
    cfw_unlock();
}
