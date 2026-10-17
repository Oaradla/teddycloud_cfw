#include "cfw_format.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t cfw_le32(const uint8_t *data)
{
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

void cfw_put_le32(uint8_t *data, uint32_t value)
{
    for (int i = 0; i < 4; i++)
    {
        data[i] = (value >> (8 * i)) & 0xFF;
    }
}

void cfw_ruid_to_bytes(uint64_t ruid, uint8_t bytes[8])
{
    for (int i = 0; i < 8; i++)
    {
        bytes[i] = (ruid >> (56 - 8 * i)) & 0xFF;
    }
}

uint64_t cfw_ruid_from_bytes(const uint8_t bytes[8])
{
    uint64_t ruid = 0;
    for (int i = 0; i < 8; i++)
    {
        ruid = (ruid << 8) | bytes[i];
    }
    return ruid;
}

/* two little-endian log arguments holding B0 ... B3 and B4 ... B7 */
uint64_t cfw_ruid_from_words(uint32_t low, uint32_t high)
{
    uint8_t bytes[8];
    cfw_put_le32(&bytes[0], low);
    cfw_put_le32(&bytes[4], high);
    return cfw_ruid_from_bytes(bytes);
}

/* the CRC of the Ogg page: polynomial 0x04C11DB7, initial value 0, not reflected */
uint32_t cfw_crc32(const uint8_t *data, size_t length)
{
    uint32_t crc = 0;
    for (size_t i = 0; i < length; i++)
    {
        crc ^= (uint32_t)data[i] << 24;
        for (int bit = 0; bit < 8; bit++)
        {
            crc = (crc & 0x80000000u) ? (crc << 1) ^ 0x04C11DB7u : (crc << 1);
        }
    }
    return crc;
}

uint32_t cfw_page_version(const uint8_t *data, size_t length)
{
    return cfw_crc32(data, length) >> 1;
}

static size_t body_length(const uint8_t *file)
{
    return file[6] | (file[7] << 8);
}

bool cfw_tbs_next_record(const uint8_t *file, size_t *pos, cfw_record_t *record)
{
    size_t length = body_length(file);
    if (*pos + 2 > length || *pos + 2 + file[12 + *pos + 1] > length)
    {
        return false;
    }
    record->key = file[12 + *pos];
    record->length = file[12 + *pos + 1];
    record->value = &file[12 + *pos + 2];
    *pos += 2 + record->length;
    return true;
}

bool cfw_tbs_valid(const uint8_t *file, size_t length)
{
    if (length < CFW_TBS_MIN || length > CFW_TBS_MAX || memcmp(file, "TBS1", 4) != 0)
    {
        return false;
    }
    if (file[4] < CFW_TBS_KIND_PROFILE || file[4] > CFW_TBS_KIND_GLOBAL || length != CFW_TBS_MIN + body_length(file))
    {
        return false;
    }
    if (cfw_crc32(file, length - 4) != cfw_le32(&file[length - 4]))
    {
        return false;
    }
    /* the records must fill the body exactly */
    size_t pos = 0;
    cfw_record_t record;
    while (cfw_tbs_next_record(file, &pos, &record))
    {
    }
    return pos == body_length(file);
}

size_t cfw_tbs_build(uint8_t kind, uint8_t origin, uint32_t timestamp, const uint8_t *body, size_t bodyLength, uint8_t *file)
{
    if (CFW_TBS_MIN + bodyLength > CFW_TBS_MAX)
    {
        return 0;
    }
    memcpy(file, "TBS1", 4);
    file[4] = kind;
    file[5] = origin;
    file[6] = bodyLength & 0xFF;
    file[7] = (bodyLength >> 8) & 0xFF;
    cfw_put_le32(&file[8], timestamp);
    if (bodyLength > 0)
    {
        memcpy(&file[12], body, bodyLength);
    }
    cfw_put_le32(&file[12 + bodyLength], cfw_crc32(file, 12 + bodyLength));
    return CFW_TBS_MIN + bodyLength;
}

uint32_t cfw_tbs_timestamp(const uint8_t *file)
{
    return cfw_le32(&file[8]);
}

/* an event tag file for a box without the extensions of bit 9: only the actions 1 to 9 in mode
   toggle, the others dropped as their meaning would change; 0 when none is left */
size_t cfw_event_for_basic_box(const uint8_t *file, uint8_t *out)
{
    uint8_t body[CFW_TBS_MAX];
    size_t length = 0;
    size_t pos = 0;
    cfw_record_t record;
    while (cfw_tbs_next_record(file, &pos, &record))
    {
        bool toggle = record.length == 3 && (record.value[2] >> 6) == 0;
        if (record.key == CFW_RECORD_ACTION && toggle && record.value[0] >= 1 && record.value[0] <= 9)
        {
            body[length++] = CFW_RECORD_ACTION;
            body[length++] = 3;
            memcpy(&body[length], record.value, 3);
            length += 3;
        }
    }
    if (length == 0)
    {
        return 0;
    }
    return cfw_tbs_build(CFW_TBS_KIND_EVENT, file[5], cfw_tbs_timestamp(file), body, length, out);
}

static size_t put_record(uint8_t *body, uint8_t key, uint32_t value, uint8_t length)
{
    body[0] = key;
    body[1] = length;
    for (uint8_t i = 0; i < length; i++)
    {
        body[2 + i] = (value >> (8 * i)) & 0xFF;
    }
    return 2 + length;
}

/* the body of the file the box wrote, from its settings change report */
size_t cfw_report_body(uint32_t packed, uint32_t values, uint8_t *body)
{
    uint8_t kind = packed & 3;
    size_t n = 0;
    for (uint8_t key = 0x01; key <= 0x07; key++)
    {
        bool present = packed & (1u << (3 + key));
        bool allowed = (kind == CFW_TBS_KIND_PROFILE) ? key != 0x07 : key >= 0x04;
        if (!present || !allowed)
        {
            continue;
        }
        switch (key)
        {
        case 0x01:
            n += put_record(&body[n], key, (packed >> 12) & 1, 1);
            break;
        case 0x02:
            n += put_record(&body[n], key, (packed >> 13) & 1, 1);
            break;
        case 0x03:
            n += put_record(&body[n], key, values & 0xFFFF, 2);
            break;
        case 0x04:
            n += put_record(&body[n], key, (values >> 16) & 0x0F, 1);
            break;
        case 0x05:
            n += put_record(&body[n], key, (values >> 20) & 0x0F, 1);
            break;
        case 0x06:
            n += put_record(&body[n], key, (packed >> 14) & 3, 1);
            break;
        case 0x07:
            n += put_record(&body[n], key, (packed >> 16) & 1, 1);
            break;
        }
    }
    for (uint8_t lock = 0; lock < 3; lock++)
    {
        if (values & (1u << (24 + lock)))
        {
            n += put_record(&body[n], 0x08 + lock, (values >> (27 + lock)) & 1, 1);
        }
    }
    return n;
}

static bool read_varint(const uint8_t *data, size_t length, size_t *pos, uint64_t *value)
{
    *value = 0;
    for (int shift = 0; shift < 64 && *pos < length; shift += 7)
    {
        uint8_t byte = data[(*pos)++];
        *value |= (uint64_t)(byte & 0x7F) << shift;
        if (!(byte & 0x80))
        {
            return true;
        }
    }
    return false;
}

/* removes fields 3 and 7 (volume limits) from a freshness-check answer: a box that answered the
   hello takes its limits in steps from the global file; unparsable input stays as is */
size_t cfw_strip_volume_fields(uint8_t *message, size_t length)
{
    size_t in = 0;
    size_t out = 0;
    while (in < length)
    {
        size_t start = in;
        uint64_t key;
        uint64_t skip = 0;
        if (!read_varint(message, length, &in, &key))
        {
            return length;
        }
        switch (key & 7)
        {
        case 0:
            if (!read_varint(message, length, &in, &skip))
            {
                return length;
            }
            skip = 0;
            break;
        case 1:
            skip = 8;
            break;
        case 2:
            if (!read_varint(message, length, &in, &skip))
            {
                return length;
            }
            break;
        case 5:
            skip = 4;
            break;
        default:
            return length;
        }
        if (skip > length - in)
        {
            return length;
        }
        in += skip;
        if ((key >> 3) != 3 && (key >> 3) != 7)
        {
            memmove(&message[out], &message[start], in - start);
            out += in - start;
        }
    }
    return out;
}

/* --- ESP32 app images --- */

static const uint8_t esp32_server_marker[8] = {'C', 'F', 'W', 'S', 'R', 'V', '0', '1'};

bool cfw_esp32_parse(const uint8_t *data, size_t size, cfw_esp32_image_t *image)
{
    memset(image, 0, sizeof(*image));
    if (size < 24 + 8 + 256 || data[0] != 0xE9)
    {
        return false;
    }
    size_t offset = 24;
    for (unsigned i = 0; i < data[1]; i++)
    {
        if (offset + 8 > size)
        {
            return false;
        }
        size_t length = cfw_le32(&data[offset + 4]);
        if (length > size - offset - 8)
        {
            return false;
        }
        offset += 8 + length;
    }
    image->checksumOffset = (offset + 16) / 16 * 16 - 1;
    image->hashAppended = data[23] == 1;
    image->length = image->checksumOffset + 1 + (image->hashAppended ? 32 : 0);
    if (image->length > size || cfw_le32(&data[32]) != 0xABCD5432u)
    {
        return false;
    }
    image->chipId = data[12] | (data[13] << 8);
    image->flashMode = data[2];
    image->flashSizeFreq = data[3];
    memcpy(image->version, &data[32 + 16], 32);
    memcpy(image->project, &data[32 + 48], 32);
    image->version[32] = '\0';
    image->project[32] = '\0';
    for (size_t i = 0; i + 112 <= image->length; i++)
    {
        if (memcmp(&data[i], esp32_server_marker, 8) == 0)
        {
            image->serverBlock = i;
            image->serverBlocks++;
        }
        if (cfw_le32(&data[i]) == 0xBEAC0005u && i + 112 <= image->length && cfw_le32(&data[i + 108]) == 0xBEAC0005u &&
            memcmp(&data[i + 93], "CFW1", 4) == 0)
        {
            image->buildBlock = i;
            image->buildBlocks++;
        }
    }
    return true;
}

uint8_t cfw_esp32_checksum(const uint8_t *data, size_t size)
{
    uint8_t checksum = 0xEF;
    size_t offset = 24;
    for (unsigned i = 0; i < data[1] && offset + 8 <= size; i++)
    {
        size_t length = cfw_le32(&data[offset + 4]);
        for (size_t k = 0; k < length && offset + 8 + k < size; k++)
        {
            checksum ^= data[offset + 8 + k];
        }
        offset += 8 + length;
    }
    return checksum;
}

bool cfw_esp32_set_server(uint8_t *data, const cfw_esp32_image_t *image, const char *host, uint16_t port)
{
    size_t length = strlen(host);
    if (image->serverBlocks != 1 || length > 64)
    {
        return false;
    }
    uint8_t *block = &data[image->serverBlock];
    memset(&block[8], 0, 72);
    memcpy(&block[8], host, length);
    block[72] = port & 0xFF;
    block[73] = port >> 8;
    return true;
}

uint32_t cfw_esp32_version_number(const char *version)
{
    uint32_t number = 0;
    int parts = 0;
    const char *p = version;
    while (*p != '\0' && parts < 3)
    {
        if (*p >= '0' && *p <= '9')
        {
            uint32_t part = 0;
            while (*p >= '0' && *p <= '9')
            {
                part = part < 1000 ? part * 10 + (uint32_t)(*p - '0') : part;
                p++;
            }
            number = number * 1000 + (part > 999 ? 999 : part);
            parts++;
        }
        else
        {
            p++;
        }
    }
    for (; parts < 3; parts++)
    {
        number *= 1000;
    }
    return number;
}

static int two_digits(const char *p)
{
    return (p[0] >= '0' && p[0] <= '9' && p[1] >= '0' && p[1] <= '9') ? (p[0] - '0') * 10 + (p[1] - '0') : -1;
}

uint32_t cfw_esp32_build_time(const uint8_t *data)
{
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    char time[17], date[17];
    memcpy(time, &data[32 + 80], 16);
    memcpy(date, &data[32 + 96], 16);
    time[16] = date[16] = '\0';
    int month = -1;
    for (int m = 0; m < 12 && strlen(date) >= 11; m++)
    {
        if (memcmp(date, &months[m * 3], 3) == 0)
        {
            month = m;
        }
    }
    char dayText[2] = {date[4] == ' ' ? '0' : date[4], date[5]};
    int day = two_digits(dayText);
    int century = two_digits(&date[7]), years = two_digits(&date[9]);
    int hour = two_digits(&time[0]), minute = two_digits(&time[3]), second = two_digits(&time[6]);
    if (month < 0 || strlen(date) != 11 || date[3] != ' ' || date[6] != ' ' || strlen(time) != 8 || time[2] != ':' || time[5] != ':' ||
        day < 1 || day > 31 || century < 0 || years < 0 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59)
    {
        return 0;
    }
    /* days since 1970-01-01 of the civil date (proleptic Gregorian) */
    int y = century * 100 + years - (month < 2);
    int era = y / 400;
    int yoe = y - era * 400;
    int mp = (month + 10) % 12; /* March 0 (month: January 0) */
    int doy = (153 * mp + 2) / 5 + day - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long days = (long)era * 146097 + doe - 719468;
    return days < 0 ? 0 : (uint32_t)(days * 86400 + hour * 3600 + minute * 60 + second);
}

bool cfw_esp32_dump_app(const uint8_t *data, size_t size, const char *project, size_t *offset)
{
    bool found = false;
    uint32_t best = 0;
    for (size_t entry = 0x9000; entry + 32 <= size && entry < 0xA000; entry += 32)
    {
        const uint8_t *e = &data[entry];
        if (e[0] != 0xAA || e[1] != 0x50)
        {
            break; /* the end of the table, or its MD5 entry */
        }
        size_t start = cfw_le32(&e[4]);
        size_t length = cfw_le32(&e[8]);
        cfw_esp32_image_t image;
        if (e[2] != 0 || start >= size || length > size - start || !cfw_esp32_parse(&data[start], length, &image) ||
            strcmp(image.project, project) != 0)
        {
            continue;
        }
        uint32_t version = cfw_esp32_version_number(image.version);
        if (!found || version > best)
        {
            found = true;
            best = version;
            *offset = start;
        }
    }
    return found;
}

size_t cfw_esp32_replace_string(uint8_t *data, size_t size, const char *from, const char *to)
{
    size_t fromLength = strlen(from) + 1;
    size_t toLength = strlen(to);
    size_t count = 0;
    if (fromLength < 2 || toLength >= fromLength || size < fromLength)
    {
        return 0;
    }
    for (size_t i = 0; i + fromLength <= size; i++)
    {
        /* the end of a string, as teddyCloud's own host patch matches it (a URL keeps its scheme) */
        if (memcmp(&data[i], from, fromLength) == 0)
        {
            memset(&data[i], 0, fromLength);
            memcpy(&data[i], to, toLength);
            count++;
            i += fromLength - 1;
        }
    }
    return count;
}

static uint16_t le16(const uint8_t *data)
{
    return (uint16_t)(data[0] | data[1] << 8);
}

bool cfw_zip_is(const uint8_t *data, size_t length)
{
    return length >= 4 && cfw_le32(data) == 0x04034B50;
}

bool cfw_zip_next(const uint8_t *zip, size_t length, size_t *pos, cfw_zip_entry_t *entry)
{
    size_t p = *pos;
    if (p > length || length - p < 30 || cfw_le32(&zip[p]) != 0x04034B50)
    {
        return false;
    }
    uint16_t flags = le16(&zip[p + 6]);
    size_t compressed = cfw_le32(&zip[p + 18]);
    size_t nameLength = le16(&zip[p + 26]);
    size_t extraLength = le16(&zip[p + 28]);
    size_t data = p + 30 + nameLength + extraLength;
    /* bit 3: the sizes follow the data in a descriptor; release packages are written without */
    if ((flags & 0x08) || data > length || compressed > length - data)
    {
        return false;
    }
    entry->name = (const char *)&zip[p + 30];
    entry->nameLength = nameLength;
    entry->method = le16(&zip[p + 8]);
    entry->data = &zip[data];
    entry->size = compressed;
    *pos = data + compressed;
    return true;
}

bool cfw_page_meta(const uint8_t *page, size_t size, const char *name, char *label, size_t labelSize)
{
    char key[64];
    if (snprintf(key, sizeof(key), "name=\"%s\" content=\"", name) >= (int)sizeof(key))
    {
        return false;
    }
    size_t k = strlen(key);
    for (size_t i = 0; i + k <= size; i++)
    {
        if (memcmp(&page[i], key, k) != 0)
        {
            continue;
        }
        size_t n = 0;
        for (size_t j = i + k; j < size && page[j] != '"'; j++, n++)
        {
            if (page[j] < 0x20 || page[j] > 0x7E || n + 1 >= labelSize)
            {
                return false;
            }
            label[n] = (char)page[j];
        }
        if (i + k + n >= size || n == 0)
        {
            return false;
        }
        label[n] = '\0';
        return true;
    }
    return false;
}

bool cfw_page_label(const uint8_t *page, size_t size, char *label, size_t labelSize)
{
    return cfw_page_meta(page, size, "cfw-page-version", label, labelSize);
}

static bool version_numbers(const char *version, unsigned long numbers[3])
{
    if (strncmp(version, "CFW_", 4) != 0)
    {
        return false;
    }
    const char *p = &version[4];
    for (int i = 0; i < 3; i++)
    {
        char *end = NULL;
        if (*p < '0' || *p > '9')
        {
            return false;
        }
        numbers[i] = strtoul(p, &end, 10);
        p = end;
        if (i < 2 && *p++ != '.')
        {
            return false;
        }
    }
    return true;
}

bool cfw_version_older(const char *version, const char *than)
{
    unsigned long a[3];
    unsigned long b[3];
    if (!version_numbers(version, a) || !version_numbers(than, b))
    {
        return false;
    }
    for (int i = 0; i < 3; i++)
    {
        if (a[i] != b[i])
        {
            return a[i] < b[i];
        }
    }
    return false;
}
