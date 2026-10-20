#include <stdint.h>
#include <string.h>

#include "taf_remux.h"
#include "toniefile.h"
#include "handler.h"
#include "hash/sha1.h"
#include "fs_port.h"
#include "fs_ext.h"
#include "os_port.h"
#include "debug.h"
#include "opus.h"
#include "ogg/ogg.h"
#include "proto/toniebox.pb.taf-header.pb-c.h"

#define BLOCK TONIEFILE_FRAME_SIZE
#define OGG_FLAG_CONTINUED 0x01
#define OGG_FLAG_BOS 0x02
#define OGG_FLAG_EOS 0x04
#define OGG_MAX_SEGMENTS 255
/* packets per page are limited by the 255 lacing values */
#define PAGE_MAX_PACKETS OGG_MAX_SEGMENTS

typedef struct
{
    const uint8_t *data;
    size_t len;
    size_t block;    /* block (of the ogg data behind the TAF header) the page starts in */
    size_t offset;   /* offset of the page inside that block */
    bool_t fills;    /* the page ends exactly at the end of its block */
    int64_t granule; /* -1: no packet ends on this page */
} taf_page_t;

typedef struct
{
    FsFile *file;
    TonieboxAudioFileHeader *header;
    uint8_t block[BLOCK];
    size_t block_len;
    size_t block_pos;
    size_t block_index;
    bool_t started;
} taf_reader_t;

typedef struct
{
    const char *path;
    FsFile *file;
    Sha1Context sha1;
    uint64_t length; /* ogg bytes written to the file */
    uint8_t pending[BLOCK];
    size_t pending_len;
    int64_t pending_granule;
    uint32_t serial;
    uint32_t pageno;
    uint64_t packets;
    int64_t granule;
    uint32_t tracks[TAF_REMUX_MAX_CHAPTERS];
    size_t n_tracks;
} taf_writer_t;

typedef struct
{
    const uint8_t *data;
    size_t len;
} taf_packet_t;

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32(uint8_t *p, uint32_t v)
{
    for (int i = 0; i < 4; i++)
    {
        p[i] = (uint8_t)(v >> (8 * i));
    }
}

static int64_t rd64(const uint8_t *p)
{
    return (int64_t)((uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32));
}

static void wr64(uint8_t *p, int64_t v)
{
    wr32(p, (uint32_t)(uint64_t)v);
    wr32(p + 4, (uint32_t)((uint64_t)v >> 32));
}

static size_t segments(size_t packet_len)
{
    return packet_len / 255 + 1;
}

/* ---- reader ---- */

static void reader_close(taf_reader_t *r)
{
    if (r->header != NULL)
    {
        toniebox_audio_file_header__free_unpacked(r->header, NULL);
        r->header = NULL;
    }
    if (r->file != NULL)
    {
        fsCloseFile(r->file);
        r->file = NULL;
    }
}

static error_t read_full(FsFile *file, uint8_t *buffer, size_t size, size_t *read)
{
    *read = 0;
    while (*read < size)
    {
        size_t got = 0;
        error_t error = fsReadFile(file, &buffer[*read], size - *read, &got);
        if (error == ERROR_END_OF_FILE || got == 0)
        {
            break;
        }
        if (error != NO_ERROR)
        {
            return error;
        }
        *read += got;
    }
    return NO_ERROR;
}

static error_t reader_open(taf_reader_t *r, const char *path)
{
    osMemset(r, 0, sizeof(*r));
    r->file = fsOpenFile(path, FS_FILE_MODE_READ);
    if (r->file == NULL)
    {
        return ERROR_FILE_OPENING_FAILED;
    }

    uint8_t buffer[BLOCK];
    size_t read = 0;
    if (read_full(r->file, buffer, BLOCK, &read) != NO_ERROR || read != BLOCK)
    {
        reader_close(r);
        return ERROR_INVALID_FILE;
    }
    uint32_t proto_size = ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) | ((uint32_t)buffer[2] << 8) | buffer[3];
    if (proto_size > TAF_HEADER_SIZE)
    {
        reader_close(r);
        return ERROR_INVALID_FILE;
    }
    r->header = toniebox_audio_file_header__unpack(NULL, proto_size, &buffer[4]);
    if (r->header == NULL || r->header->n_track_page_nums == 0)
    {
        reader_close(r);
        return ERROR_INVALID_FILE;
    }
    return NO_ERROR;
}

/* the next page of the ogg stream; ERROR_END_OF_STREAM after the last one */
static error_t reader_next(taf_reader_t *r, taf_page_t *page)
{
    if (r->block_pos >= r->block_len)
    {
        if (r->started)
        {
            r->block_index++;
        }
        r->started = true;
        r->block_pos = 0;
        error_t error = read_full(r->file, r->block, BLOCK, &r->block_len);
        if (error != NO_ERROR)
        {
            return error;
        }
        if (r->block_len == 0)
        {
            return ERROR_END_OF_STREAM;
        }
    }

    const uint8_t *p = &r->block[r->block_pos];
    size_t avail = r->block_len - r->block_pos;
    if (avail < OGG_HEADER_LENGTH || osMemcmp(p, "OggS", 4) != 0 || p[4] != 0)
    {
        TRACE_WARNING("TAF remux: no ogg page at block %" PRIuSIZE "+%" PRIuSIZE "\r\n", r->block_index, r->block_pos);
        return ERROR_INVALID_FILE;
    }
    size_t nseg = p[26];
    if (avail < OGG_HEADER_LENGTH + nseg)
    {
        return ERROR_INVALID_FILE;
    }
    size_t len = OGG_HEADER_LENGTH + nseg;
    for (size_t i = 0; i < nseg; i++)
    {
        len += p[OGG_HEADER_LENGTH + i];
    }
    if (len > avail)
    {
        /* a page over a block border: the box could not seek into such a file */
        TRACE_WARNING("TAF remux: page crosses block %" PRIuSIZE "\r\n", r->block_index);
        return ERROR_INVALID_FILE;
    }

    page->data = p;
    page->len = len;
    page->block = r->block_index;
    page->offset = r->block_pos;
    page->fills = (r->block_pos + len == BLOCK);
    page->granule = rd64(&p[6]);
    r->block_pos += len;
    return NO_ERROR;
}

static bool_t reader_is_track_start(taf_reader_t *r, size_t block)
{
    for (size_t i = 0; i < r->header->n_track_page_nums; i++)
    {
        if (r->header->track_page_nums[i] == block)
        {
            return true;
        }
    }
    return false;
}

/* ---- packets ---- */

/* the packets of a page; fails when a packet is continued from or onto another page */
static bool_t page_packets(const uint8_t *page, taf_packet_t *packets, size_t *count)
{
    size_t nseg = page[26];
    const uint8_t *lacing = &page[OGG_HEADER_LENGTH];
    const uint8_t *body = lacing + nseg;

    if ((page[5] & OGG_FLAG_CONTINUED) || nseg == 0 || lacing[nseg - 1] == 255)
    {
        return false;
    }
    size_t n = 0;
    size_t len = 0;
    for (size_t i = 0; i < nseg; i++)
    {
        len += lacing[i];
        if (lacing[i] < 255)
        {
            packets[n].data = body;
            packets[n].len = len;
            body += len;
            len = 0;
            n++;
        }
    }
    *count = n;
    return true;
}

static size_t packets_page_size(const taf_packet_t *packets, size_t count, size_t *nseg)
{
    size_t size = OGG_HEADER_LENGTH;
    *nseg = 0;
    for (size_t i = 0; i < count; i++)
    {
        *nseg += segments(packets[i].len);
        size += packets[i].len;
    }
    return size + *nseg;
}

static int64_t packets_samples(const taf_packet_t *packets, size_t count)
{
    int64_t samples = 0;
    for (size_t i = 0; i < count; i++)
    {
        int n = opus_packet_get_nb_samples(packets[i].data, (opus_int32)packets[i].len, OPUS_SAMPLING_RATE);
        if (n > 0)
        {
            samples += n;
        }
    }
    return samples;
}

/* builds a page of exactly size bytes from the packets: the packets are filled up
   with opus padding, starting with the last one */
static error_t build_page(const taf_packet_t *packets, size_t count, size_t size, uint8_t *out)
{
    size_t lens[PAGE_MAX_PACKETS];
    size_t nseg;
    size_t used = packets_page_size(packets, count, &nseg);

    if (count == 0 || count > PAGE_MAX_PACKETS || used > size || nseg > OGG_MAX_SEGMENTS)
    {
        return ERROR_FAILURE;
    }
    for (size_t i = 0; i < count; i++)
    {
        lens[i] = packets[i].len;
    }

    /* padding a packet by d bytes costs d bytes plus the lacing values it adds */
    size_t remaining = size - used;
    for (size_t j = count; j-- > 0 && remaining > 0;)
    {
        size_t best = 0;
        for (size_t d = remaining; d > 0; d--)
        {
            size_t extra = segments(lens[j] + d) - segments(lens[j]);
            size_t cost = d + extra;
            if (cost > remaining || nseg + extra > OGG_MAX_SEGMENTS || lens[j] + d > BLOCK)
            {
                continue;
            }
            /* leave either nothing or enough for the packet before to pad */
            if (cost == remaining || (j > 0 && remaining - cost >= 3))
            {
                best = d;
                break;
            }
        }
        if (best > 0)
        {
            size_t extra = segments(lens[j] + best) - segments(lens[j]);
            nseg += extra;
            remaining -= best + extra;
            lens[j] += best;
        }
    }
    if (remaining != 0)
    {
        return ERROR_FAILURE;
    }

    /* header with the fields filled in by the writer */
    osMemset(out, 0, OGG_HEADER_LENGTH);
    osMemcpy(out, "OggS", 4);
    out[26] = (uint8_t)nseg;
    uint8_t *lacing = &out[OGG_HEADER_LENGTH];
    uint8_t *body = lacing + nseg;
    for (size_t i = 0; i < count; i++)
    {
        size_t len = lens[i];
        while (len >= 255)
        {
            *lacing++ = 255;
            len -= 255;
        }
        *lacing++ = (uint8_t)len;

        osMemcpy(body, packets[i].data, packets[i].len);
        if (lens[i] != packets[i].len)
        {
            int ret = opus_packet_pad(body, (opus_int32)packets[i].len, (opus_int32)lens[i]);
            if (ret != OPUS_OK)
            {
                TRACE_WARNING("TAF remux: cannot pad packet %" PRIuSIZE " -> %" PRIuSIZE ": %s\r\n", packets[i].len, lens[i], opus_strerror(ret));
                return ERROR_FAILURE;
            }
        }
        body += lens[i];
    }
    return (size_t)(body - out) == size ? NO_ERROR : ERROR_FAILURE;
}

/* ---- writer ---- */

static error_t writer_open(taf_writer_t *w, const char *path, uint32_t audio_id)
{
    osMemset(w, 0, sizeof(*w));
    w->path = path;
    w->serial = audio_id;
    w->granule = 0;
    sha1Init(&w->sha1);

    w->file = fsOpenFile(path, FS_FILE_MODE_WRITE | FS_FILE_MODE_CREATE | FS_FILE_MODE_TRUNC);
    if (w->file == NULL)
    {
        TRACE_ERROR("TAF remux: cannot create %s\r\n", path);
        return ERROR_FILE_OPENING_FAILED;
    }
    uint8_t zero[BLOCK];
    osMemset(zero, 0, sizeof(zero));
    return fsWriteFile(w->file, zero, sizeof(zero));
}

static size_t writer_pos(taf_writer_t *w)
{
    return (size_t)w->length + w->pending_len;
}

static void writer_finish_page(uint8_t *page, size_t len)
{
    ogg_page og;
    size_t header_len = OGG_HEADER_LENGTH + page[26];
    wr32(&page[22], 0);
    og.header = page;
    og.header_len = (long)header_len;
    og.body = page + header_len;
    og.body_len = (long)(len - header_len);
    ogg_page_checksum_set(&og);
}

static error_t writer_flush(taf_writer_t *w, bool_t last)
{
    if (w->pending_len == 0)
    {
        return NO_ERROR;
    }
    if (last)
    {
        w->pending[5] |= OGG_FLAG_EOS;
        writer_finish_page(w->pending, w->pending_len);
    }
    error_t error = fsWriteFile(w->file, w->pending, w->pending_len);
    if (error != NO_ERROR)
    {
        return error;
    }
    sha1Update(&w->sha1, w->pending, w->pending_len);
    w->length += w->pending_len;
    w->pending_len = 0;
    return NO_ERROR;
}

/* queues a page; the stream fields (serial, sequence, granule, flags, crc) are set here */
static error_t writer_page(taf_writer_t *w, const uint8_t *page, size_t len, int64_t granule)
{
    error_t error = writer_flush(w, false);
    if (error != NO_ERROR)
    {
        return error;
    }
    if (len > BLOCK || (writer_pos(w) % BLOCK) + len > BLOCK)
    {
        return ERROR_FAILURE;
    }

    osMemcpy(w->pending, page, len);
    w->pending_len = len;
    w->pending_granule = granule;

    uint8_t *p = w->pending;
    p[5] = (p[5] & OGG_FLAG_CONTINUED) | ((w->pageno == 0) ? OGG_FLAG_BOS : 0);
    wr64(&p[6], granule);
    wr32(&p[14], w->serial);
    wr32(&p[18], w->pageno++);
    writer_finish_page(p, len);

    size_t nseg = p[26];
    for (size_t i = 0; i < nseg; i++)
    {
        if (p[OGG_HEADER_LENGTH + i] < 255)
        {
            w->packets++;
        }
    }
    if (granule != -1)
    {
        w->granule = granule;
    }
    return NO_ERROR;
}

/* repacks the packets of a page as one page of exactly size bytes */
static error_t writer_packets(taf_writer_t *w, const taf_packet_t *packets, size_t count, size_t size, int64_t granule)
{
    uint8_t page[BLOCK];
    error_t error = build_page(packets, count, size, page);
    if (error != NO_ERROR)
    {
        return error;
    }
    return writer_page(w, page, size, granule);
}

/* fills the rest of the current block by padding the queued page (it must not have been written yet) */
static error_t writer_align(taf_writer_t *w)
{
    size_t rest = writer_pos(w) % BLOCK;
    if (rest == 0)
    {
        return NO_ERROR;
    }
    if (w->pending_len == 0)
    {
        return ERROR_FAILURE;
    }
    taf_packet_t packets[PAGE_MAX_PACKETS];
    size_t count;
    uint8_t page[BLOCK];
    osMemcpy(page, w->pending, w->pending_len);
    if (!page_packets(page, packets, &count))
    {
        return ERROR_FAILURE;
    }
    size_t size = w->pending_len + (BLOCK - rest);
    int64_t granule = w->pending_granule;

    /* replace the queued page (same sequence number) */
    w->pending_len = 0;
    w->pageno--;
    uint8_t *lacing = &page[OGG_HEADER_LENGTH];
    for (size_t i = 0; i < page[26]; i++)
    {
        if (lacing[i] < 255)
        {
            w->packets--;
        }
    }
    return writer_packets(w, packets, count, size, granule);
}

/* puts a page of a source at the current position. A page that ended its block in the
   source has to end the block here too, so the pages after it stay block aligned. */
static error_t writer_source_page(taf_writer_t *w, const taf_page_t *page, int64_t granule)
{
    size_t space = BLOCK - (writer_pos(w) % BLOCK);

    if (page->len == space || (!page->fills && page->len < space))
    {
        return writer_page(w, page->data, page->len, granule);
    }

    taf_packet_t packets[PAGE_MAX_PACKETS];
    size_t count;
    if (!page_packets(page->data, packets, &count))
    {
        TRACE_WARNING("TAF remux: page at block %" PRIuSIZE " continues a packet, cannot repack it\r\n", page->block);
        return ERROR_INVALID_FILE;
    }

    if (page->len < space)
    {
        return writer_packets(w, packets, count, space, granule);
    }

    /* too big for the rest of the block: as many packets as fit there, the others on a page of their own */
    size_t first = count;
    size_t nseg;
    while (first > 0 && packets_page_size(packets, first, &nseg) > space)
    {
        first--;
    }
    if (first == 0)
    {
        return ERROR_FAILURE;
    }
    int64_t granule_first = granule == -1 ? -1 : granule - packets_samples(&packets[first], count - first);
    error_t error = writer_packets(w, packets, first, space, granule_first);
    if (error != NO_ERROR || first == count)
    {
        return error;
    }
    size_t rest_size = packets_page_size(&packets[first], count - first, &nseg);
    if (page->fills)
    {
        rest_size = BLOCK;
    }
    return writer_packets(w, &packets[first], count - first, rest_size, granule);
}

static error_t writer_chapter(taf_writer_t *w)
{
    uint32_t block = (uint32_t)(writer_pos(w) / BLOCK);
    if (w->n_tracks > 0 && w->tracks[w->n_tracks - 1] == block)
    {
        return NO_ERROR;
    }
    if (w->n_tracks >= TAF_REMUX_MAX_CHAPTERS)
    {
        TRACE_WARNING("TAF remux: more than %d chapters\r\n", TAF_REMUX_MAX_CHAPTERS);
        return ERROR_FAILURE;
    }
    w->tracks[w->n_tracks++] = block;
    return NO_ERROR;
}

static error_t writer_close(taf_writer_t *w, uint32_t audio_id, error_t error)
{
    if (w->file == NULL)
    {
        return error;
    }
    if (error == NO_ERROR)
    {
        error = writer_flush(w, true);
    }
    if (error == NO_ERROR)
    {
        uint8_t sha1[SHA1_DIGEST_SIZE];
        sha1Final(&w->sha1, sha1);

        TonieboxAudioFileHeader header;
        toniebox_audio_file_header__init(&header);
        header.sha1_hash.data = sha1;
        header.sha1_hash.len = SHA1_DIGEST_SIZE;
        header.num_bytes = w->length;
        header.audio_id = audio_id;
        header.track_page_nums = w->tracks;
        header.n_track_page_nums = w->n_tracks;
        header.ogg_granule_position = (uint64_t)w->granule;
        header.has_ogg_granule_position = true;
        header.ogg_packet_count = w->packets;
        header.has_ogg_packet_count = true;
        header.taf_block_num = w->length / BLOCK;
        header.has_taf_block_num = true;
        header.pageno = w->pageno;
        header.has_pageno = true;

        uint8_t buffer[BLOCK];
        osMemset(buffer, 0, sizeof(buffer));
        size_t size = toniefile_header(buffer, BLOCK - 4, &header);
        if (size == 0)
        {
            error = ERROR_FAILURE;
        }
        else
        {
            uint8_t proto_be[4] = {(uint8_t)(size >> 24), (uint8_t)(size >> 16), (uint8_t)(size >> 8), (uint8_t)size};
            fsSeekFile(w->file, 0, FS_SEEK_SET);
            error = fsWriteFile(w->file, proto_be, sizeof(proto_be));
            if (error == NO_ERROR)
            {
                error = fsWriteFile(w->file, buffer, size);
            }
        }
    }
    fsCloseFile(w->file);
    w->file = NULL;
    if (error != NO_ERROR)
    {
        fsDeleteFile(w->path);
    }
    return error;
}

/* checks the two opus header pages, returns the channel count and pre-skip and,
   with a writer, copies the pages to it */
static error_t reader_opus_header(taf_reader_t *r, taf_writer_t *w, uint8_t *channels, uint16_t *preskip)
{
    taf_page_t page;
    error_t error = reader_next(r, &page);
    if (error != NO_ERROR)
    {
        return error;
    }
    const uint8_t *body = page.data + OGG_HEADER_LENGTH + page.data[26];
    size_t body_len = page.len - OGG_HEADER_LENGTH - page.data[26];
    if (body_len < 19 || osMemcmp(body, "OpusHead", 8) != 0)
    {
        return ERROR_INVALID_FILE;
    }
    *channels = body[9];
    *preskip = (uint16_t)(body[10] | (body[11] << 8));
    if (w != NULL)
    {
        error = writer_page(w, page.data, page.len, 0);
        if (error != NO_ERROR)
        {
            return error;
        }
    }

    error = reader_next(r, &page);
    if (error != NO_ERROR)
    {
        return error;
    }
    body = page.data + OGG_HEADER_LENGTH + page.data[26];
    body_len = page.len - OGG_HEADER_LENGTH - page.data[26];
    if (body_len < 8 || osMemcmp(body, "OpusTags", 8) != 0 || (page.data[5] & OGG_FLAG_CONTINUED) || page.data[OGG_HEADER_LENGTH + page.data[26] - 1] == 255)
    {
        return ERROR_INVALID_FILE;
    }
    return w != NULL ? writer_page(w, page.data, page.len, 0) : NO_ERROR;
}

/* ---- operations ---- */

bool_t taf_remux_possible(const char *path)
{
    taf_reader_t r;
    taf_page_t page;
    uint8_t channels;
    uint16_t preskip;

    if (reader_open(&r, path) != NO_ERROR)
    {
        return false;
    }
    error_t error = reader_opus_header(&r, NULL, &channels, &preskip);
    while (error == NO_ERROR)
    {
        error = reader_next(&r, &page);
    }
    reader_close(&r);
    return error == ERROR_END_OF_STREAM;
}

error_t taf_remux_concat(const char *const *sources, size_t count, const char *target, uint32_t audio_id)
{
    taf_writer_t *w = osAllocMem(sizeof(taf_writer_t));
    taf_reader_t *r = osAllocMem(sizeof(taf_reader_t));
    if (w == NULL || r == NULL)
    {
        osFreeMem(w);
        osFreeMem(r);
        return ERROR_OUT_OF_MEMORY;
    }

    uint8_t first_channels = 0;
    error_t error = count > 0 ? writer_open(w, target, audio_id) : ERROR_INVALID_PARAMETER;
    for (size_t k = 0; k < count && error == NO_ERROR; k++)
    {
        error = reader_open(r, sources[k]);
        if (error != NO_ERROR)
        {
            TRACE_WARNING("TAF remux: %s is no TAF\r\n", sources[k]);
            break;
        }

        taf_page_t page;
        uint8_t channels;
        uint16_t preskip;
        error = reader_opus_header(r, k == 0 ? w : NULL, &channels, &preskip);
        if (error == NO_ERROR && k == 0)
        {
            first_channels = channels;
        }
        else if (error == NO_ERROR && channels != first_channels)
        {
            TRACE_WARNING("TAF remux: %s has %u channels instead of %u\r\n", sources[k], channels, first_channels);
            error = ERROR_INVALID_FILE;
        }

        /* the granule positions of this source continue after the previous ones */
        int64_t offset = w->granule;
        bool_t first_audio = true;
        while (error == NO_ERROR)
        {
            error = reader_next(r, &page);
            if (error != NO_ERROR)
            {
                break;
            }
            if ((first_audio || page.offset == 0) && reader_is_track_start(r, page.block))
            {
                error = writer_chapter(w);
            }
            if (error == NO_ERROR)
            {
                error = writer_source_page(w, &page, page.granule == -1 ? -1 : page.granule + offset);
            }
            first_audio = false;
        }
        if (error == ERROR_END_OF_STREAM)
        {
            error = (k + 1 < count) ? writer_align(w) : NO_ERROR;
        }
        reader_close(r);
        if (error != NO_ERROR)
        {
            TRACE_WARNING("TAF remux: cannot append %s: %s\r\n", sources[k], error2text(error));
        }
    }

    error = writer_close(w, audio_id, error);
    osFreeMem(w);
    osFreeMem(r);
    return error;
}

error_t taf_remux_chapter(const char *source, size_t chapter, const char *target, uint32_t audio_id)
{
    taf_writer_t *w = osAllocMem(sizeof(taf_writer_t));
    taf_reader_t *r = osAllocMem(sizeof(taf_reader_t));
    if (w == NULL || r == NULL)
    {
        osFreeMem(w);
        osFreeMem(r);
        return ERROR_OUT_OF_MEMORY;
    }

    error_t error = reader_open(r, source);
    if (error == NO_ERROR && chapter >= r->header->n_track_page_nums)
    {
        error = ERROR_INVALID_PARAMETER;
    }
    if (error != NO_ERROR)
    {
        reader_close(r);
        osFreeMem(w);
        osFreeMem(r);
        return error;
    }

    size_t start = r->header->track_page_nums[chapter];
    size_t end = (chapter + 1 < r->header->n_track_page_nums) ? r->header->track_page_nums[chapter + 1] : SIZE_MAX;

    taf_page_t page;
    uint8_t channels;
    uint16_t preskip;
    error = writer_open(w, target, audio_id);
    if (error == NO_ERROR)
    {
        error = reader_opus_header(r, w, &channels, &preskip);
    }
    if (error == NO_ERROR)
    {
        error = writer_chapter(w);
    }

    /* granule positions restart; like at the start of any opus stream the decoder drops pre-skip samples */
    int64_t chapter_start = 0;
    while (error == NO_ERROR)
    {
        error = reader_next(r, &page);
        if (error != NO_ERROR || page.block >= end)
        {
            break;
        }
        if (page.block < start)
        {
            if (page.granule != -1)
            {
                chapter_start = page.granule - preskip;
            }
            continue;
        }
        int64_t granule = page.granule == -1 ? -1 : page.granule - chapter_start;
        error = writer_source_page(w, &page, granule);
    }
    if (error == ERROR_END_OF_STREAM)
    {
        error = NO_ERROR;
    }
    reader_close(r);

    error = writer_close(w, audio_id, error);
    osFreeMem(w);
    osFreeMem(r);
    return error;
}
