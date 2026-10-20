#pragma once

#include "debug.h"

#define TAP_TYPE_TAP "tap"
/* the TAF a playlist builds next to itself is named after it: "<name>.tap" -> "<name>.tap.taf" */
#define TAP_BUILT_SUFFIX ".taf"

typedef struct
{
    char *filepath;
    char *name;
    char *_filepath_resolved;
} tap_file_t;
typedef struct
{
    char *type;
    time_t audio_id;
    char *filepath;
    char *_filepath_resolved;
    char *name;
    tap_file_t *files;
    size_t filesCount;
    bool_t _cached;
    bool_t _valid;
} tonie_audio_playlist_t;

typedef struct
{
    tonie_audio_playlist_t *tap;
    bool_t force;
} tap_generate_param_t;

void tap_init(void);
void tap_deinit(void);
bool_t is_valid_tap(char *filename);
error_t tap_load(char *filename, tonie_audio_playlist_t *tap);
error_t tap_save(char *filename, tonie_audio_playlist_t *tap);
void tap_free(tonie_audio_playlist_t *tap);
error_t tap_generate_taf(tonie_audio_playlist_t *tap, size_t *current_source, bool_t *active, bool_t force);
void tap_generate_task(void *param);
/* true when all files are TAFs, so the playlist TAF can be put together without encoding */
bool_t tap_can_remux(tonie_audio_playlist_t *tap);
/* puts the playlist TAF together from TAF files unless it is current */
error_t tap_build(char *filename, tonie_audio_playlist_t *tap);
/* true for "<name>.tap.taf" with "<name>.tap" next to it: the TAF that playlist builds */
bool_t tap_is_built_taf(const char *path);
/* after a playlist was deleted: removes the TAF it built next to itself */
void tap_deleted(const char *tapPath);
/* after a file or folder in the library was moved or renamed: a playlist takes its TAF next to it
   along, and all playlists name the new paths */
void tap_moved(const char *fromPath, const char *toPath);
