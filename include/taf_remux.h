#pragma once

#include "os_port.h"
#include "error.h"

/* Lossless TAF editing on the ogg page level: the opus packets are copied, never
   re-encoded. Only the pages next to a cut are repacked (and filled up with opus
   padding) so that every chapter still starts on a 4096 byte block. */

#define TAF_REMUX_MAX_CHAPTERS 99

/* true when the file is a TAF whose stream can be remuxed (opus header pages,
   no packet continued over a block border) */
bool_t taf_remux_possible(const char *path);

/* writes the sources one after the other into target as a new TAF with the given
   audio id. Every chapter of every source stays a chapter. */
error_t taf_remux_concat(const char *const *sources, size_t count, const char *target, uint32_t audio_id);

/* writes chapter (0 based) of source into target as a TAF with a single chapter */
error_t taf_remux_chapter(const char *source, size_t chapter, const char *target, uint32_t audio_id);
