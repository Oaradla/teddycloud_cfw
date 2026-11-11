#pragma once

/*
 * Global resume: the position of a figure as the boxes report it, so that it
 * continues on another box where it stopped.
 *
 * Each position the server hands out has a revision. A box tells with each
 * report the revision its position was taken from (its base) and how long it
 * has played since. A report that continues the current position, or starts
 * from it, replaces it. Two positions that went apart from the same revision
 * (one box played without a server) are solved by rules where that is safe: a
 * side with less than half a minute of listening loses, and two positions at most
 * three blocks apart are the same. Otherwise a conflict holds both until a user
 * chooses one; until then each box keeps its own position. A box that played
 * on after its position lost that choice goes apart from the chosen one.
 *
 * Pure logic without teddyCloud dependencies, so that it can be tested on its
 * own.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define CFW_RESUME_BOX_ID 64
#define CFW_RESUME_HISTORY 16
#define CFW_RESUME_BRANCHES 4
#define CFW_RESUME_BOXES 8
/* listening below this does not count against a position heard elsewhere */
#define CFW_RESUME_TRIVIAL_SEC 30
#define CFW_RESUME_SAME_BLOCKS 3

typedef enum
{
    CFW_RESUME_STOPPED = 0,
    CFW_RESUME_PLAYING = 1,
    CFW_RESUME_ENDED = 2,
    CFW_RESUME_LATE = 3,
    CFW_RESUME_QUERY = 4,
} cfw_resume_reason_t;

typedef enum
{
    CFW_RESUME_TAKE = 0,
    CFW_RESUME_KEEP = 1,
    CFW_RESUME_CONFLICT = 2,
} cfw_resume_answer_t;

typedef struct
{
    char box[CFW_RESUME_BOX_ID];
    uint16_t base;
    uint16_t listened; /* seconds since base */
    uint32_t audioId;
    uint32_t position; /* the next block to read */
    uint32_t seed;
    uint8_t index;
    uint8_t chapters;
    uint8_t flags;
    time_t time;
} cfw_position_t;

/* the position the server has heard from a box last */
typedef struct
{
    char box[CFW_RESUME_BOX_ID];
    uint16_t base;
    uint16_t listened;
    /* the listening elsewhere counts from this revision at listened time since */
    uint16_t revision;
    uint16_t since;
} cfw_resume_known_t;

typedef struct
{
    uint64_t ruid;
    bool global;         /* reported with global resume */
    cfw_position_t last; /* heard last, by any box */
    uint16_t revision;   /* the last one handed out, 0: none yet */
    cfw_position_t current;
    uint16_t historyRevision[CFW_RESUME_HISTORY];
    uint16_t historyListened[CFW_RESUME_HISTORY];
    size_t historyCount; /* 0: no current position */
    bool conflict;
    cfw_position_t branch[CFW_RESUME_BRANCHES];
    size_t branchCount;
    cfw_resume_known_t known[CFW_RESUME_BOXES]; /* the oldest first */
    size_t knownCount;
    char onBox[CFW_RESUME_BOX_ID]; /* the box it plays on, "" when none */
    uint32_t reports;              /* reports so far, counted from the server start */
} cfw_resume_t;

typedef enum
{
    CFW_RESUME_NONE,      /* only kept as heard last */
    CFW_RESUME_NEW,       /* a new current position */
    CFW_RESUME_UPDATED,   /* the current position moved on */
    CFW_RESUME_DROPPED,   /* the report lost against the current position */
    CFW_RESUME_CONFLICTS, /* a conflict opened */
    CFW_RESUME_BRANCH,    /* a position of an open conflict */
} cfw_resume_result_t;

/* a report (or the values of a query) of a box; global: the figure has global
 * resume */
cfw_resume_result_t cfw_resume_apply(cfw_resume_t *r, const cfw_position_t *p, bool global, cfw_resume_reason_t reason);
/* the answer to a query of box with base, after the query was applied */
cfw_resume_answer_t cfw_resume_answer_for(const cfw_resume_t *r, const char *box, uint16_t base);
/* the user chose branch: it becomes the current position; the others count
 * only with what their boxes play from then on */
bool cfw_resume_choose(cfw_resume_t *r, size_t branch);
