#include "cfw_resume_model.h"

#include <string.h>

static uint16_t next_revision(uint16_t revision) { return revision == 0xFFFF ? 1 : (uint16_t)(revision + 1); }

static bool same_origin(const cfw_position_t *a, const char *box, uint16_t base)
{
    return a->base == base && strcmp(a->box, box) == 0;
}

static void history_push(cfw_resume_t *r, const cfw_position_t *p)
{
    if (r->historyCount == CFW_RESUME_HISTORY)
    {
        memmove(&r->historyRevision[0], &r->historyRevision[1], (CFW_RESUME_HISTORY - 1) * sizeof(uint16_t));
        memmove(&r->historyListened[0], &r->historyListened[1], (CFW_RESUME_HISTORY - 1) * sizeof(uint16_t));
        r->historyCount--;
    }
    r->historyRevision[r->historyCount] = r->revision;
    r->historyListened[r->historyCount] = p->listened;
    r->historyCount++;
}

/* the listening on the current side after history entry i */
static uint32_t listened_after(const cfw_resume_t *r, size_t i)
{
    uint32_t total = 0;
    while (++i < r->historyCount)
    {
        total += r->historyListened[i];
    }
    return total;
}

/* the listening on the current side since revision had the listened time
 * since; all that is known when revision is older */
static uint32_t listened_from(const cfw_resume_t *r, uint16_t revision, uint16_t since)
{
    size_t i = r->historyCount;
    while (i > 0 && r->historyRevision[i - 1] != revision)
    {
        i--;
    }
    uint32_t own = i > 0 && r->historyListened[i - 1] > since ? r->historyListened[i - 1] - since : 0;
    return own + listened_after(r, i - 1);
}

/* what the server has heard from box with base; NULL when nothing */
static const cfw_resume_known_t *known_of(const cfw_resume_t *r, const char *box, uint16_t base)
{
    for (size_t i = 0; i < r->knownCount; i++)
    {
        if (r->known[i].base == base && strcmp(r->known[i].box, box) == 0)
        {
            return &r->known[i];
        }
    }
    return NULL;
}

/* keeps p as heard from its box, in place of the box's earlier one or of the
 * oldest */
static void know(cfw_resume_t *r, const cfw_position_t *p, uint16_t revision, uint16_t since)
{
    size_t i = 0;
    while (i < r->knownCount && strcmp(r->known[i].box, p->box) != 0)
    {
        i++;
    }
    if (i == CFW_RESUME_BOXES)
    {
        i = 0;
    }
    if (i < r->knownCount)
    {
        memmove(&r->known[i], &r->known[i + 1], (r->knownCount - i - 1) * sizeof(r->known[0]));
        r->knownCount--;
    }
    cfw_resume_known_t *k = &r->known[r->knownCount++];
    memcpy(k->box, p->box, CFW_RESUME_BOX_ID);
    k->base = p->base;
    k->listened = p->listened;
    k->revision = revision;
    k->since = since;
}

static void set_current(cfw_resume_t *r, const cfw_position_t *p)
{
    r->revision = next_revision(r->revision);
    r->current = *p;
    history_push(r, p);
    know(r, p, r->revision, p->listened);
}

static cfw_resume_result_t branch_report(cfw_resume_t *r, const cfw_position_t *p, uint16_t heard)
{
    for (size_t i = 0; i < r->branchCount; i++)
    {
        if (same_origin(&r->branch[i], p->box, p->base))
        {
            r->branch[i] = *p;
            return CFW_RESUME_BRANCH;
        }
    }
    if (p->listened - heard < CFW_RESUME_TRIVIAL_SEC || r->branchCount == CFW_RESUME_BRANCHES)
    {
        return CFW_RESUME_DROPPED;
    }
    r->branch[r->branchCount++] = *p;
    return CFW_RESUME_BRANCH;
}

cfw_resume_result_t cfw_resume_apply(cfw_resume_t *r, const cfw_position_t *p, bool global, cfw_resume_reason_t reason)
{
    if (reason != CFW_RESUME_QUERY)
    {
        r->last = *p;
        r->reports++;
    }
    if (reason == CFW_RESUME_QUERY || reason == CFW_RESUME_PLAYING)
    {
        memcpy(r->onBox, p->box, sizeof(r->onBox));
    }
    else if ((reason == CFW_RESUME_STOPPED || reason == CFW_RESUME_ENDED) && strcmp(r->onBox, p->box) == 0)
    {
        r->onBox[0] = '\0';
    }
    r->global = global;
    if (!global)
    {
        /* when it is switched on again, the boxes keep what they played since */
        r->historyCount = 0;
        return CFW_RESUME_NONE;
    }
    if (reason == CFW_RESUME_QUERY && p->listened == 0)
    {
        return CFW_RESUME_NONE;
    }
    /* a box that was not told since reports what the server has already */
    const cfw_resume_known_t *known = known_of(r, p->box, p->base);
    uint16_t heard = known != NULL ? known->listened : 0;
    bool current = r->historyCount > 0 && same_origin(&r->current, p->box, p->base);
    if (known != NULL && p->listened <= heard && !current)
    {
        return CFW_RESUME_DROPPED;
    }
    if (r->conflict)
    {
        return branch_report(r, p, heard);
    }
    if (r->historyCount == 0)
    {
        set_current(r, p);
        return CFW_RESUME_NEW;
    }
    if (current)
    {
        r->current = *p;
        r->historyListened[r->historyCount - 1] = p->listened;
        know(r, p, r->revision, p->listened);
        return CFW_RESUME_UPDATED;
    }
    if (p->base == r->revision)
    {
        set_current(r, p);
        return CFW_RESUME_NEW;
    }
    if (p->listened - heard < CFW_RESUME_TRIVIAL_SEC)
    {
        return CFW_RESUME_DROPPED;
    }
    uint32_t elsewhere = known != NULL ? listened_from(r, known->revision, known->since)
                                       : listened_from(r, p->base, UINT16_MAX);
    if (elsewhere < CFW_RESUME_TRIVIAL_SEC)
    {
        set_current(r, p);
        return CFW_RESUME_NEW;
    }
    uint32_t a = r->current.position, b = p->position;
    if (r->current.audioId == p->audioId && (a > b ? a - b : b - a) <= CFW_RESUME_SAME_BLOCKS)
    {
        return CFW_RESUME_DROPPED;
    }
    r->conflict = true;
    r->branch[0] = r->current;
    r->branch[1] = *p;
    r->branchCount = 2;
    return CFW_RESUME_CONFLICTS;
}

cfw_resume_answer_t cfw_resume_answer_for(const cfw_resume_t *r, const char *box, uint16_t base)
{
    if (r->conflict)
    {
        return CFW_RESUME_CONFLICT;
    }
    if (r->historyCount == 0 || same_origin(&r->current, box, base))
    {
        return CFW_RESUME_KEEP;
    }
    return CFW_RESUME_TAKE;
}

bool cfw_resume_choose(cfw_resume_t *r, size_t branch)
{
    if (!r->conflict || branch >= r->branchCount)
    {
        return false;
    }
    /* what the others play from now on goes apart from the chosen one */
    for (size_t i = 0; i < r->branchCount; i++)
    {
        if (i != branch)
        {
            know(r, &r->branch[i], next_revision(r->revision), r->branch[branch].listened);
        }
    }
    cfw_position_t chosen = r->branch[branch];
    r->conflict = false;
    r->branchCount = 0;
    set_current(r, &chosen);
    return true;
}
