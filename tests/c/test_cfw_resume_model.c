#include <assert.h>
#include <string.h>

#include "cfw_resume_model.h"
#include "tests.h"

static cfw_position_t pos(const char *box, uint16_t base, uint16_t listened, uint32_t position)
{
    cfw_position_t p;
    memset(&p, 0, sizeof(p));
    strcpy(p.box, box);
    p.base = base;
    p.listened = listened;
    p.position = position;
    p.audioId = 0x1234;
    return p;
}

static cfw_resume_result_t report(cfw_resume_t *r, const char *box, uint16_t base, uint16_t listened, uint32_t position)
{
    cfw_position_t p = pos(box, base, listened, position);
    return cfw_resume_apply(r, &p, true, CFW_RESUME_STOPPED);
}

void test_cfw_resume_model_handover(void)
{
    cfw_resume_t r;
    memset(&r, 0, sizeof(r));
    /* box a without a position from the server: revision 1 */
    assert(report(&r, "a", 0, 120, 30) == CFW_RESUME_NEW && r.revision == 1);
    assert(cfw_resume_answer_for(&r, "a", 0) == CFW_RESUME_KEEP);
    /* box b takes it, plays on: revision 2, its later reports move it on */
    assert(cfw_resume_answer_for(&r, "b", 0) == CFW_RESUME_TAKE);
    assert(report(&r, "b", 1, 30, 40) == CFW_RESUME_NEW && r.revision == 2);
    assert(report(&r, "b", 1, 60, 50) == CFW_RESUME_UPDATED && r.revision == 2 && r.current.position == 50);
    /* a figure without global resume is only kept as heard last */
    cfw_position_t p = pos("c", 0, 0, 7);
    assert(cfw_resume_apply(&r, &p, false, CFW_RESUME_STOPPED) == CFW_RESUME_NONE && r.last.position == 7);
}

void test_cfw_resume_model_offline(void)
{
    cfw_resume_t r;
    memset(&r, 0, sizeof(r));
    report(&r, "a", 0, 100, 10); /* revision 1 */
    /* b plays offline from revision 1, a meanwhile only briefly: b's position
     * wins */
    assert(report(&r, "a", 1, 20, 12) == CFW_RESUME_NEW && r.revision == 2);
    assert(report(&r, "b", 1, 900, 200) == CFW_RESUME_NEW && r.revision == 3 && r.current.position == 200);
    /* a short offline listening loses against a position heard since */
    assert(report(&r, "a", 2, 20, 14) == CFW_RESUME_DROPPED);
    /* both at the same place: no conflict */
    assert(report(&r, "c", 1, 600, 201) == CFW_RESUME_DROPPED && !r.conflict);
}

void test_cfw_resume_model_conflict(void)
{
    cfw_resume_t r;
    memset(&r, 0, sizeof(r));
    report(&r, "a", 0, 100, 10);  /* revision 1 */
    report(&r, "a", 1, 600, 100); /* revision 2: a played on */
    assert(report(&r, "b", 1, 900, 300) == CFW_RESUME_CONFLICTS && r.conflict && r.branchCount == 2);
    assert(cfw_resume_answer_for(&r, "a", 1) == CFW_RESUME_CONFLICT &&
           cfw_resume_answer_for(&r, "b", 1) == CFW_RESUME_CONFLICT);
    /* each side reports on, a third box joins with a long listening */
    assert(report(&r, "b", 1, 960, 310) == CFW_RESUME_BRANCH && r.branch[1].position == 310);
    assert(report(&r, "c", 0, 20, 5) == CFW_RESUME_DROPPED);
    assert(report(&r, "c", 0, 40, 6) == CFW_RESUME_BRANCH && r.branchCount == 3);
    assert(report(&r, "c", 0, 300, 50) == CFW_RESUME_BRANCH && r.branchCount == 3);
    /* the user chooses b: the others take it, b keeps its own */
    assert(cfw_resume_choose(&r, 1) && !r.conflict && r.revision == 3 && r.current.position == 310);
    assert(cfw_resume_answer_for(&r, "b", 1) == CFW_RESUME_KEEP &&
           cfw_resume_answer_for(&r, "a", 1) == CFW_RESUME_TAKE);
    assert(report(&r, "a", 1, 620, 110) == CFW_RESUME_DROPPED);
    assert(report(&r, "b", 1, 1100, 320) == CFW_RESUME_UPDATED && r.current.position == 320);
    /* a played on after the choice, b too: a new conflict */
    assert(report(&r, "a", 1, 700, 120) == CFW_RESUME_CONFLICTS);
}

void test_cfw_resume_model_after_choice(void)
{
    cfw_resume_t r;
    memset(&r, 0, sizeof(r));
    report(&r, "a", 0, 100, 10);
    report(&r, "a", 1, 600, 100);
    report(&r, "b", 1, 900, 300); /* conflict */
    /* a chosen: its known position stays no conflict once the figure was elsewhere */
    assert(cfw_resume_choose(&r, 0) && r.revision == 3);
    assert(report(&r, "a", 1, 900, 150) == CFW_RESUME_UPDATED);
    assert(report(&r, "c", 3, 300, 200) == CFW_RESUME_NEW && r.revision == 4);
    assert(report(&r, "a", 1, 900, 150) == CFW_RESUME_DROPPED && !r.conflict);
    /* b played on offline without anyone else since the choice: it wins */
    memset(&r, 0, sizeof(r));
    report(&r, "a", 0, 100, 10);
    report(&r, "a", 1, 600, 100);
    report(&r, "b", 1, 900, 300);
    cfw_resume_choose(&r, 0);
    assert(report(&r, "b", 1, 920, 310) == CFW_RESUME_DROPPED);
    assert(report(&r, "b", 1, 3900, 900) == CFW_RESUME_NEW && r.current.position == 900);
}

void test_cfw_resume_model_old_known(void)
{
    cfw_resume_t r;
    memset(&r, 0, sizeof(r));
    report(&r, "a", 0, 600, 100); /* revision 1 */
    /* the figure goes back and forth between b and c longer than the history */
    for (uint16_t revision = 1; revision <= 20; revision++)
    {
        assert(report(&r, revision % 2 ? "b" : "c", revision, 120, 100 + revision * 10) == CFW_RESUME_NEW);
    }
    cfw_position_t p = pos("a", 0, 600, 100);
    assert(cfw_resume_apply(&r, &p, true, CFW_RESUME_QUERY) == CFW_RESUME_DROPPED && !r.conflict);
    assert(cfw_resume_answer_for(&r, "a", 0) == CFW_RESUME_TAKE);
    /* more boxes than are kept: the one heard longest ago goes */
    for (char box[] = "d"; box[0] <= 'k'; box[0]++)
    {
        report(&r, box, r.revision, 120, 500);
    }
    assert(r.knownCount == CFW_RESUME_BOXES && strcmp(r.known[0].box, "d") == 0);
}

void test_cfw_resume_model_global_off(void)
{
    cfw_resume_t r;
    memset(&r, 0, sizeof(r));
    report(&r, "a", 0, 600, 100);
    assert(cfw_resume_answer_for(&r, "b", 0) == CFW_RESUME_TAKE);
    /* switched off: the position from before is not handed out when it is on again */
    cfw_position_t p = pos("b", 0, 900, 500);
    assert(cfw_resume_apply(&r, &p, false, CFW_RESUME_STOPPED) == CFW_RESUME_NONE);
    assert(cfw_resume_answer_for(&r, "b", 0) == CFW_RESUME_KEEP && r.revision == 1);
    assert(report(&r, "b", 0, 960, 520) == CFW_RESUME_NEW && r.revision == 2);
}

void test_cfw_resume_model_back(void)
{
    cfw_resume_t r;
    memset(&r, 0, sizeof(r));
    report(&r, "a", 0, 84, 247); /* revision 1 */
    assert(report(&r, "b", 1, 89, 496) == CFW_RESUME_NEW && r.revision == 2);
    /* back on a: its position is the one the server had, a takes b's */
    cfw_position_t p = pos("a", 0, 84, 247);
    assert(cfw_resume_apply(&r, &p, true, CFW_RESUME_QUERY) == CFW_RESUME_DROPPED && !r.conflict);
    assert(cfw_resume_answer_for(&r, "a", 0) == CFW_RESUME_TAKE);
    /* a played on offline after its last report: the time since counts */
    report(&r, "a", 0, 110, 380);
    assert(!r.conflict && r.revision == 2);
    assert(report(&r, "a", 0, 150, 440) == CFW_RESUME_CONFLICTS);
}
