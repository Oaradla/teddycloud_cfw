#pragma once

/* global resume (cfw_resume_model.h): the positions of the figures as the boxes
   report them, kept in <configdir>/cfw/resume.json; all functions under the CFW
   lock */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "cJSON.h"
#include "cfw_resume_model.h"

/* a position record (query: a position query) of the box; true when it opened a
 * conflict */
bool cfw_resume_record(const char *boxId, const uint8_t *payload, size_t length, bool query, uint64_t *ruid,
                       uint16_t *base);
/* the box the figure plays on, when that is another one than boxId */
const char *cfw_resume_elsewhere(uint64_t ruid, const char *boxId);
/* the number of reports of ruid so far, to tell a later one */
uint32_t cfw_resume_reports(uint64_t ruid);
/* the last report of ruid came from boxId and is not the one counted as reports
 */
bool cfw_resume_reported_since(uint64_t ruid, const char *boxId, uint32_t reports);
/* the arguments of command 74 for the query of boxId with base */
size_t cfw_resume_answer_args(uint64_t ruid, const char *boxId, uint16_t base, uint8_t *args);
cJSON *cfw_resume_json(void);
/* the positions of one figure, NULL when none was reported */
cJSON *cfw_resume_entry(uint64_t ruid);
/* the boxes of the positions in conflict of ruid; 0 when there is no conflict */
size_t cfw_resume_conflict_boxes(uint64_t ruid, char boxes[CFW_RESUME_BRANCHES][CFW_RESUME_BOX_ID]);
/* the user chose the position branch of the conflict of ruid */
bool cfw_resume_choose_branch(uint64_t ruid, size_t branch);
void cfw_resume_free(void);
