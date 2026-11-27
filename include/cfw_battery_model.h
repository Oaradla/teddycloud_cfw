#pragma once

/*
 * The charge of a box in percent, from the battery reports of the custom
 * firmware.
 *
 * The box measures the voltage only (no current). The voltage of a running box
 * says little: it sinks by 50 to 150 mV within the first hour of a start and
 * comes back during a pause, and it does not depend on the volume. So the
 * charge is counted instead: a running box uses its capacity in proportion to
 * the time it runs.
 *
 * The voltage is read at one moment only, the first report of a start after a
 * pause: there the cell has rested and a curve of voltage against charge holds.
 * That reading corrects the counted charge as far as it is more certain than
 * the count: little in the flat middle of a NiMH cell, where a few mV are many
 * percent, much near full and empty and after a long time off, in which the
 * cell also loses charge of its own (counted too). On the charger the box measures the charging voltage, so the
 * charge grows with the time there; the first start after it limits what a
 * short stay has brought.
 *
 * Per box the model learns, starting from defaults, the capacity (running time from full to
 * empty) and the curve, from every discharge that began near full: best from one that ended at
 * the critical voltage (that one may also begin above half), until the first of those also from
 * one that went below 30 percent or to the low-battery warning (a fifth is left there).
 * Between those the capacity follows slowly, a few percent a start, when the voltage of the
 * starts keeps saying that the count runs too fast or too slow: so it follows a cell that ages,
 * and a few days in the cold do not change it much.
 *
 * Pure logic without teddyCloud dependencies, so that it can be tested on its
 * own.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* curve points at 100, 90, ..., 0 percent */
#define CFW_BAT_LEVELS 11
/* starts kept per discharge; more are thinned out to every other one */
#define CFW_BAT_SAMPLES 64
/* the charge is kept in millionths of the capacity */
#define CFW_BAT_FULL 1000000u

typedef struct
{
    uint16_t curve[CFW_BAT_LEVELS]; /* mV at the start after a pause at 100 - 10 *
                                       i percent, falling */
    uint16_t cycles;                /* discharges learned from */
    uint16_t measured;              /* those that ended at the critical voltage */
    uint32_t capacity;              /* seconds a box runs from full to empty */
    bool chargeValid;
    uint32_t charge; /* 0 to CFW_BAT_FULL */
    uint32_t spread; /* how far the charge may be off */
    bool restValid;
    uint32_t restCharge; /* the charge at the last start after a pause or a charge */

    /* the discharge being recorded: the starts after a pause */
    bool cycleActive;
    uint32_t cycleFrom; /* the charge when it began */
    uint32_t cycleUsedMs; /* running time since it began */
    uint32_t cycleLowMs;  /* running time at the first low-battery warning, 0 before */
    uint16_t cycleCount;
    uint16_t cycleMv[CFW_BAT_SAMPLES];
    uint32_t cycleAt[CFW_BAT_SAMPLES]; /* running time at that start, ms */

    /* the last report */
    bool lastValid;
    bool lastStation;
    uint16_t lastMv;
    uint32_t lastUptimeMs;
    uint64_t lastTime;
} cfw_battery_model_t;

typedef struct
{
    uint16_t mv;
    bool station;
    bool low;
    bool critical;
    bool implausible;
    uint32_t uptimeMs;
    uint64_t time; /* of the report, seconds */
} cfw_battery_report_t;

typedef struct
{
    int8_t percent;        /* 0 to 100, -1 unknown (on the charger, implausible) */
    bool charging;         /* on the charger */
    uint32_t remainingSec; /* running time left, 0 until learned */
    bool learned;          /* capacity and curve come from at least one discharge of this
                              box */
} cfw_battery_result_t;

void cfw_battery_model_init(cfw_battery_model_t *model);
/* feeds one report; result may be NULL. Returns true when a discharge was
 * learned from. */
bool cfw_battery_model_report(cfw_battery_model_t *model, const cfw_battery_report_t *report, cfw_battery_result_t *result);
/* the charge for a voltage at a start after a pause on the model's curve, 0 to
 * 100 */
uint8_t cfw_battery_model_percent(const cfw_battery_model_t *model, uint16_t mv);
