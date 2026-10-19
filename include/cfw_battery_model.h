#pragma once

/*
 * The charge of a box in percent, from the battery reports of the custom firmware.
 *
 * The box measures the voltage only (no current), so the charge is read from a curve of
 * voltage against charge. The curve is kept in "idle" voltage: the voltage while the box is on
 * and does not play (all reports come from a running box). During playback the measured voltage
 * is lower by the play drop, which grows with the volume and is added back before the curve is
 * read. On the charger the box measures the charging voltage, so there is no charge then, only
 * "charging".
 *
 * The voltage drop under a load is the current times the inner resistance of the cell, so the
 * drops serve as the measure of the load: the base drop of a running box (seen between the last
 * report of a start and the first of the next) plus, while playing, the play drop of the volume.
 * Summed over time this is the charge used, in mV·s; the playing time left at a volume is the
 * charge left divided by the load at that volume.
 *
 * Per box the model learns, starting from defaults:
 * - the base drop, and the play drop per volume band (speaker steps 0-3, 4-7, 8-11, 12-15, and
 *   headphones), from changes between playback and idle within a start of the box;
 * - the curve and the capacity, from every discharge that began near full and went down to the
 *   low-battery range: the charge used maps to the charge left.
 *
 * Pure logic without teddyCloud dependencies, so that it can be tested on its own.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* curve points at 100, 90, ..., 0 percent */
#define CFW_BAT_LEVELS 11
/* reports kept per discharge; more are thinned out to every other one */
#define CFW_BAT_SAMPLES 256
/* reports in the smoothing window */
#define CFW_BAT_WINDOW 5
/* volume bands: speaker steps 0-3, 4-7, 8-11, 12-15, headphones */
#define CFW_BAT_BANDS 5
#define CFW_BAT_BAND_HEADPHONES 4

#define CFW_BAT_DEFAULT_BASE_DROP 75

typedef struct
{
    uint16_t curve[CFW_BAT_LEVELS]; /* idle voltage in mV at 100 - 10 * i percent, falling */
    uint16_t cycles;                /* discharges learned from */
    uint16_t baseDrop;              /* mV a running box is below its rest voltage */
    uint16_t baseDropSamples;
    uint16_t playDrop[CFW_BAT_BANDS]; /* mV the voltage is lower while playing, per volume band */
    uint16_t playDropSamples[CFW_BAT_BANDS];
    uint32_t capacity; /* charge from full to empty in mV·s, 0 until learned */

    /* the discharge being recorded */
    bool cycleActive;
    bool cycleFromFull;
    uint32_t cycleUsed; /* charge used since it began, mV·s */
    uint16_t cycleCount;
    uint16_t cycleStep; /* only every n-th report is kept once the buffer was full */
    uint16_t cycleSkip;
    uint16_t cycleMv[CFW_BAT_SAMPLES];
    uint32_t cycleAt[CFW_BAT_SAMPLES]; /* charge used at that report */

    /* the last report and the smoothing window, within one start of the box */
    bool lastValid;
    bool lastStation;
    uint8_t lastState;
    uint8_t lastBand;
    uint16_t lastMv;
    uint32_t lastUptimeMs;
    uint16_t window[CFW_BAT_WINDOW];
    uint8_t windowCount;
} cfw_battery_model_t;

typedef struct
{
    uint16_t mv;
    bool station;
    bool low;
    bool critical;
    bool implausible;
    uint8_t state; /* player state of the report: 2 playing */
    uint8_t step;  /* volume step */
    bool headphones;
    uint32_t uptimeMs;
} cfw_battery_report_t;

typedef struct
{
    int8_t percent;        /* 0 to 100, -1 unknown (on the charger, implausible) */
    bool charging;         /* on the charger */
    uint32_t remainingSec; /* playing time left at the volume of the report, 0 until learned */
    bool learned;          /* the curve comes from at least one discharge of this box */
} cfw_battery_result_t;

void cfw_battery_model_init(cfw_battery_model_t *model);
/* feeds one report; result may be NULL. Returns true when a discharge was learned from. */
bool cfw_battery_model_report(cfw_battery_model_t *model, const cfw_battery_report_t *report, cfw_battery_result_t *result);
/* the charge for an idle voltage on the model's curve, 0 to 100 */
uint8_t cfw_battery_model_percent(const cfw_battery_model_t *model, uint16_t idleMv);
/* the volume band of a step and output */
uint8_t cfw_battery_model_band(uint8_t step, bool headphones);
/* the load while playing in a band, mV (base drop plus play drop) */
uint32_t cfw_battery_model_play_load(const cfw_battery_model_t *model, uint8_t band);
