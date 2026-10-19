#include "cfw_battery_model.h"

#include <string.h>

/* A typical Li-ion cell, with 0 % where the firmware switches the box off (3600 mV under load):
   the rest voltage curve minus the base drop measured between a running box and its next start. */
static const uint16_t default_curve[CFW_BAT_LEVELS] = {4125, 4017, 3939, 3875, 3821, 3780, 3742, 3705, 3667, 3629, 3595};
/* play drops until learned: louder is more current; headphones need little */
static const uint16_t default_play_drop[CFW_BAT_BANDS] = {15, 30, 50, 75, 10};

/* a discharge is learned from when it began at 90 % or more and went down to 20 % or less */
#define LEARN_FROM_LEVEL 1
#define LEARN_TO_LEVEL 8
#define LEARN_MIN_SAMPLES 20
/* reports further apart than this within one start do not count as time on battery */
#define MAX_GAP_MS (15u * 60u * 1000u)
/* a change between playing and idle further apart than this says nothing about the play drop */
#define PLAY_DROP_GAP_MS (5u * 60u * 1000u)
/* the first report of a start comes before the load has pulled the voltage down */
#define START_MS (60u * 1000u)
/* a start this much above the last report of the start before: the box was charged meanwhile */
#define CHARGED_RISE_MV 150

void cfw_battery_model_init(cfw_battery_model_t *model)
{
    memset(model, 0, sizeof(*model));
    memcpy(model->curve, default_curve, sizeof(default_curve));
    memcpy(model->playDrop, default_play_drop, sizeof(default_play_drop));
    model->baseDrop = CFW_BAT_DEFAULT_BASE_DROP;
    model->cycleStep = 1;
}

uint8_t cfw_battery_model_band(uint8_t step, bool headphones)
{
    if (headphones)
    {
        return CFW_BAT_BAND_HEADPHONES;
    }
    return step >= 12 ? 3 : step / 4;
}

uint32_t cfw_battery_model_play_load(const cfw_battery_model_t *model, uint8_t band)
{
    return (uint32_t)model->baseDrop + model->playDrop[band < CFW_BAT_BANDS ? band : 0];
}

uint8_t cfw_battery_model_percent(const cfw_battery_model_t *model, uint16_t idleMv)
{
    if (idleMv >= model->curve[0])
    {
        return 100;
    }
    for (int i = 1; i < CFW_BAT_LEVELS; i++)
    {
        uint16_t hi = model->curve[i - 1];
        uint16_t lo = model->curve[i];
        if (idleMv >= lo)
        {
            int span = hi > lo ? hi - lo : 1;
            int percent = 100 - 10 * i + (10 * (idleMv - lo) + span / 2) / span;
            return (uint8_t)(percent > 100 ? 100 : percent);
        }
    }
    return 0;
}

static uint16_t median(const uint16_t *values, uint8_t count)
{
    uint16_t sorted[CFW_BAT_WINDOW];
    memcpy(sorted, values, count * sizeof(values[0]));
    for (uint8_t i = 1; i < count; i++)
    {
        for (uint8_t j = i; j > 0 && sorted[j - 1] > sorted[j]; j--)
        {
            uint16_t t = sorted[j];
            sorted[j] = sorted[j - 1];
            sorted[j - 1] = t;
        }
    }
    return count % 2 ? sorted[count / 2] : (uint16_t)((sorted[count / 2 - 1] + sorted[count / 2] + 1) / 2);
}

static void cycle_start(cfw_battery_model_t *model)
{
    model->cycleActive = true;
    model->cycleFromFull = false;
    model->cycleUsed = 0;
    model->cycleCount = 0;
    model->cycleStep = 1;
    model->cycleSkip = 0;
}

static void cycle_add(cfw_battery_model_t *model, uint16_t idleMv)
{
    if (model->cycleSkip + 1 < model->cycleStep)
    {
        model->cycleSkip++;
        return;
    }
    model->cycleSkip = 0;
    if (model->cycleCount == CFW_BAT_SAMPLES)
    {
        /* full: keep every other report from now on, and of those so far */
        for (uint16_t i = 0; i < CFW_BAT_SAMPLES / 2; i++)
        {
            model->cycleMv[i] = model->cycleMv[2 * i];
            model->cycleAt[i] = model->cycleAt[2 * i];
        }
        model->cycleCount = CFW_BAT_SAMPLES / 2;
        model->cycleStep *= 2;
    }
    model->cycleMv[model->cycleCount] = idleMv;
    model->cycleAt[model->cycleCount] = model->cycleUsed;
    model->cycleCount++;
}

/* the curve and the capacity from the recorded discharge, when it covers enough of it */
static bool cycle_learn(cfw_battery_model_t *model, bool critical)
{
    model->cycleActive = false;
    /* up to the lowest point: what came after it (a rest, a start near rest voltage) is not discharge */
    uint16_t n = 0;
    for (uint16_t i = 0; i < model->cycleCount; i++)
    {
        if (n == 0 || model->cycleMv[i] <= model->cycleMv[n - 1])
        {
            n = (uint16_t)(i + 1);
        }
    }
    if (!model->cycleFromFull || n < LEARN_MIN_SAMPLES)
    {
        return false;
    }
    uint16_t lowest = model->cycleMv[n - 1];
    if (!critical && lowest > model->curve[LEARN_TO_LEVEL])
    {
        return false;
    }
    uint32_t endUsed = model->cycleAt[n - 1];
    /* the charge left at the end, by the curve so far: the rest of the capacity is estimated */
    uint32_t endPercent = critical ? 0 : cfw_battery_model_percent(model, lowest);
    if (endUsed == 0 || endPercent >= 90)
    {
        return false;
    }
    uint32_t capacity = (uint32_t)((uint64_t)endUsed * 100 / (100 - endPercent));

    uint16_t learned[CFW_BAT_LEVELS];
    memcpy(learned, model->curve, sizeof(learned));
    uint16_t j = 0;
    for (int i = 0; i < CFW_BAT_LEVELS; i++)
    {
        uint32_t at = (uint32_t)((uint64_t)capacity * (uint32_t)(10 * i) / 100); /* used when 100 - 10 i % are left */
        if (at > endUsed)
        {
            break;
        }
        while (j + 1 < n && model->cycleAt[j + 1] < at)
        {
            j++;
        }
        uint32_t a0 = model->cycleAt[j];
        uint32_t a1 = j + 1 < n ? model->cycleAt[j + 1] : a0;
        int32_t v0 = model->cycleMv[j];
        int32_t v1 = j + 1 < n ? model->cycleMv[j + 1] : v0;
        int32_t v = (a1 > a0 && at > a0) ? v0 + (int32_t)((int64_t)(v1 - v0) * (at - a0) / (a1 - a0)) : v0;
        learned[i] = (uint16_t)v;
    }

    /* blend: the first discharge counts half, later ones less, so one odd day does not decide */
    uint32_t weight = 100 / (model->cycles + 2); /* percent of the new curve */
    if (weight < 25)
    {
        weight = 25;
    }
    for (int i = 0; i < CFW_BAT_LEVELS; i++)
    {
        model->curve[i] = (uint16_t)((model->curve[i] * (100 - weight) + learned[i] * weight + 50) / 100);
    }
    /* the curve has to fall */
    for (int i = 1; i < CFW_BAT_LEVELS; i++)
    {
        if (model->curve[i] >= model->curve[i - 1])
        {
            model->curve[i] = model->curve[i - 1] - 1;
        }
    }
    model->capacity = model->capacity ? (uint32_t)(((uint64_t)model->capacity * (100 - weight) + (uint64_t)capacity * weight) / 100) : capacity;
    model->cycles++;
    return true;
}

static uint16_t learn_drop(uint16_t old, uint16_t samples, int32_t drop)
{
    /* the first samples move it more, later ones a fifth */
    uint32_t keep = samples < 4 ? samples + 1 : 4;
    return (uint16_t)((old * keep + (uint32_t)drop + (keep + 1) / 2) / (keep + 1));
}

bool cfw_battery_model_report(cfw_battery_model_t *model, const cfw_battery_report_t *report, cfw_battery_result_t *result)
{
    bool learnedNow = false;
    cfw_battery_result_t out = {.percent = -1, .charging = report->station, .learned = model->cycles > 0};
    uint8_t band = cfw_battery_model_band(report->step, report->headphones);
    bool playing = report->state == 2;

    /* a new start of the box: the uptime went back */
    bool sameStart = model->lastValid && report->uptimeMs >= model->lastUptimeMs;
    uint32_t gapMs = sameStart ? report->uptimeMs - model->lastUptimeMs : report->uptimeMs;

    if (report->station)
    {
        /* charging: the recorded discharge ends here */
        if (model->cycleActive)
        {
            learnedNow = cycle_learn(model, false);
        }
        model->windowCount = 0;
    }
    else if (!report->implausible)
    {
        /* charged while off: the box reports nothing on the charger then, but starts much higher */
        bool chargedWhileOff = !sameStart && model->lastValid && !model->lastStation && report->mv > model->lastMv + CHARGED_RISE_MV;
        if (chargedWhileOff && model->cycleActive)
        {
            learnedNow = cycle_learn(model, false);
        }
        if (!model->cycleActive || chargedWhileOff || (model->lastValid && model->lastStation))
        {
            cycle_start(model); /* taken off the charger, charged meanwhile, or the first report seen */
        }

        if (sameStart && !model->lastStation && gapMs <= PLAY_DROP_GAP_MS && playing != (model->lastState == 2))
        {
            /* the play drop of the band that played, from a change between playing and idle */
            uint8_t playBand = playing ? band : model->lastBand;
            int32_t drop = playing ? (int32_t)model->lastMv - report->mv : (int32_t)report->mv - model->lastMv;
            if (drop >= 0 && drop <= 250)
            {
                model->playDrop[playBand] = learn_drop(model->playDrop[playBand], model->playDropSamples[playBand], drop);
                model->playDropSamples[playBand]++;
            }
        }
        else if (!sameStart && !chargedWhileOff && report->uptimeMs <= START_MS && model->lastValid && !model->lastStation && !playing && model->lastState != 2)
        {
            /* the base drop: the first report of a start is near rest, the last of the start before
               was not */
            int32_t drop = (int32_t)report->mv - model->lastMv;
            if (drop >= 0)
            {
                model->baseDrop = learn_drop(model->baseDrop, model->baseDropSamples, drop);
                model->baseDropSamples++;
            }
        }

        uint16_t idleMv = (uint16_t)(report->mv + (playing ? model->playDrop[band] : 0));
        if (report->uptimeMs <= START_MS && idleMv > model->baseDrop)
        {
            /* right after a start the cell is still near its rest voltage */
            idleMv = (uint16_t)(idleMv - model->baseDrop);
        }
        if (!sameStart)
        {
            model->windowCount = 0;
        }
        if (model->windowCount == CFW_BAT_WINDOW)
        {
            memmove(&model->window[0], &model->window[1], (CFW_BAT_WINDOW - 1) * sizeof(model->window[0]));
            model->windowCount--;
        }
        model->window[model->windowCount++] = idleMv;
        uint16_t smooth = median(model->window, model->windowCount);

        /* the charge used since the last report, at the load of what the box did meanwhile */
        uint32_t seconds = (gapMs <= MAX_GAP_MS ? gapMs : 0) / 1000;
        uint32_t load = model->baseDrop + (playing ? model->playDrop[band] : 0);
        model->cycleUsed += seconds * load;
        if (model->cycleCount == 0 && smooth >= model->curve[LEARN_FROM_LEVEL])
        {
            model->cycleFromFull = true;
        }
        cycle_add(model, smooth);

        out.percent = (int8_t)(report->critical ? 0 : cfw_battery_model_percent(model, smooth));
        if (report->critical && model->cycleActive)
        {
            learnedNow = cycle_learn(model, true);
        }
    }

    model->lastValid = true;
    model->lastStation = report->station;
    model->lastState = report->state;
    model->lastBand = band;
    model->lastMv = report->mv;
    model->lastUptimeMs = report->uptimeMs;
    out.learned = model->cycles > 0;
    if (out.percent >= 0 && model->capacity)
    {
        /* playing on at this volume */
        uint64_t left = (uint64_t)model->capacity * (uint32_t)out.percent / 100;
        out.remainingSec = (uint32_t)(left / cfw_battery_model_play_load(model, band));
    }
    if (result != NULL)
    {
        *result = out;
    }
    return learnedNow;
}
