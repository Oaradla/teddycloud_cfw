#include "cfw_battery_model.h"

#include <string.h>

/* until learned: the middle of the boxes measured, a good and an aged cell */
static const uint16_t default_curve[CFW_BAT_LEVELS] = {4170, 4050, 3990, 3945, 3900, 3865, 3830, 3795, 3755, 3710, 3650};
#define DEFAULT_CAPACITY (7u * 3600u)
#define CAPACITY_MIN (2u * 3600u)
#define CAPACITY_MAX (30u * 3600u)
/* an empty cell is full after this long on the charger */
#define CHARGE_SEC (3u * 3600u)

/* reports further apart than this within one start do not count as running time
 */
#define MAX_GAP_MS (15u * 60u * 1000u)
/* the first report of a start comes before the load has pulled the voltage down
 */
#define START_MS (60u * 1000u)
/* the clock of the server may run ahead of the uptime of one start by this much
 */
#define START_SLACK_SEC 300u
/* the cell has rested after a pause this long */
#define REST_SEC (30u * 60u)
/* a start this much above the last report of the start before: the box was
 * charged meanwhile */
#define CHARGED_RISE_MV 150
/* how far the voltage of a start after a pause scatters around the curve, mV;
 * more until the curve is learned */
#define REST_NOISE_MV 25
#define REST_NOISE_DEFAULT_MV 45
/* the count is off by this share of what it counted, percent; more until the
 * capacity is learned */
#define COUNT_ERROR 5
#define COUNT_ERROR_DEFAULT 30
/* a NiMH cell loses charge while off, and how much is not known well: share of
 * the capacity a day */
#define SELF_DISCHARGE_DAY (CFW_BAT_FULL / 100)
#define SELF_ERROR_DAY (CFW_BAT_FULL / 100)
/* how far the charge may be off after a full charge, or after the low-battery
 * warning */
#define FULL_ERROR (CFW_BAT_FULL / 50)
#define LOW_ERROR (CFW_BAT_FULL / 10)
/* the firmware's low-battery warning comes below this charge */
#define LOW_MAX (CFW_BAT_FULL / 4)
/* a discharge is learned from when it began above this and, without the
 * critical voltage, went below that */
#define LEARN_FROM (CFW_BAT_FULL / 100 * 92)
#define LEARN_TO (CFW_BAT_FULL / 100 * 30)
/* left at the first low-battery warning of a discharge, as measured on the boxes */
#define LOW_LEFT (CFW_BAT_FULL / 5)
/* a discharge to the critical voltage is learned from when it began above this */
#define LEARN_FROM_CRITICAL (CFW_BAT_FULL / 2)
#define LEARN_MIN_SAMPLES 3
/* a start after this much was counted since the start before moves the capacity, by this share of what it is off */
#define ADAPT_MIN_USED (CFW_BAT_FULL / 10)
#define ADAPT_PERCENT 4
/* neighbouring curve points are at least this far apart */
#define CURVE_MIN_STEP_MV 8

void cfw_battery_model_init(cfw_battery_model_t *model)
{
    memset(model, 0, sizeof(*model));
    memcpy(model->curve, default_curve, sizeof(default_curve));
    model->capacity = DEFAULT_CAPACITY;
}

static uint32_t curve_charge(const cfw_battery_model_t *model, uint16_t mv)
{
    if (mv >= model->curve[0])
    {
        return CFW_BAT_FULL;
    }
    for (uint32_t i = 1; i < CFW_BAT_LEVELS; i++)
    {
        uint16_t hi = model->curve[i - 1];
        uint16_t lo = model->curve[i];
        if (mv >= lo)
        {
            return (CFW_BAT_FULL / 10) * (10 - i) + (CFW_BAT_FULL / 10) * (uint32_t)(mv - lo) / (uint32_t)(hi - lo);
        }
    }
    return 0;
}

/* how far the charge by the voltage of a start may be off: much where the curve
 * is flat, as in the middle of a NiMH cell */
static uint32_t curve_error(const cfw_battery_model_t *model, uint32_t charge)
{
    uint32_t i = charge >= CFW_BAT_FULL ? 1 : 10 - charge / (CFW_BAT_FULL / 10);
    uint32_t step = model->curve[i - 1] - model->curve[i];
    uint32_t noise = model->cycles ? REST_NOISE_MV : REST_NOISE_DEFAULT_MV;
    uint32_t error = (CFW_BAT_FULL / 10) * noise / step;
    return error < CFW_BAT_FULL ? error : CFW_BAT_FULL;
}

static void spread_add(cfw_battery_model_t *model, uint64_t error)
{
    uint64_t spread = model->spread + error;
    model->spread = spread < CFW_BAT_FULL / 2 ? (uint32_t)spread : CFW_BAT_FULL / 2;
}

uint8_t cfw_battery_model_percent(const cfw_battery_model_t *model, uint16_t mv)
{
    return (uint8_t)((curve_charge(model, mv) + CFW_BAT_FULL / 200) / (CFW_BAT_FULL / 100));
}

static void cycle_add(cfw_battery_model_t *model, uint16_t mv)
{
    if (model->cycleCount == CFW_BAT_SAMPLES)
    {
        for (uint16_t i = 0; i < CFW_BAT_SAMPLES / 2; i++)
        {
            model->cycleMv[i] = model->cycleMv[2 * i];
            model->cycleAt[i] = model->cycleAt[2 * i];
        }
        model->cycleCount = CFW_BAT_SAMPLES / 2;
    }
    model->cycleMv[model->cycleCount] = mv;
    model->cycleAt[model->cycleCount] = model->cycleUsedMs;
    model->cycleCount++;
}

/* the capacity and the curve from the recorded discharge, when it covers enough
 * of it */
static bool cycle_learn(cfw_battery_model_t *model, bool critical)
{
    uint16_t n = model->cycleCount;
    uint32_t from = critical ? LEARN_FROM_CRITICAL : LEARN_FROM;
    bool usable = model->cycleActive && model->cycleFrom >= from && n >= LEARN_MIN_SAMPLES;
    model->cycleActive = false;
    if (!usable)
    {
        return false;
    }
    /* a discharge that did not begin full ran this part of the capacity */
    uint32_t began = model->cycleFrom >= LEARN_FROM ? CFW_BAT_FULL : model->cycleFrom;
    uint64_t capacityMs = (uint64_t)model->cycleUsedMs * CFW_BAT_FULL / began;
    uint64_t notRun = capacityMs - model->cycleUsedMs;
    uint32_t weight = model->measured == 0 ? 100 : model->measured == 1 ? 50
                                                                        : 25; /* percent of the new values */
    if (!critical)
    {
        /* an estimate: what the curve so far says was left at the last start. Only
           until a discharge to the critical voltage has measured the capacity. */
        uint32_t left = model->cycleLowMs ? LOW_LEFT : curve_charge(model, model->cycleMv[n - 1]);
        uint32_t at = model->cycleLowMs ? model->cycleLowMs : model->cycleAt[n - 1];
        if (model->measured || left > LEARN_TO)
        {
            return false;
        }
        capacityMs = (uint64_t)at * CFW_BAT_FULL / (CFW_BAT_FULL - left);
        notRun = 0;
        weight = 100 / (model->cycles + 2);
        weight = weight < 25 ? 25 : weight;
    }
    if (capacityMs < CAPACITY_MIN * 1000ull || capacityMs > CAPACITY_MAX * 1000ull)
    {
        return false;
    }

    for (uint32_t i = 0, j = 0; i < CFW_BAT_LEVELS; i++)
    {
        if (capacityMs * i / 10 < notRun)
        {
            continue; /* above the charge the discharge began with */
        }
        uint64_t at = capacityMs * i / 10 - notRun; /* running time when 100 - 10 i % are left */
        if (at > model->cycleAt[n - 1])
        {
            break;
        }
        while (j + 2 < n && model->cycleAt[j + 1] < at)
        {
            j++;
        }
        int64_t a0 = model->cycleAt[j];
        int64_t a1 = model->cycleAt[j + 1];
        int64_t v0 = model->cycleMv[j];
        int64_t v1 = model->cycleMv[j + 1];
        int64_t v = (a1 > a0 && (int64_t)at > a0) ? v0 + (v1 - v0) * ((int64_t)at - a0) / (a1 - a0) : v0;
        model->curve[i] = (uint16_t)((model->curve[i] * (100 - weight) + (uint32_t)v * weight + 50) / 100);
    }
    for (uint32_t i = 1; i < CFW_BAT_LEVELS; i++)
    {
        if (model->curve[i] + CURVE_MIN_STEP_MV > model->curve[i - 1])
        {
            model->curve[i] = model->curve[i - 1] - CURVE_MIN_STEP_MV;
        }
    }
    model->capacity = (uint32_t)(((uint64_t)model->capacity * (100 - weight) + capacityMs / 1000 * weight) / 100);
    model->cycles++;
    model->measured += critical ? 1 : 0;
    return true;
}

/* The slow way to the capacity, for the cell that ages and the box that never runs empty: when the
   voltage of a start says that less (or more) was used since the start before than was counted,
   the capacity moves a little that way. One odd start, such as a cold cell, moves it by 2 % at most. */
static void capacity_adapt(cfw_battery_model_t *model, uint32_t byVoltage)
{
    int64_t counted = (int64_t)model->restCharge - (int64_t)model->charge;
    if (!model->restValid || counted < ADAPT_MIN_USED)
    {
        return;
    }
    int64_t off = (int64_t)byVoltage - (int64_t)model->charge;
    off = off > counted / 2 ? counted / 2 : off < -counted / 2 ? -counted / 2
                                                               : off;
    int64_t capacity = model->capacity + (int64_t)model->capacity * off * ADAPT_PERCENT / (counted * 100);
    model->capacity = (uint32_t)(capacity < CAPACITY_MIN ? CAPACITY_MIN : capacity > CAPACITY_MAX ? CAPACITY_MAX
                                                                                                  : capacity);
}

static void charge_for(cfw_battery_model_t *model, uint64_t seconds)
{
    /* a charge not known yet stays so: the first start off the charger tells it
     */
    uint64_t charge = model->charge + seconds * CFW_BAT_FULL / CHARGE_SEC;
    model->charge = charge > CFW_BAT_FULL ? CFW_BAT_FULL : (uint32_t)charge;
    if (charge >= CFW_BAT_FULL)
    {
        model->spread = FULL_ERROR;
    }
}

static uint64_t square_root(uint64_t value)
{
    uint64_t root = 0;
    for (uint64_t bit = 1ull << 62; bit != 0; bit >>= 2)
    {
        if (value >= root + bit)
        {
            value -= root + bit;
            root = (root >> 1) + bit;
        }
        else
        {
            root >>= 1;
        }
    }
    return root;
}

/* a start after a pause: the charge moves towards the voltage as far as the
   voltage is more certain than the count */
static void rest_correct(cfw_battery_model_t *model, uint32_t byVoltage)
{
    uint64_t count = (uint64_t)model->spread * model->spread;
    uint64_t error = curve_error(model, byVoltage);
    uint64_t voltage = error * error;
    int64_t off = ((int64_t)byVoltage - (int64_t)model->charge) * (int64_t)count / (int64_t)(count + voltage + 1);
    capacity_adapt(model, byVoltage);
    model->charge = (uint32_t)((int64_t)model->charge + off);
    model->spread = (uint32_t)(model->spread * error / (square_root(count + voltage) + 1));
}

bool cfw_battery_model_report(cfw_battery_model_t *model, const cfw_battery_report_t *report, cfw_battery_result_t *result)
{
    bool learnedNow = false;
    cfw_battery_result_t out = {.percent = -1, .charging = report->station, .learned = model->cycles > 0};

    /* a new start of the box: the uptime went back, or less than the clock went
     * on */
    uint64_t pause = model->lastValid && report->time > model->lastTime ? report->time - model->lastTime : 0;
    bool sameStart = model->lastValid && report->uptimeMs >= model->lastUptimeMs &&
                     pause <= (report->uptimeMs - model->lastUptimeMs) / 1000 + START_SLACK_SEC;

    if (report->implausible)
    {
        if (result != NULL)
        {
            *result = out;
        }
        return false;
    }
    if (report->station)
    {
        /* charging: the recorded discharge ends here */
        learnedNow = cycle_learn(model, false);
        charge_for(model, model->lastValid && (model->lastStation || sameStart) ? pause : 0);
    }
    else
    {
        bool charged = sameStart && model->lastStation; /* taken off the charger while running */
        if (!sameStart && model->lastValid && (model->lastStation || report->mv > model->lastMv + CHARGED_RISE_MV))
        {
            /* charged while off: the box reports nothing then, but it was there or
             * starts much higher */
            charged = true;
            learnedNow = cycle_learn(model, false);
            charge_for(model, pause);
        }
        else if (!sameStart && model->lastValid && !model->lastStation)
        {
            uint64_t lost = pause * SELF_DISCHARGE_DAY / 86400;
            model->charge = lost < model->charge ? model->charge - (uint32_t)lost : 0;
            spread_add(model, pause * SELF_ERROR_DAY / 86400);
        }
        if (sameStart && !model->lastStation)
        {
            uint32_t ms = report->uptimeMs - model->lastUptimeMs;
            ms = ms <= MAX_GAP_MS ? ms : 0;
            uint64_t used = (uint64_t)ms * (CFW_BAT_FULL / 1000) / model->capacity;
            model->charge = used < model->charge ? model->charge - (uint32_t)used : 0;
            model->cycleUsedMs += ms;
            spread_add(model, used * (model->cycles ? COUNT_ERROR : COUNT_ERROR_DEFAULT) / 100);
        }

        bool rested = !sameStart && report->uptimeMs <= START_MS && (!model->lastValid || pause >= REST_SEC);
        uint32_t byVoltage = curve_charge(model, report->mv);
        if (!model->chargeValid)
        {
            model->charge = byVoltage;
            model->chargeValid = true;
            model->spread = curve_error(model, byVoltage);
        }
        else if (charged)
        {
            /* a short stay on the charger lifts the voltage more than the charge */
            model->charge = model->charge < byVoltage ? model->charge : byVoltage;
        }
        else if (rested)
        {
            rest_correct(model, byVoltage);
        }

        if (charged || rested)
        {
            model->restCharge = model->charge;
            model->restValid = true;
        }
        if (!model->cycleActive)
        {
            model->cycleActive = true;
            model->cycleFrom = model->charge;
            model->cycleUsedMs = 0;
            model->cycleLowMs = 0;
            model->cycleCount = 0;
        }
        if (rested || (charged && model->cycleCount == 0))
        {
            cycle_add(model, report->mv);
        }

        if (report->low && model->cycleLowMs == 0)
        {
            model->cycleLowMs = model->cycleUsedMs;
        }
        if (report->low && model->charge > LOW_MAX)
        {
            model->charge = LOW_MAX;
            model->spread = LOW_ERROR;
            model->restValid = false; /* the count was wrong: nothing to compare the next start with */
        }
        if (report->critical)
        {
            model->charge = 0;
            model->spread = 0;
            model->restValid = false;
            learnedNow = cycle_learn(model, true) || learnedNow;
        }
        else if (model->charge < CFW_BAT_FULL / 100)
        {
            model->charge = CFW_BAT_FULL / 100; /* not empty before the box says so */
        }
        out.percent = (int8_t)((model->charge + CFW_BAT_FULL / 200) / (CFW_BAT_FULL / 100));
        if (model->cycles)
        {
            out.remainingSec = (uint32_t)((uint64_t)model->capacity * model->charge / CFW_BAT_FULL);
        }
    }

    model->lastValid = true;
    model->lastStation = report->station;
    model->lastMv = report->mv;
    model->lastUptimeMs = report->uptimeMs;
    model->lastTime = report->time;
    out.learned = model->cycles > 0;
    if (result != NULL)
    {
        *result = out;
    }
    return learnedNow;
}
