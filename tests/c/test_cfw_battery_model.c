#include <assert.h>
#include <string.h>

#include "cfw_battery_model.h"
#include "tests.h"

/* the clock: when the box started, and its last report */
static uint64_t boot, last;

static cfw_battery_report_t report(uint16_t mv, uint32_t uptimeMs)
{
    cfw_battery_report_t r;
    memset(&r, 0, sizeof(r));
    r.mv = mv;
    r.uptimeMs = uptimeMs;
    r.time = last = boot + uptimeMs / 1000;
    return r;
}

/* the box starts after a pause and reports its voltage; returns the percent */
static int start(cfw_battery_model_t *m, uint32_t pauseSec, uint16_t mv)
{
    cfw_battery_result_t r;
    boot = last + pauseSec;
    cfw_battery_report_t p = report(mv, 10000);
    cfw_battery_model_report(m, &p, &r);
    return r.percent;
}

/* the box runs on, reporting every two minutes; returns the last percent */
static int run(cfw_battery_model_t *m, uint16_t mv, uint32_t minutes)
{
    cfw_battery_result_t r = {0};
    uint32_t from = m->lastUptimeMs;
    for (uint32_t i = 2; i <= minutes; i += 2)
    {
        cfw_battery_report_t p = report(mv, from + i * 60000);
        cfw_battery_model_report(m, &p, &r);
    }
    return r.percent;
}

static void on_charger(cfw_battery_model_t *m)
{
    cfw_battery_result_t r;
    cfw_battery_report_t p = report(4700, m->lastUptimeMs + 10000);
    p.station = true;
    cfw_battery_model_report(m, &p, &r);
    assert(r.percent == -1 && r.charging);
}

void test_cfw_battery_model_curve(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    assert(cfw_battery_model_percent(&m, 4300) == 100);
    assert(cfw_battery_model_percent(&m, 4170) == 100);
    assert(cfw_battery_model_percent(&m, 3865) == 50);
    assert(cfw_battery_model_percent(&m, 3848) == 45);
    assert(cfw_battery_model_percent(&m, 3650) == 0);
    assert(cfw_battery_model_percent(&m, 3400) == 0);
}

void test_cfw_battery_model_report(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    cfw_battery_result_t r;
    last = 1000000;

    /* the first report ever: the charge of the voltage */
    assert(start(&m, 0, 3865) == 50);
    assert(!m.cycles && m.capacity == 7 * 3600);

    /* running uses the charge by the time, whatever the voltage does: 42 minutes
     * of 7 hours */
    assert(run(&m, 3700, 20) == 45);
    assert(run(&m, 3990, 22) == 40);

    /* an implausible measurement changes nothing */
    cfw_battery_report_t bad = report(1000, m.lastUptimeMs + 5000);
    bad.implausible = true;
    cfw_battery_model_report(&m, &bad, &r);
    assert(r.percent == -1 && m.charge > 390000);

    /* the low-battery warning comes below a quarter */
    cfw_battery_report_t low = report(3660, m.lastUptimeMs + 5000);
    low.low = true;
    cfw_battery_model_report(&m, &low, &r);
    assert(r.percent == 25 && !r.learned && r.remainingSec == 0);

    /* not empty before the box says so */
    m.charge = 100;
    assert(run(&m, 3640, 2) == 1);
    cfw_battery_report_t critical = report(3590, m.lastUptimeMs + 5000);
    critical.critical = true;
    assert(!cfw_battery_model_report(&m, &critical, &r)); /* not from full: nothing to learn */
    assert(r.percent == 0);
}

void test_cfw_battery_model_start(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    last = 1000000;
    assert(start(&m, 0, 3865) == 50);

    /* a start right after: the cell has not rested, its voltage does not count */
    assert(start(&m, 300, 3950) == 50);
    /* a start after a pause: the voltage moves the charge most of the way */
    assert(start(&m, 3600, 3900) == 56);

    /* an hour and a half on the charger is half a charge, also when the box went
     * off there */
    on_charger(&m);
    assert(start(&m, 5400, 4200) == 100);
    assert(m.cycleActive && m.cycleFrom == CFW_BAT_FULL && m.cycleCount == 1);

    /* charged while off without a report from the charger: the start is much
     * higher */
    m.charge = 200000;
    m.lastMv = 3750;
    assert(start(&m, 1800, 3990) == 37);
    /* the charger was not plugged in: the voltage limits what the time promises
     */
    on_charger(&m);
    assert(start(&m, 36000, 3900) == 60);
    assert(m.cycleFrom == 600000);
}

void test_cfw_battery_model_adapts(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    last = 1000000;
    assert(start(&m, 0, 4050) == 90);

    /* an hour a day is counted as a seventh, but the starts say a tenth was used: the cell is larger */
    const uint16_t starts[] = {3990, 3945, 3900, 3865};
    uint32_t before = m.capacity;
    for (int i = 0; i < 4; i++)
    {
        run(&m, 3900, 60);
        start(&m, 20 * 3600, starts[i]);
        assert(m.capacity > before && m.capacity <= before + before / 50); /* slowly */
        before = m.capacity;
    }
    assert(m.capacity > 7 * 3600 + 600 && m.cycles == 0);

    /* one start in the cold, far too low: 2 % at most */
    run(&m, 3900, 60);
    start(&m, 20 * 3600, 3700);
    assert(m.capacity < before && m.capacity >= before - before / 50);
}

void test_cfw_battery_model_learns(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    cfw_battery_result_t r;
    last = 1000000;
    start(&m, 0, 3700);
    on_charger(&m);

    /* this box runs five hours, an hour a day, and starts lower than the default
     * curve */
    const uint16_t starts[] = {4100, 3950, 3850, 3780, 3720};
    for (int i = 0; i < 5; i++)
    {
        start(&m, 20 * 3600, starts[i]);
        assert(m.cycleFrom > 920000 && m.cycles == 0);
        run(&m, starts[i] - 80, 60);
    }
    cfw_battery_report_t critical = report(3590, m.lastUptimeMs + 5000);
    critical.critical = true;
    assert(cfw_battery_model_report(&m, &critical, &r));
    assert(r.percent == 0 && r.learned && m.cycles == 1 && m.measured == 1);
    /* the first measured discharge replaces the defaults */
    assert(m.capacity > 5 * 3600 - 60 && m.capacity < 5 * 3600 + 60);
    assert(m.curve[0] == 4100 && m.curve[2] > 3945 && m.curve[2] <= 3950 && m.curve[4] > 3845 && m.curve[4] <= 3850);
    for (int i = 1; i < CFW_BAT_LEVELS; i++)
    {
        assert(m.curve[i] < m.curve[i - 1]);
    }

    /* charged again and half of it used: the running time left */
    on_charger(&m);
    assert(start(&m, 4 * 3600, 4200) == 100);
    assert(run(&m, 3800, 150) == 50);
    cfw_battery_report_t half = report(3800, m.lastUptimeMs + 1000);
    cfw_battery_model_report(&m, &half, &r);
    assert(r.remainingSec > 8900 && r.remainingSec < 9100);

    /* a discharge that did not reach the critical voltage teaches nothing after a
     * measured one */
    on_charger(&m);
    assert(m.cycles == 1);
}

void test_cfw_battery_model_learns_partial(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    cfw_battery_result_t r;
    last = 1000000;
    start(&m, 0, 3700);
    on_charger(&m);

    /* charged, but long off the charger: the discharge begins at 80 % and runs
     * four hours to the critical voltage, so the box runs five hours from full */
    const uint16_t starts[] = {3990, 3880, 3800, 3720};
    for (int i = 0; i < 4; i++)
    {
        start(&m, 20 * 3600, starts[i]);
        run(&m, starts[i] - 60, 60);
    }
    assert(m.cycleFrom == 800000);
    cfw_battery_report_t critical = report(3590, m.lastUptimeMs + 5000);
    critical.critical = true;
    assert(cfw_battery_model_report(&m, &critical, &r));
    assert(r.learned && m.cycles == 1 && m.measured == 1);
    assert(m.capacity > 5 * 3600 - 60 && m.capacity < 5 * 3600 + 60);
    /* the curve above the start stays */
    assert(m.curve[0] == 4170 && m.curve[1] == 4050 && m.curve[2] == 3990 && m.curve[4] == 3880 && m.curve[6] == 3800);
}

void test_cfw_battery_model_flat_middle(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    last = 1000000;
    /* a learned NiMH cell of ten hours: 10 mV from 70 to 20 % */
    const uint16_t curve[CFW_BAT_LEVELS] = {4150, 4050, 3950, 3900, 3890, 3880, 3870, 3860, 3850, 3750, 3650};
    memcpy(m.curve, curve, sizeof(curve));
    m.cycles = 1;
    m.capacity = 10 * 3600;
    start(&m, 0, 3700);
    on_charger(&m);
    assert(start(&m, 4 * 3600, 4200) == 100);
    assert(run(&m, 3850, 300) == 50);

    /* 10 mV above the curve there is no reason to believe in 60 % */
    assert(start(&m, 3600, 3890) == 50);
    /* a week off: the cell lost charge of its own */
    int percent = start(&m, 7 * 86400, 3880);
    assert(percent >= 42 && percent <= 46);
}

void test_cfw_battery_model_learns_low(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    cfw_battery_result_t r;
    last = 1000000;
    start(&m, 0, 3700);
    on_charger(&m);

    /* four hours from full to the low-battery warning: a fifth is left there,
       so the box runs five hours; an estimate, so the default of seven keeps half */
    const uint16_t starts[] = {4100, 3950, 3850, 3780};
    for (int i = 0; i < 4; i++)
    {
        start(&m, 20 * 3600, starts[i]);
        run(&m, starts[i] - 80, 60);
    }
    cfw_battery_report_t low = report(3660, m.lastUptimeMs + 1000);
    low.low = true;
    cfw_battery_model_report(&m, &low, &r);
    on_charger(&m);
    assert(m.cycles == 1 && m.measured == 0);
    assert(m.capacity > 5 * 3600 && m.capacity < 6 * 3600 + 300);
}
