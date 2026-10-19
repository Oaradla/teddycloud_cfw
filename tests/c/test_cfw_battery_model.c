#include <assert.h>
#include <string.h>

#include "cfw_battery_model.h"
#include "tests.h"

static cfw_battery_report_t report(uint16_t mv, uint8_t state, uint8_t step, uint32_t uptimeMs)
{
    cfw_battery_report_t r;
    memset(&r, 0, sizeof(r));
    r.mv = mv;
    r.state = state;
    r.step = step;
    r.uptimeMs = uptimeMs;
    return r;
}

void test_cfw_battery_model_curve(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    assert(cfw_battery_model_percent(&m, 4300) == 100);
    assert(cfw_battery_model_percent(&m, 4125) == 100);
    assert(cfw_battery_model_percent(&m, 3780) == 50);
    assert(cfw_battery_model_percent(&m, 3761) == 45);
    assert(cfw_battery_model_percent(&m, 3595) == 0);
    assert(cfw_battery_model_percent(&m, 3400) == 0);
    /* the firmware's low-battery warning (3669 mV) lands near 20 % */
    uint8_t warn = cfw_battery_model_percent(&m, 3669);
    assert(warn >= 18 && warn <= 22);

    assert(cfw_battery_model_band(0, false) == 0 && cfw_battery_model_band(7, false) == 1);
    assert(cfw_battery_model_band(15, false) == 3 && cfw_battery_model_band(15, true) == CFW_BAT_BAND_HEADPHONES);
    /* louder is more load */
    assert(cfw_battery_model_play_load(&m, 3) > cfw_battery_model_play_load(&m, 0));
}

void test_cfw_battery_model_report(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    cfw_battery_result_t r;

    /* on the charger: no charge, only charging */
    cfw_battery_report_t c = report(4700, 0, 5, 10000);
    c.station = true;
    cfw_battery_model_report(&m, &c, &r);
    assert(r.charging && r.percent == -1);

    /* playing: the play drop of the volume is added before the curve is read */
    cfw_battery_report_t p = report((uint16_t)(3780 - m.playDrop[2]), 2, 9, 120000);
    cfw_battery_model_report(&m, &p, &r);
    assert(!r.charging && r.percent == 50 && r.remainingSec == 0 && !r.learned);

    /* implausible values are left out */
    cfw_battery_report_t bad = report(5000, 0, 5, 160000);
    bad.implausible = true;
    cfw_battery_model_report(&m, &bad, &r);
    assert(r.percent == -1);

    /* the play drop per band: idle 3800, playing loud 3730 again and again */
    uint32_t up = 200000;
    for (int i = 0; i < 20; i++)
    {
        cfw_battery_report_t idle = report(3800, 1, 13, up);
        cfw_battery_model_report(&m, &idle, NULL);
        up += 60000;
        cfw_battery_report_t loud = report(3730, 2, 13, up);
        cfw_battery_model_report(&m, &loud, NULL);
        up += 60000;
    }
    assert(m.playDrop[3] >= 68 && m.playDrop[3] <= 72); /* 70, within the rounding of mV */
    assert(m.playDrop[0] == 15); /* untouched */
}

/* a full discharge at mixed volume down to the critical shut-off: the curve and the capacity are
   learned, and the playing time left depends on the volume */
/* right after a start the voltage is near rest: the base drop comes off; a much higher start
   after the last report means a charge while off, which ends the discharge */
void test_cfw_battery_model_start(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    cfw_battery_result_t r;
    cfw_battery_report_t first = report((uint16_t)(3780 + m.baseDrop), 0, 5, 11000);
    cfw_battery_model_report(&m, &first, &r);
    assert(r.percent == 50);
    cfw_battery_report_t later = report(3700, 1, 5, 600000);
    cfw_battery_model_report(&m, &later, &r);
    assert(m.cycleActive && m.cycleCount == 2);
    cfw_battery_report_t charged = report(4100, 0, 5, 11000);
    cfw_battery_model_report(&m, &charged, &r);
    assert(m.cycleActive && m.cycleCount == 1 && m.cycleFromFull);
    assert(m.baseDrop == CFW_BAT_DEFAULT_BASE_DROP); /* a charge is no base drop */
}

void test_cfw_battery_model_learns(void)
{
    cfw_battery_model_t m;
    cfw_battery_model_init(&m);
    cfw_battery_result_t r;

    cfw_battery_report_t c = report(4700, 0, 5, 10000);
    c.station = true;
    cfw_battery_model_report(&m, &c, &r);

    /* this box: a little higher than the default curve, linear in the charge used */
    const uint16_t top = 4150, bottom = 3600;
    uint32_t up = 75000, used = 0;
    const uint32_t capacity = 1000000; /* mV·s */
    bool learned = false;
    for (int i = 0; used < capacity && i < 2000; i++)
    {
        uint8_t step = (i / 30) % 2 ? 12 : 4; /* half an hour loud, half an hour quiet */
        uint8_t band = cfw_battery_model_band(step, false);
        uint16_t idle = (uint16_t)(top - (uint32_t)(top - bottom) * used / capacity);
        cfw_battery_report_t p = report((uint16_t)(idle - m.playDrop[band]), 2, step, up);
        p.critical = used + 120 * cfw_battery_model_play_load(&m, band) >= capacity;
        learned = cfw_battery_model_report(&m, &p, &r) || learned;
        used += 120 * cfw_battery_model_play_load(&m, band);
        up += 120000;
    }
    assert(learned && m.cycles == 1 && r.percent == 0);
    /* half the new discharge: between the default and this box */
    assert(m.capacity > 900000 && m.capacity < 1100000);
    assert(m.curve[0] > 4125 && m.curve[0] <= top);
    for (int i = 1; i < CFW_BAT_LEVELS; i++)
    {
        assert(m.curve[i] < m.curve[i - 1]);
    }

    /* charged again: half full now, and the playing time left depends on the volume */
    cfw_battery_model_report(&m, &c, &r);
    cfw_battery_report_t quiet = report(m.curve[5], 1, 2, 120000);
    cfw_battery_model_report(&m, &quiet, &r);
    uint32_t quietLeft = r.remainingSec;
    assert(r.learned && r.percent == 50 && quietLeft > 0);
    cfw_battery_report_t loud = report(m.curve[5], 1, 14, 130000);
    cfw_battery_model_report(&m, &loud, &r);
    assert(r.remainingSec < quietLeft);
    assert(r.remainingSec == m.capacity / 2 / cfw_battery_model_play_load(&m, 3));
}
