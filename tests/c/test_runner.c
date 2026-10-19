/*
 * Runs pure C unit tests that don't need a running server (see tests/py/
 * for the HTTP-level integration tests). Each test function uses assert()
 * and aborts on the first failure, which is enough for `make test_c` to
 * fail loudly and point at the exact check that broke.
 */
#include <stdio.h>

#include "tests.h"

typedef struct
{
    const char *name;
    void (*fn)(void);
} test_case_t;

static const test_case_t tests[] = {
    {"os_spawnvp", test_os_spawnvp},
    {"os_shell_quote", test_os_shell_quote},
    {"os_chmod_owner_only", test_os_chmod_owner_only},
    {"fs_remove_filename", test_fs_remove_filename},
    {"hex_encode", test_hex_encode},
    {"escape_string", test_escape_string},
    {"split_url", test_split_url},
    {"ipv4_is_public", test_ipv4_is_public},
    {"esp32_port_patch", test_esp32_port_patch},
    {"socket_receive_line_from_full_buffer", test_socket_receive_line_from_full_buffer},
    {"socket_receive_line_capped_at_size", test_socket_receive_line_capped_at_size},
    {"cfw_crc", test_cfw_crc},
    {"cfw_tbs", test_cfw_tbs},
    {"cfw_zip", test_cfw_zip},
    {"cfw_page_label", test_cfw_page_label},
    {"cfw_version_older", test_cfw_version_older},
    {"cfw_ruid", test_cfw_ruid},
    {"cfw_event_for_basic_box", test_cfw_event_for_basic_box},
    {"cfw_report_body", test_cfw_report_body},
    {"cfw_strip_volume_fields", test_cfw_strip_volume_fields},
    {"cfw_esp32_image", test_cfw_esp32_image},
    {"cfw_esp32_original", test_cfw_esp32_original},
    {"cfw_battery_model_curve", test_cfw_battery_model_curve},
    {"cfw_battery_model_report", test_cfw_battery_model_report},
    {"cfw_battery_model_start", test_cfw_battery_model_start},
    {"cfw_battery_model_learns", test_cfw_battery_model_learns},
    {"box_cert_id", test_box_cert_id},
    {"box_cert_issuer_known", test_box_cert_issuer_known},
};

int main(void)
{
    size_t count = sizeof(tests) / sizeof(tests[0]);

    for (size_t i = 0; i < count; i++)
    {
        printf("[ RUN  ] %s\n", tests[i].name);
        tests[i].fn();
        printf("[  OK  ] %s\n", tests[i].name);
    }

    printf("%zu C test(s) passed\n", count);
    return 0;
}
