#pragma once

/* Each test_*.c file defines one of these and registers it in test_runner.c. */
void test_os_spawnvp(void);
void test_os_shell_quote(void);
void test_os_chmod_owner_only(void);
void test_fs_remove_filename(void);
void test_hex_encode(void);
void test_escape_string(void);
void test_split_url(void);
void test_ipv4_is_public(void);
void test_esp32_port_patch(void);
void test_socket_receive_line_from_full_buffer(void);
void test_socket_receive_line_capped_at_size(void);
void test_cfw_crc(void);
void test_cfw_tbs(void);
void test_cfw_zip(void);
void test_cfw_page_label(void);
void test_cfw_version_older(void);
void test_cfw_ruid(void);
void test_cfw_event_for_basic_box(void);
void test_cfw_report_body(void);
void test_cfw_strip_volume_fields(void);
void test_cfw_esp32_image(void);
void test_cfw_esp32_original(void);
void test_box_cert_id(void);
void test_box_cert_issuer_known(void);
