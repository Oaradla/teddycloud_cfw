#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "tests.h"
#include "web_auth_crypto.h"
#include "web_auth_net.h"

void test_web_auth_totp(void)
{
    /* RFC 6238 appendix B, SHA-1 seed "12345678901234567890", 8 digits */
    const uint8_t *key = (const uint8_t *)"12345678901234567890";
    assert(web_auth_hotp(key, 20, 59 / 30, 8) == 94287082);
    assert(web_auth_hotp(key, 20, 1111111109 / 30, 8) == 7081804);
    assert(web_auth_hotp(key, 20, 20000000000LL / 30, 8) == 65353130);
    /* RFC 4226 appendix D, 6 digits */
    assert(web_auth_hotp(key, 20, 0, 6) == 755224);
    assert(web_auth_hotp(key, 20, 9, 6) == 520489);

    char code[8];
    snprintf(code, sizeof(code), "%06u", web_auth_hotp(key, 20, 1111111109 / 30, 6));
    int64_t step = 1111111109 / 30;
    assert(web_auth_totp_match(key, 20, code, 1111111109, 1, -1) == step);
    /* the step before and after are accepted, two steps away not */
    assert(web_auth_totp_match(key, 20, code, 1111111109 + 30, 1, -1) == step);
    assert(web_auth_totp_match(key, 20, code, 1111111109 - 30, 1, -1) == step);
    assert(web_auth_totp_match(key, 20, code, 1111111109 + 60, 1, -1) == -1);
    /* a code is not accepted twice */
    assert(web_auth_totp_match(key, 20, code, 1111111109, 1, step) == -1);
    assert(web_auth_totp_match(key, 20, "12345", 1111111109, 1, -1) == -1);
    assert(web_auth_totp_match(key, 20, "12345a", 1111111109, 1, -1) == -1);
}

void test_web_auth_base32(void)
{
    char out[64];
    uint8_t back[32];
    assert(web_auth_base32_encode((const uint8_t *)"foobar", 6, out, sizeof(out)) == 10);
    assert(!strcmp(out, "MZXW6YTBOI"));
    assert(web_auth_base32_decode("mzxw 6ytb-oi", back, sizeof(back)) == 6);
    assert(!memcmp(back, "foobar", 6));
    assert(web_auth_base32_decode("MZ1W", back, sizeof(back)) == -1);
    assert(web_auth_base32_encode((const uint8_t *)"foobar", 6, out, 5) == 0);
}

void test_web_auth_password(void)
{
    uint8_t salt[WEB_AUTH_SALT_BYTES];
    char hash[WEB_AUTH_HASH_MAX];
    bool rehash = true;
    memset(salt, 0x42, sizeof(salt));
    assert(web_auth_pw_hash("correct horse", salt, WEB_AUTH_PBKDF2_MIN_ITERATIONS, hash, sizeof(hash)));
    assert(!strncmp(hash, "pbkdf2-sha256$10000$", 20));
    assert(web_auth_pw_hash_valid(hash));
    assert(web_auth_pw_verify(hash, "correct horse", &rehash));
    assert(rehash); /* fewer iterations than the default */
    assert(!web_auth_pw_verify(hash, "correct horsE", NULL));
    assert(web_auth_pw_hash("correct horse", salt, WEB_AUTH_PBKDF2_ITERATIONS, hash, sizeof(hash)));
    assert(web_auth_pw_verify(hash, "correct horse", &rehash) && !rehash);
    hash[strlen(hash) - 1] ^= 1;
    assert(!web_auth_pw_verify(hash, "correct horse", NULL));
    assert(!web_auth_pw_hash_valid("pbkdf2-sha256$1$00$00"));

    /* RFC 7914 section 11 PBKDF2-HMAC-SHA256 test vector, P="passwd" S="salt" c=1 is below the minimum,
     * so check the legacy SHA-256(salt|password) format of the first login release instead */
    char legacy[160];
    char digest_hex[65];
    uint8_t buf[16 + 6];
    memset(buf, 0x42, 16);
    memcpy(buf + 16, "secret", 6);
    web_auth_sha256_hex(buf, sizeof(buf), digest_hex, sizeof(digest_hex));
    snprintf(legacy, sizeof(legacy), "sha256$42424242424242424242424242424242$%s", digest_hex);
    assert(web_auth_pw_hash_valid(legacy));
    assert(web_auth_pw_verify(legacy, "secret", &rehash) && rehash);
    assert(!web_auth_pw_verify(legacy, "Secret", NULL));
    assert(!web_auth_pw_verify("plain", "plain", NULL));
}

void test_web_auth_seal(void)
{
    uint8_t key[WEB_AUTH_SEAL_KEY_BYTES];
    uint8_t iv[WEB_AUTH_SEAL_IV_BYTES];
    uint8_t plain[32];
    char sealed[256];
    memset(key, 7, sizeof(key));
    memset(iv, 9, sizeof(iv));
    assert(web_auth_seal(key, iv, "alice", (const uint8_t *)"0123456789abcdefghij", 20, sealed, sizeof(sealed)));
    assert(strlen(sealed) == (12 + 20 + 16) * 2);
    assert(web_auth_unseal(key, "alice", sealed, plain, sizeof(plain)) == 20);
    assert(!memcmp(plain, "0123456789abcdefghij", 20));
    /* bound to the user name and the key */
    assert(web_auth_unseal(key, "bob", sealed, plain, sizeof(plain)) == -1);
    key[0] ^= 1;
    assert(web_auth_unseal(key, "alice", sealed, plain, sizeof(plain)) == -1);
}

void test_web_auth_ip(void)
{
    char out[WEB_AUTH_IP_STR_MAX];
    uint8_t a[16];
    assert(web_auth_ip_normalize("192.168.1.10", out, sizeof(out)) && !strcmp(out, "192.168.1.10"));
    assert(web_auth_ip_normalize("::ffff:192.168.1.10", out, sizeof(out)) && !strcmp(out, "192.168.1.10"));
    assert(web_auth_ip_normalize("192.168.1.10:443", out, sizeof(out)) && !strcmp(out, "192.168.1.10"));
    assert(web_auth_ip_normalize("[2001:DB8::1]:443", out, sizeof(out)) && !strcmp(out, "2001:db8::1"));
    assert(web_auth_ip_normalize("2001:db8:0:0:1:0:0:1", out, sizeof(out)) && !strcmp(out, "2001:db8::1:0:0:1"));
    assert(web_auth_ip_normalize("fe80::1%eth0", out, sizeof(out)) && !strcmp(out, "fe80::1"));
    assert(web_auth_ip_normalize("::1", out, sizeof(out)) && !strcmp(out, "::1"));
    assert(!web_auth_ip_parse("192.168.1", a));
    assert(!web_auth_ip_parse("192.168.01.1", a));
    assert(!web_auth_ip_parse("256.1.1.1", a));
    assert(!web_auth_ip_parse("1:2:3:4:5:6:7:8:9", a));
    assert(!web_auth_ip_parse("1::2::3", a));
    assert(!web_auth_ip_parse("example.com", a));

    const char *lan = WEB_AUTH_DEFAULT_LAN_NETWORKS;
    assert(web_auth_ip_in_list(lan, "192.168.5.122"));
    assert(web_auth_ip_in_list(lan, "172.31.255.1"));
    assert(!web_auth_ip_in_list(lan, "172.32.0.1"));
    assert(web_auth_ip_in_list(lan, "fd12:3456::1"));
    assert(web_auth_ip_in_list(lan, "::ffff:10.1.2.3"));
    assert(!web_auth_ip_in_list(lan, "8.8.8.8"));
    assert(!web_auth_ip_in_list(lan, "2001:db8::1"));
    assert(web_auth_ip_in_list("8.8.8.8", "8.8.8.8"));
    assert(!web_auth_ip_in_list("", "8.8.8.8"));
    assert(web_auth_ip_in_list("0.0.0.0/0", "8.8.8.8"));
    assert(!web_auth_ip_in_list("0.0.0.0/0", "2001:db8::1"));
    assert(web_auth_ip_in_list("::/0", "2001:db8::1"));

    char bad[32];
    assert(web_auth_ip_list_valid(lan, bad, sizeof(bad)));
    assert(!web_auth_ip_list_valid("10.0.0.0/8, 10.0.0.0/33", bad, sizeof(bad)) && !strcmp(bad, "10.0.0.0/33"));
    assert(!web_auth_ip_list_valid("lan", bad, sizeof(bad)) && !strcmp(bad, "lan"));
    assert(web_auth_ip_list_valid("", bad, sizeof(bad)));
}

void test_web_auth_ip_resolve(void)
{
    char out[WEB_AUTH_IP_STR_MAX];
    web_auth_ip_lockout_key("2001:db8:1:2:aaaa::1", out, sizeof(out));
    assert(!strcmp(out, "2001:db8:1:2::/64"));
    web_auth_ip_lockout_key("2001:db8:1:2:bbbb::9", out, sizeof(out));
    assert(!strcmp(out, "2001:db8:1:2::/64"));
    web_auth_ip_lockout_key("::ffff:192.0.2.1", out, sizeof(out));
    assert(!strcmp(out, "192.0.2.1"));
    web_auth_ip_lockout_key("unknown", out, sizeof(out));
    assert(!strcmp(out, "unknown"));
    /* untrusted peer: the header is ignored */
    web_auth_ip_resolve("203.0.113.5", "1.2.3.4", "10.0.0.1", out, sizeof(out));
    assert(!strcmp(out, "203.0.113.5"));
    /* no proxy configured */
    web_auth_ip_resolve("10.0.0.1", "1.2.3.4", "", out, sizeof(out));
    assert(!strcmp(out, "10.0.0.1"));
    /* trusted proxy: rightmost address */
    web_auth_ip_resolve("10.0.0.1", "1.2.3.4", "10.0.0.1", out, sizeof(out));
    assert(!strcmp(out, "1.2.3.4"));
    /* a client can prepend fake hops, only the rightmost untrusted one counts */
    web_auth_ip_resolve("10.0.0.1", "127.0.0.1, 198.51.100.7", "10.0.0.1", out, sizeof(out));
    assert(!strcmp(out, "198.51.100.7"));
    /* chained proxies */
    web_auth_ip_resolve("10.0.0.1", "198.51.100.7, 10.0.0.2", "10.0.0.0/24", out, sizeof(out));
    assert(!strcmp(out, "198.51.100.7"));
    /* garbage in the header is an unknown client, not the trusted (local) proxy */
    web_auth_ip_resolve("10.0.0.1", "nonsense", "10.0.0.1", out, sizeof(out));
    assert(!strcmp(out, "unknown"));
    assert(!web_auth_ip_in_list(WEB_AUTH_DEFAULT_LAN_NETWORKS, out));
    web_auth_ip_resolve("10.0.0.1", "truncated, 10.0.0.1", "10.0.0.1", out, sizeof(out));
    assert(!strcmp(out, "unknown"));
    web_auth_ip_resolve("::ffff:10.0.0.1", "[2001:db8::7]:1234", "10.0.0.1", out, sizeof(out));
    assert(!strcmp(out, "2001:db8::7"));
}
