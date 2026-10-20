#ifndef _WEB_AUTH_CRYPTO_H
#define _WEB_AUTH_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

/*
 * Building blocks of the web UI login that need no server state:
 * password hashes, TOTP (RFC 6238), base32 and sealing of secrets at rest.
 * Callers supply all random bytes, so everything here is deterministic and
 * covered by tests/c.
 */

#define WEB_AUTH_SALT_BYTES 16
/* PBKDF2-HMAC-SHA256 work factor for new hashes; older hashes are upgraded on the next login */
#define WEB_AUTH_PBKDF2_ITERATIONS 50000
#define WEB_AUTH_PBKDF2_MIN_ITERATIONS 10000
#define WEB_AUTH_PBKDF2_MAX_ITERATIONS 10000000
#define WEB_AUTH_HASH_MAX 160

#define WEB_AUTH_TOTP_KEY_BYTES 20
#define WEB_AUTH_TOTP_DIGITS 6
#define WEB_AUTH_TOTP_PERIOD 30

#define WEB_AUTH_SEAL_KEY_BYTES 32
#define WEB_AUTH_SEAL_IV_BYTES 12
#define WEB_AUTH_SEAL_TAG_BYTES 16

/* "pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>" */
bool web_auth_pw_hash(const char *password, const uint8_t salt[WEB_AUTH_SALT_BYTES], uint32_t iterations, char *out, size_t out_size);
/* also accepts the legacy format "sha256$<salt hex>$<hash hex>" (single salted SHA-256);
 * needs_rehash is set when the hash is legacy or uses fewer iterations than the current default */
bool web_auth_pw_verify(const char *stored, const char *password, bool *needs_rehash);
bool web_auth_pw_hash_valid(const char *stored);

bool web_auth_const_equal(const void *a, const void *b, size_t len);
bool web_auth_const_equal_str(const char *a, const char *b);

void web_auth_hex(const uint8_t *data, size_t len, char *out, size_t out_size);
bool web_auth_unhex(const char *hex, uint8_t *out, size_t out_len);
void web_auth_sha256_hex(const void *data, size_t len, char *out, size_t out_size);

/* RFC 4648 base32 without padding; decode ignores spaces, dashes and case */
size_t web_auth_base32_encode(const uint8_t *data, size_t len, char *out, size_t out_size);
int web_auth_base32_decode(const char *in, uint8_t *out, size_t out_size);

uint32_t web_auth_hotp(const uint8_t *key, size_t key_len, uint64_t counter, int digits);
/* checks a code against the time steps now-window..now+window that are newer than last_step;
 * returns the matching time step or -1 */
int64_t web_auth_totp_match(const uint8_t *key, size_t key_len, const char *code, time_t now, int window, int64_t last_step);

/* AES-256-GCM, output hex is iv | ciphertext | tag; aad binds the blob to e.g. the user name */
bool web_auth_seal(const uint8_t key[WEB_AUTH_SEAL_KEY_BYTES], const uint8_t iv[WEB_AUTH_SEAL_IV_BYTES], const char *aad,
                   const uint8_t *plain, size_t len, char *out_hex, size_t out_size);
int web_auth_unseal(const uint8_t key[WEB_AUTH_SEAL_KEY_BYTES], const char *aad, const char *in_hex, uint8_t *plain, size_t plain_size);

#endif
