#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_auth_crypto.h"

#include "aead/gcm.h"
#include "cipher/aes.h"
#include "hash/sha1.h"
#include "hash/sha256.h"
#include "kdf/pbkdf.h"
#include "mac/hmac.h"

#define PBKDF2_PREFIX "pbkdf2-sha256$"
#define LEGACY_PREFIX "sha256$"
#define PBKDF2_DK_BYTES 32

bool web_auth_const_equal(const void *a, const void *b, size_t len)
{
    const volatile uint8_t *pa = a;
    const volatile uint8_t *pb = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
    {
        diff |= pa[i] ^ pb[i];
    }
    return diff == 0;
}

bool web_auth_const_equal_str(const char *a, const char *b)
{
    if (a == NULL || b == NULL)
    {
        return false;
    }
    size_t la = strlen(a);
    size_t lb = strlen(b);
    size_t n = la < lb ? la : lb;
    unsigned diff = (unsigned)(la ^ lb);
    for (size_t i = 0; i < n; i++)
    {
        diff |= (unsigned char)a[i] ^ (unsigned char)b[i];
    }
    return diff == 0;
}

void web_auth_hex(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    if (out_size == 0)
    {
        return;
    }
    for (size_t i = 0; i < len && o + 2 < out_size; i++)
    {
        out[o++] = hex[data[i] >> 4];
        out[o++] = hex[data[i] & 0x0F];
    }
    out[o] = '\0';
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

bool web_auth_unhex(const char *hex, uint8_t *out, size_t out_len)
{
    if (hex == NULL || strlen(hex) != out_len * 2)
    {
        return false;
    }
    for (size_t i = 0; i < out_len; i++)
    {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
        {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

void web_auth_sha256_hex(const void *data, size_t len, char *out, size_t out_size)
{
    uint8_t digest[SHA256_DIGEST_SIZE];
    sha256Compute(data, len, digest);
    web_auth_hex(digest, sizeof(digest), out, out_size);
}

bool web_auth_pw_hash(const char *password, const uint8_t salt[WEB_AUTH_SALT_BYTES], uint32_t iterations, char *out, size_t out_size)
{
    uint8_t dk[PBKDF2_DK_BYTES];
    char salt_hex[WEB_AUTH_SALT_BYTES * 2 + 1];
    char dk_hex[PBKDF2_DK_BYTES * 2 + 1];
    if (password == NULL || out == NULL || iterations < WEB_AUTH_PBKDF2_MIN_ITERATIONS || iterations > WEB_AUTH_PBKDF2_MAX_ITERATIONS)
    {
        return false;
    }
    if (pbkdf2(SHA256_HASH_ALGO, (const uint8_t *)password, strlen(password), salt, WEB_AUTH_SALT_BYTES, iterations, dk, sizeof(dk)) != 0)
    {
        return false;
    }
    web_auth_hex(salt, WEB_AUTH_SALT_BYTES, salt_hex, sizeof(salt_hex));
    web_auth_hex(dk, sizeof(dk), dk_hex, sizeof(dk_hex));
    memset(dk, 0, sizeof(dk));
    int n = snprintf(out, out_size, PBKDF2_PREFIX "%u$%s$%s", (unsigned)iterations, salt_hex, dk_hex);
    return n > 0 && (size_t)n < out_size;
}

/* splits "<a>$<b>" of fixed lengths after a prefix; returns false on any deviation */
static bool parse_pbkdf2(const char *stored, uint32_t *iterations, uint8_t salt[WEB_AUTH_SALT_BYTES], uint8_t dk[PBKDF2_DK_BYTES])
{
    const char *p = stored + strlen(PBKDF2_PREFIX);
    char *end = NULL;
    if (!isdigit((unsigned char)*p))
    {
        return false;
    }
    unsigned long it = strtoul(p, &end, 10);
    if (end == NULL || *end != '$' || it < WEB_AUTH_PBKDF2_MIN_ITERATIONS || it > WEB_AUTH_PBKDF2_MAX_ITERATIONS)
    {
        return false;
    }
    p = end + 1;
    char salt_hex[WEB_AUTH_SALT_BYTES * 2 + 1];
    if (strlen(p) != sizeof(salt_hex) - 1 + 1 + PBKDF2_DK_BYTES * 2 || p[sizeof(salt_hex) - 1] != '$')
    {
        return false;
    }
    memcpy(salt_hex, p, sizeof(salt_hex) - 1);
    salt_hex[sizeof(salt_hex) - 1] = '\0';
    if (!web_auth_unhex(salt_hex, salt, WEB_AUTH_SALT_BYTES) || !web_auth_unhex(p + sizeof(salt_hex), dk, PBKDF2_DK_BYTES))
    {
        return false;
    }
    *iterations = (uint32_t)it;
    return true;
}

static bool parse_legacy(const char *stored, uint8_t salt[WEB_AUTH_SALT_BYTES], uint8_t digest[SHA256_DIGEST_SIZE])
{
    const char *p = stored + strlen(LEGACY_PREFIX);
    if (strlen(p) != WEB_AUTH_SALT_BYTES * 2 + 1 + SHA256_DIGEST_SIZE * 2 || p[WEB_AUTH_SALT_BYTES * 2] != '$')
    {
        return false;
    }
    char salt_hex[WEB_AUTH_SALT_BYTES * 2 + 1];
    memcpy(salt_hex, p, WEB_AUTH_SALT_BYTES * 2);
    salt_hex[WEB_AUTH_SALT_BYTES * 2] = '\0';
    return web_auth_unhex(salt_hex, salt, WEB_AUTH_SALT_BYTES) && web_auth_unhex(p + WEB_AUTH_SALT_BYTES * 2 + 1, digest, SHA256_DIGEST_SIZE);
}

bool web_auth_pw_hash_valid(const char *stored)
{
    uint8_t salt[WEB_AUTH_SALT_BYTES];
    uint8_t dk[SHA256_DIGEST_SIZE];
    uint32_t it;
    if (stored == NULL)
    {
        return false;
    }
    if (!strncmp(stored, PBKDF2_PREFIX, strlen(PBKDF2_PREFIX)))
    {
        return parse_pbkdf2(stored, &it, salt, dk);
    }
    if (!strncmp(stored, LEGACY_PREFIX, strlen(LEGACY_PREFIX)))
    {
        return parse_legacy(stored, salt, dk);
    }
    return false;
}

bool web_auth_pw_verify(const char *stored, const char *password, bool *needs_rehash)
{
    uint8_t salt[WEB_AUTH_SALT_BYTES];
    uint8_t expected[PBKDF2_DK_BYTES];
    uint8_t actual[PBKDF2_DK_BYTES];
    bool ok = false;
    if (needs_rehash != NULL)
    {
        *needs_rehash = false;
    }
    if (stored == NULL || password == NULL)
    {
        return false;
    }
    if (!strncmp(stored, PBKDF2_PREFIX, strlen(PBKDF2_PREFIX)))
    {
        uint32_t iterations = 0;
        if (!parse_pbkdf2(stored, &iterations, salt, expected))
        {
            return false;
        }
        if (pbkdf2(SHA256_HASH_ALGO, (const uint8_t *)password, strlen(password), salt, sizeof(salt), iterations, actual, sizeof(actual)) != 0)
        {
            return false;
        }
        ok = web_auth_const_equal(expected, actual, sizeof(actual));
        if (ok && needs_rehash != NULL && iterations < WEB_AUTH_PBKDF2_ITERATIONS)
        {
            *needs_rehash = true;
        }
    }
    else if (!strncmp(stored, LEGACY_PREFIX, strlen(LEGACY_PREFIX)))
    {
        /* hash format of the first web login release: SHA-256(salt | password) */
        Sha256Context ctx;
        if (!parse_legacy(stored, salt, expected))
        {
            return false;
        }
        sha256Init(&ctx);
        sha256Update(&ctx, salt, sizeof(salt));
        sha256Update(&ctx, password, strlen(password));
        sha256Final(&ctx, actual);
        ok = web_auth_const_equal(expected, actual, SHA256_DIGEST_SIZE);
        if (ok && needs_rehash != NULL)
        {
            *needs_rehash = true;
        }
    }
    memset(actual, 0, sizeof(actual));
    return ok;
}

static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

size_t web_auth_base32_encode(const uint8_t *data, size_t len, char *out, size_t out_size)
{
    size_t o = 0;
    uint32_t buffer = 0;
    int bits = 0;
    if (out_size == 0)
    {
        return 0;
    }
    for (size_t i = 0; i < len; i++)
    {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5)
        {
            if (o + 1 >= out_size)
            {
                out[o] = '\0';
                return 0;
            }
            out[o++] = base32_alphabet[(buffer >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    if (bits > 0)
    {
        if (o + 1 >= out_size)
        {
            out[o] = '\0';
            return 0;
        }
        out[o++] = base32_alphabet[(buffer << (5 - bits)) & 0x1F];
    }
    out[o] = '\0';
    return o;
}

int web_auth_base32_decode(const char *in, uint8_t *out, size_t out_size)
{
    uint32_t buffer = 0;
    int bits = 0;
    size_t o = 0;
    for (const char *p = in; *p; p++)
    {
        char c = (char)toupper((unsigned char)*p);
        if (c == ' ' || c == '-' || c == '=')
        {
            continue;
        }
        const char *pos = strchr(base32_alphabet, c);
        if (pos == NULL || c == '\0')
        {
            return -1;
        }
        buffer = (buffer << 5) | (uint32_t)(pos - base32_alphabet);
        bits += 5;
        if (bits >= 8)
        {
            if (o >= out_size)
            {
                return -1;
            }
            out[o++] = (uint8_t)(buffer >> (bits - 8));
            bits -= 8;
        }
    }
    return (int)o;
}

uint32_t web_auth_hotp(const uint8_t *key, size_t key_len, uint64_t counter, int digits)
{
    uint8_t msg[8];
    uint8_t mac[SHA1_DIGEST_SIZE];
    for (int i = 7; i >= 0; i--)
    {
        msg[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }
    if (hmacCompute(SHA1_HASH_ALGO, key, key_len, msg, sizeof(msg), mac) != 0)
    {
        return UINT32_MAX;
    }
    int offset = mac[SHA1_DIGEST_SIZE - 1] & 0x0F;
    uint32_t bin = ((uint32_t)(mac[offset] & 0x7F) << 24) | ((uint32_t)mac[offset + 1] << 16) | ((uint32_t)mac[offset + 2] << 8) | (uint32_t)mac[offset + 3];
    uint32_t mod = 1;
    for (int i = 0; i < digits; i++)
    {
        mod *= 10;
    }
    return bin % mod;
}

int64_t web_auth_totp_match(const uint8_t *key, size_t key_len, const char *code, time_t now, int window, int64_t last_step)
{
    char digits[WEB_AUTH_TOTP_DIGITS + 1];
    size_t n = 0;
    if (code == NULL || now < 0)
    {
        return -1;
    }
    for (const char *p = code; *p; p++)
    {
        if (*p == ' ')
        {
            continue;
        }
        if (!isdigit((unsigned char)*p) || n >= WEB_AUTH_TOTP_DIGITS)
        {
            return -1;
        }
        digits[n++] = *p;
    }
    if (n != WEB_AUTH_TOTP_DIGITS)
    {
        return -1;
    }
    digits[n] = '\0';
    uint32_t wanted = (uint32_t)strtoul(digits, NULL, 10);
    int64_t step = (int64_t)now / WEB_AUTH_TOTP_PERIOD;
    int64_t found = -1;
    /* check every step of the window, so the time taken does not tell which one matched */
    for (int64_t s = step - window; s <= step + window; s++)
    {
        if (s < 0)
        {
            continue;
        }
        uint32_t value = web_auth_hotp(key, key_len, (uint64_t)s, WEB_AUTH_TOTP_DIGITS);
        if (value == wanted && s > last_step && found < 0)
        {
            found = s;
        }
    }
    return found;
}

bool web_auth_seal(const uint8_t key[WEB_AUTH_SEAL_KEY_BYTES], const uint8_t iv[WEB_AUTH_SEAL_IV_BYTES], const char *aad,
                   const uint8_t *plain, size_t len, char *out_hex, size_t out_size)
{
    AesContext aes;
    GcmContext gcm;
    size_t total = WEB_AUTH_SEAL_IV_BYTES + len + WEB_AUTH_SEAL_TAG_BYTES;
    if (out_size < total * 2 + 1 || len > 256)
    {
        return false;
    }
    uint8_t buf[WEB_AUTH_SEAL_IV_BYTES + 256 + WEB_AUTH_SEAL_TAG_BYTES];
    memcpy(buf, iv, WEB_AUTH_SEAL_IV_BYTES);
    if (aesInit(&aes, key, WEB_AUTH_SEAL_KEY_BYTES) != 0 || gcmInit(&gcm, AES_CIPHER_ALGO, &aes) != 0)
    {
        return false;
    }
    bool ok = gcmEncrypt(&gcm, iv, WEB_AUTH_SEAL_IV_BYTES, (const uint8_t *)aad, aad ? strlen(aad) : 0, plain,
                         buf + WEB_AUTH_SEAL_IV_BYTES, len, buf + WEB_AUTH_SEAL_IV_BYTES + len, WEB_AUTH_SEAL_TAG_BYTES) == 0;
    memset(&aes, 0, sizeof(aes));
    if (ok)
    {
        web_auth_hex(buf, total, out_hex, out_size);
    }
    memset(buf, 0, sizeof(buf));
    return ok;
}

int web_auth_unseal(const uint8_t key[WEB_AUTH_SEAL_KEY_BYTES], const char *aad, const char *in_hex, uint8_t *plain, size_t plain_size)
{
    AesContext aes;
    GcmContext gcm;
    uint8_t buf[WEB_AUTH_SEAL_IV_BYTES + 256 + WEB_AUTH_SEAL_TAG_BYTES];
    if (in_hex == NULL)
    {
        return -1;
    }
    size_t hex_len = strlen(in_hex);
    if (hex_len % 2 != 0)
    {
        return -1;
    }
    size_t total = hex_len / 2;
    if (total < WEB_AUTH_SEAL_IV_BYTES + WEB_AUTH_SEAL_TAG_BYTES || total > sizeof(buf))
    {
        return -1;
    }
    size_t len = total - WEB_AUTH_SEAL_IV_BYTES - WEB_AUTH_SEAL_TAG_BYTES;
    if (len > plain_size || !web_auth_unhex(in_hex, buf, total))
    {
        return -1;
    }
    if (aesInit(&aes, key, WEB_AUTH_SEAL_KEY_BYTES) != 0 || gcmInit(&gcm, AES_CIPHER_ALGO, &aes) != 0)
    {
        return -1;
    }
    bool ok = gcmDecrypt(&gcm, buf, WEB_AUTH_SEAL_IV_BYTES, (const uint8_t *)aad, aad ? strlen(aad) : 0, buf + WEB_AUTH_SEAL_IV_BYTES,
                         plain, len, buf + WEB_AUTH_SEAL_IV_BYTES + len, WEB_AUTH_SEAL_TAG_BYTES) == 0;
    memset(&aes, 0, sizeof(aes));
    memset(buf, 0, sizeof(buf));
    if (!ok)
    {
        memset(plain, 0, len);
        return -1;
    }
    return (int)len;
}
