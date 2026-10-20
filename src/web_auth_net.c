#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "web_auth_net.h"

static bool parse_ipv4(const char *s, size_t len, uint8_t out[4])
{
    int part = 0;
    unsigned value = 0;
    int digits = 0;
    for (size_t i = 0; i <= len; i++)
    {
        char c = i < len ? s[i] : '.';
        if (c >= '0' && c <= '9')
        {
            if (digits > 0 && value == 0)
            {
                return false; /* no leading zeros, they are octal for some parsers */
            }
            value = value * 10 + (unsigned)(c - '0');
            if (++digits > 3 || value > 255)
            {
                return false;
            }
        }
        else if (c == '.')
        {
            if (digits == 0 || part > 3)
            {
                return false;
            }
            out[part++] = (uint8_t)value;
            value = 0;
            digits = 0;
        }
        else
        {
            return false;
        }
    }
    return part == 4;
}

static bool parse_ipv6(const char *s, size_t len, uint8_t out[16])
{
    uint16_t groups[8] = {0};
    int count = 0;
    int gap = -1;
    size_t i = 0;
    if (len >= 2 && s[0] == ':' && s[1] == ':')
    {
        gap = 0;
        i = 2;
    }
    else if (len >= 1 && s[0] == ':')
    {
        return false;
    }
    while (i < len)
    {
        size_t start = i;
        unsigned value = 0;
        int digits = 0;
        while (i < len && isxdigit((unsigned char)s[i]))
        {
            value = value * 16 + (unsigned)(isdigit((unsigned char)s[i]) ? s[i] - '0' : (tolower((unsigned char)s[i]) - 'a' + 10));
            i++;
            if (++digits > 4)
            {
                return false;
            }
        }
        if (i < len && s[i] == '.')
        {
            /* embedded IPv4 as the last two groups */
            uint8_t v4[4];
            if (count > 6 || !parse_ipv4(s + start, len - start, v4))
            {
                return false;
            }
            groups[count++] = (uint16_t)((v4[0] << 8) | v4[1]);
            groups[count++] = (uint16_t)((v4[2] << 8) | v4[3]);
            i = len;
            break;
        }
        if (digits == 0 || count >= 8)
        {
            return false;
        }
        groups[count++] = (uint16_t)value;
        if (i == len)
        {
            break;
        }
        if (s[i] != ':')
        {
            return false;
        }
        i++;
        if (i < len && s[i] == ':')
        {
            if (gap >= 0)
            {
                return false;
            }
            gap = count;
            i++;
        }
        else if (i == len)
        {
            return false;
        }
    }
    if (gap < 0 && count != 8)
    {
        return false;
    }
    if (gap >= 0 && count > 7)
    {
        return false;
    }
    uint16_t full[8] = {0};
    if (gap < 0)
    {
        memcpy(full, groups, sizeof(full));
    }
    else
    {
        int tail = count - gap;
        for (int g = 0; g < gap; g++)
        {
            full[g] = groups[g];
        }
        for (int g = 0; g < tail; g++)
        {
            full[8 - tail + g] = groups[gap + g];
        }
    }
    for (int g = 0; g < 8; g++)
    {
        out[g * 2] = (uint8_t)(full[g] >> 8);
        out[g * 2 + 1] = (uint8_t)(full[g] & 0xFF);
    }
    return true;
}

static void map_v4(const uint8_t v4[4], uint8_t out[16])
{
    memset(out, 0, 10);
    out[10] = 0xFF;
    out[11] = 0xFF;
    memcpy(out + 12, v4, 4);
}

static bool is_mapped_v4(const uint8_t a[16])
{
    static const uint8_t prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF};
    return memcmp(a, prefix, sizeof(prefix)) == 0;
}

/* parses an address of exactly len characters, without ports or brackets */
static bool parse_plain(const char *s, size_t len, uint8_t out[16])
{
    uint8_t v4[4];
    if (len == 0 || len >= 64)
    {
        return false;
    }
    if (memchr(s, ':', len) == NULL)
    {
        if (!parse_ipv4(s, len, v4))
        {
            return false;
        }
        map_v4(v4, out);
        return true;
    }
    const char *zone = memchr(s, '%', len);
    if (zone != NULL)
    {
        len = (size_t)(zone - s);
    }
    return parse_ipv6(s, len, out);
}

bool web_auth_ip_parse(const char *str, uint8_t out[16])
{
    if (str == NULL)
    {
        return false;
    }
    while (*str == ' ' || *str == '\t')
    {
        str++;
    }
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == ' ' || str[len - 1] == '\t'))
    {
        len--;
    }
    if (len > 0 && str[0] == '[')
    {
        const char *close = memchr(str, ']', len);
        if (close == NULL)
        {
            return false;
        }
        size_t rest = len - (size_t)(close - str) - 1;
        if (rest != 0 && close[1] != ':')
        {
            return false;
        }
        return parse_plain(str + 1, (size_t)(close - str) - 1, out);
    }
    const char *colon = memchr(str, ':', len);
    if (colon != NULL && memchr(colon + 1, ':', len - (size_t)(colon - str) - 1) == NULL)
    {
        /* exactly one colon: IPv4 with a port */
        return parse_plain(str, (size_t)(colon - str), out) && is_mapped_v4(out);
    }
    return parse_plain(str, len, out);
}

bool web_auth_ip_normalize(const char *str, char *out, size_t out_size)
{
    uint8_t a[16];
    if (out_size == 0 || !web_auth_ip_parse(str, a))
    {
        if (out_size > 0)
        {
            out[0] = '\0';
        }
        return false;
    }
    if (is_mapped_v4(a))
    {
        snprintf(out, out_size, "%u.%u.%u.%u", a[12], a[13], a[14], a[15]);
        return true;
    }
    /* RFC 5952: lower case, longest run of zero groups as "::" */
    uint16_t g[8];
    for (int i = 0; i < 8; i++)
    {
        g[i] = (uint16_t)((a[i * 2] << 8) | a[i * 2 + 1]);
    }
    int best = -1, best_len = 0;
    for (int i = 0; i < 8;)
    {
        if (g[i] != 0)
        {
            i++;
            continue;
        }
        int j = i;
        while (j < 8 && g[j] == 0)
        {
            j++;
        }
        if (j - i > best_len && j - i > 1)
        {
            best = i;
            best_len = j - i;
        }
        i = j;
    }
    char buf[WEB_AUTH_IP_STR_MAX];
    size_t o = 0;
    for (int i = 0; i < 8; i++)
    {
        if (i == best)
        {
            o += (size_t)snprintf(buf + o, sizeof(buf) - o, "::");
            i += best_len - 1;
            continue;
        }
        if (o > 0 && buf[o - 1] != ':')
        {
            buf[o++] = ':';
        }
        o += (size_t)snprintf(buf + o, sizeof(buf) - o, "%x", g[i]);
    }
    buf[o] = '\0';
    snprintf(out, out_size, "%s", buf);
    return true;
}

/* parses "addr" or "addr/prefix" of len characters into a network */
static bool parse_entry(const char *s, size_t len, uint8_t net[16], int *prefix)
{
    char buf[80];
    if (len == 0 || len >= sizeof(buf))
    {
        return false;
    }
    memcpy(buf, s, len);
    buf[len] = '\0';
    char *slash = strchr(buf, '/');
    int bits = -1;
    if (slash != NULL)
    {
        char *end = NULL;
        *slash = '\0';
        if (!isdigit((unsigned char)slash[1]))
        {
            return false;
        }
        bits = (int)strtol(slash + 1, &end, 10);
        if (end == NULL || *end != '\0')
        {
            return false;
        }
    }
    if (strchr(buf, '[') != NULL || !parse_plain(buf, strlen(buf), net))
    {
        return false;
    }
    bool v4 = is_mapped_v4(net) && strchr(buf, ':') == NULL;
    if (bits < 0)
    {
        bits = v4 ? 32 : 128;
    }
    if ((v4 && bits > 32) || bits > 128)
    {
        return false;
    }
    *prefix = v4 ? bits + 96 : bits;
    return true;
}

static bool in_network(const uint8_t ip[16], const uint8_t net[16], int prefix)
{
    for (int i = 0; i < 16 && prefix > 0; i++, prefix -= 8)
    {
        uint8_t mask = prefix >= 8 ? 0xFF : (uint8_t)(0xFF << (8 - prefix));
        if ((ip[i] & mask) != (net[i] & mask))
        {
            return false;
        }
    }
    return true;
}

typedef bool (*entry_cb)(const char *s, size_t len, void *ctx);

static bool for_each_entry(const char *list, entry_cb cb, void *ctx)
{
    if (list == NULL)
    {
        return false;
    }
    const char *p = list;
    while (*p)
    {
        while (*p == ',' || *p == ' ' || *p == ';' || *p == '\t' || *p == '\n' || *p == '\r')
        {
            p++;
        }
        const char *start = p;
        while (*p && *p != ',' && *p != ' ' && *p != ';' && *p != '\t' && *p != '\n' && *p != '\r')
        {
            p++;
        }
        if (p > start && cb(start, (size_t)(p - start), ctx))
        {
            return true;
        }
    }
    return false;
}

typedef struct
{
    uint8_t ip[16];
} match_ctx_t;

static bool match_cb(const char *s, size_t len, void *ctx)
{
    uint8_t net[16];
    int prefix;
    match_ctx_t *m = ctx;
    return parse_entry(s, len, net, &prefix) && in_network(m->ip, net, prefix);
}

bool web_auth_ip_in_list(const char *list, const char *ip)
{
    match_ctx_t m;
    if (!web_auth_ip_parse(ip, m.ip))
    {
        return false;
    }
    return for_each_entry(list, match_cb, &m);
}

typedef struct
{
    char *bad;
    size_t bad_size;
} valid_ctx_t;

static bool invalid_cb(const char *s, size_t len, void *ctx)
{
    uint8_t net[16];
    int prefix;
    valid_ctx_t *v = ctx;
    if (parse_entry(s, len, net, &prefix))
    {
        return false;
    }
    if (v->bad != NULL && v->bad_size > 0)
    {
        size_t n = len < v->bad_size - 1 ? len : v->bad_size - 1;
        memcpy(v->bad, s, n);
        v->bad[n] = '\0';
    }
    return true;
}

bool web_auth_ip_list_valid(const char *list, char *bad, size_t bad_size)
{
    valid_ctx_t v = {bad, bad_size};
    if (bad != NULL && bad_size > 0)
    {
        bad[0] = '\0';
    }
    return !for_each_entry(list, invalid_cb, &v);
}

void web_auth_ip_resolve(const char *peer, const char *forwarded_for, const char *trusted_proxies, char *out, size_t out_size)
{
    if (out_size == 0)
    {
        return;
    }
    if (!web_auth_ip_normalize(peer, out, out_size))
    {
        snprintf(out, out_size, "%s", peer ? peer : "");
        return;
    }
    if (forwarded_for == NULL || forwarded_for[0] == '\0' || trusted_proxies == NULL || trusted_proxies[0] == '\0' ||
        !web_auth_ip_in_list(trusted_proxies, out))
    {
        return;
    }
    /* walk the hops from the right; every proxy appends the address it saw */
    size_t end = strlen(forwarded_for);
    while (end > 0)
    {
        size_t start = end;
        while (start > 0 && forwarded_for[start - 1] != ',')
        {
            start--;
        }
        char hop[80];
        size_t len = end - start;
        char normalized[WEB_AUTH_IP_STR_MAX];
        bool valid = len < sizeof(hop);
        if (valid)
        {
            memcpy(hop, forwarded_for + start, len);
            hop[len] = '\0';
            valid = web_auth_ip_normalize(hop, normalized, sizeof(normalized));
        }
        if (!valid)
        {
            /* not an address: unknown client, never the (often local) proxy */
            snprintf(out, out_size, "%s", WEB_AUTH_IP_UNKNOWN);
            return;
        }
        snprintf(out, out_size, "%s", normalized);
        if (!web_auth_ip_in_list(trusted_proxies, normalized))
        {
            return;
        }
        end = start > 0 ? start - 1 : 0;
    }
}

void web_auth_ip_lockout_key(const char *ip, char *out, size_t out_size)
{
    uint8_t a[16];
    if (out_size == 0)
    {
        return;
    }
    if (!web_auth_ip_parse(ip, a))
    {
        snprintf(out, out_size, "%s", ip ? ip : "");
        return;
    }
    if (is_mapped_v4(a))
    {
        snprintf(out, out_size, "%u.%u.%u.%u", a[12], a[13], a[14], a[15]);
        return;
    }
    snprintf(out, out_size, "%x:%x:%x:%x::/64", (a[0] << 8) | a[1], (a[2] << 8) | a[3], (a[4] << 8) | a[5], (a[6] << 8) | a[7]);
}
