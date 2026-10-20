#ifndef _WEB_AUTH_NET_H
#define _WEB_AUTH_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Address helpers of the web UI login: IP and CIDR lists such as
 * "192.168.0.0/16, fd00::/8, 10.1.2.3" and the client address behind
 * trusted reverse proxies. IPv4 addresses are handled as IPv4-mapped IPv6.
 */

#define WEB_AUTH_IP_STR_MAX 48
/* client address when a trusted proxy sent something that is no address; matches no list */
#define WEB_AUTH_IP_UNKNOWN "unknown"

#define WEB_AUTH_DEFAULT_LAN_NETWORKS "127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10, ::1/128, fc00::/7, fe80::/10"

/* accepts "1.2.3.4", "1.2.3.4:80", "::1", "[::1]:80", "fe80::1%eth0" */
bool web_auth_ip_parse(const char *str, uint8_t out[16]);
/* canonical text form (IPv4 without the mapped prefix); false if not an address */
bool web_auth_ip_normalize(const char *str, char *out, size_t out_size);
/* true if the address matches an entry of the comma or space separated list */
bool web_auth_ip_in_list(const char *list, const char *ip);
/* true if every entry of the list is a valid address or network; the first bad entry is copied to bad */
bool web_auth_ip_list_valid(const char *list, char *bad, size_t bad_size);

/* key of the lockout: the address, for IPv6 its /64 network (one client usually has all of it) */
void web_auth_ip_lockout_key(const char *ip, char *out, size_t out_size);

/*
 * Client address of a request. When the peer is a trusted proxy, the
 * X-Forwarded-For list is walked from the right and the first address that is
 * not a trusted proxy is the client. Untrusted peers can not spoof an address.
 */
void web_auth_ip_resolve(const char *peer, const char *forwarded_for, const char *trusted_proxies, char *out, size_t out_size);

#endif
