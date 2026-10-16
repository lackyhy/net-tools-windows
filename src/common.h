/* lnx-net: Linux iproute2 / net-tools style utilities for Windows.
 * Shared helpers: fast buffered output, UTF-8 <-> console, addresses, interfaces. */
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>

#define LNX_VERSION "1.0.0"

/* ---------- growable string buffer ---------- */
typedef struct { char *p; size_t n, cap; } sbuf;

extern sbuf g_out;

void sb_grow(sbuf *b, size_t need);
static __forceinline void sb_put(sbuf *b, const char *s, size_t n) {
    if (b->n + n + 1 > b->cap) sb_grow(b, n + 1);
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}
static __forceinline void sb_puts(sbuf *b, const char *s) { sb_put(b, s, strlen(s)); }
static __forceinline void sb_putc(sbuf *b, char c) {
    if (b->n + 2 > b->cap) sb_grow(b, 2);
    b->p[b->n++] = c;
    b->p[b->n] = 0;
}
void sb_printf(sbuf *b, const char *fmt, ...);
void sb_pad(sbuf *b, int n);
void sb_padstr(sbuf *b, const char *s, int width, int right);
void sb_u64(sbuf *b, uint64_t v);

/* ---------- output ---------- */
void out_init(void);
void out_flush(void);
int  out_is_console(void);
void out_enable_vt(void);
void errf(const char *fmt, ...);
void win_errf(DWORD e, const char *prefix);
char *win_errmsg(DWORD e); /* static buffer, utf-8 */

/* ---------- strings ---------- */
int      utf8_width(const char *s);
char    *w2u(const wchar_t *w);
wchar_t *u2w(const char *s);
char   **argv_utf8(int argc, wchar_t **wargv);
int      matches(const char *arg, const char *full); /* arg is a prefix of full */
int      streqi(const char *a, const char *b);       /* unicode case-insensitive */
void     human_size(char *dst, uint64_t v, int si);  /* 1.2K / 3.4M style */

/* ---------- addresses ---------- */
typedef struct {
    int family;      /* AF_INET / AF_INET6 */
    int plen;        /* prefix length */
    int has_plen;
    int is_any;      /* "default" / "any" */
    uint32_t scope;
    uint8_t a[16];
} inaddr;

int  ip_fmt(char *dst, int family, const uint8_t *a); /* dst >= 64 bytes; returns length */
int  ip_parse(const char *s, int family_hint, inaddr *out);
int  prefix_match(int family, const uint8_t *a, const uint8_t *net, int plen);
void sa_get(const SOCKADDR_INET *sa, int *family, uint8_t *a, uint32_t *scope);
void sa_set(SOCKADDR_INET *sa, int family, const uint8_t *a, uint32_t scope);
int  ip_is_multicast(int family, const uint8_t *a);
int  ip_is_unspec(int family, const uint8_t *a);
const char *ip_scope_name(int family, const uint8_t *a);
int  mac_fmt(char *dst, const uint8_t *m, int len);
int  mac_parse(const char *s, uint8_t *m);

/* ---------- interfaces ---------- */
typedef struct {
    int family;
    uint8_t a[16];
    int plen;
    uint32_t valid, pref;
    int porigin, sorigin, dad;
} ifaddr_t;

typedef struct {
    uint32_t index;
    NET_LUID luid;
    char *name;  wchar_t *wname;
    char *desc;  wchar_t *wdesc;
    char *guid;
    uint32_t type;
    uint32_t mtu;
    uint8_t mac[8];
    uint32_t maclen;
    int oper;          /* IF_OPER_STATUS */
    int oper_up, admin_up, connected, no_mcast, dhcp;
    uint64_t speed;
    ifaddr_t *addr;
    int naddr;
    MIB_IF_ROW2 row;
    int have_row;
} iface_t;

int         ifaces_load(iface_t **out);
iface_t    *iface_find(iface_t *v, int n, const char *name);
iface_t    *iface_by_index(iface_t *v, int n, uint32_t idx);
const char *ifname_idx(uint32_t idx);
uint32_t    ifindex_by_name(const char *name); /* 0 if not found */
int         iface_is_loopback(const iface_t *f);
int         iface_is_p2p(const iface_t *f);
const char *iface_operstate(const iface_t *f);

/* ---------- services (port <-> name) ---------- */
const char *svc_name(int udp, uint16_t port);
int         svc_port(const char *name); /* -1 if unknown */
