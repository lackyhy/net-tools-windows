#include "common.h"

sbuf g_out;
static HANDLE h_out, h_err;
static int out_con, err_con;
static DWORD out_mode_saved;
static int vt_changed;

/* ======================= buffers ======================= */

void sb_grow(sbuf *b, size_t need) {
    size_t nc = b->cap ? b->cap : 4096;
    while (nc < b->n + need) nc *= 2;
    char *p = (char *)realloc(b->p, nc);
    if (!p) { ExitProcess(12); }
    b->p = p;
    b->cap = nc;
}

void sb_printf(sbuf *b, const char *fmt, ...) {
    va_list ap;
    for (;;) {
        size_t avail = b->cap - b->n;
        va_start(ap, fmt);
        int r = vsnprintf(b->p ? b->p + b->n : NULL, avail, fmt, ap);
        va_end(ap);
        if (r < 0) return;
        if ((size_t)r < avail) { b->n += r; return; }
        sb_grow(b, (size_t)r + 1);
    }
}

void sb_pad(sbuf *b, int n) {
    if (n <= 0) return;
    if (b->n + n + 1 > b->cap) sb_grow(b, n + 1);
    memset(b->p + b->n, ' ', n);
    b->n += n;
    b->p[b->n] = 0;
}

void sb_padstr(sbuf *b, const char *s, int width, int right) {
    int w = utf8_width(s);
    if (right) sb_pad(b, width - w);
    sb_puts(b, s);
    if (!right) sb_pad(b, width - w);
}

void sb_u64(sbuf *b, uint64_t v) {
    char t[24];
    int i = 23;
    t[i] = 0;
    do { t[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    sb_put(b, t + i, 23 - i);
}

/* ======================= output ======================= */

static int is_ascii(const char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if ((unsigned char)s[i] >= 0x80) return 0;
    return 1;
}

static void write_all(HANDLE h, const char *s, size_t n) {
    while (n) {
        DWORD w = 0, chunk = n > (1u << 30) ? (1u << 30) : (DWORD)n;
        if (!WriteFile(h, s, chunk, &w, NULL) || !w) return;
        s += w;
        n -= w;
    }
}

static void write_utf8(HANDLE h, int console, const char *s, size_t n) {
    if (!n) return;
    if (!console && is_ascii(s, n)) { write_all(h, s, n); return; }
    int wn = MultiByteToWideChar(CP_UTF8, 0, s, (int)n, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(sizeof(wchar_t) * (wn + 1));
    if (!w) return;
    MultiByteToWideChar(CP_UTF8, 0, s, (int)n, w, wn);
    if (console) {
        int off = 0;
        while (off < wn) {
            int chunk = wn - off > 16384 ? 16384 : wn - off;
            if (off + chunk < wn && IS_HIGH_SURROGATE(w[off + chunk - 1])) chunk--;
            DWORD done;
            if (!WriteConsoleW(h, w + off, chunk, &done, NULL)) break;
            off += chunk;
        }
    } else {
        /* redirected: use the console code page (what PowerShell / cmd decode with) */
        UINT cp = GetConsoleOutputCP();
        if (!cp || cp == CP_UTF8) {
            write_all(h, s, n);
        } else {
            int bn = WideCharToMultiByte(cp, 0, w, wn, NULL, 0, NULL, NULL);
            char *b = (char *)malloc(bn + 1);
            if (b) {
                WideCharToMultiByte(cp, 0, w, wn, b, bn, NULL, NULL);
                write_all(h, b, bn);
                free(b);
            }
        }
    }
    free(w);
}

static void restore_console(void) {
    if (vt_changed) SetConsoleMode(h_out, out_mode_saved);
}

void out_init(void) {
    DWORD m;
    h_out = GetStdHandle(STD_OUTPUT_HANDLE);
    h_err = GetStdHandle(STD_ERROR_HANDLE);
    out_con = GetConsoleMode(h_out, &m) ? 1 : 0;
    if (out_con) out_mode_saved = m;
    err_con = GetConsoleMode(h_err, &m) ? 1 : 0;
    g_out.cap = 64 * 1024;
    g_out.p = (char *)malloc(g_out.cap);
    g_out.n = 0;
    g_out.p[0] = 0;
    atexit(restore_console);
}

int out_is_console(void) { return out_con; }

void out_enable_vt(void) {
    if (!out_con || vt_changed) return;
    if (!(out_mode_saved & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        if (SetConsoleMode(h_out, out_mode_saved | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) vt_changed = 1;
    }
}

void out_flush(void) {
    if (!g_out.n) return;
    write_utf8(h_out, out_con, g_out.p, g_out.n);
    g_out.n = 0;
    g_out.p[0] = 0;
}

void errf(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    int r = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (r < 0) return;
    if (r >= (int)sizeof buf) r = sizeof buf - 1;
    out_flush();
    write_utf8(h_err, err_con, buf, r);
}

char *win_errmsg(DWORD e) {
    static char msg[1024];
    wchar_t wb[512];
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, e, 0, wb, 512, NULL);
    while (n && (wb[n - 1] == L'\r' || wb[n - 1] == L'\n' || wb[n - 1] == L' ' || wb[n - 1] == L'.')) wb[--n] = 0;
    if (!n) { snprintf(msg, sizeof msg, "error %lu", (unsigned long)e); return msg; }
    WideCharToMultiByte(CP_UTF8, 0, wb, -1, msg, sizeof msg, NULL, NULL);
    return msg;
}

void win_errf(DWORD e, const char *prefix) {
    errf("%s%s\n", prefix ? prefix : "", win_errmsg(e));
}

/* ======================= strings ======================= */

int utf8_width(const char *s) {
    int w = 0;
    for (; *s; s++)
        if (((unsigned char)*s & 0xC0) != 0x80) w++;
    return w;
}

char *w2u(const wchar_t *w) {
    if (!w) w = L"";
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s = (char *)malloc(n ? n : 1);
    if (!n) { s[0] = 0; return s; }
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s, n, NULL, NULL);
    return s;
}

wchar_t *u2w(const char *s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(sizeof(wchar_t) * (n ? n : 1));
    if (!n) { w[0] = 0; return w; }
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

char **argv_utf8(int argc, wchar_t **wargv) {
    char **v = (char **)calloc(argc + 1, sizeof(char *));
    for (int i = 0; i < argc; i++) v[i] = w2u(wargv[i]);
    return v;
}

int matches(const char *arg, const char *full) {
    size_t n = strlen(arg);
    return n && n <= strlen(full) && strncmp(full, arg, n) == 0;
}

int streqi(const char *a, const char *b) {
    wchar_t *wa = u2w(a), *wb = u2w(b);
    int r = CompareStringOrdinal(wa, -1, wb, -1, TRUE) == CSTR_EQUAL;
    free(wa);
    free(wb);
    return r;
}

void human_size(char *dst, uint64_t v, int si) {
    const char *u = "KMGTPE";
    double base = si ? 1000.0 : 1024.0, d = (double)v;
    int i = -1;
    if (d < base) { sprintf(dst, "%llu", (unsigned long long)v); return; }
    while (d >= base && i < 5) { d /= base; i++; }
    if (d < 10) sprintf(dst, "%.1f%c", d, u[i]);
    else sprintf(dst, "%.0f%c", d, u[i]);
}

/* ======================= addresses ======================= */

static char *u8dec(char *p, unsigned v) {
    if (v >= 100) { *p++ = (char)('0' + v / 100); v %= 100; *p++ = (char)('0' + v / 10); *p++ = (char)('0' + v % 10); }
    else if (v >= 10) { *p++ = (char)('0' + v / 10); *p++ = (char)('0' + v % 10); }
    else *p++ = (char)('0' + v);
    return p;
}

int ip_fmt(char *dst, int family, const uint8_t *a) {
    if (family == AF_INET) {
        char *p = dst;
        p = u8dec(p, a[0]); *p++ = '.';
        p = u8dec(p, a[1]); *p++ = '.';
        p = u8dec(p, a[2]); *p++ = '.';
        p = u8dec(p, a[3]); *p = 0;
        return (int)(p - dst);
    }
    if (!InetNtopA(AF_INET6, (void *)a, dst, 64)) { strcpy(dst, "?"); return 1; }
    return (int)strlen(dst);
}

static int parse_v4(const char *s, uint8_t *a) {
    /* accepts 1..4 dotted decimal parts ("10" -> 10.0.0.0), like iproute2 for prefixes */
    int parts = 0;
    memset(a, 0, 4);
    while (*s) {
        if (parts == 4) return 0;
        if (*s < '0' || *s > '9') return 0;
        unsigned v = 0;
        int digits = 0;
        while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; if (++digits > 3) return 0; }
        if (v > 255) return 0;
        a[parts++] = (uint8_t)v;
        if (*s == '.') { s++; if (!*s) return 0; }
        else if (*s) return 0;
    }
    return parts;
}

int ip_parse(const char *s, int family_hint, inaddr *o) {
    char buf[128];
    memset(o, 0, sizeof *o);
    if (!_stricmp(s, "default") || !_stricmp(s, "all") || !_stricmp(s, "any")) {
        o->family = family_hint ? family_hint : AF_INET;
        o->is_any = 1;
        o->plen = 0;
        o->has_plen = 1;
        return 1;
    }
    if (strlen(s) >= sizeof buf) return 0;
    strcpy(buf, s);
    int plen = -1;
    char *slash = strchr(buf, '/');
    if (slash) {
        char *e;
        *slash = 0;
        plen = (int)strtol(slash + 1, &e, 10);
        if (*e || e == slash + 1 || plen < 0) return 0;
    }
    char *pct = strchr(buf, '%');
    if (pct) {
        *pct = 0;
        char *e;
        unsigned long sc = strtoul(pct + 1, &e, 10);
        o->scope = *e ? ifindex_by_name(pct + 1) : (uint32_t)sc;
    }
    int maxl;
    if (strchr(buf, ':')) {
        if (InetPtonA(AF_INET6, buf, o->a) != 1) return 0;
        o->family = AF_INET6;
        maxl = 128;
    } else {
        int parts = parse_v4(buf, o->a);
        if (!parts) return 0;
        if (parts < 4 && plen < 0) return 0; /* short form only valid with prefix length */
        o->family = AF_INET;
        maxl = 32;
    }
    if (plen > maxl) return 0;
    o->has_plen = plen >= 0;
    o->plen = plen >= 0 ? plen : maxl;
    return 1;
}

int prefix_match(int family, const uint8_t *a, const uint8_t *net, int plen) {
    int max = family == AF_INET ? 32 : 128;
    if (plen > max) plen = max;
    int bytes = plen / 8, bits = plen % 8;
    if (memcmp(a, net, bytes)) return 0;
    if (bits) {
        uint8_t m = (uint8_t)(0xFF << (8 - bits));
        if ((a[bytes] & m) != (net[bytes] & m)) return 0;
    }
    return 1;
}

void sa_get(const SOCKADDR_INET *sa, int *family, uint8_t *a, uint32_t *scope) {
    if (sa->si_family == AF_INET6) {
        *family = AF_INET6;
        memcpy(a, &sa->Ipv6.sin6_addr, 16);
        if (scope) *scope = sa->Ipv6.sin6_scope_id;
    } else {
        *family = AF_INET;
        memset(a, 0, 16);
        memcpy(a, &sa->Ipv4.sin_addr, 4);
        if (scope) *scope = 0;
    }
}

void sa_set(SOCKADDR_INET *sa, int family, const uint8_t *a, uint32_t scope) {
    memset(sa, 0, sizeof *sa);
    sa->si_family = (ADDRESS_FAMILY)family;
    if (family == AF_INET6) {
        memcpy(&sa->Ipv6.sin6_addr, a, 16);
        sa->Ipv6.sin6_scope_id = scope;
    } else {
        memcpy(&sa->Ipv4.sin_addr, a, 4);
    }
}

int ip_is_multicast(int family, const uint8_t *a) {
    return family == AF_INET ? (a[0] & 0xF0) == 0xE0 : a[0] == 0xFF;
}

int ip_is_unspec(int family, const uint8_t *a) {
    static const uint8_t z[16];
    return !memcmp(a, z, family == AF_INET ? 4 : 16);
}

const char *ip_scope_name(int family, const uint8_t *a) {
    if (family == AF_INET) {
        if (a[0] == 127) return "host";
        if (a[0] == 169 && a[1] == 254) return "link";
        return "global";
    }
    static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (!memcmp(a, lo6, 16)) return "host";
    if (a[0] == 0xFE && (a[1] & 0xC0) == 0x80) return "link";
    if (a[0] == 0xFE && (a[1] & 0xC0) == 0xC0) return "site";
    return "global";
}

int mac_fmt(char *dst, const uint8_t *m, int len) {
    static const char hx[] = "0123456789abcdef";
    char *p = dst;
    for (int i = 0; i < len; i++) {
        if (i) *p++ = ':';
        *p++ = hx[m[i] >> 4];
        *p++ = hx[m[i] & 15];
    }
    *p = 0;
    return (int)(p - dst);
}

static int hexv(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int mac_parse(const char *s, uint8_t *m) {
    int n = 0;
    while (*s && n < 8) {
        int h = hexv(s[0]), l = hexv(s[1]);
        if (h < 0 || l < 0) return 0;
        m[n++] = (uint8_t)(h * 16 + l);
        s += 2;
        if (*s == ':' || *s == '-' || *s == '.') s++;
    }
    return *s ? 0 : n;
}

/* ======================= interfaces ======================= */

static int addr_cmp(const void *x, const void *y) {
    const ifaddr_t *a = (const ifaddr_t *)x, *b = (const ifaddr_t *)y;
    if (a->family != b->family) return a->family == AF_INET ? -1 : 1;
    return 0;
}

static int iface_cmp(const void *x, const void *y) {
    const iface_t *a = (const iface_t *)x, *b = (const iface_t *)y;
    return a->index < b->index ? -1 : a->index > b->index;
}

int ifaces_load(iface_t **out) {
    ULONG sz = 64 * 1024, r = 0;
    IP_ADAPTER_ADDRESSES *aa = NULL;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    for (int tries = 0; tries < 5; tries++) {
        aa = (IP_ADAPTER_ADDRESSES *)malloc(sz);
        r = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, aa, &sz);
        if (r == ERROR_BUFFER_OVERFLOW) { free(aa); aa = NULL; continue; }
        break;
    }
    if (r != NO_ERROR) {
        free(aa);
        *out = NULL;
        if (r == ERROR_NO_DATA) return 0;
        win_errf(r, "GetAdaptersAddresses: ");
        return -1;
    }
    int n = 0;
    for (IP_ADAPTER_ADDRESSES *a = aa; a; a = a->Next) n++;
    iface_t *v = (iface_t *)calloc(n ? n : 1, sizeof(iface_t));
    int i = 0;
    for (IP_ADAPTER_ADDRESSES *a = aa; a; a = a->Next, i++) {
        iface_t *f = &v[i];
        f->index = a->IfIndex ? a->IfIndex : a->Ipv6IfIndex;
        f->luid = a->Luid;
        f->wname = _wcsdup(a->FriendlyName ? a->FriendlyName : L"");
        f->name = w2u(f->wname);
        f->wdesc = _wcsdup(a->Description ? a->Description : L"");
        f->desc = w2u(f->wdesc);
        f->guid = _strdup(a->AdapterName ? a->AdapterName : "");
        f->type = a->IfType;
        f->mtu = a->Mtu;
        f->maclen = a->PhysicalAddressLength > 8 ? 8 : a->PhysicalAddressLength;
        memcpy(f->mac, a->PhysicalAddress, f->maclen);
        f->oper = a->OperStatus;
        f->oper_up = a->OperStatus == IfOperStatusUp;
        f->no_mcast = (a->Flags & IP_ADAPTER_NO_MULTICAST) != 0;
        f->dhcp = (a->Flags & IP_ADAPTER_DHCP_ENABLED) != 0;
        f->speed = a->TransmitLinkSpeed;

        int na = 0;
        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) na++;
        f->addr = (ifaddr_t *)calloc(na ? na : 1, sizeof(ifaddr_t));
        for (IP_ADAPTER_UNICAST_ADDRESS *u = a->FirstUnicastAddress; u; u = u->Next) {
            ifaddr_t *x = &f->addr[f->naddr];
            SOCKADDR *sa = u->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                x->family = AF_INET;
                memcpy(x->a, &((SOCKADDR_IN *)sa)->sin_addr, 4);
            } else if (sa->sa_family == AF_INET6) {
                x->family = AF_INET6;
                memcpy(x->a, &((SOCKADDR_IN6 *)sa)->sin6_addr, 16);
            } else continue;
            x->plen = u->OnLinkPrefixLength;
            x->valid = u->ValidLifetime;
            x->pref = u->PreferredLifetime;
            x->porigin = u->PrefixOrigin;
            x->sorigin = u->SuffixOrigin;
            x->dad = u->DadState;
            f->naddr++;
        }
        qsort(f->addr, f->naddr, sizeof(ifaddr_t), addr_cmp); /* stable enough: v4 first */

        f->row.InterfaceLuid = a->Luid;
        if (GetIfEntry2(&f->row) == NO_ERROR) {
            f->have_row = 1;
            f->admin_up = f->row.AdminStatus == NET_IF_ADMIN_STATUS_UP;
            f->connected = f->row.MediaConnectState == MediaConnectStateConnected;
        } else {
            f->admin_up = f->oper_up;
            f->connected = f->oper_up;
        }
    }
    free(aa);
    qsort(v, n, sizeof(iface_t), iface_cmp);
    *out = v;
    return n;
}

iface_t *iface_by_index(iface_t *v, int n, uint32_t idx) {
    for (int i = 0; i < n; i++)
        if (v[i].index == idx) return &v[i];
    return NULL;
}

iface_t *iface_find(iface_t *v, int n, const char *name) {
    wchar_t *w = u2w(name);
    iface_t *r = NULL;
    for (int i = 0; i < n && !r; i++)
        if (CompareStringOrdinal(v[i].wname, -1, w, -1, TRUE) == CSTR_EQUAL) r = &v[i];
    for (int i = 0; i < n && !r; i++)
        if (CompareStringOrdinal(v[i].wdesc, -1, w, -1, TRUE) == CSTR_EQUAL) r = &v[i];
    for (int i = 0; i < n && !r; i++)
        if (!_stricmp(v[i].guid, name)) r = &v[i];
    if (!r) {
        char *e;
        unsigned long idx = strtoul(name, &e, 10);
        if (!*e && e != name) r = iface_by_index(v, n, (uint32_t)idx);
    }
    free(w);
    return r;
}

static struct { uint32_t idx; char *name; } ifn_cache[64];
static int ifn_cache_n;

const char *ifname_idx(uint32_t idx) {
    for (int i = 0; i < ifn_cache_n; i++)
        if (ifn_cache[i].idx == idx) return ifn_cache[i].name;
    NET_LUID luid;
    wchar_t w[NDIS_IF_MAX_STRING_SIZE + 1];
    char *name;
    if (ConvertInterfaceIndexToLuid(idx, &luid) == NO_ERROR &&
        ConvertInterfaceLuidToAlias(&luid, w, NDIS_IF_MAX_STRING_SIZE + 1) == NO_ERROR) {
        name = w2u(w);
    } else {
        name = (char *)malloc(16);
        sprintf(name, "if%u", idx);
    }
    if (ifn_cache_n < 64) {
        ifn_cache[ifn_cache_n].idx = idx;
        ifn_cache[ifn_cache_n].name = name;
        ifn_cache_n++;
    }
    return name;
}

uint32_t ifindex_by_name(const char *name) {
    wchar_t *w = u2w(name);
    NET_LUID luid;
    NET_IFINDEX idx = 0;
    if (ConvertInterfaceAliasToLuid(w, &luid) == NO_ERROR) ConvertInterfaceLuidToIndex(&luid, &idx);
    free(w);
    if (!idx) {
        char *e;
        unsigned long v = strtoul(name, &e, 10);
        if (!*e && e != name) idx = v;
    }
    return idx;
}

int iface_is_loopback(const iface_t *f) { return f->type == IF_TYPE_SOFTWARE_LOOPBACK; }
int iface_is_p2p(const iface_t *f) { return f->type == IF_TYPE_TUNNEL || f->type == IF_TYPE_PPP; }

const char *iface_operstate(const iface_t *f) {
    if (iface_is_loopback(f)) return "UNKNOWN";
    switch (f->oper) {
    case IfOperStatusUp: return "UP";
    case IfOperStatusDown: return "DOWN";
    case IfOperStatusTesting: return "TESTING";
    case IfOperStatusDormant: return "DORMANT";
    case IfOperStatusNotPresent: return "NOTPRESENT";
    case IfOperStatusLowerLayerDown: return "LOWERLAYERDOWN";
    default: return "UNKNOWN";
    }
}

/* ======================= services ======================= */

static const char **svc_tab[2];
static int svc_loaded;
typedef struct { char *name; uint16_t port; } svc_ent;
static svc_ent *svc_list;
static int svc_n, svc_cap;

static void svc_load(void) {
    if (svc_loaded) return;
    svc_loaded = 1;
    svc_tab[0] = (const char **)calloc(65536, sizeof(char *));
    svc_tab[1] = (const char **)calloc(65536, sizeof(char *));
    char path[MAX_PATH];
    UINT n = GetSystemDirectoryA(path, MAX_PATH - 40);
    if (!n) return;
    strcpy(path + n, "\\drivers\\etc\\services");
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD size = GetFileSize(h, NULL), got = 0;
    char *buf = (char *)malloc(size + 1);
    ReadFile(h, buf, size, &got, NULL);
    CloseHandle(h);
    buf[got] = 0;
    char *p = buf;
    while (*p) {
        char *line = p;
        while (*p && *p != '\n') p++;
        if (*p) *p++ = 0;
        char *hash = strchr(line, '#');
        if (hash) *hash = 0;
        char *name = strtok(line, " \t\r");
        char *pp = name ? strtok(NULL, " \t\r") : NULL;
        if (!pp) continue;
        char *sl = strchr(pp, '/');
        if (!sl) continue;
        *sl = 0;
        int port = atoi(pp);
        if (port <= 0 || port > 65535) continue;
        int udp = !_stricmp(sl + 1, "udp");
        if (!udp && _stricmp(sl + 1, "tcp")) continue;
        if (!svc_tab[udp][port]) svc_tab[udp][port] = name;
        if (svc_n == svc_cap) {
            svc_cap = svc_cap ? svc_cap * 2 : 256;
            svc_list = (svc_ent *)realloc(svc_list, svc_cap * sizeof(svc_ent));
        }
        svc_list[svc_n].name = name;
        svc_list[svc_n].port = (uint16_t)port;
        svc_n++;
    }
    /* buf intentionally kept: names point into it */
}

const char *svc_name(int udp, uint16_t port) {
    svc_load();
    return svc_tab[udp ? 1 : 0] ? svc_tab[udp ? 1 : 0][port] : NULL;
}

int svc_port(const char *name) {
    svc_load();
    for (int i = 0; i < svc_n; i++)
        if (!_stricmp(svc_list[i].name, name)) return svc_list[i].port;
    return -1;
}
