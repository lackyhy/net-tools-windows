/* ip - show / manipulate routing, devices, addresses, neighbours (iproute2 style) for Windows */
#include "common.h"

static int g_fam, g_brief, g_color, g_stats, g_details, g_json, g_pretty, g_oneline, g_human;

#define C_IF   "\x1b[36m"
#define C_UP   "\x1b[32m"
#define C_DOWN "\x1b[31m"
#define C_MAC  "\x1b[33m"
#define C_V4   "\x1b[35m"
#define C_V6   "\x1b[34m"
#define C_RST  "\x1b[0m"

static void cput(const char *col, const char *s) {
    if (g_color && col) { sb_puts(&g_out, col); sb_puts(&g_out, s); sb_puts(&g_out, C_RST); }
    else sb_puts(&g_out, s);
}
static void cpad(const char *col, const char *s, int w) {
    cput(col, s);
    sb_pad(&g_out, w - utf8_width(s));
}
static const char *state_col(const char *st) {
    if (!strcmp(st, "UP")) return C_UP;
    if (!strcmp(st, "DOWN") || !strcmp(st, "LOWERLAYERDOWN")) return C_DOWN;
    return NULL;
}

/* ======================= JSON ======================= */

static sbuf J;
static int jfirst[64];
static int jdepth;

static void j_raw(const char *s) { sb_puts(&J, s); }
static void j_str(const char *s) {
    sb_putc(&J, '"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { sb_putc(&J, '\\'); sb_putc(&J, (char)c); }
        else if (c < 0x20) sb_printf(&J, "\\u%04x", c);
        else sb_putc(&J, (char)c);
    }
    sb_putc(&J, '"');
}
static void j_sep(void) {
    if (!jfirst[jdepth]) sb_putc(&J, ',');
    jfirst[jdepth] = 0;
}
static void j_open(char c) { j_sep(); sb_putc(&J, c); jfirst[++jdepth] = 1; }
static void j_close(char c) { sb_putc(&J, c); jdepth--; }
static void j_key(const char *k) { j_sep(); j_str(k); sb_putc(&J, ':'); jfirst[jdepth] = 1; jfirst[jdepth] = 0; }
static void j_kopen(const char *k, char c) { j_key(k); sb_putc(&J, c); jfirst[++jdepth] = 1; }
static void j_kstr(const char *k, const char *v) { j_key(k); j_str(v); }
static void j_ku64(const char *k, uint64_t v) { j_key(k); sb_u64(&J, v); }
static void j_kbool(const char *k) { j_key(k); j_raw("true"); }
static void j_kraw(const char *k, const char *v) { j_key(k); j_raw(v); }
static void j_vstr(const char *v) { j_sep(); j_str(v); }

static void j_begin(void) { J.n = 0; jdepth = 0; jfirst[0] = 1; j_open('['); }

static void j_end(void) {
    j_close(']');
    if (!g_pretty) { sb_put(&g_out, J.p, J.n); sb_putc(&g_out, '\n'); return; }
    int ind = 0, instr = 0;
    for (size_t i = 0; i < J.n; i++) {
        char c = J.p[i];
        if (instr) {
            sb_putc(&g_out, c);
            if (c == '\\') sb_putc(&g_out, J.p[++i]);
            else if (c == '"') instr = 0;
            continue;
        }
        switch (c) {
        case '"': instr = 1; sb_putc(&g_out, c); break;
        case '{': case '[': {
            char cl = c == '{' ? '}' : ']';
            sb_putc(&g_out, c);
            if (J.p[i + 1] == cl) { sb_putc(&g_out, cl); i++; break; }
            ind++;
            sb_putc(&g_out, '\n');
            sb_pad(&g_out, ind * 4);
            break;
        }
        case '}': case ']':
            ind--;
            sb_putc(&g_out, '\n');
            sb_pad(&g_out, ind * 4);
            sb_putc(&g_out, c);
            break;
        case ',': sb_putc(&g_out, ','); sb_putc(&g_out, '\n'); sb_pad(&g_out, ind * 4); break;
        case ':': sb_puts(&g_out, ": "); break;
        default: sb_putc(&g_out, c);
        }
    }
    sb_putc(&g_out, '\n');
}

/* ======================= errors ======================= */

static int rt_err(DWORD e) {
    const char *m = NULL;
    switch (e) {
    case ERROR_ACCESS_DENIED: m = "Operation not permitted (run as Administrator)"; break;
    case ERROR_OBJECT_ALREADY_EXISTS: case ERROR_ALREADY_EXISTS: m = "File exists"; break;
    case ERROR_NOT_FOUND: case ERROR_FILE_NOT_FOUND: m = "No such process"; break;
    case ERROR_INVALID_PARAMETER: m = "Invalid argument"; break;
    case ERROR_NETWORK_UNREACHABLE: m = "Network is unreachable"; break;
    case ERROR_NOT_SUPPORTED: m = "Operation not supported"; break;
    }
    if (m) errf("RTNETLINK answers: %s\n", m);
    else errf("RTNETLINK answers: %s\n", win_errmsg(e));
    return 2;
}

static void need_arg(int argc, const char *what) {
    if (argc < 1) { errf("Command line is not complete. Try option \"help\"\n"); exit(255); }
    (void)what;
}

static void bad_prefix(const char *s) {
    errf("Error: %s prefix is expected rather than \"%s\".\n",
         g_fam == AF_INET6 ? "inet6" : g_fam == AF_INET ? "inet" : "any valid", s);
    exit(1);
}

static void parse_or_die(const char *s, inaddr *a) {
    if (!ip_parse(s, g_fam, a)) bad_prefix(s);
    if (g_fam && a->family != g_fam) bad_prefix(s);
}

static iface_t *IFS;
static int NIFS = -1;

static void load_ifs(void) {
    if (NIFS >= 0) return;
    NIFS = ifaces_load(&IFS);
    if (NIFS < 0) exit(1);
}

static iface_t *dev_or_die(const char *name) {
    load_ifs();
    iface_t *f = iface_find(IFS, NIFS, name);
    if (!f) { errf("Cannot find device \"%s\"\n", name); exit(1); }
    return f;
}

static const char *dev_name(uint32_t idx) {
    iface_t *f = NIFS > 0 ? iface_by_index(IFS, NIFS, idx) : NULL;
    return f ? f->name : ifname_idx(idx);
}

/* ======================= link helpers ======================= */

static int iface_flags(const iface_t *f, const char **fl) {
    int n = 0, lo = iface_is_loopback(f), p2p = iface_is_p2p(f);
    if (f->admin_up && !f->oper_up && !lo) fl[n++] = "NO-CARRIER";
    if (lo) fl[n++] = "LOOPBACK";
    else if (p2p) { fl[n++] = "POINTOPOINT"; fl[n++] = "NOARP"; }
    else {
        fl[n++] = "BROADCAST";
        if (!f->no_mcast) fl[n++] = "MULTICAST";
    }
    if (f->admin_up) fl[n++] = "UP";
    if (f->oper_up) fl[n++] = "LOWER_UP";
    return n;
}

static const char *link_type(const iface_t *f) {
    if (iface_is_loopback(f)) return "loopback";
    if (f->maclen == 6) return "ether";
    if (f->type == IF_TYPE_PPP) return "ppp";
    return "none";
}

static void link_mac(const iface_t *f, char *mac, char *brd) {
    if (iface_is_loopback(f) || !f->maclen) {
        strcpy(mac, "00:00:00:00:00:00");
        strcpy(brd, "00:00:00:00:00:00");
    } else {
        mac_fmt(mac, f->mac, f->maclen);
        strcpy(brd, "ff:ff:ff:ff:ff:ff");
    }
}

static void bcast4(const uint8_t *a, int plen, uint8_t *b) {
    uint32_t v = ((uint32_t)a[0] << 24) | ((uint32_t)a[1] << 16) | ((uint32_t)a[2] << 8) | a[3];
    uint32_t m = plen ? 0xFFFFFFFFu << (32 - plen) : 0;
    v |= ~m;
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v;
}

static void fmt_lft(char *d, uint32_t v) {
    if (v == 0xFFFFFFFFu) strcpy(d, "forever");
    else sprintf(d, "%usec", v);
}

static void print_head(const iface_t *f) {
    const char *fl[8];
    int n = iface_flags(f, fl);
    sb_printf(&g_out, "%u: ", f->index);
    cput(C_IF, f->name);
    sb_puts(&g_out, ": <");
    for (int i = 0; i < n; i++) { if (i) sb_putc(&g_out, ','); sb_puts(&g_out, fl[i]); }
    sb_printf(&g_out, "> mtu %u state ", f->mtu);
    const char *st = iface_operstate(f);
    cput(state_col(st), st);
    if (g_details && f->speed && f->speed != (uint64_t)-1) {
        if (f->speed >= 1000000000ull && f->speed % 1000000000ull == 0)
            sb_printf(&g_out, " speed %lluGbit", (unsigned long long)(f->speed / 1000000000ull));
        else
            sb_printf(&g_out, " speed %lluMbit", (unsigned long long)(f->speed / 1000000ull));
    }
}

static void print_linkline(const iface_t *f, const char *nl) {
    const char *lt = link_type(f);
    sb_printf(&g_out, "%s    link/%s", nl, lt);
    if (strcmp(lt, "none")) {
        char mac[32], brd[32];
        link_mac(f, mac, brd);
        sb_putc(&g_out, ' ');
        cput(C_MAC, mac);
        sb_puts(&g_out, " brd ");
        cput(C_MAC, brd);
    }
    if (g_details) {
        sb_printf(&g_out, "%s    alias %s", nl, f->desc);
        sb_printf(&g_out, "%s    iftype %u guid %s dhcp %s", nl, f->type, f->guid, f->dhcp ? "on" : "off");
    }
}

static void stat_val(char *d, uint64_t v) {
    if (g_human) human_size(d, v, 0);
    else sprintf(d, "%llu", (unsigned long long)v);
}

static void print_stats(const iface_t *f) {
    if (!f->have_row) return;
    const MIB_IF_ROW2 *r = &f->row;
    const char *rh[6] = {"RX:  bytes", "packets", "errors", "dropped", "missed", "mcast"};
    const char *th[6] = {"TX:  bytes", "packets", "errors", "dropped", "carrier", "collsns"};
    uint64_t rv[6] = {r->InOctets, r->InUcastPkts + r->InNUcastPkts, r->InErrors, r->InDiscards, r->InUnknownProtos,
                      r->InNUcastPkts};
    uint64_t tv[6] = {r->OutOctets, r->OutUcastPkts + r->OutNUcastPkts, r->OutErrors, r->OutDiscards, 0, 0};
    char rs[6][32], ts[6][32];
    int w[6];
    for (int i = 0; i < 6; i++) {
        stat_val(rs[i], rv[i]);
        stat_val(ts[i], tv[i]);
        w[i] = (int)strlen(rh[i]);
        if ((int)strlen(rs[i]) > w[i]) w[i] = (int)strlen(rs[i]);
        if ((int)strlen(ts[i]) > w[i]) w[i] = (int)strlen(ts[i]);
    }
    for (int pass = 0; pass < 2; pass++) {
        const char **h = pass ? th : rh;
        char(*v)[32] = pass ? ts : rs;
        sb_puts(&g_out, "    ");
        for (int i = 0; i < 6; i++) { if (i) sb_putc(&g_out, ' '); sb_padstr(&g_out, h[i], w[i], 1); }
        sb_puts(&g_out, "\n    ");
        for (int i = 0; i < 6; i++) { if (i) sb_putc(&g_out, ' '); sb_padstr(&g_out, v[i], w[i], 1); }
        sb_putc(&g_out, '\n');
    }
}

static void json_stats(const iface_t *f) {
    if (!f->have_row) return;
    const MIB_IF_ROW2 *r = &f->row;
    j_kopen("stats64", '{');
    j_kopen("rx", '{');
    j_ku64("bytes", r->InOctets);
    j_ku64("packets", r->InUcastPkts + r->InNUcastPkts);
    j_ku64("errors", r->InErrors);
    j_ku64("dropped", r->InDiscards);
    j_ku64("over_errors", 0);
    j_ku64("multicast", r->InNUcastPkts);
    j_close('}');
    j_kopen("tx", '{');
    j_ku64("bytes", r->OutOctets);
    j_ku64("packets", r->OutUcastPkts + r->OutNUcastPkts);
    j_ku64("errors", r->OutErrors);
    j_ku64("dropped", r->OutDiscards);
    j_ku64("carrier_errors", 0);
    j_ku64("collisions", 0);
    j_close('}');
    j_close('}');
}

/* ======================= addresses ======================= */

static int addr_dynamic(const ifaddr_t *a) {
    return a->porigin == IpPrefixOriginDhcp || a->porigin == IpPrefixOriginRouterAdvertisement;
}

static int addr_visible(const ifaddr_t *a, const char *scope) {
    if (g_fam && a->family != g_fam) return 0;
    if (scope && strcmp(scope, "all") && strcmp(ip_scope_name(a->family, a->a), scope)) return 0;
    return 1;
}

static void print_addr(const iface_t *f, const ifaddr_t *a) {
    char ip[64], b[64], v[24], p[24];
    const char *nl = g_oneline ? "\\" : "\n";
    if (g_oneline) sb_printf(&g_out, "%u: %s    ", f->index, f->name);
    else sb_puts(&g_out, "    ");
    ip_fmt(ip, a->family, a->a);
    sb_puts(&g_out, a->family == AF_INET ? "inet " : "inet6 ");
    cput(a->family == AF_INET ? C_V4 : C_V6, ip);
    sb_printf(&g_out, "/%d", a->plen);
    if (a->family == AF_INET && a->plen < 31) {
        uint8_t bb[4];
        bcast4(a->a, a->plen, bb);
        ip_fmt(b, AF_INET, bb);
        sb_puts(&g_out, " brd ");
        cput(C_V4, b);
    }
    sb_printf(&g_out, " scope %s", ip_scope_name(a->family, a->a));
    if (a->family == AF_INET6 && a->sorigin == IpSuffixOriginRandom) sb_puts(&g_out, " temporary");
    if (addr_dynamic(a)) sb_puts(&g_out, " dynamic");
    if (a->dad == IpDadStateTentative) sb_puts(&g_out, " tentative");
    else if (a->dad == IpDadStateDeprecated) sb_puts(&g_out, " deprecated");
    else if (a->dad == IpDadStateDuplicate) sb_puts(&g_out, " dadfailed");
    if (a->family == AF_INET) { sb_putc(&g_out, ' '); sb_puts(&g_out, f->name); }
    fmt_lft(v, a->valid);
    fmt_lft(p, a->pref);
    sb_printf(&g_out, "%s       valid_lft %s preferred_lft %s\n", nl, v, p);
}

static void json_addr(const iface_t *f, const ifaddr_t *a, int brief) {
    char ip[64];
    ip_fmt(ip, a->family, a->a);
    j_open('{');
    if (!brief) j_kstr("family", a->family == AF_INET ? "inet" : "inet6");
    j_kstr("local", ip);
    j_ku64("prefixlen", a->plen);
    if (brief) { j_close('}'); return; }
    if (a->family == AF_INET && a->plen < 31) {
        uint8_t bb[4];
        char b[64];
        bcast4(a->a, a->plen, bb);
        ip_fmt(b, AF_INET, bb);
        j_kstr("broadcast", b);
    }
    j_kstr("scope", ip_scope_name(a->family, a->a));
    if (a->family == AF_INET6 && a->sorigin == IpSuffixOriginRandom) j_kbool("temporary");
    if (addr_dynamic(a)) j_kbool("dynamic");
    if (a->dad == IpDadStateTentative) j_kbool("tentative");
    if (a->dad == IpDadStateDeprecated) j_kbool("deprecated");
    if (a->dad == IpDadStateDuplicate) j_kbool("dadfailed");
    if (a->family == AF_INET) j_kstr("label", f->name);
    j_ku64("valid_life_time", a->valid);
    j_ku64("preferred_life_time", a->pref);
    j_close('}');
}

static void json_iface(const iface_t *f, int with_addrs, const char *scope) {
    const char *fl[8];
    char mac[32], brd[32];
    int n = iface_flags(f, fl);
    j_open('{');
    j_ku64("ifindex", f->index);
    j_kstr("ifname", f->name);
    j_kopen("flags", '[');
    for (int i = 0; i < n; i++) j_vstr(fl[i]);
    j_close(']');
    j_ku64("mtu", f->mtu);
    j_kstr("operstate", iface_operstate(f));
    j_kstr("link_type", link_type(f));
    if (strcmp(link_type(f), "none")) {
        link_mac(f, mac, brd);
        j_kstr("address", mac);
        j_kstr("broadcast", brd);
    }
    j_kstr("ifalias", f->desc);
    if (g_stats) json_stats(f);
    if (with_addrs) {
        j_kopen("addr_info", '[');
        for (int i = 0; i < f->naddr; i++)
            if (addr_visible(&f->addr[i], scope)) json_addr(f, &f->addr[i], 0);
        j_close(']');
    }
    j_close('}');
}

static int has_visible_addr(const iface_t *f, const char *scope) {
    for (int i = 0; i < f->naddr; i++)
        if (addr_visible(&f->addr[i], scope)) return 1;
    return 0;
}

static int show_links(int argc, char **argv, int with_addrs) {
    const char *dev = NULL, *scope = NULL;
    int up_only = 0;
    while (argc > 0) {
        if (!strcmp(*argv, "dev")) { argc--; argv++; need_arg(argc, "dev"); dev = *argv; }
        else if (!strcmp(*argv, "up")) up_only = 1;
        else if (!strcmp(*argv, "scope")) { argc--; argv++; need_arg(argc, "scope"); scope = *argv; }
        else if (!strcmp(*argv, "label") || !strcmp(*argv, "to") || !strcmp(*argv, "type") ||
                 !strcmp(*argv, "group") || !strcmp(*argv, "master")) { argc--; argv++; }
        else if (!strcmp(*argv, "primary") || !strcmp(*argv, "secondary") || !strcmp(*argv, "dynamic") ||
                 !strcmp(*argv, "permanent")) ;
        else if (!strcmp(*argv, "help")) { return -1; }
        else {
            if (dev) { errf("Error: either \"dev\" is duplicate, or \"%s\" is a garbage.\n", *argv); return 1; }
            dev = *argv;
        }
        argc--; argv++;
    }
    if (scope && !strcmp(scope, "host")) ; /* valid */
    load_ifs();
    iface_t *only = NULL;
    if (dev) {
        only = iface_find(IFS, NIFS, dev);
        if (!only) { errf("Device \"%s\" does not exist.\n", dev); return 1; }
    }
    int addr_filter = with_addrs && (g_fam || scope);
    int wname = 16;
    if (g_brief)
        for (int i = 0; i < NIFS; i++) {
            int w = utf8_width(IFS[i].name) + 1;
            if (w > wname) wname = w;
        }
    if (g_json) j_begin();
    for (int i = 0; i < NIFS; i++) {
        iface_t *f = &IFS[i];
        if (only && f != only) continue;
        if (up_only && !f->admin_up) continue;
        if (addr_filter && !has_visible_addr(f, scope)) continue;
        if (g_json) {
            if (g_brief) {
                j_open('{');
                j_kstr("ifname", f->name);
                j_kstr("operstate", iface_operstate(f));
                if (with_addrs) {
                    j_kopen("addr_info", '[');
                    for (int k = 0; k < f->naddr; k++)
                        if (addr_visible(&f->addr[k], scope)) json_addr(f, &f->addr[k], 1);
                    j_close(']');
                } else {
                    char mac[32], brd[32];
                    const char *fl[8];
                    int n = iface_flags(f, fl);
                    link_mac(f, mac, brd);
                    j_kstr("address", mac);
                    j_kopen("flags", '[');
                    for (int k = 0; k < n; k++) j_vstr(fl[k]);
                    j_close(']');
                }
                j_close('}');
            } else {
                json_iface(f, with_addrs, scope);
            }
            continue;
        }
        if (g_brief) {
            const char *st = iface_operstate(f);
            cpad(C_IF, f->name, wname);
            sb_putc(&g_out, ' ');
            cpad(state_col(st), st, 14);
            sb_putc(&g_out, ' ');
            if (with_addrs) {
                for (int k = 0; k < f->naddr; k++) {
                    ifaddr_t *a = &f->addr[k];
                    if (!addr_visible(a, scope)) continue;
                    char ip[64];
                    ip_fmt(ip, a->family, a->a);
                    cput(a->family == AF_INET ? C_V4 : C_V6, ip);
                    sb_printf(&g_out, "/%d ", a->plen);
                }
            } else {
                char mac[32], brd[32];
                const char *fl[8];
                int n = iface_flags(f, fl);
                link_mac(f, mac, brd);
                if (!strcmp(link_type(f), "none")) mac[0] = 0;
                cpad(C_MAC, mac, 17);
                sb_puts(&g_out, " <");
                for (int k = 0; k < n; k++) { if (k) sb_putc(&g_out, ','); sb_puts(&g_out, fl[k]); }
                sb_putc(&g_out, '>');
            }
            sb_putc(&g_out, '\n');
            continue;
        }
        if (g_oneline && with_addrs) {
            for (int k = 0; k < f->naddr; k++)
                if (addr_visible(&f->addr[k], scope)) print_addr(f, &f->addr[k]);
            continue;
        }
        print_head(f);
        print_linkline(f, g_oneline ? "\\" : "\n");
        sb_putc(&g_out, '\n');
        if (with_addrs)
            for (int k = 0; k < f->naddr; k++)
                if (addr_visible(&f->addr[k], scope)) print_addr(f, &f->addr[k]);
        if (g_stats && !g_oneline) print_stats(f);
    }
    if (g_json) j_end();
    return 0;
}

static int addr_modify(int add, int argc, char **argv) {
    inaddr ia;
    int have = 0;
    const char *dev = NULL;
    uint32_t valid = 0xFFFFFFFFu, pref = 0xFFFFFFFFu;
    while (argc > 0) {
        const char *a = *argv;
        if (!strcmp(a, "dev")) { argc--; argv++; need_arg(argc, a); dev = *argv; }
        else if (!strcmp(a, "local")) { argc--; argv++; need_arg(argc, a); parse_or_die(*argv, &ia); have = 1; }
        else if (!strcmp(a, "valid_lft") || !strcmp(a, "preferred_lft")) {
            argc--; argv++; need_arg(argc, a);
            uint32_t v = !strcmp(*argv, "forever") ? 0xFFFFFFFFu : (uint32_t)strtoul(*argv, NULL, 10);
            if (a[0] == 'v') valid = v; else pref = v;
        }
        else if (!strcmp(a, "brd") || !strcmp(a, "broadcast") || !strcmp(a, "label") || !strcmp(a, "scope") ||
                 !strcmp(a, "metric") || !strcmp(a, "priority") || !strcmp(a, "anycast")) { argc--; argv++; }
        else if (!strcmp(a, "peer") || !strcmp(a, "remote")) { errf("Error: peer addresses are not supported on Windows.\n"); return 1; }
        else if (!strcmp(a, "noprefixroute") || !strcmp(a, "nodad") || !strcmp(a, "home") ||
                 !strcmp(a, "mngtmpaddr") || !strcmp(a, "autojoin")) ;
        else {
            if (have) { errf("Error: either \"local\" is duplicate, or \"%s\" is a garbage.\n", a); return 1; }
            parse_or_die(a, &ia);
            have = 1;
        }
        argc--; argv++;
    }
    if (!dev) { errf("Not enough information: \"dev\" argument is required.\n"); return 1; }
    if (!have) { errf("Not enough information: address is required.\n"); return 1; }
    iface_t *f = dev_or_die(dev);
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = f->luid;
    row.InterfaceIndex = f->index;
    sa_set(&row.Address, ia.family, ia.a, 0);
    row.OnLinkPrefixLength = (UINT8)ia.plen;
    row.ValidLifetime = valid;
    row.PreferredLifetime = pref;
    row.DadState = IpDadStatePreferred;
    DWORD e = add ? CreateUnicastIpAddressEntry(&row) : DeleteUnicastIpAddressEntry(&row);
    if (e == ERROR_NOT_FOUND && !add) { errf("RTNETLINK answers: Cannot assign requested address\n"); return 2; }
    return e ? rt_err(e) : 0;
}

static int addr_flush(int argc, char **argv) {
    const char *dev = NULL, *scope = NULL;
    while (argc > 0) {
        if (!strcmp(*argv, "dev")) { argc--; argv++; need_arg(argc, "dev"); dev = *argv; }
        else if (!strcmp(*argv, "scope")) { argc--; argv++; need_arg(argc, "scope"); scope = *argv; }
        else dev = *argv;
        argc--; argv++;
    }
    if (!dev) { errf("Flush requires arguments.\n"); return 1; }
    iface_t *f = dev_or_die(dev);
    int rc = 0;
    for (int i = 0; i < f->naddr; i++) {
        ifaddr_t *a = &f->addr[i];
        if (!addr_visible(a, scope)) continue;
        MIB_UNICASTIPADDRESS_ROW row;
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = f->luid;
        row.InterfaceIndex = f->index;
        sa_set(&row.Address, a->family, a->a, 0);
        DWORD e = DeleteUnicastIpAddressEntry(&row);
        if (e && e != ERROR_NOT_FOUND) { rc = rt_err(e); break; }
    }
    return rc;
}

static int usage_addr(void) {
    errf("Usage: ip address {add|change|replace} IFADDR dev IFNAME [ LIFETIME ]\n"
         "       ip address del IFADDR dev IFNAME\n"
         "       ip address flush dev IFNAME [ scope SCOPE ]\n"
         "       ip address [ show [ dev IFNAME ] [ scope SCOPE ] [ up ] ]\n"
         "IFADDR := PREFIX\n"
         "SCOPE := { host | link | global }\n"
         "LIFETIME := [ valid_lft LFT ] [ preferred_lft LFT ]\n"
         "LFT := forever | SECONDS\n");
    return 255;
}

static int do_addr(int argc, char **argv) {
    if (argc < 1) return show_links(0, NULL, 1);
    const char *c = *argv;
    if (matches(c, "add") || matches(c, "change") || matches(c, "replace")) {
        int r = addr_modify(1, argc - 1, argv + 1);
        if (r == 2 && !matches(c, "add")) return 0; /* replace of existing address: already present */
        return r;
    }
    if (matches(c, "delete")) return addr_modify(0, argc - 1, argv + 1);
    if (matches(c, "flush")) return addr_flush(argc - 1, argv + 1);
    if (matches(c, "show") || matches(c, "list") || matches(c, "lst")) {
        int r = show_links(argc - 1, argv + 1, 1);
        return r < 0 ? usage_addr() : r;
    }
    if (matches(c, "help")) return usage_addr();
    int r = show_links(argc, argv, 1);
    return r < 0 ? usage_addr() : r;
}

/* ======================= link ======================= */

static int run_netsh(const wchar_t *args) {
    wchar_t cmd[1024];
    _snwprintf(cmd, 1024, L"netsh.exe %s", args);
    cmd[1023] = 0;
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi;
    out_flush();
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        win_errf(GetLastError(), "netsh: ");
        return 2;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code ? 2 : 0;
}

static int set_mtu(iface_t *f, unsigned long mtu) {
    int ok = 0;
    DWORD last = 0;
    for (int k = 0; k < 2; k++) {
        MIB_IPINTERFACE_ROW r;
        InitializeIpInterfaceEntry(&r);
        r.Family = k ? AF_INET6 : AF_INET;
        r.InterfaceLuid = f->luid;
        if (GetIpInterfaceEntry(&r) != NO_ERROR) continue;
        if (r.Family == AF_INET) r.SitePrefixLength = 0;
        r.NlMtu = mtu;
        DWORD e = SetIpInterfaceEntry(&r);
        if (e == NO_ERROR) ok = 1; else last = e;
    }
    if (!ok) return rt_err(last ? last : ERROR_NOT_FOUND);
    return 0;
}

static int link_set(int argc, char **argv) {
    const char *dev = NULL;
    iface_t *f = NULL;
    int rc = 0;
    while (argc > 0) {
        const char *a = *argv;
        if (!strcmp(a, "dev")) { argc--; argv++; need_arg(argc, a); dev = *argv; f = dev_or_die(dev); }
        else if (!strcmp(a, "up") || !strcmp(a, "down")) {
            if (!f) { errf("Not enough information: \"dev\" argument is required.\n"); return 1; }
            wchar_t buf[600];
            _snwprintf(buf, 600, L"interface set interface name=\"%s\" admin=%s", f->wname,
                       a[0] == 'u' ? L"enabled" : L"disabled");
            buf[599] = 0;
            if ((rc = run_netsh(buf))) return rc;
        }
        else if (!strcmp(a, "mtu")) {
            argc--; argv++; need_arg(argc, a);
            if (!f) { errf("Not enough information: \"dev\" argument is required.\n"); return 1; }
            char *e;
            unsigned long m = strtoul(*argv, &e, 10);
            if (*e || !m) { errf("Error: argument \"%s\" is wrong: Invalid \"mtu\" value\n", *argv); return 1; }
            if ((rc = set_mtu(f, m))) return rc;
        }
        else if (!strcmp(a, "name")) {
            argc--; argv++; need_arg(argc, a);
            if (!f) { errf("Not enough information: \"dev\" argument is required.\n"); return 1; }
            wchar_t *nn = u2w(*argv);
            wchar_t buf[800];
            _snwprintf(buf, 800, L"interface set interface name=\"%s\" newname=\"%s\"", f->wname, nn);
            buf[799] = 0;
            free(nn);
            if ((rc = run_netsh(buf))) return rc;
        }
        else if (!strcmp(a, "address") || !strcmp(a, "arp") || !strcmp(a, "multicast") || !strcmp(a, "txqueuelen") ||
                 !strcmp(a, "txqlen") || !strcmp(a, "promisc") || !strcmp(a, "alias") || !strcmp(a, "master") ||
                 !strcmp(a, "netns")) {
            errf("Error: \"%s\" is not supported on Windows.\n", a);
            return 1;
        }
        else {
            if (f) { errf("Error: either \"dev\" is duplicate, or \"%s\" is a garbage.\n", a); return 1; }
            dev = a;
            f = dev_or_die(dev);
        }
        argc--; argv++;
    }
    if (!f) { errf("Not enough information: \"dev\" argument is required.\n"); return 1; }
    return 0;
}

static int usage_link(void) {
    errf("Usage: ip link set { DEVICE | dev DEVICE } [ { up | down } ] [ mtu MTU ] [ name NEWNAME ]\n"
         "       ip link show [ DEVICE | dev DEVICE ] [ up ]\n");
    return 255;
}

static int do_link(int argc, char **argv) {
    if (argc < 1) return show_links(0, NULL, 0);
    const char *c = *argv;
    if (matches(c, "set") || matches(c, "change")) return link_set(argc - 1, argv + 1);
    if (matches(c, "show") || matches(c, "list") || matches(c, "lst")) {
        int r = show_links(argc - 1, argv + 1, 0);
        return r < 0 ? usage_link() : r;
    }
    if (matches(c, "help")) return usage_link();
    if (matches(c, "add") || matches(c, "delete")) {
        errf("Error: creating/deleting virtual links is not supported on Windows.\n");
        return 1;
    }
    errf("Command \"%s\" is unknown, try \"ip link help\".\n", c);
    return 1;
}

/* ======================= routes ======================= */

enum { RT_UNICAST, RT_LOCAL, RT_BROADCAST, RT_MULTICAST };
static const char *rt_type_name[] = {"unicast", "local", "broadcast", "multicast"};

typedef struct {
    MIB_IPFORWARD_ROW2 *r;
    int fam, plen, has_gw, type;
    uint8_t dst[16], gw[16];
    uint32_t metric;
} rt_t;

static uint32_t if_metric(MIB_IPINTERFACE_TABLE *it, uint32_t idx) {
    if (!it) return 0;
    for (ULONG i = 0; i < it->NumEntries; i++)
        if (it->Table[i].InterfaceIndex == idx) return it->Table[i].Metric;
    return 0;
}

static int rt_classify(const rt_t *t) {
    if (ip_is_multicast(t->fam, t->dst)) return RT_MULTICAST;
    int full = t->fam == AF_INET ? 32 : 128;
    if (t->fam == AF_INET && t->dst[0] == 127) {
        static const uint8_t b[4] = {127, 255, 255, 255};
        return (t->plen == 32 && !memcmp(t->dst, b, 4)) ? RT_BROADCAST : RT_LOCAL;
    }
    if (t->plen != full) return RT_UNICAST;
    if (t->fam == AF_INET) {
        static const uint8_t all1[4] = {255, 255, 255, 255};
        if (!memcmp(t->dst, all1, 4)) return RT_BROADCAST;
    } else {
        static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        if (!memcmp(t->dst, lo6, 16)) return RT_LOCAL;
    }
    for (int i = 0; i < NIFS; i++)
        for (int k = 0; k < IFS[i].naddr; k++) {
            ifaddr_t *a = &IFS[i].addr[k];
            if (a->family != t->fam) continue;
            if (!memcmp(a->a, t->dst, t->fam == AF_INET ? 4 : 16)) return RT_LOCAL;
            if (t->fam == AF_INET && a->plen < 31) {
                uint8_t b[4];
                bcast4(a->a, a->plen, b);
                if (!memcmp(b, t->dst, 4)) return RT_BROADCAST;
            }
        }
    return RT_UNICAST;
}

static int rt_cmp(const void *x, const void *y) {
    const rt_t *a = (const rt_t *)x, *b = (const rt_t *)y;
    int ua = a->type != RT_UNICAST, ub = b->type != RT_UNICAST;
    if (ua != ub) return ua - ub;
    if (a->fam != b->fam) return a->fam == AF_INET ? -1 : 1;
    if ((a->plen == 0) != (b->plen == 0)) return a->plen == 0 ? -1 : 1;
    int c = memcmp(a->dst, b->dst, a->fam == AF_INET ? 4 : 16);
    if (c) return c;
    if (a->plen != b->plen) return a->plen - b->plen;
    return a->metric < b->metric ? -1 : a->metric > b->metric;
}

static const char *rt_proto(const MIB_IPFORWARD_ROW2 *r) {
    switch (r->Origin) {
    case NlroDHCP: return "dhcp";
    case NlroRouterAdvertisement: return "ra";
    case Nlro6to4: return "6to4";
    default: break;
    }
    switch ((int)r->Protocol) {
    case MIB_IPPROTO_NETMGMT: {
        /* Windows installs the DHCP default gateway as a NetMgmt route */
        iface_t *f = iface_by_index(IFS, NIFS, r->InterfaceIndex);
        if (f && f->dhcp && r->DestinationPrefix.PrefixLength == 0 &&
            r->DestinationPrefix.Prefix.si_family == AF_INET)
            return "dhcp";
        return "static";
    }
    case MIB_IPPROTO_NT_STATIC: case MIB_IPPROTO_NT_STATIC_NON_DOD: case MIB_IPPROTO_NT_AUTOSTATIC: return "static";
    case MIB_IPPROTO_RIP: return "rip";
    case MIB_IPPROTO_OSPF: return "ospf";
    case MIB_IPPROTO_BGP: return "bgp";
    default: return "kernel";
    }
}

static const ifaddr_t *pick_src(uint32_t idx, int fam, const uint8_t *dst, int plen) {
    iface_t *f = iface_by_index(IFS, NIFS, idx);
    if (!f) return NULL;
    const ifaddr_t *first = NULL;
    for (int k = 0; k < f->naddr; k++) {
        const ifaddr_t *a = &f->addr[k];
        if (a->family != fam) continue;
        if (!first) first = a;
        if (prefix_match(fam, a->a, dst, plen)) return a;
    }
    return first;
}

static void fmt_dst(char *d, const rt_t *t) {
    int full = t->fam == AF_INET ? 32 : 128;
    if (t->plen == 0 && t->type == RT_UNICAST) { strcpy(d, "default"); return; }
    int n = ip_fmt(d, t->fam, t->dst);
    if (t->plen != full) sprintf(d + n, "/%d", t->plen);
}

static void print_route(const rt_t *t, int show_table) {
    char d[80], g[64], s[64];
    iface_t *f = iface_by_index(IFS, NIFS, t->r->InterfaceIndex);
    fmt_dst(d, t);
    if (g_json) {
        j_open('{');
        if (t->type != RT_UNICAST) j_kstr("type", rt_type_name[t->type]);
        j_kstr("dst", d);
        if (t->has_gw) { ip_fmt(g, t->fam, t->gw); j_kstr("gateway", g); }
        j_kstr("dev", dev_name(t->r->InterfaceIndex));
        if (show_table && t->type != RT_UNICAST) j_kstr("table", "local");
        j_kstr("protocol", t->type == RT_UNICAST ? rt_proto(t->r) : "kernel");
        if (t->type == RT_LOCAL) j_kstr("scope", "host");
        else if (!t->has_gw && t->fam == AF_INET) j_kstr("scope", "link");
        if (t->fam == AF_INET && (!t->has_gw || t->type != RT_UNICAST)) {
            const ifaddr_t *a = pick_src(t->r->InterfaceIndex, t->fam, t->dst, t->type == RT_UNICAST ? t->plen : 0);
            if (t->type == RT_LOCAL && t->plen == 32 && t->dst[0] != 127) { ip_fmt(s, AF_INET, t->dst); j_kstr("prefsrc", s); }
            else if (a) { ip_fmt(s, AF_INET, a->a); j_kstr("prefsrc", s); }
        }
        j_ku64("metric", t->metric);
        j_kopen("flags", '[');
        if (f && !f->oper_up && !iface_is_loopback(f)) j_vstr("linkdown");
        j_close(']');
        if (t->fam == AF_INET6) j_kstr("pref", "medium");
        j_close('}');
        return;
    }
    if (t->type != RT_UNICAST) { sb_puts(&g_out, rt_type_name[t->type]); sb_putc(&g_out, ' '); }
    cput(t->fam == AF_INET ? C_V4 : C_V6, d);
    if (t->has_gw) {
        ip_fmt(g, t->fam, t->gw);
        sb_puts(&g_out, " via ");
        cput(t->fam == AF_INET ? C_V4 : C_V6, g);
    }
    sb_puts(&g_out, " dev ");
    cput(C_IF, dev_name(t->r->InterfaceIndex));
    if (show_table && t->type != RT_UNICAST) sb_puts(&g_out, " table local");
    sb_printf(&g_out, " proto %s", t->type == RT_UNICAST ? rt_proto(t->r) : "kernel");
    if (t->type == RT_LOCAL) sb_puts(&g_out, " scope host");
    else if (!t->has_gw && t->fam == AF_INET) sb_puts(&g_out, " scope link");
    if (t->fam == AF_INET && (!t->has_gw || t->type != RT_UNICAST)) {
        const ifaddr_t *a = pick_src(t->r->InterfaceIndex, t->fam, t->dst, t->type == RT_UNICAST ? t->plen : 0);
        if (t->type == RT_LOCAL && t->plen == 32 && t->dst[0] != 127) { ip_fmt(s, AF_INET, t->dst); sb_printf(&g_out, " src %s", s); }
        else if (a) { ip_fmt(s, AF_INET, a->a); sb_printf(&g_out, " src %s", s); }
    }
    if (t->type == RT_UNICAST || t->fam == AF_INET6) sb_printf(&g_out, " metric %u", t->metric);
    if (f && !f->oper_up && !iface_is_loopback(f)) sb_puts(&g_out, " linkdown");
    if (t->fam == AF_INET6) sb_puts(&g_out, " pref medium");
    sb_putc(&g_out, '\n');
}

typedef struct {
    MIB_IPFORWARD_TABLE2 *tb[2];
    MIB_IPINTERFACE_TABLE *it[2];
    rt_t *v;
    int n;
} rtab_t;

static void rtab_load(rtab_t *R, int fam_mask) {
    memset(R, 0, sizeof *R);
    load_ifs();
    int total = 0;
    for (int k = 0; k < 2; k++) {
        int fam = k ? AF_INET6 : AF_INET;
        if (!(fam_mask & (1 << k))) continue;
        DWORD e = GetIpForwardTable2((ADDRESS_FAMILY)fam, &R->tb[k]);
        if (e != NO_ERROR) { R->tb[k] = NULL; continue; }
        GetIpInterfaceTable((ADDRESS_FAMILY)fam, &R->it[k]);
        total += R->tb[k]->NumEntries;
    }
    R->v = (rt_t *)calloc(total ? total : 1, sizeof(rt_t));
    for (int k = 0; k < 2; k++) {
        if (!R->tb[k]) continue;
        for (ULONG i = 0; i < R->tb[k]->NumEntries; i++) {
            MIB_IPFORWARD_ROW2 *r = &R->tb[k]->Table[i];
            rt_t *t = &R->v[R->n++];
            uint32_t sc;
            t->r = r;
            sa_get(&r->DestinationPrefix.Prefix, &t->fam, t->dst, &sc);
            t->plen = r->DestinationPrefix.PrefixLength;
            int gf;
            sa_get(&r->NextHop, &gf, t->gw, &sc);
            t->has_gw = !ip_is_unspec(t->fam, t->gw);
            t->metric = r->Metric + if_metric(R->it[k], r->InterfaceIndex);
            t->type = rt_classify(t);
        }
    }
    qsort(R->v, R->n, sizeof(rt_t), rt_cmp);
}

static int route_show(int argc, char **argv) {
    int table = 0; /* 0 main, 1 local, 2 all */
    const char *dev = NULL;
    inaddr pfx;
    int have_pfx = 0;
    const char *proto = NULL;
    inaddr via;
    int have_via = 0;
    while (argc > 0) {
        const char *a = *argv;
        if (!strcmp(a, "table")) {
            argc--; argv++; need_arg(argc, a);
            if (!strcmp(*argv, "local") || !strcmp(*argv, "255")) table = 1;
            else if (!strcmp(*argv, "all") || !strcmp(*argv, "0")) table = 2;
            else if (!strcmp(*argv, "main") || !strcmp(*argv, "254")) table = 0;
            else { errf("Error: argument \"%s\" is wrong: table id value is invalid\n", *argv); return 1; }
        }
        else if (!strcmp(a, "dev") || !strcmp(a, "oif")) { argc--; argv++; need_arg(argc, a); dev = *argv; }
        else if (!strcmp(a, "proto") || !strcmp(a, "protocol")) { argc--; argv++; need_arg(argc, a); proto = *argv; }
        else if (!strcmp(a, "via")) { argc--; argv++; need_arg(argc, a); parse_or_die(*argv, &via); have_via = 1; }
        else if (!strcmp(a, "scope") || !strcmp(a, "type") || !strcmp(a, "src") || !strcmp(a, "from")) { argc--; argv++; }
        else if (!strcmp(a, "root") || !strcmp(a, "match") || !strcmp(a, "exact")) { argc--; argv++; need_arg(argc, a); parse_or_die(*argv, &pfx); have_pfx = 1; }
        else if (!strcmp(a, "cached") || !strcmp(a, "cloned")) ;
        else if (!strcmp(a, "help")) return -1;
        else { parse_or_die(a, &pfx); have_pfx = 1; }
        argc--; argv++;
    }
    int fam_mask = g_fam == AF_INET6 ? 2 : 1;
    if (have_pfx) fam_mask = pfx.family == AF_INET6 ? 2 : 1;
    rtab_t R;
    rtab_load(&R, fam_mask);
    iface_t *only = dev ? dev_or_die(dev) : NULL;
    if (g_json) j_begin();
    for (int i = 0; i < R.n; i++) {
        rt_t *t = &R.v[i];
        if (table == 0 && t->type != RT_UNICAST) continue;
        if (table == 1 && t->type == RT_UNICAST) continue;
        if (only && t->r->InterfaceIndex != only->index) continue;
        if (have_pfx && (t->fam != pfx.family || t->plen != pfx.plen ||
                         !prefix_match(t->fam, t->dst, pfx.a, pfx.plen)))
            continue;
        if (have_via && (!t->has_gw || t->fam != via.family || memcmp(t->gw, via.a, via.family == AF_INET ? 4 : 16)))
            continue;
        if (proto && strcmp(proto, t->type == RT_UNICAST ? rt_proto(t->r) : "kernel")) continue;
        print_route(t, table != 0);
    }
    if (g_json) j_end();
    return 0;
}

static int route_get(int argc, char **argv) {
    inaddr dst, src;
    int have_dst = 0, have_src = 0;
    const char *dev = NULL;
    while (argc > 0) {
        const char *a = *argv;
        if (!strcmp(a, "from")) { argc--; argv++; need_arg(argc, a); parse_or_die(*argv, &src); have_src = 1; }
        else if (!strcmp(a, "oif") || !strcmp(a, "dev")) { argc--; argv++; need_arg(argc, a); dev = *argv; }
        else if (!strcmp(a, "iif") || !strcmp(a, "mark") || !strcmp(a, "tos") || !strcmp(a, "dsfield") ||
                 !strcmp(a, "uid") || !strcmp(a, "ipproto") || !strcmp(a, "sport") || !strcmp(a, "dport") ||
                 !strcmp(a, "vrf")) { argc--; argv++; }
        else if (!strcmp(a, "to")) { argc--; argv++; need_arg(argc, a); parse_or_die(*argv, &dst); have_dst = 1; }
        else if (!strcmp(a, "connected") || !strcmp(a, "fibmatch") || !strcmp(a, "notify")) ;
        else { parse_or_die(a, &dst); have_dst = 1; }
        argc--; argv++;
    }
    if (!have_dst) { errf("need at least a destination address\n"); return 1; }
    load_ifs();
    uint32_t idx = dev ? dev_or_die(dev)->index : 0;
    SOCKADDR_INET d, s, best;
    sa_set(&d, dst.family, dst.a, dst.scope);
    if (have_src) sa_set(&s, src.family, src.a, 0);
    MIB_IPFORWARD_ROW2 row;
    DWORD e = GetBestRoute2(NULL, idx, have_src ? &s : NULL, &d, 0, &row, &best);
    if (e != NO_ERROR) return rt_err(e == ERROR_NOT_FOUND ? ERROR_NETWORK_UNREACHABLE : e);
    char ds[64], gs[64], ss[64];
    uint8_t gw[16], sa[16];
    int gf, sf;
    uint32_t sc;
    ip_fmt(ds, dst.family, dst.a);
    sa_get(&row.NextHop, &gf, gw, &sc);
    sa_get(&best, &sf, sa, &sc);
    int has_gw = !ip_is_unspec(dst.family, gw);
    int local = 0;
    for (int i = 0; i < NIFS && !local; i++)
        for (int k = 0; k < IFS[i].naddr; k++)
            if (IFS[i].addr[k].family == dst.family && !memcmp(IFS[i].addr[k].a, dst.a, dst.family == AF_INET ? 4 : 16)) { local = 1; break; }
    if (dst.family == AF_INET && dst.a[0] == 127) local = 1;
    ip_fmt(ss, dst.family, sa);
    if (g_json) {
        j_begin();
        j_open('{');
        if (local) j_kstr("type", "local");
        j_kstr("dst", ds);
        if (has_gw) { ip_fmt(gs, dst.family, gw); j_kstr("gateway", gs); }
        j_kstr("dev", dev_name(row.InterfaceIndex));
        j_kstr("prefsrc", ss);
        j_kopen("flags", '[');
        j_close(']');
        j_kopen("cache", '[');
        j_close(']');
        j_close('}');
        j_end();
        return 0;
    }
    if (local) sb_puts(&g_out, "local ");
    cput(dst.family == AF_INET ? C_V4 : C_V6, ds);
    if (has_gw) { ip_fmt(gs, dst.family, gw); sb_puts(&g_out, " via "); cput(dst.family == AF_INET ? C_V4 : C_V6, gs); }
    sb_puts(&g_out, " dev ");
    cput(C_IF, dev_name(row.InterfaceIndex));
    if (local) sb_puts(&g_out, " table local");
    sb_printf(&g_out, " src %s", ss);
    if (dst.family == AF_INET6) sb_printf(&g_out, " metric %u pref medium", row.Metric);
    sb_puts(&g_out, "\n    cache\n");
    return 0;
}

/* cmd: 0 add, 1 del, 2 replace/change, 3 append */
static int route_modify(int cmd, int argc, char **argv) {
    inaddr dst, gw;
    int have_dst = 0, have_gw = 0;
    const char *dev = NULL;
    long metric = -1;
    while (argc > 0) {
        const char *a = *argv;
        if (!strcmp(a, "via")) {
            argc--; argv++; need_arg(argc, a);
            if (!strcmp(*argv, "inet") || !strcmp(*argv, "inet6")) { argc--; argv++; need_arg(argc, a); }
            if (!ip_parse(*argv, 0, &gw) || gw.has_plen) bad_prefix(*argv);
            have_gw = 1;
        }
        else if (!strcmp(a, "dev") || !strcmp(a, "oif")) { argc--; argv++; need_arg(argc, a); dev = *argv; }
        else if (!strcmp(a, "metric") || !strcmp(a, "priority") || !strcmp(a, "preference")) {
            argc--; argv++; need_arg(argc, a);
            char *e;
            metric = strtol(*argv, &e, 10);
            if (*e || metric < 0) { errf("Error: argument \"%s\" is wrong: \"metric\" value is invalid\n", *argv); return 1; }
        }
        else if (!strcmp(a, "table")) {
            argc--; argv++; need_arg(argc, a);
            if (strcmp(*argv, "main") && strcmp(*argv, "254")) { errf("Error: only the main table is supported on Windows.\n"); return 1; }
        }
        else if (!strcmp(a, "proto") || !strcmp(a, "protocol") || !strcmp(a, "scope") || !strcmp(a, "src") ||
                 !strcmp(a, "mtu") || !strcmp(a, "advmss") || !strcmp(a, "realm") || !strcmp(a, "pref")) { argc--; argv++; }
        else if (!strcmp(a, "onlink") || !strcmp(a, "unicast") || !strcmp(a, "pervasive")) ;
        else if (!strcmp(a, "to")) { argc--; argv++; need_arg(argc, a); parse_or_die(*argv, &dst); have_dst = 1; }
        else {
            if (have_dst) { errf("Error: either \"to\" is duplicate, or \"%s\" is a garbage.\n", a); return 1; }
            parse_or_die(a, &dst);
            have_dst = 1;
        }
        argc--; argv++;
    }
    if (!have_dst) { errf("Error: destination is required.\n"); return 1; }
    if (dst.is_any && have_gw) dst.family = gw.family;
    if (have_gw && gw.family != dst.family) { errf("Error: gateway family does not match destination.\n"); return 1; }
    load_ifs();
    iface_t *f = dev ? dev_or_die(dev) : NULL;

    if (cmd == 1 || cmd == 2) {
        rtab_t R;
        rtab_load(&R, dst.family == AF_INET6 ? 2 : 1);
        rt_t *found = NULL;
        for (int i = 0; i < R.n && !found; i++) {
            rt_t *t = &R.v[i];
            if (t->type != RT_UNICAST || t->fam != dst.family || t->plen != dst.plen) continue;
            if (!prefix_match(t->fam, t->dst, dst.a, dst.plen) || !prefix_match(t->fam, dst.a, t->dst, dst.plen)) continue;
            if (f && t->r->InterfaceIndex != f->index) continue;
            if (cmd == 1 && have_gw && (!t->has_gw || memcmp(t->gw, gw.a, gw.family == AF_INET ? 4 : 16))) continue;
            found = t;
        }
        if (found) {
            DWORD e = DeleteIpForwardEntry2(found->r);
            if (e) return rt_err(e);
        } else if (cmd == 1) {
            errf("RTNETLINK answers: No such process\n");
            return 2;
        }
        if (cmd == 1) return 0;
    }

    uint32_t idx;
    NET_LUID luid;
    if (f) { idx = f->index; luid = f->luid; }
    else if (have_gw) {
        SOCKADDR_INET d, best;
        MIB_IPFORWARD_ROW2 br;
        sa_set(&d, gw.family, gw.a, gw.scope);
        DWORD e = GetBestRoute2(NULL, 0, NULL, &d, 0, &br, &best);
        if (e) { errf("Error: Nexthop has invalid gateway.\n"); return 2; }
        idx = br.InterfaceIndex;
        luid = br.InterfaceLuid;
    } else {
        errf("Error: Device for nexthop is not specified.\n");
        return 2;
    }
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceIndex = idx;
    row.InterfaceLuid = luid;
    sa_set(&row.DestinationPrefix.Prefix, dst.family, dst.a, 0);
    row.DestinationPrefix.PrefixLength = (UINT8)dst.plen;
    static const uint8_t zero[16];
    sa_set(&row.NextHop, dst.family, have_gw ? gw.a : zero, have_gw ? gw.scope : 0);
    row.Metric = metric >= 0 ? (ULONG)metric : 0;
    row.Protocol = (NL_ROUTE_PROTOCOL)MIB_IPPROTO_NETMGMT;
    row.Origin = NlroManual;
    DWORD e = CreateIpForwardEntry2(&row);
    if (e) return rt_err(e);
    return 0;
}

static int usage_route(void) {
    errf("Usage: ip route [ list [ SELECTOR ] ]\n"
         "       ip route get ADDRESS [ from ADDRESS ] [ oif IFNAME ]\n"
         "       ip route { add | del | change | append | replace } ROUTE\n"
         "SELECTOR := [ PREFIX ] [ table TABLE_ID ] [ dev IFNAME ] [ via ADDRESS ] [ proto RTPROTO ]\n"
         "ROUTE := PREFIX [ via ADDRESS ] [ dev IFNAME ] [ metric NUMBER ]\n"
         "TABLE_ID := [ local | main | all ]\n"
         "PREFIX := { default | ADDRESS[/LEN] }\n"
         "Note: metric shown = route metric + interface metric (effective Windows metric).\n");
    return 255;
}

static int do_route(int argc, char **argv) {
    if (argc < 1) return route_show(0, NULL);
    const char *c = *argv;
    int r;
    if (matches(c, "add")) return route_modify(0, argc - 1, argv + 1);
    if (matches(c, "append")) return route_modify(0, argc - 1, argv + 1);
    if (matches(c, "change") || matches(c, "replace")) return route_modify(2, argc - 1, argv + 1);
    if (matches(c, "delete")) return route_modify(1, argc - 1, argv + 1);
    if (matches(c, "get")) return route_get(argc - 1, argv + 1);
    if (matches(c, "flush")) {
        if (argc > 1 && !strcmp(argv[1], "cache")) return 0;
        errf("Error: \"ip route flush\" is disabled on Windows (too destructive). Use \"ip route del\".\n");
        return 1;
    }
    if (matches(c, "help")) return usage_route();
    if (matches(c, "show") || matches(c, "list") || matches(c, "lst")) r = route_show(argc - 1, argv + 1);
    else r = route_show(argc, argv);
    return r < 0 ? usage_route() : r;
}

/* ======================= neighbours ======================= */

static const char *nud_name(int st) {
    switch (st) {
    case NlnsUnreachable: return "FAILED";
    case NlnsIncomplete: return "INCOMPLETE";
    case NlnsProbe: return "PROBE";
    case NlnsDelay: return "DELAY";
    case NlnsStale: return "STALE";
    case NlnsReachable: return "REACHABLE";
    case NlnsPermanent: return "PERMANENT";
    default: return "NONE";
    }
}

static int nud_parse(const char *s) {
    static const char *n[] = {"failed", "incomplete", "probe", "delay", "stale", "reachable", "permanent"};
    for (int i = 0; i < 7; i++)
        if (!_stricmp(s, n[i])) return 1 << i;
    if (!_stricmp(s, "all")) return 0x7F;
    if (!_stricmp(s, "noarp") || !_stricmp(s, "none")) return 0;
    errf("Error: argument \"%s\" is wrong: nud state is bad\n", s);
    exit(1);
}

static int neigh_show(int argc, char **argv) {
    const char *dev = NULL;
    int nud = 0;
    inaddr pfx;
    int have_pfx = 0;
    while (argc > 0) {
        const char *a = *argv;
        if (!strcmp(a, "dev")) { argc--; argv++; need_arg(argc, a); dev = *argv; }
        else if (!strcmp(a, "nud")) { argc--; argv++; need_arg(argc, a); nud |= nud_parse(*argv); }
        else if (!strcmp(a, "to")) { argc--; argv++; need_arg(argc, a); parse_or_die(*argv, &pfx); have_pfx = 1; }
        else if (!strcmp(a, "proxy") || !strcmp(a, "unused") || !strcmp(a, "nomaster")) ;
        else if (!strcmp(a, "help")) return -1;
        else { parse_or_die(a, &pfx); have_pfx = 1; }
        argc--; argv++;
    }
    load_ifs();
    uint32_t only = dev ? dev_or_die(dev)->index : 0;
    MIB_IPNET_TABLE2 *t = NULL;
    DWORD e = GetIpNetTable2((ADDRESS_FAMILY)(g_fam ? g_fam : AF_UNSPEC), &t);
    if (e) return rt_err(e);
    if (g_json) j_begin();
    for (ULONG i = 0; i < t->NumEntries; i++) {
        MIB_IPNET_ROW2 *r = &t->Table[i];
        int fam;
        uint8_t a[16];
        uint32_t sc;
        sa_get(&r->Address, &fam, a, &sc);
        if (ip_is_multicast(fam, a) || ip_is_unspec(fam, a)) continue;
        if (r->InterfaceLuid.Info.IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        if (only && r->InterfaceIndex != only) continue;
        if (have_pfx && (fam != pfx.family || !prefix_match(fam, a, pfx.a, pfx.plen))) continue;
        int maclen = r->PhysicalAddressLength > 8 ? 8 : r->PhysicalAddressLength;
        int macz = 1, macff = maclen > 0;
        for (int k = 0; k < maclen; k++) {
            if (r->PhysicalAddress[k]) macz = 0;
            if (r->PhysicalAddress[k] != 0xFF) macff = 0;
        }
        if (fam == AF_INET && macff && r->State == NlnsPermanent) continue; /* broadcast entries */
        if (nud && !(nud & (1 << r->State))) continue;
        char ip[64], mac[32];
        ip_fmt(ip, fam, a);
        int show_mac = maclen && !macz && r->State != NlnsUnreachable && r->State != NlnsIncomplete;
        if (show_mac) mac_fmt(mac, r->PhysicalAddress, maclen);
        if (g_json) {
            j_open('{');
            j_kstr("dst", ip);
            j_kstr("dev", dev_name(r->InterfaceIndex));
            if (show_mac) j_kstr("lladdr", mac);
            if (r->IsRouter) j_kraw("router", "null");
            j_kopen("state", '[');
            j_vstr(nud_name(r->State));
            j_close(']');
            j_close('}');
            continue;
        }
        cput(fam == AF_INET ? C_V4 : C_V6, ip);
        sb_puts(&g_out, " dev ");
        cput(C_IF, dev_name(r->InterfaceIndex));
        if (show_mac) { sb_puts(&g_out, " lladdr "); cput(C_MAC, mac); }
        if (r->IsRouter) sb_puts(&g_out, " router");
        sb_putc(&g_out, ' ');
        sb_puts(&g_out, nud_name(r->State));
        sb_putc(&g_out, '\n');
    }
    if (g_json) j_end();
    FreeMibTable(t);
    return 0;
}

/* cmd: 0 add, 1 del, 2 replace/change */
static int neigh_modify(int cmd, int argc, char **argv) {
    inaddr dst;
    int have_dst = 0, have_mac = 0, maclen = 0;
    uint8_t mac[8];
    const char *dev = NULL;
    NL_NEIGHBOR_STATE st = NlnsPermanent;
    while (argc > 0) {
        const char *a = *argv;
        if (!strcmp(a, "dev")) { argc--; argv++; need_arg(argc, a); dev = *argv; }
        else if (!strcmp(a, "lladdr")) {
            argc--; argv++; need_arg(argc, a);
            maclen = mac_parse(*argv, mac);
            if (!maclen) { errf("Error: \"%s\" is invalid lladdr.\n", *argv); return 1; }
            have_mac = 1;
        }
        else if (!strcmp(a, "nud")) {
            argc--; argv++; need_arg(argc, a);
            int m = nud_parse(*argv);
            st = m == (1 << NlnsReachable) ? NlnsReachable : m == (1 << NlnsStale) ? NlnsStale : NlnsPermanent;
        }
        else if (!strcmp(a, "router") || !strcmp(a, "proxy") || !strcmp(a, "extern_learn")) ;
        else if (!strcmp(a, "to")) { argc--; argv++; need_arg(argc, a); parse_or_die(*argv, &dst); have_dst = 1; }
        else { parse_or_die(a, &dst); have_dst = 1; }
        argc--; argv++;
    }
    if (!have_dst || !dev) { errf("Device and destination are required arguments.\n"); return 1; }
    iface_t *f = dev_or_die(dev);
    MIB_IPNET_ROW2 row;
    memset(&row, 0, sizeof row);
    sa_set(&row.Address, dst.family, dst.a, 0);
    row.InterfaceIndex = f->index;
    row.InterfaceLuid = f->luid;
    DWORD e;
    if (cmd == 1) {
        e = DeleteIpNetEntry2(&row);
        return e ? rt_err(e) : 0;
    }
    if (!have_mac) { errf("Error: lladdr is required.\n"); return 1; }
    memcpy(row.PhysicalAddress, mac, maclen);
    row.PhysicalAddressLength = maclen;
    row.State = st;
    if (cmd == 2) {
        e = SetIpNetEntry2(&row);
        if (e == ERROR_NOT_FOUND || e == ERROR_FILE_NOT_FOUND) e = CreateIpNetEntry2(&row);
    } else {
        e = CreateIpNetEntry2(&row);
    }
    return e ? rt_err(e) : 0;
}

static int neigh_flush(int argc, char **argv) {
    const char *dev = NULL;
    int all = 0;
    while (argc > 0) {
        if (!strcmp(*argv, "dev")) { argc--; argv++; need_arg(argc, "dev"); dev = *argv; }
        else if (!strcmp(*argv, "all")) all = 1;
        else if (!strcmp(*argv, "nud")) { argc--; argv++; }
        else dev = *argv;
        argc--; argv++;
    }
    if (!dev && !all) { errf("Flush requires arguments.\n"); return 1; }
    load_ifs();
    ADDRESS_FAMILY fam = (ADDRESS_FAMILY)(g_fam ? g_fam : AF_UNSPEC);
    if (dev) {
        DWORD e = FlushIpNetTable2(fam, dev_or_die(dev)->index);
        return e ? rt_err(e) : 0;
    }
    for (int i = 0; i < NIFS; i++) {
        if (iface_is_loopback(&IFS[i])) continue;
        DWORD e = FlushIpNetTable2(fam, IFS[i].index);
        if (e == ERROR_ACCESS_DENIED) return rt_err(e);
    }
    return 0;
}

static int usage_neigh(void) {
    errf("Usage: ip neigh { add | del | change | replace } ADDR [ lladdr LLADDR ] [ nud STATE ] dev DEV\n"
         "       ip neigh { show | flush } [ to PREFIX ] [ dev DEV ] [ nud STATE ]\n"
         "       ip neigh flush all\n"
         "STATE := { permanent | reachable | stale | delay | probe | incomplete | failed | all }\n");
    return 255;
}

static int do_neigh(int argc, char **argv) {
    if (argc < 1) return neigh_show(0, NULL);
    const char *c = *argv;
    if (matches(c, "add")) return neigh_modify(0, argc - 1, argv + 1);
    if (matches(c, "delete")) return neigh_modify(1, argc - 1, argv + 1);
    if (matches(c, "change") || matches(c, "replace")) return neigh_modify(2, argc - 1, argv + 1);
    if (matches(c, "flush")) return neigh_flush(argc - 1, argv + 1);
    if (matches(c, "help")) return usage_neigh();
    int r;
    if (matches(c, "show") || matches(c, "list") || matches(c, "lst")) r = neigh_show(argc - 1, argv + 1);
    else r = neigh_show(argc, argv);
    return r < 0 ? usage_neigh() : r;
}

/* ======================= main ======================= */

static int usage(int code) {
    errf("Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }\n"
         "where  OBJECT := { address | link | route | neigh }\n"
         "       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | -h[uman-readable] |\n"
         "                    -f[amily] { inet | inet6 | link } | -4 | -6 | -0 |\n"
         "                    -o[neline] | -br[ief] | -c[olor] | -j[son] | -p[retty] }\n"
         "lnx-net " LNX_VERSION " for Windows. Device names are Windows interface names\n"
         "(e.g. \"Ethernet\", \"Wi-Fi\"); description, GUID or index also work.\n");
    return code;
}

int wmain(int argc, wchar_t **wargv) {
    char **argv = argv_utf8(argc, wargv);
    out_init();
    argc--; argv++;
    int color_mode = 0; /* 0 never, 1 always, 2 auto */
    while (argc > 0 && argv[0][0] == '-') {
        char *o = argv[0] + 1;
        if (*o == '-') o++;
        if (!*o) { argc--; argv++; break; }
        char *eq = strchr(o, '=');
        if (eq) *eq = 0;
        if (!strcmp(o, "4")) g_fam = AF_INET;
        else if (!strcmp(o, "6")) g_fam = AF_INET6;
        else if (!strcmp(o, "0")) g_fam = -1;
        else if (matches(o, "family") && strlen(o) >= 1 && o[0] == 'f') {
            const char *v = eq ? eq + 1 : (argc > 1 ? (argc--, argv++, argv[0]) : NULL);
            if (!v) return usage(255);
            if (!strcmp(v, "inet")) g_fam = AF_INET;
            else if (!strcmp(v, "inet6")) g_fam = AF_INET6;
            else if (!strcmp(v, "link")) g_fam = -1;
            else { errf("Error: argument \"%s\" is wrong: invalid address family\n", v); return 255; }
        }
        else if (!strcmp(o, "br") || matches(o, "brief") && strlen(o) >= 2) g_brief = 1;
        else if (matches(o, "statistics") || matches(o, "stats")) g_stats++;
        else if (matches(o, "details")) g_details = 1;
        else if (matches(o, "human-readable") || matches(o, "human")) g_human = 1;
        else if (matches(o, "oneline")) g_oneline = 1;
        else if (matches(o, "json")) g_json = 1;
        else if (matches(o, "pretty")) g_pretty = 1;
        else if (matches(o, "color") || matches(o, "colour")) {
            color_mode = 1;
            if (eq) {
                if (!strcmp(eq + 1, "auto")) color_mode = 2;
                else if (!strcmp(eq + 1, "never")) color_mode = 0;
            }
        }
        else if (matches(o, "Version")) { sb_puts(&g_out, "ip utility, lnx-net " LNX_VERSION " (Windows)\n"); out_flush(); return 0; }
        else if (matches(o, "help")) return usage(0);
        else if (matches(o, "resolve") || matches(o, "all") || matches(o, "timestamp") || matches(o, "force")) ;
        else { errf("Option \"%s\" is unknown, try \"ip -help\".\n", argv[0]); return 255; }
        argc--; argv++;
    }
    if (g_fam == -1) g_fam = 0;
    if (color_mode == 1 || (color_mode == 2 && out_is_console())) {
        if (!g_json) { g_color = 1; out_enable_vt(); }
    }
    if (argc < 1) return usage(255);
    const char *obj = argv[0];
    int rc;
    argc--; argv++;
    if (matches(obj, "address")) rc = do_addr(argc, argv);
    else if (matches(obj, "route")) rc = do_route(argc, argv);
    else if (matches(obj, "neighbor") || matches(obj, "neighbour")) rc = do_neigh(argc, argv);
    else if (matches(obj, "link")) rc = do_link(argc, argv);
    else if (matches(obj, "help")) rc = usage(0);
    else if (matches(obj, "rule") || matches(obj, "tunnel") || matches(obj, "maddress") || matches(obj, "monitor") ||
             matches(obj, "netns") || matches(obj, "xfrm") || matches(obj, "mroute") || matches(obj, "tuntap") ||
             matches(obj, "vrf") || matches(obj, "nexthop") || matches(obj, "netconf") || matches(obj, "token")) {
        errf("Object \"%s\" is not supported on Windows.\n", obj);
        rc = 1;
    } else {
        errf("Object \"%s\" is unknown, try \"ip help\".\n", obj);
        rc = 1;
    }
    out_flush();
    return rc;
}
