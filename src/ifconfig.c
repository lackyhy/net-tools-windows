/* ifconfig - configure a network interface (net-tools style) for Windows */
#include "common.h"

static void bytes_h(char *d, uint64_t v) {
    const char *u[] = {"B", "KB", "MB", "GB", "TB", "PB"};
    double x = (double)v;
    int i = 0;
    while (x >= 1000.0 && i < 5) { x /= 1000.0; i++; }
    sprintf(d, "%.1f %s", x, u[i]);
}

static unsigned iff_flags(const iface_t *f, sbuf *names) {
    unsigned fl = 0;
    int lo = iface_is_loopback(f), p2p = iface_is_p2p(f);
    struct { unsigned bit; const char *n; int on; } t[] = {
        {0x1, "UP", f->admin_up},
        {0x2, "BROADCAST", !lo && !p2p},
        {0x8, "LOOPBACK", lo},
        {0x10, "POINTOPOINT", p2p},
        {0x40, "RUNNING", f->oper_up},
        {0x80, "NOARP", p2p},
        {0x1000, "MULTICAST", !lo && !p2p && !f->no_mcast},
    };
    int first = 1;
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        if (!t[i].on) continue;
        fl |= t[i].bit;
        if (!first) sb_putc(names, ',');
        sb_puts(names, t[i].n);
        first = 0;
    }
    return fl;
}

static void mask4(int plen, char *d) {
    uint32_t m = plen ? 0xFFFFFFFFu << (32 - plen) : 0;
    uint8_t b[4] = {(uint8_t)(m >> 24), (uint8_t)(m >> 16), (uint8_t)(m >> 8), (uint8_t)m};
    ip_fmt(d, AF_INET, b);
}

static void print_iface(const iface_t *f) {
    sbuf fn = {0};
    sb_puts(&fn, "");
    unsigned fl = iff_flags(f, &fn);
    sb_printf(&g_out, "%s: flags=%u<%s>  mtu %u\n", f->name, fl, fn.p, f->mtu);
    free(fn.p);
    for (int i = 0; i < f->naddr; i++) {
        const ifaddr_t *a = &f->addr[i];
        char ip[64], m[64];
        ip_fmt(ip, a->family, a->a);
        if (a->family == AF_INET) {
            mask4(a->plen, m);
            sb_printf(&g_out, "        inet %s  netmask %s", ip, m);
            if (a->plen < 31 && !iface_is_loopback(f)) {
                uint32_t v = ((uint32_t)a->a[0] << 24) | ((uint32_t)a->a[1] << 16) | ((uint32_t)a->a[2] << 8) | a->a[3];
                uint32_t mk = a->plen ? 0xFFFFFFFFu << (32 - a->plen) : 0;
                v |= ~mk;
                uint8_t b[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v};
                char bs[64];
                ip_fmt(bs, AF_INET, b);
                sb_printf(&g_out, "  broadcast %s", bs);
            }
            sb_putc(&g_out, '\n');
        } else {
            const char *sc = ip_scope_name(AF_INET6, a->a);
            int sid = !strcmp(sc, "host") ? 0x10 : !strcmp(sc, "link") ? 0x20 : !strcmp(sc, "site") ? 0x40 : 0;
            sb_printf(&g_out, "        inet6 %s  prefixlen %d  scopeid 0x%x<%s>\n", ip, a->plen, sid,
                      !strcmp(sc, "global") ? "global" : sc);
        }
    }
    if (iface_is_loopback(f)) {
        sb_puts(&g_out, "        loop  txqueuelen 1000  (Local Loopback)\n");
    } else if (f->maclen == 6) {
        char mac[32];
        mac_fmt(mac, f->mac, 6);
        sb_printf(&g_out, "        ether %s  txqueuelen 1000  (%s)\n", mac,
                  f->type == IF_TYPE_IEEE80211 ? "Wi-Fi" : "Ethernet");
    } else {
        sb_printf(&g_out, "        unspec  txqueuelen 1000  (%s)\n", f->type == IF_TYPE_TUNNEL ? "Tunnel" : "UNSPEC");
    }
    if (f->have_row) {
        const MIB_IF_ROW2 *r = &f->row;
        char h[32];
        bytes_h(h, r->InOctets);
        sb_printf(&g_out, "        RX packets %llu  bytes %llu (%s)\n",
                  (unsigned long long)(r->InUcastPkts + r->InNUcastPkts), (unsigned long long)r->InOctets, h);
        sb_printf(&g_out, "        RX errors %llu  dropped %llu  overruns 0  frame 0\n",
                  (unsigned long long)r->InErrors, (unsigned long long)r->InDiscards);
        bytes_h(h, r->OutOctets);
        sb_printf(&g_out, "        TX packets %llu  bytes %llu (%s)\n",
                  (unsigned long long)(r->OutUcastPkts + r->OutNUcastPkts), (unsigned long long)r->OutOctets, h);
        sb_printf(&g_out, "        TX errors %llu  dropped %llu overruns 0  carrier 0  collisions 0\n",
                  (unsigned long long)r->OutErrors, (unsigned long long)r->OutDiscards);
    }
    sb_putc(&g_out, '\n');
}

static void print_short(iface_t *v, int n, int all) {
    int w = 9;
    for (int i = 0; i < n; i++) {
        int x = utf8_width(v[i].name);
        if (x > w) w = x;
    }
    sb_padstr(&g_out, "Iface", w, 0);
    sb_puts(&g_out, "      MTU    RX-OK RX-ERR RX-DRP RX-OVR    TX-OK TX-ERR TX-DRP TX-OVR Flg\n");
    for (int i = 0; i < n; i++) {
        iface_t *f = &v[i];
        if (!all && !f->oper_up) continue;
        const MIB_IF_ROW2 *r = &f->row;
        char flg[8];
        int k = 0;
        if (!iface_is_loopback(f) && !iface_is_p2p(f)) flg[k++] = 'B';
        if (iface_is_loopback(f)) flg[k++] = 'L';
        if (!iface_is_loopback(f) && !f->no_mcast && !iface_is_p2p(f)) flg[k++] = 'M';
        if (iface_is_p2p(f)) flg[k++] = 'P';
        if (f->oper_up) flg[k++] = 'R';
        if (f->admin_up) flg[k++] = 'U';
        flg[k] = 0;
        sb_padstr(&g_out, f->name, w, 0);
        sb_printf(&g_out, " %8u %8llu %6llu %6llu %6u %8llu %6llu %6llu %6u %s\n", f->mtu,
                  (unsigned long long)(r->InUcastPkts + r->InNUcastPkts), (unsigned long long)r->InErrors,
                  (unsigned long long)r->InDiscards, 0u,
                  (unsigned long long)(r->OutUcastPkts + r->OutNUcastPkts), (unsigned long long)r->OutErrors,
                  (unsigned long long)r->OutDiscards, 0u, flg);
    }
}

static int report(DWORD e, const char *what) {
    if (!e) return 0;
    if (e == ERROR_ACCESS_DENIED) errf("SIOCSIF%s: Operation not permitted (run as Administrator)\n", what);
    else if (e == ERROR_OBJECT_ALREADY_EXISTS) errf("SIOCSIF%s: File exists\n", what);
    else errf("SIOCSIF%s: %s\n", what, win_errmsg(e));
    return 1;
}

static int addr_op(iface_t *f, int add, const char *spec, const char *netmask) {
    inaddr ia;
    if (!ip_parse(spec, 0, &ia)) { errf("%s: Unknown host\n", spec); return 1; }
    if (netmask && ia.family == AF_INET) {
        inaddr m;
        if (!ip_parse(netmask, AF_INET, &m) || m.family != AF_INET) { errf("%s: Unknown host\n", netmask); return 1; }
        uint32_t v = ((uint32_t)m.a[0] << 24) | ((uint32_t)m.a[1] << 16) | ((uint32_t)m.a[2] << 8) | m.a[3];
        int p = 0;
        while (p < 32 && (v & (0x80000000u >> p))) p++;
        ia.plen = p;
    } else if (!ia.has_plen && ia.family == AF_INET) {
        ia.plen = ia.a[0] < 128 ? 8 : ia.a[0] < 192 ? 16 : 24; /* classful default like net-tools */
    } else if (!ia.has_plen) {
        ia.plen = 64;
    }
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = f->luid;
    row.InterfaceIndex = f->index;
    sa_set(&row.Address, ia.family, ia.a, 0);
    row.OnLinkPrefixLength = (UINT8)ia.plen;
    row.DadState = IpDadStatePreferred;
    return report(add ? CreateUnicastIpAddressEntry(&row) : DeleteUnicastIpAddressEntry(&row), "ADDR");
}

static int netsh_admin(iface_t *f, int up) {
    wchar_t cmd[700];
    _snwprintf(cmd, 700, L"netsh.exe interface set interface name=\"%s\" admin=%s", f->wname,
               up ? L"enabled" : L"disabled");
    cmd[699] = 0;
    STARTUPINFOW si = {sizeof si};
    PROCESS_INFORMATION pi;
    out_flush();
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        win_errf(GetLastError(), "netsh: ");
        return 1;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code != 0;
}

static int set_mtu(iface_t *f, unsigned long mtu) {
    DWORD last = ERROR_NOT_FOUND;
    int ok = 0;
    for (int k = 0; k < 2; k++) {
        MIB_IPINTERFACE_ROW r;
        InitializeIpInterfaceEntry(&r);
        r.Family = k ? AF_INET6 : AF_INET;
        r.InterfaceLuid = f->luid;
        if (GetIpInterfaceEntry(&r) != NO_ERROR) continue;
        if (r.Family == AF_INET) r.SitePrefixLength = 0;
        r.NlMtu = mtu;
        DWORD e = SetIpInterfaceEntry(&r);
        if (!e) ok = 1; else last = e;
    }
    return ok ? 0 : report(last, "MTU");
}

static void usage(void) {
    errf("Usage:\n"
         "  ifconfig [-a] [-s] [interface]\n"
         "  ifconfig <interface> [up|down] [mtu <NN>]\n"
         "  ifconfig <interface> [add|del <address>[/<prefixlen>]]\n"
         "  ifconfig <interface> <address> [netmask <mask>]   (adds the address)\n"
         "  -a  show all interfaces, including those that are down\n"
         "  -s  short list (like netstat -i)\n"
         "lnx-net " LNX_VERSION " for Windows. Interface = Windows name (\"Ethernet\", \"Wi-Fi\"), index or description.\n");
}

int wmain(int argc, wchar_t **wargv) {
    char **argv = argv_utf8(argc, wargv);
    out_init();
    int all = 0, shrt = 0, i = 1;
    for (; i < argc && argv[i][0] == '-'; i++) {
        if (!strcmp(argv[i], "-a")) all = 1;
        else if (!strcmp(argv[i], "-s")) shrt = 1;
        else if (!strcmp(argv[i], "-v")) ;
        else if (!strcmp(argv[i], "-V") || !strcmp(argv[i], "--version")) {
            sb_puts(&g_out, "net-tools ifconfig, lnx-net " LNX_VERSION " (Windows)\n");
            out_flush();
            return 0;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(); return 0; }
        else { errf("ifconfig: option `%s' not recognised.\n", argv[i]); usage(); return 1; }
    }
    iface_t *v;
    int n = ifaces_load(&v);
    if (n < 0) return 1;
    if (i >= argc) {
        if (shrt) print_short(v, n, all);
        else
            for (int k = 0; k < n; k++)
                if (all || v[k].oper_up) print_iface(&v[k]);
        out_flush();
        return 0;
    }
    iface_t *f = iface_find(v, n, argv[i]);
    if (!f) { errf("%s: error fetching interface information: Device not found\n", argv[i]); return 1; }
    i++;
    if (i >= argc) {
        if (shrt) {
            iface_t one = *f;
            print_short(&one, 1, 1);
        } else print_iface(f);
        out_flush();
        return 0;
    }
    int rc = 0;
    while (i < argc && !rc) {
        const char *a = argv[i++];
        if (!strcmp(a, "up")) rc = netsh_admin(f, 1);
        else if (!strcmp(a, "down")) rc = netsh_admin(f, 0);
        else if (!strcmp(a, "mtu")) {
            if (i >= argc) { usage(); return 1; }
            rc = set_mtu(f, strtoul(argv[i++], NULL, 10));
        }
        else if (!strcmp(a, "add") || !strcmp(a, "del")) {
            if (i >= argc) { usage(); return 1; }
            rc = addr_op(f, a[0] == 'a', argv[i++], NULL);
        }
        else if (!strcmp(a, "netmask") || !strcmp(a, "broadcast")) {
            errf("ifconfig: \"%s\" must follow an address\n", a);
            return 1;
        }
        else if (!strcmp(a, "-arp") || !strcmp(a, "arp") || !strcmp(a, "promisc") || !strcmp(a, "-promisc") ||
                 !strcmp(a, "hw") || !strcmp(a, "txqueuelen") || !strcmp(a, "multicast") || !strcmp(a, "-multicast") ||
                 !strcmp(a, "pointopoint") || !strcmp(a, "dstaddr")) {
            errf("ifconfig: \"%s\" is not supported on Windows\n", a);
            return 1;
        }
        else {
            const char *mask = NULL;
            if (i + 1 < argc && !strcmp(argv[i], "netmask")) { mask = argv[i + 1]; i += 2; }
            if (i + 1 < argc && !strcmp(argv[i], "broadcast")) i += 2;
            rc = addr_op(f, 1, a, mask);
        }
    }
    out_flush();
    return rc;
}
